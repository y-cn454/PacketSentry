package com.packetsentry.core;

import com.packetsentry.detect.LocalRules;
import com.packetsentry.detect.LogicHints;
import com.packetsentry.detect.Pivot;
import com.packetsentry.detect.PiiScanner;
import com.packetsentry.sanitize.Sanitizer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 实时抓包管道 —— 把 Burp 的每个报文变成一条本地画像，并做去重。
 *
 * <h3>为什么必须异步</h3>
 * {@link #submit} 会被 {@code IHttpListener.processHttpMessage} 调用，
 * 也就是 Burp 处理的<b>每一个</b>报文都会走一次。在里面做解析、扫描、脱敏
 * 会乘以报文总数，直接拖慢整个 Burp。
 * 所以这里只做一件事：<b>把数据塞进有界队列，立刻返回</b>。
 * 真正的扫描和脱敏由一条后台线程消费。
 *
 * <h3>去重是这个类存在的最大理由</h3>
 * 一个真实 Web 渗透会话里 90% 以上的包是<b>重复的接口调用</b>：
 * {@code GET /api/product/1001}、{@code /1002}、{@code /1003}……
 * 结构完全一样，只有 ID 不同。全送 AI 既费钱又没信息量。
 * 去重键是 {@code 方法 + 路径模板 + 参数名集合}，
 * 数字段被归一化成 {@code {n}}，所以上例只算一个结构。
 *
 * <h3>有界队列</h3>
 * 队列满了就丢弃并计数，<b>绝不阻塞 Burp</b>。
 * 抓包场景下「漏几个包」远比「Burp 卡住」可接受。
 */
public final class RealtimePipe {

    /**
     * 队列容量。
     *
     * <p>原来是 512，实测中发现偏小：一次页面加载的突发能到 50-100 个，
     * 而 Intruder 多线程扫描可以瞬间灌几千个，512 会大量丢弃。
     * 现在放到 2048 —— 每个 Job 只持有两个 byte[] 引用，
     * 典型 10 KB 报文下最坏内存占用约 2048 × 2 × 10 KB ≈ 40 MB。
     *
     * <p><b>仍然有界</b>：满了就丢弃并计数，绝不阻塞 Burp。
     * 抓包场景下「漏几个包」远比「Burp 卡住」可接受。
     */
    private static final int QUEUE_CAPACITY = 2048;

    /** 队列里的一项：极轻量，只存必要信息。 */
    private static final class Job {
        final byte[] request;
        final byte[] response;
        final int toolFlag;
        final boolean isRequest;
        final burp.IHttpService service;

        Job(byte[] request, byte[] response, int toolFlag, boolean isRequest,
            burp.IHttpService service) {
            this.request = request;
            this.response = response;
            this.toolFlag = toolFlag;
            this.isRequest = isRequest;
            this.service = service;
        }
    }

    /** 记录回调。实现方要保证<b>不阻塞</b>（UI 侧请自行 invokeLater）。 */
    public interface Listener {
        void onRecord(PacketRecord record);

        /** 队列溢出时通知一次。 */
        default void onOverflow(long totalDropped) {
        }
    }

    private final Supplier<Config> configSupplier;
    private final List<Listener> listeners = new java.util.concurrent.CopyOnWriteArrayList<>();

    private final ArrayBlockingQueue<Job> queue = new ArrayBlockingQueue<>(QUEUE_CAPACITY);
    /**
     * 去重签名表。
     *
     * <p>▲ 必须有上界。这个 bug 是「内存与资源上界」测试逼出来的：
     * 早期版本是无界的 {@code ConcurrentHashMap.newKeySet()}。
     * 绝大多数站点签名数是有限的（接口数量级），但<b>高基数路径</b>
     * 会把它撑爆 —— 例如目标用 {@code /download/<随机ID>} 这种路径时，
     * 每个请求都会产生一个全新签名。实测灌 3000 个随机 ID 就涨到 2062 条，
     * 挂一整天可以涨到任意大。
     *
     * <p>到界之后的行为是<b>优雅降级</b>：不再记录新签名，
     * 于是新出现的结构一律按「非重复」处理（照常分析，只是省不下钱）。
     * 这比 OOM 或者清空整张表（会让已分析过的接口重新被分析、成本突增）都更温和。
     */
    private final Set<String> seenSignatures = ConcurrentHashMap.newKeySet();
    private static final int SIGNATURES_MAX = 20000;
    private final AtomicLong dedupOverflow = new AtomicLong();

    /**
     * 请求阶段挂起表，键是 Burp 的 IHttpRequestResponse 对象身份。
     * 用于把「请求+响应」两次回调合并成一条记录。
     */
    private final Map<Object, Pending> pending = new java.util.concurrent.ConcurrentHashMap<>();
    private static final int PENDING_MAX = 512;
    private static final long PENDING_TIMEOUT_MS = 5000;
    private final AtomicLong overflows = new AtomicLong();
    /** 最近 N 条记录，供 UI 展示 / 选中分析。 */
    private final List<PacketRecord> recent =
            Collections.synchronizedList(new ArrayList<>());
    private static final int RECENT_MAX = 500;

    private final AtomicInteger seq = new AtomicInteger();
    private final AtomicLong dropped = new AtomicLong();

    // 全量计数器。刻意与 `recent` 列表分开：
    // recent 只保留最近 RECENT_MAX 条用于界面展示，但「省了多少钱」这个数字
    // 必须是全量统计，否则会随窗口滑动而失真（实测中确实把 1820 个包统计成了 500 个）。
    private final AtomicLong processed = new AtomicLong();
    private final AtomicLong countLow = new AtomicLong();
    private final AtomicLong countDup = new AtomicLong();
    private final AtomicLong countWorth = new AtomicLong();
    private final AtomicLong countIssues = new AtomicLong();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private Thread worker;

    private final Sanitizer sanitizer = new Sanitizer();
    /** 业务逻辑线索引擎 —— 看的是「一串」报文，不是单个。 */
    private final LogicHints logicHints = new LogicHints();
    private final PiiScanner scanner = new PiiScanner();

    public RealtimePipe(Supplier<Config> configSupplier) {
        this.configSupplier = configSupplier;
    }

    // ==================================================================
    // 生命周期
    // ==================================================================

    public void addListener(Listener l) {
        if (l != null) {
            listeners.add(l);
        }
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        worker = new Thread(this::loop, "packetsentry-pipe");
        worker.setDaemon(true);          // 不阻止 JVM 退出
        worker.start();
    }

    public void stop() {
        running.set(false);
        Thread w = worker;
        if (w != null) {
            w.interrupt();
        }
    }

    /** 暂停处理（队列仍然接收，只是不消费）。用于用户想停下来看的时候。 */
    public void setPaused(boolean p) {
        paused.set(p);
    }

    public boolean isPaused() {
        return paused.get();
    }

    /**
     * 清空去重表和最近记录 —— 相当于「开始一个新会话」。
     *
     * <p>▲ 必须连 {@code pending} 一起清。
     * 这个 bug 是并发/生命周期测试逼出来的：早期版本漏了这一句，
     * 于是点「清空」之后，旧会话里那些「只发了请求、响应一直没来」的挂起项
     * 会在 5 秒超时后被冲进<b>新会话</b>—— 用户会看到「清空完又冒出一条旧记录」。
     */
    public void reset() {
        seenSignatures.clear();
        logicHints.reset();
        pending.clear();
        synchronized (recent) {
            recent.clear();
        }
        seq.set(0);
        dropped.set(0);
        dedupOverflow.set(0);
    }

    // ==================================================================
    // 入口 —— 必须极快
    // ==================================================================

    /**
     * 从 {@code processHttpMessage} 调用。
     *
     * <p><b>这个方法必须立刻返回。</b> 它只做入队，不做任何解析。
     *
     * <h4>▲ 为什么需要 transactionKey</h4>
     * Burp 对一个 HTTP 事务会调用 {@code processHttpMessage} <b>两次以上</b>：
     * 请求发出时一次（此时 {@code getResponse()} 为 null），响应到达时再一次。
     * 早期版本两次都入队，结果<b>每个事务产生两条记录、漏洞被报两遍</b>。
     *
     * <p>修法：用 {@code System.identityHashCode(message)} 做关联键 ——
     * Burp 对同一事务的两次回调传的是<b>同一个 IHttpRequestResponse 对象</b>。
     * 请求阶段先挂起，响应阶段合并成一条记录发出。
     * 如果响应一直不来（请求失败 / 被丢弃），由后台线程超时冲刷。
     */
    public void submit(byte[] request, byte[] response, int toolFlag, boolean isRequest,
                       Object transactionKey, burp.IHttpService service) {
        if (!running.get()) {
            return;
        }

        // 响应阶段（或请求阶段但已经有响应）→ 完整事务，直接入队
        boolean complete = response != null && response.length > 0;
        if (complete) {
            pending.remove(transactionKey);
            enqueue(new Job(request, response, toolFlag, false, service));
            return;
        }

        // 请求阶段且暂无响应 → 先挂起，等响应阶段合并。
        // 只保留有界的挂起表，避免请求从不返回时无限增长。
        if (pending.size() > PENDING_MAX) {
            pending.clear();
            overflows.incrementAndGet();
        }
        pending.put(transactionKey, new Pending(System.currentTimeMillis(), request, toolFlag, service));
    }

    /** 超时冲刷请求阶段挂起的项 —— 那些请求永远没等到响应。 */
    private void flushStalePending() {
        if (pending.isEmpty()) {
            return;
        }
        long now = System.currentTimeMillis();
        java.util.List<Object> stale = new java.util.ArrayList<>();
        for (Map.Entry<Object, Pending> e : pending.entrySet()) {
            if (now - e.getValue().at > PENDING_TIMEOUT_MS) {
                stale.add(e.getKey());
            }
        }
        for (Object k : stale) {
            Pending p = pending.remove(k);
            if (p != null) {
                enqueue(new Job(p.request, null, p.toolFlag, true, p.service));
            }
        }
    }

    private void enqueue(Job j) {
        if (!queue.offer(j)) {
            long n = dropped.incrementAndGet();
            if (n == 1 || n % 100 == 0) {
                for (Listener l : listeners) {
                    l.onOverflow(n);
                }
            }
        }
    }

    /** 挂起中的请求（等待响应）。 */
    private static final class Pending {
        final long at;
        final byte[] request;
        final int toolFlag;
        final burp.IHttpService service;

        Pending(long at, byte[] request, int toolFlag, burp.IHttpService service) {
            this.at = at;
            this.request = request;
            this.toolFlag = toolFlag;
            this.service = service;
        }
    }

    // ==================================================================
    // 后台消费
    // ==================================================================

    private void loop() {
        long lastFlush = 0;
        while (running.get()) {
            try {
                // ▲ 暂停必须在 poll <b>之前</b>判断 —— 不能「取出来再放回去」。
                //
                //    这个 bug 是并发/生命周期测试逼出来的，而且挺严重：
                //    早期写法是 poll 之后才发现暂停，于是把任务 offer 回队尾。
                //    但队列容量有限（2048）—— 一旦队列是满的，这个 offer 就失败，
                //    任务被<b>静默丢弃</b>并只计入一个 dropped 数字。
                //    实测「暂停期间提交 2600 条」会丢 552 条，
                //    用户暂停一下回来就少了几百个包，而且不知道丢了什么。
                //
                //    那种写法还有个副作用：暂停期间消费者仍在「取出-放回」旋转，
                //    队列顺序被打乱。
                //
                //    正确做法：暂停时直接睡，<b>完全不碰队列</b>。
                if (paused.get()) {
                    Thread.sleep(100);
                    continue;
                }

                Job j = queue.poll(200, TimeUnit.MILLISECONDS);

                // 定期冲刷「只发了请求、永远没等到响应」的挂起项
                long now = System.currentTimeMillis();
                if (now - lastFlush > 1000) {
                    lastFlush = now;
                    flushStalePending();
                }

                if (j == null) {
                    continue;
                }
                PacketRecord r = build(j);
                if (r != null) {
                    synchronized (recent) {
                        recent.add(r);
                        if (recent.size() > RECENT_MAX) {
                            recent.remove(0);
                        }
                    }
                    for (Listener l : listeners) {
                        l.onRecord(r);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Throwable t) {
                // 单个包处理失败不能弄死整条管道
                // （这里刻意不静默 —— 打到 stderr，Burp 会把扩展的 stderr 显示出来）
                System.err.println("[PacketSentry] 处理报文失败：" + t);
            }
        }
    }

    // ==================================================================
    // 构造画像
    // ==================================================================

    private PacketRecord build(Job j) {
        Config cfg = configSupplier.get();
        boolean hasResp = j.response != null && j.response.length > 0;
        byte[] msg = hasResp ? j.response : j.request;
        if (msg == null || msg.length == 0) {
            return null;
        }

        // ▲ 分析主体必须是<b>请求</b>，响应只作为附加上下文。
        //    早期版本把「有响应就用响应」当成分析对象，结果 brief 变成了
        //    「从响应体提参数名 + 响应体当请求体」，完全错位。
        String reqRaw = j.request == null ? "" : new String(j.request, StandardCharsets.UTF_8);

        // ⚠️ 二进制响应<b>不能</b>转成字符串参与扫描。
        //
        //    实测漏过一个 HLS 视频分片：
        //      GET mts.xxx.mobi/video5/xxx.ts   Content-Type: binary/octet-stream
        //    它的 MIME 不是 video/*（所以 isLowValue 放过了），扩展名 .ts 也有歧义
        //    （HLS 视频分片 / TypeScript 都用它）。于是它被：
        //      ① 当成 UTF-8 字符串扫了一遍 —— 二进制里恰好有 `<%=` → 误报「源码泄露」
        //      ② 整段塞进 AI prompt —— 模型吃进一堆乱码，请求直接失败
        //    所以先用字节判断，二进制就一律当空响应对待。
        boolean respBinary = hasResp && looksBinary(j.response);
        String respRaw = respBinary
                ? ""
                : (j.response == null ? "" : new String(j.response, StandardCharsets.UTF_8));

        Meta meta = parseMeta(hasResp ? reqRaw : new String(msg, StandardCharsets.UTF_8), true);
        if (hasResp) {
            meta.status = parseStatus(respRaw);
            String mime = mimeOf(respRaw);
            if (!mime.isEmpty()) {
                meta.mime = mime;
            }
        }

        // 扫描与脱敏都针对请求（这是被测对象）
        PiiScanner.Report scan = cfg.scanEnabled ? scanner.scan(reqRaw) : null;

        Sanitizer.Result san = null;
        if (cfg.sanitizeEnabled) {
            Sanitizer s = new Sanitizer(parseStrategy(cfg.maskStrategy),
                    cfg.layerHeaders, cfg.layerFields, cfg.layerValues);
            san = s.sanitize(reqRaw);
        }

        // ---- 本地业务规则：作用推断 + 漏洞检测（零成本，零网络）----
        // 用<b>原始</b>报文而不是脱敏后的 —— 漏洞检测要判断「响应里有没有回显
        // 请求里的密码」，脱敏后两边都被抹掉就比不出来了。
        String purpose = LocalRules.inferPurpose(meta.method, meta.path);
        String signature = signature(meta, reqRaw);
        java.util.List<LocalRules.Issue> issues =
                LocalRules.detect(reqRaw, respRaw, scan, cfg.rangeMode);
        // 业务逻辑线索：需要看「一串」报文才能得出的结论
        // （ID 可预测、金额可控、可重复提交、频控缺失…），单独一个引擎算。
        issues.addAll(logicHints.analyze(signature, reqRaw, respRaw));

        // ▲ 本地发现必须在 buildBrief <b>之前</b>算出来，并且传给 buildBrief。
        //
        //    这是踩过坑才调的顺序。原来的顺序是先 buildBrief 再检测，
        //    结果 brief 里<b>完全不含本地结论</b> —— AI 拿到的只有「报文长什么样」，
        //    不知道插件已经判定「CRITICAL Flag」。
        //
        //    症状就是用户反馈的那句：「已经确定包有漏洞却还是在分析可能性」。
        //    明明 flag 已经在响应里了，AI 还在写「疑似敏感信息泄露」。
        //    根因不是提示词写得不好，是<b>AI 缺少「哪些已经确认」这个前提</b>。
        String brief = san != null ? san.cleanText : reqRaw;
        brief = buildBrief(meta, brief, cfg.maxBodyChars, respRaw,
                cfg.sanitizeEnabled, issues);

        // 延伸测试方向 —— <b>机械推导</b>，不靠 AI 自由发挥。
        //
        // 用户反馈过「无法根据这个包的漏洞延伸其他漏洞」。
        // 把「已知」系统展开成「待验证」这件事，一部分是纯机械的
        // （既然 /page/edit/1 返回了 flag，/page/edit/2 显然值得试），
        // 做成规则表比指望 AI 每次都想得到更可靠，而且零成本。
        // 推导结果一并塞进 brief，让 AI 在此基础上补充，而不是从零想。
        String pivotText = Pivot.toPromptText(Pivot.derive(issues, meta.method,
                meta.path, meta.host, hasBusinessAuth(san != null ? san.cleanText : reqRaw)));
        if (!pivotText.isEmpty()) {
            brief = brief + "\n\n" + pivotText;
        }

        // ⭐ 二进制响应一律算低价值 —— 它既不会被本地规则分析，也不该送去 AI。
        boolean lowValue = isLowValue(meta, cfg) || respBinary;

        // ▲ 低价值报文<b>不进去重表</b>。
        //    实测发现：600 个 /static/chunk{n}.js 虽然都被正确判为低价值，
        //    却仍然注册了 600 个唯一签名，把去重表撑到 623 条
        //    （真正有意义的只有 23 条）。既然永远不会分析它们，
        //    就没有理由为它们分配去重记录。
        boolean dup;
        if (lowValue) {
            dup = false;
        } else if (seenSignatures.size() >= SIGNATURES_MAX) {
            // 到界了：不再记录新签名，一律按「非重复」处理。
            // 代价是省不下钱，但内存有界、且不会把已分析过的接口重新分析一遍。
            dedupOverflow.incrementAndGet();
            dup = false;
        } else {
            dup = !seenSignatures.add(signature);
        }

        // 计数器独立于 recent 列表 —— recent 只保留最近 RECENT_MAX 条用于展示，
        // 但统计必须是全量，否则「省了多少钱」这个数字会随窗口滑动而失真。
        processed.incrementAndGet();
        if (lowValue) {
            countLow.incrementAndGet();
        } else if (dup) {
            countDup.incrementAndGet();
        } else {
            countWorth.incrementAndGet();
        }
        if (!issues.isEmpty()) {
            countIssues.incrementAndGet();
        }

        return new PacketRecord(
                seq.incrementAndGet(), j.toolFlag, !hasResp,
                meta.method, meta.host, meta.path, meta.status, meta.mime, msg.length,
                scan, san, brief, signature, dup, lowValue,
                purpose, issues, j.request, j.response, j.service);
    }

    /** 报文的元信息。 */
    private static final class Meta {
        String method = "?";
        String host = "";
        String path = "";
        int status = 0;
        String mime = "";
    }

    private Meta parseMeta(String raw, boolean isRequest) {
        Meta m = new Meta();
        int lineEnd = raw.indexOf('\n');
        String firstLine = lineEnd < 0 ? raw : raw.substring(0, lineEnd).trim();

        if (isRequest) {
            String[] parts = firstLine.split("\\s+");
            if (parts.length >= 2) {
                m.method = parts[0];
                m.path = stripQuery(parts[1]);
            }
        } else {
            String[] parts = firstLine.split("\\s+");
            if (parts.length >= 2) {
                try {
                    m.status = Integer.parseInt(parts[1]);
                } catch (NumberFormatException ignored) {
                    // 状态行不是标准格式，保留 0
                }
            }
        }

        // 头区扫一遍找 Host / Content-Type
        int headEnd = raw.indexOf("\r\n\r\n");
        if (headEnd < 0) {
            headEnd = raw.indexOf("\n\n");
        }
        String head = headEnd < 0 ? raw : raw.substring(0, headEnd);
        for (String line : head.split("\r?\n")) {
            String lower = line.toLowerCase();
            if (lower.startsWith("host:")) {
                m.host = line.substring(5).trim();
            } else if (lower.startsWith("content-type:")) {
                String ct = line.substring(13).trim();
                int semi = ct.indexOf(';');
                m.mime = semi > 0 ? ct.substring(0, semi).trim() : ct;
            }
        }
        return m;
    }

    private static String stripQuery(String path) {
        int q = path.indexOf('?');
        return q > 0 ? path.substring(0, q) : path;
    }

    // ------------------------------------------------------------------
    // 去重签名
    // ------------------------------------------------------------------

    private static final Pattern NUMERIC_SEG = Pattern.compile("/\\d+(?=/|$)");
    private static final Pattern UUID_SEG = Pattern.compile(
            "/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    /** 段内的数字串 —— 处理 chunk123.js / resource0 / item42 这类。 */
    private static final Pattern DIGIT_RUN = Pattern.compile("\\d+");

    /**
     * 版本号段 —— 这些段里的数字<b>不能</b>归一化。
     *
     * <p>▲ 这个常量是「语义正确性测试」逼出来的，属于<b>漏漏洞</b>级别的问题：
     * 早期实现无差别地把所有数字串换成 {@code {n}}，于是
     * {@code /api/v1/admin/users}、{@code /api/v2/admin/users}、
     * {@code /api/v3/admin/users} 全变成 {@code /api/v{n}/admin/users} ——
     * 被当成同一个接口，<b>只有第一次出现的那个会被分析</b>，
     * 后面两个版本永远跳过。用户会漏掉 v2/v3 上的漏洞，而且完全察觉不到。
     *
     * <p>这在真实目标上很常见：不少系统长期并行跑 v1/v2 接口，
     * 而旧版本往往正是安全性较差的那个。
     *
     * <p>注意：这里只认<b>显式的版本前缀</b>（v / ver / version / api_v）。
     * 纯数字段（如 {@code /api/2/tweets}）看不出来是版本还是 ID ——
     * 把纯数字段一律保留会严重破坏 ID 去重（{@code /order/1} 与 {@code /order/2}
     * 就再也合并不了），所以那种歧义情况维持归一化。
     */
    private static final Pattern VERSION_SEG = Pattern.compile(
            "(?i)(?:v|ver|version|api[-_]?v)\\d{1,4}");

    /**
     * 计算结构签名。
     *
     * <p>把路径里的「高基数段」归一化：
     * <ul>
     *   <li>{@code /api/user/1001} → {@code /api/user/{n}}（整段是数字）</li>
     *   <li>{@code /api/order/<uuid>} → {@code /api/order/{uuid}}</li>
     *   <li>{@code /static/chunk123.js} → {@code /static/chunk{n}.js}（段内数字串）</li>
     *   <li>{@code /api/resource0/create} → {@code /api/resource{n}/create}</li>
     * </ul>
     *
     * <p>▲ 段内数字串这条是实测后补的。早期只处理「整段是数字」，
     * 结果 {@code chunk1.js … chunk600.js} 被算成 600 个不同结构，
     * {@code resource0…resource19} 被算成 20 个不同接口 ——
     * 前者污染去重表，后者直接让成本翻 20 倍。
     *
     * <p>归一化「宁可过粗」：把同一个接口的不同实例认成一个，
     * 最多是少分析几个变体；认不出来则是成倍多花钱。
     */
    static String signature(Meta meta, String raw) {
        String p = meta.path == null ? "" : meta.path;
        p = UUID_SEG.matcher(p).replaceAll("/{uuid}");
        p = NUMERIC_SEG.matcher(p).replaceAll("/{n}");
        // 很长的十六进制段（hash / token 作路径）也归一化
        p = p.replaceAll("/[0-9a-fA-F]{16,}", "/{hex}");
        // 段内数字串：chunk123.js → chunk{n}.js，resource0 → resource{n}
        //
        // ▲ 但要<b>跳过版本号段</b>。无差别替换会把 v1/v2/v3 认成同一个接口，
        //    导致只有第一个版本被分析 —— 详见 VERSION_SEG 的说明。
        //    所以这里改成「分段处理」：版本段原样保留，其它段才做数字归一化。
        if (p.indexOf('/') >= 0) {
            String[] segs = p.split("/", -1);
            StringBuilder sb = new StringBuilder(p.length());
            for (int i = 0; i < segs.length; i++) {
                if (i > 0) {
                    sb.append('/');
                }
                String seg = segs[i];
                if (VERSION_SEG.matcher(seg).matches()) {
                    sb.append(seg);          // v1 / v2 / version3 → 原样保留
                } else {
                    sb.append(DIGIT_RUN.matcher(seg).replaceAll("{n}"));
                }
            }
            p = sb.toString();
        } else {
            p = DIGIT_RUN.matcher(p).replaceAll("{n}");
        }
        // 连续的 {n} 合并
        p = p.replaceAll("(\\{n\\})+", "{n}");

        java.util.TreeSet<String> params = new java.util.TreeSet<>();
        int headEnd = raw.indexOf("\r\n\r\n");
        if (headEnd < 0) {
            headEnd = raw.indexOf("\n\n");
        }
        if (headEnd >= 0) {
            String body = raw.substring(headEnd).trim();
            // JSON 的 key
            Matcher jm = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]{0,40})\"\\s*:").matcher(body);
            while (jm.find()) {
                params.add(jm.group(1));
            }
            // form 的 key
            Matcher fm = Pattern.compile("(?:^|&)([A-Za-z_][A-Za-z0-9_]{0,40})=").matcher(body);
            while (fm.find()) {
                params.add(fm.group(1));
            }
        }
        // URL 上的 query 参数名
        int q = raw.indexOf('?');
        int sp = raw.indexOf(' ', q > 0 ? q : 0);
        if (q > 0 && sp > q) {
            String query = raw.substring(q + 1, sp);
            for (String kv : query.split("&")) {
                int eq = kv.indexOf('=');
                if (eq > 0) {
                    params.add(kv.substring(0, eq));
                }
            }
        }
        return meta.method + " " + meta.host + p + " ?" + String.join(",", params);
    }

    /** 静态资源和明显的无价值目标 —— 送 AI 纯属浪费。 */
    /**
     * 这个请求有没有带业务认证凭据。
     *
     * 必须把统计类 Cookie 排除掉。用户的真实案例里，请求只带了
     * _ga / _ga_XXXX（Google Analytics）却返回了 flag ——
     * 如果把它们当「已认证」，就会漏掉「这个接口根本没鉴权」这个最重要的判断。
     *
     * 只看三类：Authorization、业务 Cookie、自定义 token 头。
     */
    public static boolean hasBusinessAuth(String rawRequest) {
        if (rawRequest == null || rawRequest.isEmpty()) {
            return false;
        }
        for (String line : rawRequest.split("\\r?\\n")) {
            String l = line.trim();
            String lower = l.toLowerCase();
            if (lower.startsWith("authorization:") || lower.startsWith("x-token:")
                    || lower.startsWith("x-auth-token:") || lower.startsWith("x-csrf-token:")
                    || lower.startsWith("x-access-token:") || lower.startsWith("x-api-key:")) {
                return true;
            }
            if (lower.startsWith("cookie:")) {
                String cookies = l.substring(l.indexOf(':') + 1);
                for (String kv : cookies.split(";")) {
                    String name = kv.trim();
                    int eq = name.indexOf('=');
                    if (eq > 0) {
                        name = name.substring(0, eq).trim().toLowerCase();
                    }
                    if (name.isEmpty()) {
                        continue;
                    }
                    if (name.equals("_ga") || name.equals("_gid") || name.equals("_gat")
                            || name.startsWith("_ga_") || name.startsWith("_gcl")) {
                        continue;
                    }
                    return true;
                }
            }
        }
        return false;
    }
    /**
     * 这段原始报文看起来是不是二进制？
     *
     * <h3>为什么必须看字节，不能只看 Content-Type / 扩展名</h3>
     *
     * 实测漏过一个 HLS 视频分片：{@code mts.xxx.mobi/video5/xxx.ts}，
     * 它的 {@code Content-Type} 是 {@code binary/octet-stream}（不是 {@code video/*}），
     * 扩展名 {@code .ts} 又有歧义（视频分片 / TypeScript 都用）。
     * 结果它一路过关：
     * <ol>
     *   <li>被转成 UTF-8 字符串扫了一遍 → 二进制里恰好出现 {@code <%=} →
     *       误报「源码泄露」（高危）</li>
     *   <li>被整段拼进 AI prompt → 模型吃进乱码，请求直接失败</li>
     * </ol>
     *
     * <p>MIME 和扩展名都能骗人，字节本身不会。判据：
     * <ul>
     *   <li><b>出现 NUL 字节</b> —— 文本（含 UTF-8 中文）里不可能有，直接判二进制</li>
     *   <li>其他控制字符（除 \t \n \r）占比 &gt; 10% —— 判二进制</li>
     * </ul>
     *
     * <p>结论偏保守：宁可把少数不寻常的文本误判成二进制（代价是少分析一个包），
     * 也不要把二进制当文本（代价是误报 + AI 调用失败）。
     */
    static boolean looksBinary(byte[] buf) {
        if (buf == null || buf.length == 0) {
            return false;
        }
        // 只看前面一段 —— 二进制文件的头部通常已经足够判断
        int n = Math.min(buf.length, 1024);
        int ctrl = 0;
        for (int i = 0; i < n; i++) {
            int b = buf[i] & 0xFF;
            if (b == 0x09 || b == 0x0A || b == 0x0D) {
                continue;              // 制表 / 换行 / 回车是正常文本
            }
            if (b == 0x00) {
                return true;           // ⭐ NUL：最可靠的二进制信号
            }
            if (b < 0x20) {
                ctrl++;                // 其他控制字符
            }
        }
        return ctrl * 100 / n > 10;
    }

    static boolean isLowValue(Meta meta, Config cfg) {
        String path = meta.path == null ? "" : meta.path.toLowerCase();
        String mime = meta.mime == null ? "" : meta.mime.toLowerCase();

        // ⚠️ 这里必须覆盖 binary/ 和 octet-stream：
        //    视频流分片、下载文件常报 `binary/octet-stream`，
        //    它既不是 video/* 也不是 audio/*，会从上面那行漏过去。
        if (mime.startsWith("image/") || mime.startsWith("font/")
                || mime.startsWith("audio/") || mime.startsWith("video/")
                || mime.startsWith("binary/")
                || mime.contains("octet-stream")
                || mime.contains("application/zip")
                || mime.contains("application/pdf")
                || mime.contains("application/x-protobuf")
                || mime.contains("application/wasm")) {
            return true;
        }
        if (mime.contains("css") || mime.contains("javascript")) {
            return true;
        }
        String[] junkExt = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp", ".avif"};
        for (String e : junkExt) {
            if (path.endsWith(e)) {
                return true;
            }
        }
        // favicon / 埋点 / 心跳这类也跳过
        return path.contains("/favicon") || path.contains("/beacon")
                || path.contains("/ping") || path.contains("/health");
    }

    // ------------------------------------------------------------------
    // 摘要
    // ------------------------------------------------------------------

    /**
     * 把报文压成「发给 AI 的摘要」。
     *
     * <p>▲ 这里踩过两个坑：
     * <ol>
     *   <li><b>早期版本把整个原始报文贴进来</b> —— 请求行、User-Agent、Accept、
     *       Accept-Encoding 这些噪音全被发出去，既浪费 token（约翻倍），
     *       又和我自己加的那行头部信息重复。</li>
     *   <li><b>后来又错把响应当成分析主体</b> —— 参数名从响应体里提、
     *       响应体被当成请求体。分析请求就得以请求为主体。</li>
     * </ol>
     *
     * <p>现在只挑 AI 真正需要的：
     * <ul>
     *   <li><b>方法 + 主机 + 路径 + 状态</b>（自己拼一行，比原始请求行规整）</li>
     *   <li><b>参数名列表</b> —— 让模型知道有哪些可控输入点</li>
     *   <li><b>Content-Type</b> —— 决定 body 怎么解读</li>
     *   <li><b>只有敏感头（已脱敏）</b> —— 说明"有没有认证"，但不需要值</li>
     *   <li><b>请求 body</b>（脱敏 + 截断）</li>
     *   <li><b>响应摘要</b> —— 状态 + 响应体开头一小段（附加上下文，不是主体）</li>
     * </ul>
     *
     * <p>被丢掉的噪音头：User-Agent / Accept* / Connection / Referer / Origin /
     * Cache-Control / Pragma / Upgrade-* / Sec-* 等，对安全分析几乎没有信息量。
     */
    private static String buildBrief(Meta m, String sanitizedRequest, int maxBody,
                                     String rawResponse, boolean sanitizeResponse,
                                     java.util.List<LocalRules.Issue> issues) {
        StringBuilder sb = new StringBuilder();

        // ▲ 把本地已确认的发现放在<b>最前面</b>，并明确标注「已确认」。
        //
        //    这一段是解决「已经确定有漏洞，AI 还在写可能性」的关键：
        //    有原文证据的结论和推测要分开说，AI 才敢下结论。
        //    放在最前面是因为它对整段分析的语气起决定作用 ——
        //    如果这里写着「严重 Flag 已确认」，AI 就不会再写「疑似信息泄露」。
        if (issues != null && !issues.isEmpty()) {
            sb.append("【本地规则已确认的发现】\n");
            sb.append("（下面这些都有原文证据，是已确认事实，"
                    + "分析时不要再把它们当成「可能」来讨论）\n");
            java.util.List<LocalRules.Issue> sorted = new java.util.ArrayList<>(issues);
            sorted.sort((a, b) -> b.level.rank - a.level.rank);
            int n = 0;
            for (LocalRules.Issue i : sorted) {
                if (n++ >= 12) {
                    sb.append("  …（另有 ").append(sorted.size() - 12).append(" 条）\n");
                    break;
                }
                sb.append("  · ").append(i.level.label).append("危 ").append(i.name)
                        .append("：").append(i.detail);
                if (i.evidence != null && !i.evidence.isEmpty()) {
                    sb.append("\n      证据：").append(i.evidence);
                }
                sb.append('\n');
            }
            sb.append('\n');
        }

        // 第一行：结构化的目标描述
        sb.append(m.method).append(' ').append(m.host).append(m.path);
        if (m.status > 0) {
            sb.append("  → HTTP ").append(m.status);
        }
        if (!m.mime.isEmpty()) {
            sb.append("  (").append(m.mime).append(')');
        }

        // 参数名（从请求的 query 和 body 里抽）
        java.util.TreeSet<String> params = extractParamNames(sanitizedRequest);
        if (!params.isEmpty()) {
            sb.append("\n参数: ").append(String.join(", ", params));
        }

        // 只保留敏感头（已脱敏）—— 说明认证/会话的存在，值本身无信息量
        for (String line : sanitizedRequest.split("\r?\n")) {
            String lower = line.toLowerCase();
            for (String h : KEEP_HEADERS) {
                if (lower.startsWith(h + ":")) {
                    sb.append('\n').append(line.trim());
                    break;
                }
            }
        }

        // 请求 body
        String body = extractBody(sanitizedRequest);
        if (body != null && !body.trim().isEmpty()) {
            sb.append("\nbody:\n").append(trimBodyPlain(body, maxBody));
        }

        // 响应摘要 —— 附加上下文，让 AI 知道服务端怎么回的
        if (rawResponse != null && !rawResponse.isEmpty()) {
            String respText = rawResponse;
            if (sanitizeResponse) {
                try {
                    respText = new Sanitizer().sanitize(rawResponse).cleanText;
                } catch (Throwable ignored) {
                    // 脱敏失败就用原文 —— 但下面的截断会限制泄露面
                }
            }
            String rBody = extractBody(respText);
            sb.append("\n响应: HTTP ").append(m.status);
            if (rBody != null && !rBody.trim().isEmpty()) {
                // 响应只给开头一小段 —— 主体是请求，响应是辅助
                sb.append("\n").append(trimBodyPlain(rBody, Math.min(600, maxBody)));
            }
        }

        return sb.toString();
    }

    /** 从响应头里取 Content-Type。 */
    private static String mimeOf(String respRaw) {
        for (String line : respRaw.split("\r?\n")) {
            String lower = line.toLowerCase();
            if (lower.startsWith("content-type:")) {
                String ct = line.substring(13).trim();
                int semi = ct.indexOf(';');
                return semi > 0 ? ct.substring(0, semi).trim() : ct;
            }
        }
        return "";
    }

    /** 从响应行解析状态码。 */
    private static int parseStatus(String respRaw) {
        int end = respRaw.indexOf('\n');
        String first = end < 0 ? respRaw : respRaw.substring(0, end);
        String[] parts = first.trim().split("\\s+");
        if (parts.length >= 2) {
            try {
                return Integer.parseInt(parts[1]);
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    /** 值得保留给 AI 看的头 —— 其余都是噪音。 */
    private static final String[] KEEP_HEADERS = {
            "authorization", "cookie", "set-cookie",
            "x-token", "x-auth-token", "x-access-token", "x-csrf-token",
            "x-api-key", "content-type"
    };

    /** 从 query 和 body 里抽参数名。 */
    private static java.util.TreeSet<String> extractParamNames(String msg) {
        java.util.TreeSet<String> out = new java.util.TreeSet<>();

        // URL query
        int q = msg.indexOf('?');
        int sp = msg.indexOf(' ', q > 0 ? q : 0);
        if (q > 0 && sp > q) {
            for (String kv : msg.substring(q + 1, sp).split("&")) {
                int eq = kv.indexOf('=');
                if (eq > 0) {
                    out.add(kv.substring(0, eq));
                }
            }
        }

        String body = extractBody(msg);
        if (body == null) {
            return out;
        }
        Matcher jm = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]{0,40})\"\\s*:").matcher(body);
        while (jm.find()) {
            out.add(jm.group(1));
        }
        Matcher fm = Pattern.compile("(?:^|&)([A-Za-z_][A-Za-z0-9_]{0,40})=").matcher(body);
        while (fm.find()) {
            out.add(fm.group(1));
        }
        return out;
    }

    private static String extractBody(String msg) {
        int sep = msg.indexOf("\r\n\r\n");
        if (sep >= 0) {
            return msg.substring(sep + 4);
        }
        sep = msg.indexOf("\n\n");
        if (sep >= 0) {
            return msg.substring(sep + 2);
        }
        return null;
    }

    private static String trimBodyPlain(String body, int max) {
        String b = body;
        if (b.length() <= max) {
            return b;
        }
        return b.substring(0, max) + "\n…（已截断到 " + max + " 字符）";
    }

    /** 只截断 body，保留头部 —— 头部是理解上下文的关键，body 才是体积大头。 */
    static String trimBody(String msg, int maxBody) {
        if (msg == null) {
            return "";
        }
        int sep = msg.indexOf("\r\n\r\n");
        int len = 4;
        if (sep < 0) {
            sep = msg.indexOf("\n\n");
            len = 2;
        }
        if (sep < 0) {
            return msg.length() <= maxBody ? msg : msg.substring(0, maxBody) + "\n…（已截断）";
        }
        int bodyStart = sep + len;
        String head = msg.substring(0, bodyStart);
        String body = msg.substring(bodyStart);
        if (body.length() <= maxBody) {
            return msg;
        }
        return head + body.substring(0, maxBody) + "\n…（body 已截断到 " + maxBody + " 字符）";
    }

    private static Sanitizer.MaskStrategy parseStrategy(String name) {
        if (name == null) {
            return Sanitizer.MaskStrategy.KEEP_EDGES;
        }
        try {
            return Sanitizer.MaskStrategy.valueOf(name.trim().toUpperCase());
        } catch (Exception e) {
            return Sanitizer.MaskStrategy.KEEP_EDGES;
        }
    }

    // ==================================================================

    /** 最近记录的快照（拷贝，避免 UI 与后台线程竞争）。 */
    public List<PacketRecord> snapshot() {
        synchronized (recent) {
            return new ArrayList<>(recent);
        }
    }

    public long droppedCount() {
        return dropped.get();
    }

    public int queuedCount() {
        return queue.size();
    }

    /** 去重表大小 —— 也就是「见过多少种不同的接口结构」。 */
    public int distinctStructures() {
        return seenSignatures.size();
    }

    // ---- 全量统计（不受 recent 窗口影响）----

    /** 已处理报文总数。 */
    public long processedCount() {
        return processed.get();
    }

    /** 判定为低价值（静态资源等）的数量。 */
    public long lowValueCount() {
        return countLow.get();
    }

    /** 判定为结构重复的数量。 */
    public long duplicateCount() {
        return countDup.get();
    }

    /** 判定为值得送 AI 的数量 —— 这就是实际会花钱的包数。 */
    public long worthCount() {
        return countWorth.get();
    }

    /**
     * 去重带来的节省比例（0..1）。
     *
     * <p>这是给用户看的核心数字：它回答「不做去重要花多少，做了省多少」。
     */
    public double savedRatio() {
        long total = processed.get();
        if (total <= 0) {
            return 0;
        }
        return 1.0 - ((double) countWorth.get() / total);
    }

    /**
     * 去重表是否已经到界（到界后去重能力下降）。
     *
     * <p>给界面用 —— 到界了就该告诉用户，而不是让「省下的比例」
     * 莫名其妙变低却不知道原因。
     */
    public boolean dedupSaturated() {
        return seenSignatures.size() >= SIGNATURES_MAX;
    }

    /** 因为去重表到界而未能记录的签名数。 */
    public long dedupOverflowCount() {
        return dedupOverflow.get();
    }

    /**
     * 当前会话里「签名种类 / 已处理报文」的比值，用来判断去重是否失效。
     *
     * <p>接近 1 说明几乎每个报文都是新结构 —— 通常是目标用了
     * <b>高基数路径</b>（{@code /download/<随机ID>} 之类），
     * 去重在这类目标上帮不上忙，成本会显著高于预期。
     */
    public double structureRatio() {
        long p = processed.get();
        return p == 0 ? 0.0 : (double) seenSignatures.size() / p;
    }

    /** 已跟踪的接口结构数（逻辑线索引擎）。 */
    public int logicTrackedSignatures() {
        return logicHints.trackedSignatures();
    }

    /** 本地检出问题的报文数。 */
    public long issueCount() {
        return countIssues.get();
    }

    // ==================================================================
    // 宏观：业务流量分析
    // ==================================================================

    /** 快照里出现过的所有主机名（按出现次数降序）。 */
    public List<String> hosts() {
        Map<String, Integer> counts = new java.util.HashMap<>();
        synchronized (recent) {
            for (PacketRecord r : recent) {
                if (r.host != null && !r.host.isEmpty()) {
                    counts.merge(r.host, 1, Integer::sum);
                }
            }
        }
        List<String> out = new ArrayList<>(counts.keySet());
        out.sort((a, b) -> counts.get(b) - counts.get(a));
        return out;
    }

    /**
     * 构建某个域名的<b>业务地图</b> —— 宏观业务流量分析的输入。
     *
     * <p>它把「几百个包」收敛成「几十个接口」，每个接口带上：
     * 方法、路径模板、业务作用、出现次数、本地已发现的问题。
     *
     * <p>这份地图有两个用途：
     * <ol>
     *   <li><b>本地展示</b> —— 让人一眼看懂这个系统有哪些业务模块</li>
     *   <li><b>喂给 AI 做一次逻辑推断</b> —— 一次调用覆盖整个域名，
     *       而不是每个包调一次。典型 20-60 个接口约 800-2000 tokens，
     *       成本约 ¥0.01-0.03</li>
     * </ol>
     *
     * @param host 目标域名；null 或空表示全部
     */
    public LocalRules.BusinessMap buildBusinessMap(String host) {
        LocalRules.BusinessMap map = new LocalRules.BusinessMap(
                host == null || host.isEmpty() ? "(全部域名)" : host);

        // 按签名聚合：同结构的多次调用合成一条，保留最严重的问题
        Map<String, Agg> aggs = new LinkedHashMap<>();
        synchronized (recent) {
            for (PacketRecord r : recent) {
                if (host != null && !host.isEmpty()
                        && (r.host == null || !r.host.equalsIgnoreCase(host))) {
                    continue;
                }
                if (r.lowValue) {
                    continue;      // 静态资源不进业务地图
                }
                Agg a = aggs.get(r.signature);
                if (a == null) {
                    a = new Agg(r);
                    aggs.put(r.signature, a);
                } else {
                    a.merge(r);
                }
            }
        }

        List<LocalRules.BusinessMap.Entry> entries = new ArrayList<>();
        for (Agg a : aggs.values()) {
            entries.add(new LocalRules.BusinessMap.Entry(
                    a.method, a.pathTemplate(), a.purpose, a.count, a.worst, a.issueText()));
            map.byPurpose.merge(a.purpose, 1, Integer::sum);
        }
        // 按作用分组排序，让同模块的接口挨在一起
        entries.sort((x, y) -> {
            int c = x.purpose.compareTo(y.purpose);
            return c != 0 ? c : x.pathTemplate.compareTo(y.pathTemplate);
        });
        map.entries.addAll(entries);
        return map;
    }

    /** 聚合器：同签名的多个包合成一条。 */
    private static final class Agg {
        final String method;
        final String path;
        final String purpose;
        int count;
        LocalRules.Level worst = LocalRules.Level.NONE;
        final java.util.LinkedHashSet<String> issueNames = new java.util.LinkedHashSet<>();

        Agg(PacketRecord r) {
            this.method = r.method;
            this.path = r.path;
            this.purpose = r.purpose;
            this.count = 1;
            mergeIssues(r);
        }

        void merge(PacketRecord r) {
            count++;
            mergeIssues(r);
        }

        private void mergeIssues(PacketRecord r) {
            for (LocalRules.Issue i : r.issues) {
                if (i.level.rank > worst.rank) {
                    worst = i.level;
                }
                issueNames.add(i.level.label + "危" + i.name);
            }
        }

        String issueText() {
            if (issueNames.isEmpty()) {
                return "无";
            }
            return String.join("、", issueNames);
        }

        /** 路径只保留一层，避免列表过长。 */
        String pathTemplate() {
            return path == null || path.isEmpty() ? "/" : path;
        }
    }
}
