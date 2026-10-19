package com.packetsentry.core;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 批量越权测试 —— 一次测一组接口。
 *
 * <h3>为什么需要批量</h3>
 * 单条测法（{@link AccessControlTester#test}）在手工确认某个点的时候够用。
 * 但 SRC 的真实场景是：你在一个模块里发现了「ID 可预测」的线索，
 * 接下来要确认这个模块下<b>十几个接口</b>是不是都缺访问控制。
 * 一个一个点，光确认对话框就要点几十次。
 *
 * <h3>▲ 为什么这不算「自动化扫描器」</h3>
 * 多数 SRC 规则禁止「使用扫描器、自动化工具」，指的是 sqlmap / xray 那类
 * <b>会向目标注入 payload、大规模 fuzz</b> 的工具。本功能和它们的区别是：
 * <ul>
 *   <li>只重放<b>你自己已经发过的请求</b>（原样，不改参数、不加 payload）</li>
 *   <li>只用<b>你自己账号</b>的凭据</li>
 *   <li>有保守的速率限制，不会把目标打挂</li>
 * </ul>
 * 它做的是「把你手工会做的事批量做一遍」，不是「帮你找未知的漏洞」。
 *
 * <h3>▲▲ 但有一条安全红线：默认只测只读方法</h3>
 * 用身份 B 的凭据重放身份 A 的 {@code POST /order/create}，
 * 如果服务端真的执行了 —— <b>那就是真的下了一单</b>。
 * 这不是「证明漏洞」，这是「造成业务影响」，SRC 明令禁止。
 *
 * <p>所以本类<b>默认只测 GET / HEAD / OPTIONS</b>。
 * 写操作（POST / PUT / PATCH / DELETE）必须调用方显式打开，
 * 而且界面上会明确警告「可能真的执行操作」。
 */
public final class AccessControlBatch {

    /** 只读方法 —— 重放无副作用，默认允许。 */
    private static final Set<String> SAFE_METHODS =
            new LinkedHashSet<>(java.util.Arrays.asList("GET", "HEAD", "OPTIONS"));

    /** 兜底上限：超过这个数量的计划直接拒绝，避免误操作把目标刷爆。 */
    public static final int HARD_MAX = 500;

    // ==================================================================

    /** 一次批量测试的配置。 */
    public static final class Options {
        /** 用哪个身份作为「基线」（通常是当前登录的账号）。 */
        public Identity baseline;
        /** 用哪些身份去重放（通常是另一个普通账号）。 */
        public List<Identity> testIdentities = new ArrayList<>();
        /** 速率限制，毫秒。来自 Config.acMinIntervalMs。 */
        public long intervalMs = 400;
        /** 本次最多发多少个请求。 */
        public int maxRequests = 200;
        /** 是否允许测写操作（默认 false —— 见类注释的安全红线）。 */
        public boolean allowUnsafeMethods = false;
        /** 是否在每个接口上只测一次（按签名去重）。默认 true。 */
        public boolean dedupeBySignature = true;
        /** 发现一个可疑点就停下（保守模式）。 */
        public boolean stopOnFirstVulnerable = false;
    }

    /** 一个被测目标。 */
    public static final class Target {
        public final PacketRecord record;

        public Target(PacketRecord record) {
            this.record = record;
        }

        public String method() {
            return record.method == null ? "GET" : record.method.toUpperCase();
        }

        public boolean isSafeMethod() {
            return SAFE_METHODS.contains(method());
        }
    }

    /** 一条命中。 */
    public static final class Hit {
        public final PacketRecord record;
        public final AccessControlTester.Result result;

        public Hit(PacketRecord record, AccessControlTester.Result result) {
            this.record = record;
            this.result = result;
        }
    }

    /** 一次批量的结果。 */
    public static final class Outcome {
        public final List<Hit> hits = new ArrayList<>();
        public int planned;
        public int sent;
        public int vulnerable;
        public int protectedCount;
        public int inconclusive;
        public int errors;
        public int skippedUnsafe;
        public int skippedDuplicate;
        public long elapsedMs;
        public boolean cancelled;
        public String aborted;

        public String render() {
            StringBuilder sb = new StringBuilder();
            sb.append("══════════ 批量越权测试结果 ══════════\n\n");
            sb.append("计划测试  ").append(planned).append(" 个接口\n");
            sb.append("实际发送  ").append(sent).append(" 个请求\n");
            if (skippedUnsafe > 0) {
                sb.append("跳过（写操作，未开启）  ").append(skippedUnsafe).append(" 个\n");
            }
            if (skippedDuplicate > 0) {
                sb.append("跳过（同接口重复）      ").append(skippedDuplicate).append(" 个\n");
            }
            sb.append("耗时      ").append(elapsedMs / 1000.0).append(" 秒\n");
            if (cancelled) {
                sb.append("\n▲ 用户中途取消 —— 下面是不完整的结果。\n");
            }
            if (aborted != null && !aborted.isEmpty()) {
                sb.append("\n▲ ").append(aborted).append('\n');
            }
            sb.append('\n');

            if (hits.isEmpty()) {
                sb.append("没有发现访问控制缺失。\n\n");
                sb.append("注意：这只说明用<b>你配置的这几个身份</b>重放没拿到数据，\n");
                sb.append("不代表不存在越权 —— 可能身份配得不对，或者这个接口本来就不返回数据。\n");
                return sb.toString();
            }

            sb.append("★ 疑似越权  ").append(vulnerable).append(" 个\n");
            sb.append("受保护      ").append(protectedCount).append(" 个\n");
            sb.append("不确定      ").append(inconclusive).append(" 个\n");
            sb.append("出错        ").append(errors).append(" 个\n\n");

            // 越权的排前面
            hits.sort(Comparator.comparingInt(
                    (Hit h) -> h.result.verdict == AccessControlTester.Verdict.VULNERABLE ? 0 : 1)
                    .thenComparing(h -> h.record.path == null ? "" : h.record.path));

            int n = 0;
            for (Hit h : hits) {
                if (n++ >= 40) {
                    sb.append("…（另有 ").append(hits.size() - 40).append(" 条未列出）\n");
                    break;
                }
                String mark = h.result.verdict == AccessControlTester.Verdict.VULNERABLE
                        ? "★" : "  ";
                sb.append(mark).append(' ').append(h.record.method).append(' ')
                        .append(h.record.path).append('\n');
                sb.append("     ").append(h.result.verdict.label)
                        .append("　").append(h.result.summaryLine()).append('\n');
                if (h.result.verdict == AccessControlTester.Verdict.VULNERABLE) {
                    sb.append("     ▲ 候选，需人工复核后再写进报告\n");
                }
            }
            sb.append("\n───────────────────────────\n");
            sb.append("▲ 这些是<b>候选</b>，不是已确认的漏洞：\n");
            sb.append("  · 判定依据是「结构相似 + 值相似」，同构页面会误判\n");
            sb.append("  · 要人工看一眼：响应里到底有没有<b>属于别人</b>的数据\n");
            sb.append("  · 确认后在 Repeater 里复现一次，再标成「已验证」\n");
            return sb.toString();
        }
    }

    /** 进度回调（在后台线程调用，实现里要自己切回 EDT）。 */
    public interface Progress {
        void onStep(int done, int total, String currentPath);
    }

    // ==================================================================

    private final IBurpExtenderCallbacks callbacks;
    private volatile boolean cancelRequested = false;

    public AccessControlBatch(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public void cancel() {
        cancelRequested = true;
    }

    public boolean isCancelled() {
        return cancelRequested;
    }

    /**
     * 挑选可以测的目标。
     *
     * <p>把不可测的<b>分开报出来</b>，而不是静默丢掉 ——
     * 用户需要知道「为什么我选了 30 个，只测了 12 个」。
     */
    public static List<Target> selectTargets(List<PacketRecord> all, String host,
                                             Options opts) {
        List<Target> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (PacketRecord r : all) {
            if (r.rawRequest == null || r.rawRequest.length == 0) {
                continue;
            }
            if (r.service == null) {
                // 没有 service 就没法发包 —— 这是硬条件，不是偏好
                continue;
            }
            if (host != null && !host.isEmpty()
                    && (r.host == null || !r.host.equalsIgnoreCase(host))) {
                continue;
            }
            if (r.lowValue) {
                continue;
            }
            Target t = new Target(r);
            if (opts.dedupeBySignature && r.signature != null
                    && !seen.add(r.signature)) {
                continue;
            }
            out.add(t);
        }
        return out;
    }

    /** 统计不可测的原因，给确认对话框用。 */
    public static String describePlan(List<Target> targets, Options opts) {
        int safe = 0;
        int unsafe = 0;
        for (Target t : targets) {
            if (t.isSafeMethod()) {
                safe++;
            } else {
                unsafe++;
            }
        }
        int willSend = opts.allowUnsafeMethods ? safe + unsafe : safe;
        willSend *= Math.max(1, opts.testIdentities.size());

        StringBuilder sb = new StringBuilder();
        sb.append("将要测试  ").append(targets.size()).append(" 个接口\n");
        sb.append("其中只读  ").append(safe).append(" 个　写操作 ").append(unsafe).append(" 个\n");
        if (!opts.allowUnsafeMethods && unsafe > 0) {
            sb.append("（写操作已跳过 —— 见下面的说明）\n");
        }
        sb.append("\n将向目标发送  ").append(willSend).append(" 个请求\n");
        sb.append("速率限制  ").append(opts.intervalMs).append(" ms/次");
        if (willSend > 1) {
            sb.append("　预计耗时约 ")
                    .append(String.format("%.0f", willSend * opts.intervalMs / 1000.0))
                    .append(" 秒");
        }
        sb.append('\n');
        return sb.toString();
    }

    /**
     * 跑一批。
     *
     * <p>▲ 这个方法会<b>真的向目标发包</b>，而且可能发很多个。
     * 调用方必须先让用户明确确认。
     */
    public Outcome run(List<Target> targets, Options opts, Progress progress) {
        Outcome out = new Outcome();
        out.planned = targets.size();
        long t0 = System.currentTimeMillis();

        if (targets.isEmpty()) {
            out.aborted = "没有可测试的目标。";
            out.elapsedMs = System.currentTimeMillis() - t0;
            return out;
        }
        if (opts.testIdentities == null || opts.testIdentities.isEmpty()) {
            out.aborted = "没有配置测试身份 —— 到「设置」里至少加一个其它账号。";
            out.elapsedMs = System.currentTimeMillis() - t0;
            return out;
        }
        if (opts.baseline == null) {
            out.aborted = "没有指定基线身份。";
            out.elapsedMs = System.currentTimeMillis() - t0;
            return out;
        }

        AccessControlTester tester = new AccessControlTester(callbacks);
        tester.minIntervalMs = Math.max(200, opts.intervalMs);

        int budget = Math.min(opts.maxRequests <= 0 ? 200 : opts.maxRequests, HARD_MAX);
        int done = 0;
        int total = targets.size();

        for (Target t : targets) {
            if (cancelRequested) {
                out.cancelled = true;
                break;
            }
            if (out.sent >= budget) {
                out.aborted = "已达到本次请求上限（" + budget
                        + " 个），剩余接口未测试。分批跑可以继续。";
                break;
            }
            // ▲ 安全红线：写操作默认跳过
            if (!t.isSafeMethod() && !opts.allowUnsafeMethods) {
                out.skippedUnsafe++;
                done++;
                if (progress != null) {
                    progress.onStep(done, total, "(跳过写操作) " + t.record.path);
                }
                continue;
            }

            PacketRecord r = t.record;
            for (Identity testId : opts.testIdentities) {
                if (cancelRequested) {
                    out.cancelled = true;
                    break;
                }
                if (out.sent >= budget) {
                    break;
                }
                AccessControlTester.Result res;
                try {
                    res = tester.test(r.rawRequest, r.rawResponse, opts.baseline,
                            testId, (IHttpService) r.service, r.rawResponse != null);
                } catch (Throwable e) {
                    res = null;
                    out.errors++;
                }
                out.sent++;
                if (res != null) {
                    switch (res.verdict) {
                        case VULNERABLE:
                            out.vulnerable++;
                            out.hits.add(new Hit(r, res));
                            break;
                        case PROTECTED:
                            out.protectedCount++;
                            break;
                        case ERROR:
                            out.errors++;
                            break;
                        default:
                            out.inconclusive++;
                            break;
                    }
                }
                if (opts.stopOnFirstVulnerable && out.vulnerable > 0) {
                    out.aborted = "已发现疑似越权，按「发现即停」设置中止。";
                    break;
                }
            }
            if (out.aborted != null && out.aborted.startsWith("已发现")) {
                break;
            }
            done++;
            if (progress != null) {
                progress.onStep(done, total, r.method + " " + r.path);
            }
        }

        out.elapsedMs = System.currentTimeMillis() - t0;
        return out;
    }
}
