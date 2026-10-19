package com.packetsentry.audit;

import com.packetsentry.detect.LocalRules;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 代码审计引擎 —— 从响应里的 JS / HTML / 前端代码中挖信息。
 *
 * <h3>为什么「代码审计」在抓包工具里有意义</h3>
 * 现代 Web 应用把大量逻辑放在了前端：接口地址、参数结构、权限判断、
 * 甚至硬编码的密钥。这些东西全都在 JS 里 —— 而 JS 会经过你的代理。
 *
 * <p>所以「代码审计」在这里不是审计后端源码，而是<b>审计流经代理的前端代码</b>：
 * <ul>
 *   <li>硬编码的密钥 / AK/SK</li>
 *   <li>被注释掉的接口、测试账号</li>
 *   <li>散落在 JS 里的 API 路径（很多是页面上没入口的隐藏接口）</li>
 *   <li>危险的 DOM 操作（innerHTML / eval / document.write）</li>
 *   <li>前端的权限判断（绕过去就是垂直越权）</li>
 *   <li>Source Map 泄露（能把压缩代码还原成源码）</li>
 *   <li>postMessage 监听器（跨域消息处理不当 → XSS / 信息泄露）</li>
 * </ul>
 *
 * <h3>▲ 审计结论分三态</h3>
 * 这是本引擎和普通「规则匹配器」最大的区别：
 * <ol>
 *   <li><b>有发现</b> —— 确实挖到了东西，列出证据</li>
 *   <li><b>有可能</b> —— 没挖到具体东西，但这是�javaScript/HTML，
 *       存在可攻击面，列出<b>值得试的方向</b></li>
 *   <li><b>无</b> —— 连可能性都没有（如纯静态图片、二进制），明确说「无」</li>
 * </ol>
 * 只报「有/没有」会让人误以为「没报就是安全」；
 * 三态才能说清「这里是干净的」还是「这里还没看」。
 */
public final class CodeAudit {

    // ==================================================================
    // 结果模型
    // ==================================================================

    /** 审计结论的三种状态。 */
    public enum Verdict {
        /** 挖到了具体东西。 */
        FOUND("★ 有发现"),
        /** 没挖到，但存在可攻击面，有挖掘可能性。 */
        POSSIBLE("☆ 有可能"),
        /** 连可能性都没有。 */
        NOTHING("○ 无"),
        /** 不是可审计的内容（图片/二进制等）。 */
        NOT_APPLICABLE("➖ 不适用");

        public final String label;

        Verdict(String label) {
            this.label = label;
        }
    }

    /** 一条审计发现。 */
    public static final class Finding {
        public final LocalRules.Level level;
        public final String category;
        public final String detail;
        /** 证据片段（已截断），用于报告引用。 */
        public final String evidence;
        /** 这条发现引出的「可以试试什么」。 */
        public final String nextStep;

        public Finding(LocalRules.Level level, String category, String detail,
                       String evidence, String nextStep) {
            this.level = level;
            this.category = category;
            this.detail = detail;
            this.evidence = evidence;
            this.nextStep = nextStep;
        }

        @Override
        public String toString() {
            return "[" + level.label + "] " + category + " —— " + detail
                    + (evidence == null || evidence.isEmpty() ? "" : "　证据：" + evidence);
        }
    }

    /** 一次审计的完整结果。 */
    public static final class Result {
        public final Verdict verdict;
        public final List<Finding> findings = new ArrayList<>();
        /** 无具体发现但值得尝试的方向。 */
        public final List<String> hypotheses = new ArrayList<>();
        /** 内容类型说明。 */
        public final String contentType;
        /** 审计了多少字节。 */
        public final int auditedBytes;
        /** 说明为什么是「无」。 */
        public final String nothingReason;

        Result(Verdict v, String ct, int bytes, String reason) {
            this.verdict = v;
            this.contentType = ct;
            this.auditedBytes = bytes;
            this.nothingReason = reason;
        }

        public boolean hasFindings() {
            return !findings.isEmpty();
        }

        /**
         * 最严重等级。
         *
         * <p>这里不能复用 {@code LocalRules.worst()} —— 那个方法的入参是
         * {@code List<Issue>}，而审计用的是自己的 {@code Finding} 类型。
         * 两个类型字段不同，硬套会在编译期就被拦下（也确实被拦下了）。
         */
        public LocalRules.Level worst() {
            LocalRules.Level w = LocalRules.Level.NONE;
            for (Finding f : findings) {
                if (f.level.rank > w.rank) {
                    w = f.level;
                }
            }
            return w;
        }
    }

    /** 设置结论与原因后返回同一个对象。 */
    private static Result withVerdict(Result r, Verdict v, String reason) {
        Result out = new Result(v, r.contentType, r.auditedBytes,
                reason != null ? reason : r.nothingReason);
        out.findings.addAll(r.findings);
        out.hypotheses.addAll(r.hypotheses);
        return out;
    }

    // ==================================================================
    // 检测模式
    // ==================================================================

    /** 硬编码密钥。 */
    private static final Pattern[] SECRET_PATTERNS = {
            // AWS
            Pattern.compile("(?i)(AKIA[0-9A-Z]{16})"),
            // Google
            Pattern.compile("(AIza[0-9A-Za-z_\\-]{35})"),
            // GitHub / GitLab
            Pattern.compile("(?i)(gh[pousr]_[0-9A-Za-z]{36,})"),
            Pattern.compile("(?i)(glpat-[0-9A-Za-z_\\-]{20,})"),
            // Slack
            Pattern.compile("(xox[baprs]-[0-9A-Za-z\\-]{10,})"),
            // 阿里云 / 腾讯云
            Pattern.compile("(?i)(LTAI[0-9A-Za-z]{12,})"),
            Pattern.compile("(?i)(AKID[0-9A-Za-z]{13,})"),
            // JWT 形态的密钥
            Pattern.compile("(eyJ[A-Za-z0-9_\\-]{10,}\\.eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,})"),
            // 通用赋值
            Pattern.compile("(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|"
                    + "private[_-]?key|client[_-]?secret|app[_-]?secret|auth[_-]?token)"
                    + "\\s*[:=]\\s*[\"']([A-Za-z0-9_\\-+/=]{16,})[\"']"),
            // 密码赋值
            Pattern.compile("(?i)(?:password|passwd|pwd)\\s*[:=]\\s*[\"']([^\"']{6,60})[\"']"),
            // 私有 IP 或内网域名（可能泄露内网结构）
            Pattern.compile("(?i)(?:https?://)?(?:10\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])|"
                    + "192\\.168)\\.\\d{1,3}\\.\\d{1,3}(?::\\d+)?"),
    };

    /** 危险的 DOM / JS 操作 —— 前端 XSS 的常见汇聚点。 */
    private static final Pattern[] SINK_PATTERNS = {
            Pattern.compile("(?i)\\.innerHTML\\s*="),
            Pattern.compile("(?i)\\.outerHTML\\s*="),
            Pattern.compile("(?i)document\\.write\\s*\\("),
            Pattern.compile("(?i)\\beval\\s*\\("),
            Pattern.compile("(?i)new\\s+Function\\s*\\("),
            Pattern.compile("(?i)setTimeout\\s*\\(\\s*[\"']"),
            Pattern.compile("(?i)dangerouslySetInnerHTML"),
            Pattern.compile("(?i)\\$\\s*\\([^)]*\\)\\s*\\.html\\s*\\("),
            Pattern.compile("(?i)v-html\\s*="),
            Pattern.compile("(?i)\\[innerHTML\\]\\s*="),
            Pattern.compile("(?i)location\\s*=\\s*(?:location|document\\.URL|.*hash|.*search)"),
            Pattern.compile("(?i)insertAdjacentHTML\\s*\\("),
    };

    /** 前端权限判断 —— 绕过就是垂直越权。 */
    private static final Pattern[] AUTHZ_PATTERNS = {
            Pattern.compile("(?i)(?:isAdmin|is_admin|isSuper|isRoot|hasPermission|checkRole|"
                    + "userRole|user\\.role|role\\s*===?\\s*[\"']admin)"),
            Pattern.compile("(?i)(?:v-if|ng-if|wx:if)\\s*=\\s*[\"'][^\"']*"
                    + "(?:admin|role|permission|vip|level)"),
            Pattern.compile("(?i)if\\s*\\([^)]*(?:role|permission|isAdmin|level)[^)]*\\)\\s*\\{"),
    };

    /** 只在前端做的校验 —— 服务端可能没校验。 */
    private static final Pattern[] CLIENT_VALIDATION_PATTERNS = {
            Pattern.compile("(?i)<input[^>]*\\bmaxlength\\s*="),
            Pattern.compile("(?i)<input[^>]*\\breadonly\\b"),
            Pattern.compile("(?i)<input[^>]*\\bdisabled\\b"),
            Pattern.compile("(?i)<input[^>]*\\bpattern\\s*="),
            Pattern.compile("(?i)<input[^>]*type\\s*=\\s*[\"']hidden[\"']"),
    };

    /** 注释里的线索。 */
    private static final Pattern COMMENT_PATTERN = Pattern.compile(
            "(?is)(?:<!--|/\\*|//)\\s*([^\\n>*]{0,200}?(?:"
                    + "TODO|FIXME|HACK|XXX|BUG|test|测试|后门|临时|先这样|"
                    + "password|passwd|account|admin|token|key|secret|"
                    + "接口|api|url)"
                    + "[^\\n>*]{0,200})");

    /** API 路径（从 JS 字符串里抽）。 */
    private static final Pattern API_PATH_PATTERN = Pattern.compile(
            "[\"']((?:/|\\./)?(?:api|v\\d+|rest|graphql|admin|manage|internal)[a-zA-Z0-9_\\-./{}$:]{2,80})[\"']");

    /** Source Map 引用。 */
    private static final Pattern SOURCE_MAP_PATTERN = Pattern.compile(
            "(?i)sourceMappingURL\\s*=\\s*([^\\s*]+)");

    /** postMessage 监听。 */
    private static final Pattern POSTMESSAGE_PATTERN = Pattern.compile(
            "(?i)addEventListener\\s*\\(\\s*[\"']message[\"']");

    // ==================================================================

    private static final int MAX_AUDIT_BYTES = 1_500_000;

    /**
     * 审计一个响应。
     *
     * @param reqRaw  请求（用来把路径也纳入审计）
     * @param respRaw 响应
     */
    public Result audit(String reqRaw, String respRaw) {
        if (respRaw == null || respRaw.isEmpty()) {
            Result r = new Result(Verdict.NOT_APPLICABLE, "(空)", 0, "没有响应内容");
            return r;
        }

        int headEnd = respRaw.indexOf("\r\n\r\n");
        if (headEnd < 0) {
            headEnd = respRaw.indexOf("\n\n");
        }
        String head = headEnd > 0 ? respRaw.substring(0, headEnd) : "";
        String body = headEnd > 0 ? respRaw.substring(headEnd) : respRaw;

        String ct = contentTypeOf(head);
        int bytes = body.length();

        // ---- 判断是否可审计 ----
        Verdict na = notAuditable(ct, body);
        if (na != null) {
            return new Result(na, ct, bytes, na == Verdict.NOT_APPLICABLE
                    ? "内容类型不可审计：" + (ct.isEmpty() ? "未知" : ct)
                    : "内容过短，没有可审计的代码");
        }

        if (body.length() > MAX_AUDIT_BYTES) {
            body = body.substring(0, MAX_AUDIT_BYTES);
        }

        Result r = new Result(Verdict.NOTHING, ct, bytes, null);

        // ---- 1. 硬编码密钥 ----
        for (Pattern p : SECRET_PATTERNS) {
            Matcher m = p.matcher(body);
            if (m.find()) {
                String hit = m.group(m.groupCount() >= 1 && m.group(1) != null ? 1 : 0);
                r.findings.add(new Finding(LocalRules.Level.HIGH, "硬编码凭据",
                        "前端代码里出现疑似密钥/凭据的硬编码值，任何人打开页面就能读到",
                        mask(hit),
                        "把该值拿去试其它接口（尤其是云服务 API），或确认它是不是有效的生产凭据"));
            }
        }

        // ---- 2. 危险 DOM 汇聚点 ----
        Set<String> sinks = new LinkedHashSet<>();
        for (Pattern p : SINK_PATTERNS) {
            Matcher m = p.matcher(body);
            if (m.find()) {
                sinks.add(m.group().trim());
            }
        }
        if (!sinks.isEmpty()) {
            r.findings.add(new Finding(LocalRules.Level.MEDIUM, "危险DOM操作",
                    "代码里使用了容易造成 XSS 的 DOM 操作。"
                            + "如果数据来源可控（URL 参数 / 后端返回未转义内容），就构成 XSS",
                    String.join("、", sinks),
                    "找到这些汇聚点的数据来源，看能不能通过 URL hash / 查询参数 / 接口返回注入"));
        }

        // ---- 3. 前端权限判断 ----
        Set<String> authz = new LinkedHashSet<>();
        for (Pattern p : AUTHZ_PATTERNS) {
            Matcher m = p.matcher(body);
            if (m.find()) {
                authz.add(truncate(m.group().trim(), 60));
            }
        }
        if (!authz.isEmpty()) {
            r.findings.add(new Finding(LocalRules.Level.HIGH, "前端权限判断",
                    "权限/角色判断写在前端。前端判断可被绕过，"
                            + "如果服务端不重复校验，就是垂直越权",
                    String.join("；", authz),
                    "找到被这个判断保护的接口，用低权限账号直接调用，看服务端是否也校验"));
        }

        // ---- 4. 前端校验 ----
        Set<String> cvs = new LinkedHashSet<>();
        for (Pattern p : CLIENT_VALIDATION_PATTERNS) {
            Matcher m = p.matcher(body);
            while (m.find() && cvs.size() < 6) {
                cvs.add(truncate(m.group().trim(), 70));
            }
        }
        if (!cvs.isEmpty()) {
            r.findings.add(new Finding(LocalRules.Level.LOW, "前端校验",
                    "存在只在前端做的校验（长度/只读/禁用/正则/隐藏字段）。"
                            + "改包绕过即可测试服务端是否也校验",
                    String.join(" | ", cvs),
                    "把对应字段改成非法值直接提交，看服务端是否接受"));
        }

        // ---- 5. 注释线索 ----
        Matcher cm = COMMENT_PATTERN.matcher(body);
        Set<String> comments = new LinkedHashSet<>();
        while (cm.find() && comments.size() < 8) {
            comments.add(truncate(cm.group(1).trim().replaceAll("\\s+", " "), 120));
        }
        if (!comments.isEmpty()) {
            r.findings.add(new Finding(LocalRules.Level.MEDIUM, "注释线索",
                    "注释里出现敏感关键词，可能泄露测试账号、隐藏接口或内部说明",
                    String.join(" // ", comments),
                    "按注释里提到的接口/账号去试，很多开发遗留的入口就藏在这里"));
        }

        // ---- 6. API 路径搜集 ----
        Matcher ap = API_PATH_PATTERN.matcher(body);
        Set<String> paths = new LinkedHashSet<>();
        while (ap.find() && paths.size() < 60) {
            paths.add(ap.group(1));
        }
        if (!paths.isEmpty()) {
            r.findings.add(new Finding(LocalRules.Level.MEDIUM, "接口路径泄露",
                    "JS 里散落着 " + paths.size() + " 个接口路径。"
                            + "页面上没入口的隐藏接口常常就藏在这里（越权的高发区）",
                    String.join("  ", new ArrayList<>(paths).subList(0, Math.min(12, paths.size()))),
                    "逐个访问这些接口，重点看管理类/导出类/内部类路径"));
        }

        // ---- 7. Source Map ----
        Matcher sm = SOURCE_MAP_PATTERN.matcher(body);
        if (sm.find()) {
            r.findings.add(new Finding(LocalRules.Level.MEDIUM, "Source Map 泄露",
                    "代码里引用了 Source Map，若该文件可访问就能把压缩代码还原成可读源码",
                    sm.group(1),
                    "直接访问 " + sm.group(1) + "，成功则用 source-map 工具还原源码再审计"));
        }

        // ---- 8. postMessage ----
        if (POSTMESSAGE_PATTERN.matcher(body).find()) {
            boolean originChecked = Pattern.compile(
                    "(?i)addEventListener\\s*\\(\\s*[\"']message[\"'][^)]{0,400}"
                            + "(?:origin|source)\\s*(?:===?|!==?|indexOf|includes)")
                    .matcher(body).find();
            r.findings.add(new Finding(originChecked ? LocalRules.Level.LOW : LocalRules.Level.MEDIUM,
                    "postMessage 监听",
                    originChecked
                            ? "存在 postMessage 监听，代码里似乎有 origin 校验，但仍建议确认校验是否严谨"
                            : "存在 postMessage 监听，且<b>没看到 origin 校验</b> —— "
                            + "任意页面都能给它发消息，可能导致 XSS 或信息泄露",
                    "addEventListener('message', ...)",
                    "构造一个外部页面向该站点 postMessage，看是否触发敏感操作"));
        }

        // ---- 9. 请求侧也纳入审计（路径参数等）----
        if (reqRaw != null) {
            Matcher q = Pattern.compile("\\?([^\\s]{1,200})").matcher(reqRaw);
            if (q.find()) {
                r.hypotheses.add("请求带查询参数：" + truncate(q.group(1), 100)
                        + " —— 逐个改值试参数篡改 / 越权 / 注入");
            }
        }

        // ---- 汇总判定 ----
        if (!r.findings.isEmpty()) {
            return withVerdict(r, Verdict.FOUND, null);
        }

        // 没挖到具体东西 —— 判断「有可能」还是「无」
        if (isDynamic(ct, body)) {
            seedHypotheses(r, ct, reqRaw);
            return withVerdict(r, Verdict.POSSIBLE, null);
        }

        return withVerdict(r, Verdict.NOTHING, "纯静态内容，没有可挖掘的攻击面");
    }

    // ==================================================================

    /** 不可审计的内容类型 → 返回原因状态；可审计 → null。 */
    private static Verdict notAuditable(String ct, String body) {
        String c = ct.toLowerCase();
        if (c.startsWith("image/") || c.startsWith("font/") || c.startsWith("audio/")
                || c.startsWith("video/") || c.contains("octet-stream")
                || c.contains("application/zip") || c.contains("application/pdf")
                || c.contains("application/x-protobuf")) {
            return Verdict.NOT_APPLICABLE;
        }
        if (body.trim().isEmpty()) {
            return Verdict.NOT_APPLICABLE;
        }
        // 太短的响应没有审计价值（但要说清是「太短」而不是「安全」）
        if (body.length() < 32) {
            return Verdict.NOTHING;
        }
        return null;
    }

    /** 是不是「动态内容」—— 也就是有可挖掘面。 */
    private static boolean isDynamic(String ct, String body) {
        String c = ct.toLowerCase();
        if (c.contains("javascript") || c.contains("ecmascript")
                || c.contains("html") || c.contains("json") || c.contains("xml")
                || c.contains("text/plain")) {
            return true;
        }
        // 内容类型不对但内容像代码，也算
        String t = body.trim();
        return t.startsWith("{") || t.startsWith("[") || t.startsWith("<")
                || t.contains("function ") || t.contains("=>");
    }

    /**
     * 给「没挖到具体东西但有攻击面」的情况补上值得试的方向。
     *
     * <p>这是三态设计里最重要的一环：<b>「没发现」不等于「没问题」</b>，
     * 要明确告诉用户「这里还能试什么」，而不是给一个空洞的「无」。
     */
    private static void seedHypotheses(Result r, String ct, String reqRaw) {
        String c = ct.toLowerCase();
        String path = reqRaw == null ? "" : reqRaw;

        if (c.contains("json")) {
            r.hypotheses.add("JSON 接口：试着加一个响应里出现过、但请求没提交的字段（如 isAdmin / balance / status），测试批量赋值");
            r.hypotheses.add("试着删除必填参数、传空值、传错误类型（数字传字符串），看服务端校验是否完备");
            r.hypotheses.add("如果是 GET 查询：试着把 id 改成别人的 / 改成不存在的大数 / 传数组 id[]=1");
        } else if (c.contains("html")) {
            r.hypotheses.add("HTML 页面：试着在 URL 参数里注入 \"'<>，观察是否被原样输出（反射型 XSS）");
            r.hypotheses.add("试着访问同目录下的备份文件（.bak / .old / ~ / .swp）与编辑器残留文件");
        } else if (c.contains("javascript")) {
            r.hypotheses.add("JS 文件：搜索里面硬编码的接口地址与测试账号，很多隐藏入口在这里");
            r.hypotheses.add("检查是否引用了 .map 文件，能访问就能还原源码");
        }
        if (path.contains("?")) {
            r.hypotheses.add("带参数的请求：逐个参数试 SQL 注入（加单引号看报错）、越权（换成别人的 ID）、参数污染（同名参数传两次）");
        }
    }

    static String contentTypeOf(String head) {
        Matcher m = Pattern.compile("(?im)^Content-Type:\\s*(.+)$").matcher(head);
        if (m.find()) {
            String ct = m.group(1).trim();
            int semi = ct.indexOf(';');
            return semi > 0 ? ct.substring(0, semi).trim() : ct;
        }
        return "";
    }

    /** 展示用脱敏 —— 审计证据本身也不该把凭据完整写进报告。 */
    static String mask(String v) {
        if (v == null) {
            return "";
        }
        if (v.length() <= 12) {
            return "****";
        }
        return v.substring(0, 6) + "****" + v.substring(v.length() - 4);
    }

    /** 截断展示。realtime 面板汇总时也要用，所以是 public。 */
    public static String truncate(String s, int n) {
        if (s == null) {
            return "";
        }
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }

    /** 把结论整理成给 AI 的文本（报告生成用）。 */
    public static String toPromptText(Result r) {
        StringBuilder sb = new StringBuilder();
        sb.append("审计结论：").append(r.verdict.label).append('\n');
        sb.append("内容类型：").append(r.contentType).append("　审计 ").append(r.auditedBytes).append(" 字节\n");
        if (r.nothingReason != null) {
            sb.append("说明：").append(r.nothingReason).append('\n');
        }
        if (!r.findings.isEmpty()) {
            sb.append("\n发现：\n");
            for (Finding f : r.findings) {
                sb.append("  [").append(f.level.label).append("] ").append(f.category)
                        .append("：").append(f.detail).append('\n');
                if (f.evidence != null && !f.evidence.isEmpty()) {
                    sb.append("      证据：").append(f.evidence).append('\n');
                }
                if (f.nextStep != null && !f.nextStep.isEmpty()) {
                    sb.append("      下一步：").append(f.nextStep).append('\n');
                }
            }
        }
        if (!r.hypotheses.isEmpty()) {
            sb.append("\n没挖到具体问题，但值得尝试：\n");
            for (String h : r.hypotheses) {
                sb.append("  · ").append(h).append('\n');
            }
        }
        return sb.toString();
    }
}
