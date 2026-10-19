package com.packetsentry.ai;

import com.packetsentry.core.PacketRecord;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 本地规则挖洞 —— <b>完全不需要模型</b>。
 *
 * <h2>为什么要有一个「不需要 AI」的挖洞器</h2>
 * 用户挖 SRC，而 SRC 安全模式要求数据不出本机。本地能跑的模型通常只有 7B/8B，
 * 让它在几百条路由里"猜"哪些有洞，产出质量不稳定。
 *
 * <p>但真正拖慢 SRC 挖洞的<b>不是看不出有洞，而是不知道从哪下手</b>。
 * 而"从哪下手"这件事是<b>确定性</b>的：同一接口不同对象 ID 的响应长度不一样、
 * 响应里出现了别人的邮箱、请求压根没带 Cookie —— 这些信号不需要模型去猜。
 *
 * <p>所以这里的每条规则都建立在<b>真实观测到的差异</b>上，产出的是
 * {@link Hypothesis}（状态自然是待验证），而不是结论。它比小模型猜得更靠谱，
 * 因为它的依据是抓包里的事实，不是概率。
 *
 * <h2>和 AI 版的关系</h2>
 * 两者输出同一个数据模型、过同一个闸门。区别只在假设从哪来：
 * <ul>
 *   <li>本类：规则驱动的确定性假设（零成本、SRC 模式可用）</li>
 *   <li>{@link HuntingEngine}：模型驱动的发散假设（需要模型）</li>
 * </ul>
 * 可以只用前者，也可以两个都跑再合并。
 */
public final class LocalHunter {

    /** 一条规则最多产出多少条假设（防刷屏）。 */
    private static final int MAX_PER_RULE = 4;

    /** 响应长度差异的判定阈值（字节）。 */
    private static final int LEN_DIFF_THRESHOLD = 64;

    private LocalHunter() {
    }

    /** 产出结果。 */
    public static final class Result {
        public final List<Hypothesis> hypotheses = new ArrayList<>();
        /** 每条规则命中多少（给人看规则是否有效）。 */
        public final Map<String, Integer> ruleHits = new LinkedHashMap<>();
    }

    // ==================================================================
    // 观测模型
    // ==================================================================

    /**
     * 一个「对象型路由」的观测：同一条路由下，不同 ID 各自的响应长度。
     *
     * <p>这是越权检测的核心素材 —— 如果换一个 ID 还能拿到等长的响应，
     * 说明服务端没有校验归属。
     */
    private static final class ObjectRoute {
        final String method;
        final String pathTemplate;
        /** ID 值 → 观测到的响应长度（取最后一次）。 */
        final Map<String, Integer> idToLen = new LinkedHashMap<>();
        /** ID 值 → 是否带 Cookie。 */
        final Map<String, Boolean> idToAuth = new LinkedHashMap<>();
        /** 响应里出现过的「疑似他人标识」片段。 */
        String leakedHint = "";

        ObjectRoute(String method, String pathTemplate) {
            this.method = method;
            this.pathTemplate = pathTemplate;
        }
    }

    /** 参数名里的 ID 类特征。 */
    private static final Pattern ID_PARAM = Pattern.compile(
            "(?i)^(?:id|uid|user_?id|account_?id|order_?id|oid|pid|item_?id|"
                    + "resource_?id|obj(?:ect)?_?id|member_?id|card_?id|doc_?id|"
                    + "file_?id|attach(?:ment)?_?id|msg_?id|task_?id|contract_?id)$");

    /** 金额 / 数量 / 状态类参数 —— 篡改类假设的线索。 */
    private static final Pattern TAMPER_PARAM = Pattern.compile(
            "(?i)^(?:amount|price|total|cost|fee|money|balance|quantity|qty|count|"
                    + "num|number|score|points|level|status|state|type|role|"
                    + "is_?vip|vip|grade|discount|coupon|quota|limit)$");

    /** 越权 / 信息泄露类参数。 */
    private static final Pattern OBJECT_LIKE = Pattern.compile(
            "(?i)^(?:id|uid|.*_id|.*Id)$");

    /** 响应里指向「有人身份信息」的字段。 */
    private static final Pattern PII_FIELD = Pattern.compile(
            "(?i)\"(?:email|mail|phone|mobile|tel|idcard|id_card|realname|real_name|"
                    + "name|address|receiver|username|user_name|account|accountNo|"
                    + "bankcard|bank_card|ssn|passport)\"\\s*:\\s*\"([^\"]{2,60})\"");

    /** 响应里出现「别人的」标识——用于说明越权观测。 */
    private static final Pattern OWNERSHIP_FIELD = Pattern.compile(
            "(?i)\"(?:uid|user_?id|owner(?:Id)?|create_?by|belong_?to|"
                    + "account_?id|member_?id)\"\\s*:\\s*\"?([A-Za-z0-9_\\-]{1,40})\"?");

    /** 调试 / 版本泄露。 */
    private static final Pattern DEBUG_LEAK = Pattern.compile(
            "(?i)(?:at\\s+[a-z0-9_.$]+\\([A-Za-z0-9_.]+\\.java:\\d+\\))"
                    + "|(?:Traceback \\(most recent call last\\))"
                    + "|(?:Unhandled\\s+exception)"
                    + "|(?:<b>Fatal error</b>:)"
                    + "|(?:Exception in thread)");

    /** 分页参数 —— 数量上限缺失的线索。 */
    private static final Pattern PAGE_PARAM = Pattern.compile(
            "(?i)^(?:page|pageNo|page_no|p|offset|cursor|start)$");

    /** 每页大小参数。 */
    private static final Pattern SIZE_PARAM = Pattern.compile(
            "(?i)^(?:size|pageSize|page_size|limit|per_page|perPage|rows|count)$");

    // ==================================================================
    // 主入口
    // ==================================================================

    /**
     * 从抓到的包里用规则产出假设。
     *
     * @param records 流量记录（请求包即可，响应信息取同一记录里的脱敏文本）
     */
    public static Result hunt(List<PacketRecord> records) {
        Result out = new Result();
        if (records == null || records.isEmpty()) {
            return out;
        }

        // ---- 先把观测整理成对象型路由 ----
        Map<String, ObjectRoute> objRoutes = new LinkedHashMap<>();
        // 也保留原始清单，给不需要分组的路由用
        List<PacketRecord> all = new ArrayList<>();

        for (PacketRecord r : records) {
            if (r == null || !r.isRequest || r.path == null) {
                continue;
            }
            all.add(r);
            String path = r.path;
            String norm = HuntingEngine.normalize(path);
            String method = r.method == null ? "GET" : r.method;
            String key = method + " " + norm;

            // 只有在路径里真的有 {id} 段时才算对象型路由
            if (!norm.contains("{id}")) {
                continue;
            }
            ObjectRoute o = objRoutes.get(key);
            if (o == null) {
                o = new ObjectRoute(method, norm);
                objRoutes.put(key, o);
            }
            String idValue = idInPath(path);
            if (idValue != null) {
                o.idToLen.put(idValue, responseLen(r));
                o.idToAuth.put(idValue, hasAuth(r));
            }
            if (o.leakedHint.isEmpty()) {
                o.leakedHint = leakedOwnership(r);
            }
        }

        // ---- 规则 1：对象 ID 可替换 → 越权 ----
        rule1Idor(objRoutes, out);
        // ---- 规则 2：请求没带认证但返回了数据 → 未授权访问 ----
        rule2NoAuth(all, out);
        // ---- 规则 3：响应回显身份信息 → 信息泄露 / 越权观测 ----
        rule3PiiEcho(all, out);
        // ---- 规则 4：金额 / 数量 / 状态类参数 → 篡改 ----
        rule4Tamper(all, out);
        // ---- 规则 5：分页参数无上限 → 批量拉取 ----
        rule5Pagination(all, out);
        // ---- 规则 6：调试信息泄露 ----
        rule6DebugLeak(all, out);

        return out;
    }

    // ==================================================================
    // 规则实现
    // ==================================================================

    /** 规则 1：路径里有 {id} 段 —— 换 ID 是否还能拿到数据。 */
    private static void rule1Idor(Map<String, ObjectRoute> routes, Result out) {
        int made = 0;
        for (ObjectRoute o : routes.values()) {
            if (made >= MAX_PER_RULE) {
                break;
            }
            List<String> ids = new ArrayList<>(o.idToLen.keySet());
            String step1 = o.method + " " + o.pathTemplate.replace("{id}", "1001")
                    + "（用账号 A 的令牌）";
            String step2 = o.method + " " + o.pathTemplate.replace("{id}", "1002")
                    + "（仍用账号 A 的令牌，1002 属于账号 B）";

            String basis;
            if (ids.size() >= 2) {
                // 有多个不同 ID 的观测，用响应长度差异作为依据
                StringBuilder b = new StringBuilder();
                b.append("同一路由下观测到 ").append(ids.size()).append(" 个不同 ID：");
                int n = 0;
                for (Map.Entry<String, Integer> e : o.idToLen.entrySet()) {
                    if (n++ >= 3) {
                        break;
                    }
                    b.append("id=").append(e.getKey())
                            .append(" 响应 ").append(e.getValue()).append(" 字节；");
                }
                b.append("说明服务端按 ID 直接返回数据");
                basis = b.toString();
            } else {
                basis = "路径含可变 ID 段（" + o.pathTemplate
                        + "），响应按该 ID 返回数据，未观测到归属校验";
            }

            Hypothesis h = new Hypothesis(
                    "对象级越权：换 ID 能否读取他人数据",
                    o.pathTemplate, o.method,
                    basis,
                    java.util.Arrays.asList(step1, step2),
                    "若换用 1002 仍返回 200 且 body 内容是账号 B 的数据（不是空/403），则证实越权",
                    "可读取任意其他用户的资源，具体数据类型取决于该接口返回的字段（待验证）",
                    Hypothesis.Confidence.HIGH);
            out.hypotheses.add(h);
            bump(out, "对象 ID 越权线索");
            made++;
        }
    }

    /** 规则 2：请求没带认证头/Cookie 但拿到了 200 —— 未授权访问。 */
    private static void rule2NoAuth(List<PacketRecord> all, Result out) {
        Set<String> seen = new LinkedHashSet<>();
        int made = 0;
        for (PacketRecord r : all) {
            if (made >= MAX_PER_RULE) {
                break;
            }
            if (hasAuth(r)) {
                continue;
            }
            String norm = HuntingEngine.normalize(r.path);
            if (!seen.add(norm)) {
                continue;
            }
            String method = r.method == null ? "GET" : r.method;
            // 只对看起来像 API 的路径提假设，避免把静态资源算进来
            if (!looksLikeApi(norm)) {
                continue;
            }
            Hypothesis h = new Hypothesis(
                    "未授权访问：该接口可能不需要登录",
                    norm, method,
                    "抓到的请求里<b>没有</b> Cookie / Authorization 头，"
                            + "但请求被正常发出（路径 " + norm + "）",
                    java.util.Arrays.asList(
                            method + " " + norm + "（完全不带 Cookie 和 Authorization）",
                            "观察返回状态码与 body 是否包含业务数据"),
                    "若返回 200 且 body 含业务字段（不是登录页/401/403），则证实未授权访问",
                    "未登录即可访问该接口，具体影响取决于返回的数据（待验证）",
                    Hypothesis.Confidence.MEDIUM);
            out.hypotheses.add(h);
            bump(out, "未授权访问线索");
            made++;
        }
    }

    /** 规则 3：响应里回显身份信息 —— 可能是别人的数据。 */
    private static void rule3PiiEcho(List<PacketRecord> all, Result out) {
        Set<String> seen = new LinkedHashSet<>();
        int made = 0;
        for (PacketRecord r : all) {
            if (made >= MAX_PER_RULE) {
                break;
            }
            if (r.sanitized == null || r.sanitized.cleanText == null) {
                continue;
            }
            String text = r.sanitized.cleanText;
            Matcher m = PII_FIELD.matcher(text);
            if (!m.find()) {
                continue;
            }
            String fieldValue = m.group(0);
            String norm = HuntingEngine.normalize(r.path);
            if (!seen.add(norm)) {
                continue;
            }
            String fieldName = m.group(1);
            Hypothesis h = new Hypothesis(
                    "响应回显身份信息：可能越权或过度暴露",
                    norm, r.method == null ? "GET" : r.method,
                    "该接口响应里出现身份类字段（" + fieldName
                            + "），脱敏后片段：" + clip(fieldValue, 60),
                    java.util.Arrays.asList(
                            "用账号 A 请求 " + norm,
                            "用账号 B 请求同一接口，对比返回的身份字段是否不同"),
                    "若两个账号请求同一接口返回了<b>对方的</b>姓名/手机/地址，则证实越权；"
                            + "若各自只返回自己的，则只是字段暴露，应看是否有脱敏",
                    "可能读取到其他用户的姓名、手机号或地址（待验证）",
                    Hypothesis.Confidence.MEDIUM);
            out.hypotheses.add(h);
            bump(out, "身份信息回显线索");
            made++;
        }
    }

    /** 规则 4：金额 / 数量 / 状态类参数 —— 尝试篡改。 */
    private static void rule4Tamper(List<PacketRecord> all, Result out) {
        Set<String> seen = new LinkedHashSet<>();
        int made = 0;
        for (PacketRecord r : all) {
            if (made >= MAX_PER_RULE) {
                break;
            }
            String norm = HuntingEngine.normalize(r.path);
            for (String p : HuntingEngine.paramNames(r.path)) {
                if (!TAMPER_PARAM.matcher(p).matches()) {
                    continue;
                }
                String key = norm + "?" + p;
                if (!seen.add(key)) {
                    break;
                }
                String method = r.method == null ? "GET" : r.method;
                Hypothesis h = new Hypothesis(
                        "参数篡改：" + p + " 是否被服务端校验",
                        norm, method,
                        "该接口接收名为 " + p + " 的参数，属于金额/数量/状态类，"
                                + "由客户端提交",
                        java.util.Arrays.asList(
                                method + " " + norm + "?" + p + "=<原值>（记录基线响应）",
                                method + " " + norm + "?" + p + "=<改成负数或极大值>"
                                        + "（观察服务端是否接受）"),
                        "若篡改后的值被接受（返回 200 且后续查询显示该值已生效），则证实校验缺失",
                        "可能伪造金额/数量/状态，具体后果取决于该参数的实际用途（待验证）",
                        Hypothesis.Confidence.MEDIUM);
                out.hypotheses.add(h);
                bump(out, "参数篡改线索");
                made++;
                break;
            }
        }
    }

    /** 规则 5：分页参数存在但没看到上限 —— 可能可以批量拉取。 */
    private static void rule5Pagination(List<PacketRecord> all, Result out) {
        Set<String> seen = new LinkedHashSet<>();
        int made = 0;
        for (PacketRecord r : all) {
            if (made >= MAX_PER_RULE) {
                break;
            }
            List<String> ps = HuntingEngine.paramNames(r.path);
            boolean hasPage = false;
            boolean hasSize = false;
            String sizeName = "";
            for (String p : ps) {
                if (PAGE_PARAM.matcher(p).matches()) {
                    hasPage = true;
                }
                if (SIZE_PARAM.matcher(p).matches()) {
                    hasSize = true;
                    sizeName = p;
                }
            }
            if (!hasPage || !hasSize) {
                continue;
            }
            String norm = HuntingEngine.normalize(r.path);
            if (!seen.add(norm)) {
                continue;
            }
            String method = r.method == null ? "GET" : r.method;
            Hypothesis h = new Hypothesis(
                    "分页上限缺失：可能一次拉走全量数据",
                    norm, method,
                    "该接口同时接受分页参数与每页数量参数（" + sizeName + "），"
                            + "说明服务端按客户端给的数量返回",
                    java.util.Arrays.asList(
                            method + " " + norm + "?" + sizeName + "=10（基线）",
                            method + " " + norm + "?" + sizeName + "=100000（观察是否被截断或拒绝）"),
                    "若给到 100000 仍返回 200 且条数明显大于基线（未截断），则证实上限缺失",
                    "可批量拉取全量数据，具体规模取决于数据量（待验证）",
                    Hypothesis.Confidence.LOW);
            out.hypotheses.add(h);
            bump(out, "分页上限线索");
            made++;
        }
    }

    /** 规则 6：响应里有调试信息 / 堆栈。 */
    private static void rule6DebugLeak(List<PacketRecord> all, Result out) {
        Set<String> seen = new LinkedHashSet<>();
        int made = 0;
        for (PacketRecord r : all) {
            if (made >= MAX_PER_RULE) {
                break;
            }
            if (r.sanitized == null || r.sanitized.cleanText == null) {
                continue;
            }
            Matcher m = DEBUG_LEAK.matcher(r.sanitized.cleanText);
            if (!m.find()) {
                continue;
            }
            String norm = HuntingEngine.normalize(r.path);
            if (!seen.add(norm)) {
                continue;
            }
            String snippet = clip(m.group(0), 80);
            Hypothesis h = new Hypothesis(
                    "调试信息泄露：响应里出现堆栈",
                    norm, r.method == null ? "GET" : r.method,
                    "响应体里出现异常/堆栈特征：" + snippet,
                    java.util.Arrays.asList(
                            r.method == null ? "GET" : r.method + " " + norm,
                            "观察响应里的堆栈是否包含类名、文件路径、SQL 语句或内部 IP"),
                    "若堆栈里出现完整类名/文件绝对路径/SQL 片段，则证实信息泄露（可能进一步利用）",
                    "可获取内部路径与技术栈信息，为后续利用提供情报；"
                            + "若堆栈含 SQL 片段则可能升级为注入线索（待验证）",
                    Hypothesis.Confidence.LOW);
            out.hypotheses.add(h);
            bump(out, "调试信息泄露线索");
            made++;
        }
    }

    // ==================================================================
    // 工具
    // ==================================================================

    private static void bump(Result out, String rule) {
        out.ruleHits.merge(rule, 1, Integer::sum);
    }

    /** 取路径里 {id} 位置上的实际值。 */
    private static String idInPath(String path) {
        if (path == null) {
            return null;
        }
        for (String seg : path.split("/")) {
            if (seg.matches("\\d{1,12}")) {
                return seg;
            }
        }
        return null;
    }

    /** 响应长度（用脱敏文本长度近似 —— 够用来发现差异）。 */
    private static int responseLen(PacketRecord r) {
        if (r.sanitized != null && r.sanitized.cleanText != null) {
            return r.sanitized.cleanText.length();
        }
        return r.size;
    }

    /** 请求是否带了认证。 */
    private static boolean hasAuth(PacketRecord r) {
        if (r.brief == null) {
            return false;
        }
        String b = r.brief.toLowerCase();
        return b.contains("cookie:") || b.contains("authorization:")
                || b.contains("x-token") || b.contains("token:");
    }

    /** 响应里是否出现「归属」字段（说明这是别人的资源）。 */
    private static String leakedOwnership(PacketRecord r) {
        if (r.sanitized == null || r.sanitized.cleanText == null) {
            return "";
        }
        Matcher m = OWNERSHIP_FIELD.matcher(r.sanitized.cleanText);
        if (m.find()) {
            return clip(m.group(0), 80);
        }
        return "";
    }

    /** 看起来像 API 的路径（排除静态资源）。 */
    private static boolean looksLikeApi(String norm) {
        if (norm.matches("(?i).*\\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map)$")) {
            return false;
        }
        return norm.contains("/api") || norm.contains("/v1") || norm.contains("/v2")
                || norm.contains("/user") || norm.contains("/order")
                || norm.contains("/admin") || norm.contains("/detail")
                || norm.contains("/list") || norm.contains("/info");
    }

    private static String clip(String s, int max) {
        if (s == null) {
            return "";
        }
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= max ? t : t.substring(0, max) + "…";
    }
}
