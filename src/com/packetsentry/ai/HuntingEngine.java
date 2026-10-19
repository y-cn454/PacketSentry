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
 * 「AI 挖洞」—— 严格说是<b>假设生成器</b>。
 *
 * <h2>为什么不叫「AI 挖洞」</h2>
 * 因为 AI 挖不了洞。它读一遍抓到的 HTTP 流量，能做的最有价值的事是：
 * 把散落的接口、参数、响应差异，<b>归纳成一组可验证的假设</b>，
 * 并给出精确到「发什么请求、看什么现象」的验证步骤。
 *
 * <p>真正的确认必须由人在授权目标上做。所以这里输出的是
 * {@link Hypothesis}（状态一律 {@code PROPOSED}），而不是「发现」。
 *
 * <h2>本引擎对抗「五类拒收」的四道关卡</h2>
 * <ol>
 *   <li><b>输入约束</b>：prompt 只给观测事实，明确禁止引用文档、禁止编造接口</li>
 *   <li><b>路由校验</b>：AI 给出的路由必须能在真实抓包里找到，
 *       否则直接标成「时空错位型」</li>
 *   <li><b>格式解析</b>：解析失败或字段不全的，直接丢弃（不猜）</li>
 *   <li><b>状态锁</b>：AI 无法设置 {@code CONFIRMED} —— 这个字段由人负责</li>
 * </ol>
 */
public final class HuntingEngine {

    /** 单次最多接受的假设条数（防 AI 灌水）。 */
    public static final int MAX_HYPOTHESES = 12;

    /** 业务地图里最多保留的路由数。 */
    public static final int MAX_ROUTES = 120;

    /** 每条路由最多列出的参数名。 */
    public static final int MAX_PARAMS = 12;

    private HuntingEngine() {
    }

    // ==================================================================
    // 业务地图
    // ==================================================================

    /** 一条路由的观测摘要。 */
    public static final class RouteFact {
        public final String method;
        public final String path;
        /** 参数名（去重、有序）。 */
        public final Set<String> params = new LinkedHashSet<>();
        /** 观测到的状态码（去重）。 */
        public final Set<Integer> statuses = new LinkedHashSet<>();
        /** 响应体的短摘要（前 N 字符）。 */
        public String responseHint = "";
        /** 出现次数。 */
        public int hits = 0;

        RouteFact(String method, String path) {
            this.method = method;
            this.path = path;
        }

        public String oneLine() {
            StringBuilder sb = new StringBuilder();
            sb.append(method).append(' ').append(path);
            if (!params.isEmpty()) {
                sb.append("　参数: ").append(String.join(",", params));
            }
            if (!statuses.isEmpty()) {
                List<String> s = new ArrayList<>();
                for (Integer i : statuses) {
                    s.add(String.valueOf(i));
                }
                sb.append("　状态: ").append(String.join("/", s));
            }
            sb.append("　出现 ").append(hits).append(" 次");
            if (!responseHint.isEmpty()) {
                sb.append("\n      响应摘录: ").append(responseHint);
            }
            return sb.toString();
        }
    }

    /**
     * 把抓到的包压成一份<b>可观测量</b>的清单。
     *
     * <p>只保留路径、参数名、状态码和响应摘录 —— <b>不带上任何敏感值</b>。
     * 这些是 AI 提出假设所必需的，也是唯一需要的。
     */
    public static List<RouteFact> buildFacts(List<PacketRecord> records) {
        Map<String, RouteFact> byKey = new LinkedHashMap<>();
        if (records == null) {
            return new ArrayList<>();
        }
        for (PacketRecord r : records) {
            // ⚠️ isRequest 是字段（boolean），不是方法
            if (r == null || !r.isRequest || r.path == null) {
                continue;
            }
            String path = normalize(r.path);
            String method = r.method == null ? "GET" : r.method;
            String key = method + " " + path;
            RouteFact f = byKey.get(key);
            if (f == null) {
                if (byKey.size() >= MAX_ROUTES) {
                    continue;
                }
                f = new RouteFact(method, path);
                byKey.put(key, f);
            }
            f.hits++;

            // 参数名：从原始路径的 query 里取
            for (String p : paramNames(r.path)) {
                if (f.params.size() < MAX_PARAMS) {
                    f.params.add(p);
                }
            }

            // 响应状态码来自<b>请求包的配对响应</b>这里拿不到（RealtimePipe 是按包记录），
            // 所以只用 brief 里可能出现的信息，拿不到就留空 —— 不猜。
            if (f.responseHint.isEmpty() && r.sanitized != null
                    && r.sanitized.cleanText != null) {
                String body = r.sanitized.cleanText.replaceAll("\\s+", " ").trim();
                if (body.length() > 220) {
                    body = body.substring(0, 220) + "…";
                }
                f.responseHint = body;
            }
        }
        return new ArrayList<>(byKey.values());
    }

    /** 从 path 的 query 部分取参数名。 */
    public static List<String> paramNames(String path) {
        List<String> out = new ArrayList<>();
        if (path == null) {
            return out;
        }
        int q = path.indexOf('?');
        if (q < 0) {
            return out;
        }
        for (String pair : path.substring(q + 1).split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String name = eq > 0 ? pair.substring(0, eq) : pair;
            if (!name.isEmpty()) {
                out.add(name);
            }
        }
        return out;
    }

    /** 路径归一化：把数字段换成 {id}，让 /order/1 和 /order/2 归成一条。 */
    public static String normalize(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        int q = path.indexOf('?');
        String p = q >= 0 ? path.substring(0, q) : path;
        String[] seg = p.split("/");
        StringBuilder sb = new StringBuilder();
        for (String s : seg) {
            if (s.isEmpty()) {
                continue;
            }
            sb.append('/');
            if (s.matches("\\d{1,12}")) {
                sb.append("{id}");
            } else if (s.matches("[0-9a-fA-F]{16,}")) {
                sb.append("{hash}");
            } else {
                sb.append(s);
            }
        }
        return sb.length() == 0 ? "/" : sb.toString();
    }

    // ==================================================================
    // Prompt
    // ==================================================================

    /**
     * 生成给模型的 prompt。
     *
     * <h3>⚠️ 这个 prompt 的每一句禁令都对应一种真实失败</h3>
     * <ul>
     *   <li>「不要引用文档」→ 挡拼贴怪</li>
     *   <li>「不要编造不存在的接口」→ 挡时空错位型</li>
     *   <li>「判据必须可证伪」→ 挡薛定谔漏洞</li>
     *   <li>「影响必须有具体宾语，不知道写待验证」→ 挡量子态危害</li>
     *   <li>「不要声称已验证」→ 挡文字幻觉体</li>
     * </ul>
     */
    public static String buildPrompt(List<RouteFact> facts, String domain) {
        StringBuilder sb = new StringBuilder();

        sb.append("你是渗透测试专家，正在帮助一名经过授权的测试人员分析自己的目标。\n");
        sb.append("下面是只读观测到的流量摘要（域名：")
                .append(domain == null || domain.isEmpty() ? "（全部）" : domain)
                .append("）。\n");
        sb.append("敏感值已被脱敏，只有路径、参数名、状态码和响应摘录。\n\n");

        sb.append("==================== 观测事实 ====================\n");
        int n = 0;
        for (RouteFact f : facts) {
            n++;
            if (n > MAX_ROUTES) {
                break;
            }
            sb.append(n).append(". ").append(f.oneLine()).append('\n');
        }
        sb.append("================== 观测事实结束 ==================\n\n");

        sb.append("你的任务是：从上面的观测里，提出**可验证的漏洞假设**。\n\n");

        sb.append("必须遵守的规则（违反任一条，你的输出会被丢弃）：\n");
        sb.append("1. **只用上面给出的事实**。不要引用官方文档、SDK 说明、教程或你的记忆。\n");
        sb.append("2. **不要编造接口**。路由必须逐字出现在上面的清单里，")
                .append("包括方法名。\n");
        sb.append("3. **每条假设必须给出可执行的验证步骤**，")
                .append("至少两步，且要写清发什么请求（方法 + 路径 + 参数/载荷）。\n");
        sb.append("4. **必须给出可证伪的判据**：什么现象算证实。")
                .append("「可能越权」不是判据；")
                .append("「用 A 的令牌请求 B 的订单，若返回 200 且 body 含 B 的数据则证实」才是。\n");
        sb.append("5. **影响必须具体**：说清拿到什么数据、能做什么操作。")
                .append("不知道就写「待验证」，**不要写「可能导致风险」**。\n");
        sb.append("6. **绝对不要声称已验证**。你只是提出假设，确认由人负责。\n");
        sb.append("7. 最多提 ").append(MAX_HYPOTHESES).append(" 条，按可信度从高到低排。\n");
        sb.append("8. 如果观测事实不足以提出任何假设，就只输出「无法提出假设」，")
                .append("不要勉强凑数。\n\n");

        sb.append("优先关注这几类（按 SRC 常见程度排序）：\n");
        sb.append("- 访问控制：同一接口不同身份/不同对象 ID 的响应差异\n");
        sb.append("- 业务逻辑：状态流转能否跳步、金额/数量能否篡改、次数限制能否绕过\n");
        sb.append("- 信息泄露：响应里有没有别的用户的数据、内部路径、调试信息\n");
        sb.append("- 参数处理：同一参数不同编码方式的回显差异\n\n");

        sb.append("输出格式（严格遵守，每个假设一块）：\n\n");
        sb.append("## 假设: <一句话说清猜的是什么>\n");
        sb.append("路由: <METHOD> <path，必须与上面清单逐字一致>\n");
        sb.append("依据: <引用上面观测到的具体现象，不要写文档>\n");
        sb.append("步骤:\n");
        sb.append("1. <具体请求>\n");
        sb.append("2. <具体请求>\n");
        sb.append("判据: <若...则证实...，必须可证伪>\n");
        sb.append("影响: <具体影响；未知写「待验证」>\n");
        sb.append("可信度: 高|中|低\n");

        return sb.toString();
    }

    // ==================================================================
    // 解析
    // ==================================================================

    /** 解析出的假设 + 被丢弃的行数与原因。 */
    public static final class ParseResult {
        public final List<Hypothesis> hypotheses = new ArrayList<>();
        public final List<String> dropped = new ArrayList<>();
    }

    /** 匹配 AI 输出的假设块。 */
    private static final Pattern BLOCK = Pattern.compile(
            "(?m)^#{2,4}\\s*假设\\s*[:：]\\s*(.+)$");

    /**
     * 把模型输出解析成假设列表。
     *
     * <p><b>解析失败就丢弃，绝不猜。</b>一个格式不完整的假设，
     * 补全它的过程本身就是幻觉的来源。
     *
     * @param raw        模型原始输出
     * @param knownPaths 真实抓包里存在的路由集合（用于挡时空错位型）
     */
    public static ParseResult parse(String raw, Set<String> knownPaths) {
        ParseResult out = new ParseResult();
        if (raw == null || raw.trim().isEmpty()) {
            out.dropped.add("模型没有返回内容");
            return out;
        }

        Matcher m = BLOCK.matcher(raw);
        List<int[]> spans = new ArrayList<>();
        List<String> titles = new ArrayList<>();
        while (m.find()) {
            spans.add(new int[]{m.start(), m.end()});
            titles.add(m.group(1).trim());
        }
        if (spans.isEmpty()) {
            out.dropped.add("没找到任何「## 假设:」块 —— 模型没按格式输出");
            return out;
        }

        for (int i = 0; i < spans.size() && out.hypotheses.size() < MAX_HYPOTHESES; i++) {
            int from = spans.get(i)[1];
            int to = (i + 1 < spans.size()) ? spans.get(i + 1)[0] : raw.length();
            String block = raw.substring(from, to);

            String route = field(block, "路由");
            String method = "";
            String path = route;
            if (route.contains(" ")) {
                int sp = route.indexOf(' ');
                method = route.substring(0, sp).trim();
                path = route.substring(sp + 1).trim();
            }
            path = stripTicks(path);
            if (path.contains("?")) {
                path = path.substring(0, path.indexOf('?'));
            }

            String basis = field(block, "依据");
            String expected = field(block, "判据");
            String impact = field(block, "影响");
            String conf = field(block, "可信度");
            List<String> steps = steps(block);

            // 基本完整性：标题、路由、依据、判据、影响、步骤任一缺失就丢
            if (path.isEmpty() || basis.isEmpty() || expected.isEmpty()
                    || impact.isEmpty() || steps.isEmpty()) {
                out.dropped.add("「" + titles.get(i) + "」字段不全（缺 "
                        + missingFields(path, basis, expected, impact, steps) + "）");
                continue;
            }

            // ⭐ 路由校验：挡「时空错位型」。
            //    如果 AI 提到一个抓包里根本没出现过的路径，说明它在编。
            String norm = normalize(path);
            boolean known = knownPaths == null || knownPaths.isEmpty()
                    || knownPaths.contains(norm)
                    || knownPaths.contains(path);
            if (!known) {
                out.dropped.add("「" + titles.get(i) + "」路由 " + path
                        + " 没在抓包流量里出现过 —— 判为时空错位型（AI 编造接口）");
                continue;
            }

            Hypothesis h = new Hypothesis(
                    titles.get(i), path, method.isEmpty() ? "GET" : method,
                    basis, steps, expected, impact, confidence(conf));
            // ⚠️ 状态锁：无论模型说什么，这里都只能是 PROPOSED
            h.status = Hypothesis.Status.PROPOSED;
            out.hypotheses.add(h);
        }
        return out;
    }

    private static String missingFields(String path, String basis, String expected,
                                        String impact, List<String> steps) {
        List<String> miss = new ArrayList<>();
        if (path.isEmpty()) miss.add("路由");
        if (basis.isEmpty()) miss.add("依据");
        if (expected.isEmpty()) miss.add("判据");
        if (impact.isEmpty()) miss.add("影响");
        if (steps.isEmpty()) miss.add("步骤");
        return String.join("/", miss);
    }

    private static String stripTicks(String s) {
        return s == null ? "" : s.replace("`", "").trim();
    }

    /** 取「字段名: 值」这一行。 */
    private static String field(String block, String name) {
        Pattern p = Pattern.compile("(?m)^\\s*(?:[-*]\\s*)?" + name + "\\s*[:：]\\s*(.+)$");
        Matcher m = p.matcher(block);
        if (m.find()) {
            return stripTicks(m.group(1)).trim();
        }
        return "";
    }

    /** 取步骤列表（支持 1. / - / * 开头）。 */
    private static List<String> steps(String block) {
        List<String> out = new ArrayList<>();
        Pattern p = Pattern.compile(
                "(?m)^\\s*(?:\\d+[.、)]|[-*])\\s+(.+)$");
        Matcher m = p.matcher(block);
        while (m.find()) {
            String s = stripTicks(m.group(1)).trim();
            // 排除被当成步骤抓到的其它字段行
            if (s.isEmpty() || s.matches("^(路由|依据|判据|影响|可信度)\\s*[:：].*")) {
                continue;
            }
            out.add(s);
        }
        return out;
    }

    private static Hypothesis.Confidence confidence(String s) {
        if (s == null) {
            return Hypothesis.Confidence.LOW;
        }
        if (s.contains("高")) {
            return Hypothesis.Confidence.HIGH;
        }
        if (s.contains("中")) {
            return Hypothesis.Confidence.MEDIUM;
        }
        return Hypothesis.Confidence.LOW;
    }
}
