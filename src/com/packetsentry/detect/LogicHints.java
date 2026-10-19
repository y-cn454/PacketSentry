package com.packetsentry.detect;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 业务逻辑线索引擎 —— 分析<b>流量流</b>而非单个报文。
 *
 * <h3>和 {@link LocalRules} 的分工</h3>
 * <ul>
 *   <li>{@code LocalRules}：看<b>一个</b>报文 —— 泄露了什么、配置有什么问题</li>
 *   <li>{@code LogicHints}：看<b>一串</b>报文 —— 业务逻辑上有什么可疑的「形状」</li>
 * </ul>
 * 逻辑漏洞的本质是「业务流程上的缺陷」，单看一个包看不出来，但
 * <b>流量的统计特征会暴露它</b>。
 *
 * <h3>能自动发现的和不能的</h3>
 * <table border="1">
 *   <tr><th>类型</th><th>例子</th><th>本引擎</th></tr>
 *   <tr><td>需要主动改包</td><td>price=0.01 支付成功、跳过支付步骤</td>
 *       <td>× 必须构造请求（用 Repeater 或越权测试）</td></tr>
 *   <tr><td>流量形状已暴露</td><td>ID 连续、金额字段在客户端、可重复提交</td>
 *       <td>√ <b>能自动发现</b></td></tr>
 * </table>
 *
 * <h3>▲ 这些是「线索」，不是「漏洞」</h3>
 * 引擎只负责指出「这里值得试」，能不能利用必须<b>人工改包验证</b>。
 * 所以所有输出的名字都带「线索」二字，避免被当成结论提交。
 */
public final class LogicHints {

    /** 签名状态表上限，防止长时间抓包把内存吃满。 */
    private static final int MAX_SIGS = 4000;

    // ==================================================================
    // 参数名分类
    // ==================================================================

    /** 金额类 —— 改了直接影响钱。 */
    private static final Pattern MONEY_PARAM = Pattern.compile(
            "(?i)\\b(price|amount|total|money|fee|cost|pay|payment|discount|"
                    + "coupon|voucher|points|credit|balance|refund|deposit)\\b");

    /** 数量类 —— 负数量、超大批量常被用来套利。 */
    private static final Pattern QUANTITY_PARAM = Pattern.compile(
            "(?i)\\b(qty|quantity|num|count|number|amount_num|buy_num|stock)\\b");

    /** 权限 / 身份类 —— 客户端可控就是垂直越权。 */
    private static final Pattern PRIV_PARAM = Pattern.compile(
            "(?i)\\b(role|roles|is_?admin|is_?super|admin|privilege|permission|"
                    + "level|vip|user_?type|user_?role|group_?id|dept_?id|tenant_?id)\\b");

    /** 状态机类 —— 客户端能直接指定状态就是流程绕过。 */
    private static final Pattern STATE_PARAM = Pattern.compile(
            "(?i)\\b(status|state|step|stage|phase|verified|is_?paid|is_?verified|"
                    + "is_?deleted|approved|audit_?status|order_?status|progress)\\b");

    /** 归属类 —— 改了就可能是越权。 */
    private static final Pattern OWNER_PARAM = Pattern.compile(
            "(?i)\\b(user_?id|uid|owner_?id|account_?id|member_?id|customer_?id|"
                    + "creator_?id|belong_?id)\\b");

    /** CSRF 令牌字段名。 */
    private static final Pattern CSRF_FIELD = Pattern.compile(
            "(?i)(csrf|xsrf|_token|authenticity_?token|__requestverificationtoken)");

    // ==================================================================

    /** 每个接口结构的累积状态。 */
    private static final class SigState {
        final AtomicInteger count = new AtomicInteger();
        /** 观察到的数字段取值（用于判断 ID 是否可预测）。 */
        final java.util.TreeSet<Long> numericIds = new java.util.TreeSet<>();
        /** 请求体的哈希（判断是否真的重复提交同样的内容）。 */
        final java.util.Set<Integer> bodyHashes = ConcurrentHashMap.newKeySet();
        /** 首次 / 最近一次出现时间（判断频控）。 */
        volatile long firstAt = 0;
        volatile long lastAt = 0;
        /** 是否已经报过某类线索，避免刷屏。 */
        final java.util.Set<String> reported = ConcurrentHashMap.newKeySet();
    }

    private final Map<String, SigState> states = new ConcurrentHashMap<>();

    // ==================================================================
    // 入口
    // ==================================================================

    /**
     * 分析一个请求，返回业务逻辑线索。
     *
     * @param signature 结构签名（{@link com.packetsentry.core.RealtimePipe} 生成）
     * @param reqRaw    原始请求
     * @param respRaw   原始响应，可为 null
     */
    public List<LocalRules.Issue> analyze(String signature, String reqRaw, String respRaw) {
        List<LocalRules.Issue> out = new ArrayList<>();
        if (signature == null || reqRaw == null || reqRaw.isEmpty()) {
            return out;
        }
        // 静态资源没有业务逻辑可谈
        if (signature.contains("/static/") || signature.contains(".js ")
                || signature.contains(".css")) {
            return out;
        }

        if (states.size() > MAX_SIGS) {
            states.clear();
        }
        SigState st = states.computeIfAbsent(signature, k -> new SigState());
        int n = st.count.incrementAndGet();
        long now = System.currentTimeMillis();
        if (st.firstAt == 0) {
            st.firstAt = now;
        }
        st.lastAt = now;

        String method = methodOf(reqRaw);
        String body = bodyOf(reqRaw);
        String query = queryOf(reqRaw);
        String all = query + " " + body;

        // ---- 1. ID 可预测性（最重要的越权线索）----
        collectIds(st, reqRaw);
        if (n >= 5 && st.reported.add("id")) {
            String verdict = idPredictability(st);
            if (verdict != null) {
                out.add(new LocalRules.Issue(LocalRules.Level.MEDIUM, "ID可预测线索",
                        "同一接口的标识符呈顺序或小范围分布，改一个数字很可能拿到别人的数据"
                                + "（水平越权的高价值入口）", verdict));
            }
        }

        // ---- 2. 金额 / 数量参数在客户端 ----
        Matcher money = MONEY_PARAM.matcher(all);
        if (money.find() && st.reported.add("money")) {
            out.add(new LocalRules.Issue(LocalRules.Level.HIGH, "金额可篡改线索",
                    "请求里出现金额/优惠类参数，改小或改成负数试试 —— 服务端若不重新计价就是逻辑漏洞",
                    "参数：" + money.group()));
        }
        Matcher qty = QUANTITY_PARAM.matcher(all);
        if (qty.find() && st.reported.add("qty")) {
            out.add(new LocalRules.Issue(LocalRules.Level.MEDIUM, "数量可篡改线索",
                    "请求里出现数量类参数，试试 0 / 负数 / 超大值 —— 常见于套利与超卖",
                    "参数：" + qty.group()));
        }

        // ---- 3. 权限字段在客户端 ----
        Matcher priv = PRIV_PARAM.matcher(all);
        if (priv.find() && st.reported.add("priv")) {
            out.add(new LocalRules.Issue(LocalRules.Level.HIGH, "权限字段可控线索",
                    "请求里出现角色/等级/身份类参数，试着改成管理员值。"
                            + "服务端若直接信任客户端传入的权限字段就是垂直越权",
                    "参数：" + priv.group()));
        }

        // ---- 4. 状态字段在客户端 ----
        Matcher state = STATE_PARAM.matcher(all);
        if (state.find() && st.reported.add("state")) {
            out.add(new LocalRules.Issue(LocalRules.Level.MEDIUM, "状态字段可控线索",
                    "请求里出现状态/步骤类参数，试着直接跳到终态（如 status=paid、step=done）"
                            + "看能否绕过流程",
                    "参数：" + state.group()));
        }

        // ---- 5. 归属字段（越权入口）----
        Matcher owner = OWNER_PARAM.matcher(all);
        if (owner.find() && st.reported.add("owner")) {
            out.add(new LocalRules.Issue(LocalRules.Level.MEDIUM, "归属字段可控线索",
                    "请求里出现资源归属类参数，改成别人的 ID 即可测试越权",
                    "参数：" + owner.group()));
        }

        // ---- 6. 缺少 CSRF 令牌 ----
        if (isStateChanging(method)) {
            boolean hasCsrf = CSRF_FIELD.matcher(all).find();
            boolean hasCookie = reqRaw.toLowerCase().contains("\ncookie:");
            if (!hasCsrf && hasCookie && st.reported.add("csrf")) {
                out.add(new LocalRules.Issue(LocalRules.Level.MEDIUM, "无CSRF令牌线索",
                        "会改变状态的请求既没有 CSRF 令牌、又依赖 Cookie 认证，"
                                + "可能存在 CSRF（若服务端只靠 SameSite 防护则风险较低）",
                        method + " 无 csrf 字段"));
            }
        }

        // ---- 7. HTTP 参数污染 ----
        String pollution = findParamPollution(query, body);
        if (pollution != null && st.reported.add("hpp")) {
            out.add(new LocalRules.Issue(LocalRules.Level.MEDIUM, "参数重复线索",
                    "同名参数出现多次，不同框架取值规则不同，可能存在参数污染绕过",
                    "参数：" + pollution));
        }

        // ---- 8. 重复提交（幂等性缺失）----
        if (isStateChanging(method) && body != null && !body.isEmpty()) {
            st.bodyHashes.add(body.hashCode());
            if (n >= 4 && st.bodyHashes.size() <= 2 && st.reported.add("idem")) {
                out.add(new LocalRules.Issue(LocalRules.Level.MEDIUM, "可重复提交线索",
                        "同一个会改变状态的请求被重复发送了多次，且内容基本相同。"
                                + "如果服务端没有幂等保护，可能存在重复领券 / 重复下单 / 重复扣款",
                        "重复 " + n + " 次，仅 " + st.bodyHashes.size() + " 种内容"));
            }
        }

        // ---- 9. 频控缺失 ----
        long span = st.lastAt - st.firstAt;
        if (n >= 15 && span > 0 && span < 60_000 && st.reported.add("rate")) {
            double perSec = n / (span / 1000.0);
            out.add(new LocalRules.Issue(LocalRules.Level.MEDIUM, "频控缺失线索",
                    "同一接口在短时间内被高频调用，服务端似乎没有速率限制。"
                            + "若是短信 / 验证码 / 登录 / 查询类接口，可能是频控缺陷",
                    String.format("%d 次 / %.1f 秒（约 %.1f 次/秒）", n, span / 1000.0, perSec)));
        }

        // ---- 10. 前端校验痕迹（响应里）----
        if (respRaw != null && !respRaw.isEmpty() && st.reported.add("clientval")) {
            String cv = findClientSideValidation(respRaw);
            if (cv != null) {
                out.add(new LocalRules.Issue(LocalRules.Level.LOW, "前端校验线索",
                        "页面存在纯前端校验（maxlength / readonly / pattern 等），"
                                + "直接改包绕过即可测试服务端是否也校验",
                        cv));
            }
        }

        // ---- 11. 参数数量暗示批量赋值 ----
        if (isStateChanging(method) && body != null) {
            int fieldCount = countJsonFields(body);
            if (fieldCount >= 8 && st.reported.add("mass")) {
                out.add(new LocalRules.Issue(LocalRules.Level.LOW, "多字段提交线索",
                        "一次提交大量字段，可尝试加一个响应里出现过但请求没提交的字段"
                                + "（如 isAdmin / balance），测试是否存在批量赋值",
                        fieldCount + " 个字段"));
            }
        }

        return out;
    }

    // ==================================================================
    // 各条检测的实现
    // ==================================================================

    /**
     * 从请求路径里收集数字段，用于判断 ID 是否可预测。
     *
     * <p>▲ 这里踩过一个坑：早期写成 {@code reqRaw.substring(0, reqRaw.indexOf(' '))}，
     * 取到的是<b>方法名</b>（{@code "GET"}）而不是路径 —— 里面当然没有 ID，
     * 于是「顺序 ID」这条最重要的越权线索永远不触发。
     * 正确做法是取<b>第一个空格和第二个空格之间</b>的那一段。
     */
    private void collectIds(SigState st, String reqRaw) {
        String path = extractPath(reqRaw);
        Matcher m = Pattern.compile("/(\\d{1,15})(?=/|\\?|$)").matcher(path);
        while (m.find()) {
            try {
                st.numericIds.add(Long.parseLong(m.group(1)));
            } catch (NumberFormatException ignored) {
                // 超长数字，跳过
            }
            if (st.numericIds.size() > 200) {
                break;      // 只看最近一批，避免大范围爬取时内存膨胀
            }
        }
    }

    /** 取请求行里的路径部分：第一个空格之后、第二个空格之前。 */
    static String extractPath(String reqRaw) {
        if (reqRaw == null) {
            return "";
        }
        int sp1 = reqRaw.indexOf(' ');
        if (sp1 < 0) {
            return reqRaw;
        }
        int sp2 = reqRaw.indexOf(' ', sp1 + 1);
        return sp2 > sp1 ? reqRaw.substring(sp1 + 1, sp2) : reqRaw.substring(sp1 + 1);
    }

    /**
     * 判断 ID 是否可预测。
     *
     * <p>依据是<b>分布密度</b>而不是「有没有连续」：
     * <pre>
     *   1001,1002,1003,1005,1008 → 跨度 8，5 个值 → 密度 0.63 → 顺序，可疑
     *   8273619, 55, 918273, 4, 7712 → 跨度 918269，5 个值 → 密度 0.000005 → 随机，不可疑
     * </pre>
     *
     * <p>还要排除「自增但属于自己」的误判 —— 所以只在密度高<b>且</b>跨度小时报。
     */
    static String idPredictability(SigState st) {
        if (st.numericIds.size() < 4) {
            return null;
        }
        long min = st.numericIds.first();
        long max = st.numericIds.last();
        long span = max - min + 1;
        if (span <= 0) {
            return null;
        }
        double density = (double) st.numericIds.size() / span;
        // 跨度大且密度低 = 随机 ID，不可预测
        if (span > 100000 || density < 0.20) {
            return null;
        }
        return String.format("观察到 %d 个值，范围 %d～%d（跨度 %d，密度 %.0f%%）",
                st.numericIds.size(), min, max, span, density * 100);
    }

    /** 找出重复出现的参数名。 */
    static String findParamPollution(String query, String body) {
        java.util.Map<String, Integer> seen = new java.util.HashMap<>();
        if (query != null) {
            for (String kv : query.split("&")) {
                int eq = kv.indexOf('=');
                if (eq > 0) {
                    String k = kv.substring(0, eq);
                    seen.merge(k, 1, Integer::sum);
                }
            }
        }
        if (body != null) {
            Matcher fm = Pattern.compile("(?:^|&)([A-Za-z_][A-Za-z0-9_]{0,40})=").matcher(body);
            while (fm.find()) {
                seen.merge(fm.group(1), 1, Integer::sum);
            }
            Matcher jm = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]{0,40})\"\\s*:").matcher(body);
            java.util.Map<String, Integer> jseen = new java.util.HashMap<>();
            while (jm.find()) {
                jseen.merge(jm.group(1), 1, Integer::sum);
            }
            for (Map.Entry<String, Integer> e : jseen.entrySet()) {
                if (e.getValue() > 1) {
                    return e.getKey() + "（出现 " + e.getValue() + " 次）";
                }
            }
        }
        for (Map.Entry<String, Integer> e : seen.entrySet()) {
            if (e.getValue() > 1) {
                return e.getKey() + "（出现 " + e.getValue() + " 次）";
            }
        }
        return null;
    }

    /** 响应里的前端校验痕迹。 */
    static String findClientSideValidation(String resp) {
        Matcher m = Pattern.compile(
                "(?is)<input[^>]*?(maxlength|readonly|disabled|pattern|min|max)\\s*="
                        + "[^>]*>").matcher(resp);
        if (m.find()) {
            String tag = m.group();
            return tag.length() > 90 ? tag.substring(0, 90) + "…" : tag;
        }
        return null;
    }

    static int countJsonFields(String body) {
        Matcher m = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]{0,40})\"\\s*:").matcher(body);
        java.util.Set<String> keys = new java.util.HashSet<>();
        while (m.find()) {
            keys.add(m.group(1));
        }
        return keys.size();
    }

    static boolean isStateChanging(String method) {
        return "POST".equals(method) || "PUT".equals(method)
                || "PATCH".equals(method) || "DELETE".equals(method);
    }

    static String methodOf(String reqRaw) {
        int sp = reqRaw.indexOf(' ');
        return sp > 0 ? reqRaw.substring(0, sp).toUpperCase() : "";
    }

    static String queryOf(String reqRaw) {
        int q = reqRaw.indexOf('?');
        if (q < 0) {
            return "";
        }
        int sp = reqRaw.indexOf(' ', q);
        return sp > q ? reqRaw.substring(q + 1, sp) : reqRaw.substring(q + 1);
    }

    static String bodyOf(String reqRaw) {
        int sep = reqRaw.indexOf("\r\n\r\n");
        if (sep >= 0) {
            return reqRaw.substring(sep + 4);
        }
        sep = reqRaw.indexOf("\n\n");
        return sep >= 0 ? reqRaw.substring(sep + 2) : "";
    }

    /** 清空状态（用户点「清空」时调用）。 */
    public void reset() {
        states.clear();
    }

    /** 已观察到的接口结构数。 */
    public int trackedSignatures() {
        return states.size();
    }
}
