package com.packetsentry.core;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;

import com.packetsentry.sanitize.Sanitizer;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 越权检测引擎 —— 水平越权（IDOR）与垂直越权。
 *
 * <h3>测试协议</h3>
 * <pre>
 * 基线  用身份 A 发请求 R，得到响应 Resp_A
 * 测试  把 R 里的认证头换成身份 B 的，重发，得到 Resp_B
 * 判定  见 {@link #compare}
 * </pre>
 *
 * <h3>▲ 这是主动测试 —— 会向目标发送额外请求</h3>
 * 所以调用方必须：
 * <ul>
 *   <li>只在用户<b>明确点击</b>后调用（绝不自动触发）</li>
 *   <li>调用前弹窗告知「将发送 N 个请求到 host」</li>
 *   <li>只在<b>已获授权</b>的目标上使用</li>
 *   <li>限制频率（见 {@link #minIntervalMs}）</li>
 * </ul>
 *
 * <h3>判定为什么要两个相似度指标</h3>
 * 只看「响应像不像」会误判。考虑两个场景：
 * <pre>
 * 场景甲（越权）  A 和 B 请求同一资源，都拿到 {"orderId":5001,"userId":1001,"amount":100}
 *                 → 结构像，<b>值也一样</b> → 可疑
 *
 * 场景乙（正常）  A 拿到 {"id":1001,"name":"Alice"}，B 拿到 {"id":1002,"name":"Bob"}
 *                 → 结构像，<b>值不同</b> → 这是各拿各的，正常
 * </pre>
 * 所以：<b>结构相似度高是正常的，值相似度高才可疑</b>。
 * 把这两个分开算，才能把「越权」和「各拿各的」区分开。
 */
public final class AccessControlTester {

    /** 判定结论。 */
    public enum Verdict {
        /** 换了身份仍拿到相同数据 —— 越权。 */
        VULNERABLE("▲ 疑似越权", "换身份后仍返回相同数据，访问控制可能缺失"),
        /** 被正确拦截。 */
        PROTECTED("√ 有访问控制", "换身份后被拒绝（401/403/404），符合预期"),
        /** 各拿各的数据 —— 不是越权。 */
        SEPARATE("√ 各取各的数据", "换身份后返回的是该身份自己的数据，不是越权"),
        /** 拿不准，要人工看。 */
        INCONCLUSIVE("? 需人工判断", "响应既不像同一份数据，也不像明确拒绝"),
        /** 请求本身失败。 */
        ERROR("× 测试失败", "请求未成功完成"),
        /** 基线不可用。 */
        NO_BASELINE("— 无基线", "缺少身份 A 的响应，无法对比");

        public final String label;
        public final String reason;

        Verdict(String label, String reason) {
            this.label = label;
            this.reason = reason;
        }
    }

    /** 一次对比的完整结果。 */
    public static final class Result {
        public final Identity baselineIdentity;
        public final Identity testIdentity;
        public final Verdict verdict;

        public final int baseStatus;
        public final int testStatus;
        public final int baseLength;
        public final int testLength;

        /** 结构相似度（键名/字段名重合度）。 */
        public final double structureSim;
        /** 值相似度（标量值重合度）—— 高才可疑。 */
        public final double valueSim;

        /** 从响应里猜出来的「拥有者标识」对比，可为空。 */
        public final String baseOwner;
        public final String testOwner;

        public final String testRequestText;
        public final String testResponseText;
        public final String error;

        Result(Identity bi, Identity ti, Verdict v,
               int bs, int ts, int bl, int tl,
               double ss, double vs, String bo, String to,
               String reqText, String respText, String err) {
            this.baselineIdentity = bi;
            this.testIdentity = ti;
            this.verdict = v;
            this.baseStatus = bs;
            this.testStatus = ts;
            this.baseLength = bl;
            this.testLength = tl;
            this.structureSim = ss;
            this.valueSim = vs;
            this.baseOwner = bo;
            this.testOwner = to;
            this.testRequestText = reqText;
            this.testResponseText = respText;
            this.error = err;
        }

        public String summaryLine() {
            return verdict.label + "　"
                    + baseStatus + " → " + testStatus
                    + "　结构相似 " + pct(structureSim)
                    + "　值相似 " + pct(valueSim);
        }

        private static String pct(double d) {
            return String.format("%.0f%%", d * 100);
        }

        public String detail() {
            StringBuilder sb = new StringBuilder();
            sb.append("判定    ").append(verdict.label).append('\n');
            sb.append("说明    ").append(verdict.reason).append('\n');
            if (error != null) {
                sb.append("错误    ").append(error).append('\n');
            }
            sb.append('\n');
            sb.append("基线身份  ").append(baselineIdentity == null ? "(无)" : baselineIdentity.describe()).append('\n');
            sb.append("测试身份  ").append(testIdentity == null ? "(无)" : testIdentity.describe()).append('\n');
            sb.append('\n');
            sb.append(String.format("状态码    %d  →  %d%n", baseStatus, testStatus));
            sb.append(String.format("响应长度  %d  →  %d 字节%n", baseLength, testLength));
            sb.append(String.format("结构相似度 %.1f%%   （键名/字段名重合，高是正常的）%n", structureSim * 100));
            sb.append(String.format("值相似度   %.1f%%   （标量值重合，高才可疑）%n", valueSim * 100));
            if (baseOwner != null || testOwner != null) {
                sb.append('\n');
                sb.append("响应里的拥有者标识：\n");
                sb.append("  基线  ").append(baseOwner == null ? "(未提取到)" : baseOwner).append('\n');
                sb.append("  测试  ").append(testOwner == null ? "(未提取到)" : testOwner).append('\n');
                if (baseOwner != null && baseOwner.equals(testOwner)) {
                    sb.append("  ▲ 两者相同 —— 换身份后仍然拿到同一个对象的标识\n");
                }
            }
            return sb.toString();
        }
    }

    // ------------------------------------------------------------------

    /** 发包间隔（毫秒）—— 避免测试时把目标打挂。 */
    public volatile long minIntervalMs = 400;

    private final IBurpExtenderCallbacks callbacks;
    private final Sanitizer sanitizer = new Sanitizer();
    private long lastSendAt = 0;

    public AccessControlTester(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    // ==================================================================

    /**
     * 用 {@code testIdentity} 重放请求，与基线响应对比。
     *
     * @param baselineRequest  身份 A 发的原始请求
     * @param baselineResponse 身份 A 收到的响应（可为 null）
     * @param baselineIdentity 身份 A 的描述（仅用于报告）
     * @param testIdentity     要替换成的身份
     * @param service          目标服务
     * @param hasResponse      基线有没有响应
     */
    public Result test(byte[] baselineRequest,
                       byte[] baselineResponse,
                       Identity baselineIdentity,
                       Identity testIdentity,
                       IHttpService service,
                       boolean hasResponse) {
        if (callbacks == null) {
            return err(baselineIdentity, testIdentity, "当前环境没有 Burp callbacks");
        }
        if (testIdentity == null || !testIdentity.usable()) {
            return err(baselineIdentity, testIdentity, "测试身份不可用（没填认证头）");
        }
        if (baselineRequest == null || baselineRequest.length == 0) {
            return err(baselineIdentity, testIdentity, "基线请求为空");
        }
        if (!hasResponse || baselineResponse == null) {
            return new Result(baselineIdentity, testIdentity, Verdict.NO_BASELINE,
                    0, 0, 0, 0, 0, 0, null, null, "", "", null);
        }

        // ---- 构造测试请求：只换认证头，其它不动 ----
        byte[] testReq = testIdentity.apply(baselineRequest, true);

        // ---- 限速 ----
        long now = System.currentTimeMillis();
        long wait = minIntervalMs - (now - lastSendAt);
        if (wait > 0) {
            try {
                Thread.sleep(wait);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        lastSendAt = System.currentTimeMillis();

        // ---- 发包 ----
        IHttpRequestResponse rr;
        try {
            rr = callbacks.makeHttpRequest(service, testReq);
        } catch (Throwable t) {
            return err(baselineIdentity, testIdentity, "发送失败：" + t);
        }
        if (rr == null || rr.getResponse() == null) {
            return err(baselineIdentity, testIdentity, "目标没有返回响应");
        }

        byte[] testResp = rr.getResponse();
        String bs = new String(baselineResponse, StandardCharsets.UTF_8);
        String ts = new String(testResp, StandardCharsets.UTF_8);

        // ---- 判定 ----
        int baseStatus = statusOf(bs);
        int testStatus = statusOf(ts);

        // ▲ 对比用<b>脱敏后</b>的文本 —— 避免把真实凭据写进报告和日志
        String bsClean = clean(bs);
        String tsClean = clean(ts);

        double structSim = structureSimilarity(bsClean, tsClean);
        double valueSim = valueSimilarity(bsClean, tsClean);

        String baseOwner = extractOwner(bsClean);
        String testOwner = extractOwner(tsClean);

        Verdict v = judge(baseStatus, testStatus, structSim, valueSim);

        return new Result(baselineIdentity, testIdentity, v,
                baseStatus, testStatus,
                baselineResponse.length, testResp.length,
                structSim, valueSim, baseOwner, testOwner,
                new String(testReq, StandardCharsets.UTF_8), tsClean, null);
    }

    private Result err(Identity bi, Identity ti, String msg) {
        return new Result(bi, ti, Verdict.ERROR, 0, 0, 0, 0, 0, 0, null, null, "", "", msg);
    }

    /**
     * 判定规则。
     *
     * <p>顺序很重要 —— 先看状态码（最硬的信号），再看值相似度（最关键的区分指标）。
     */
    public static Verdict judge(int baseStatus, int testStatus, double structSim, double valueSim) {
        // ① 被拒绝 → 有访问控制
        if (testStatus == 401 || testStatus == 403 || testStatus == 404) {
            return Verdict.PROTECTED;
        }
        // ② 测试请求失败（5xx / 0）→ 拿不准
        if (testStatus == 0 || testStatus >= 500) {
            return Verdict.INCONCLUSIVE;
        }
        // ③ 值高度重合 → 换了身份还拿到同一份数据 → 越权
        if (testStatus >= 200 && testStatus < 300 && valueSim >= 0.80) {
            return Verdict.VULNERABLE;
        }
        // ④ 值基本不重合，但结构像 → 各拿各的数据
        if (testStatus >= 200 && testStatus < 300 && structSim >= 0.50 && valueSim < 0.35) {
            return Verdict.SEPARATE;
        }
        // ⑤ 状态码变了但没被明确拒绝 → 拿不准
        if (baseStatus != testStatus) {
            return Verdict.INCONCLUSIVE;
        }
        return Verdict.INCONCLUSIVE;
    }

    // ==================================================================
    // 相似度
    // ==================================================================

    /** 结构 = 所有键名/字段名的集合。 */
    public static Set<String> structureTokens(String text) {
        Set<String> out = new TreeSet<>();
        Matcher m = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]{0,40})\"\\s*:").matcher(text);
        while (m.find()) {
            out.add(m.group(1).toLowerCase());
        }
        // HTML 的 id/name 属性也算结构
        Matcher h = Pattern.compile("(?:id|name|class)=\"([^\"]{1,40})\"").matcher(text);
        while (h.find()) {
            out.add(h.group(1).toLowerCase());
        }
        return out;
    }

    /** 值 = 所有标量值（字符串、数字、布尔）的集合。 */
    public static Set<String> valueTokens(String text) {
        Set<String> out = new LinkedHashSet<>();
        Matcher m = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]{0,40})\"\\s*:\\s*(\"[^\"]{0,120}\"|-?\\d+(?:\\.\\d+)?|true|false|null)")
                .matcher(text);
        while (m.find()) {
            String v = m.group(2);
            // 跳过空值和无信息量的值
            if (v == null || v.equals("null") || v.equals("\"\"") || v.equals("\"-\"")) {
                continue;
            }
            out.add(v);
        }
        // HTML 文本节点里也能捞到值，但噪音大，这里只取 JSON 标量
        return out;
    }

    public static double jaccard(Set<String> a, Set<String> b) {
        if (a.isEmpty() && b.isEmpty()) {
            return 1.0;
        }
        if (a.isEmpty() || b.isEmpty()) {
            return 0.0;
        }
        Set<String> inter = new java.util.HashSet<>(a);
        inter.retainAll(b);
        Set<String> union = new java.util.HashSet<>(a);
        union.addAll(b);
        return (double) inter.size() / union.size();
    }

    /** 结构相似度 —— 键名/字段名的 Jaccard 重合度。 */
    public static double structureSimilarity(String a, String b) {
        return jaccard(structureTokens(a), structureTokens(b));
    }

    /** 值相似度 —— 标量值的 Jaccard 重合度。高才可疑。 */
    public static double valueSimilarity(String a, String b) {
        return jaccard(valueTokens(a), valueTokens(b));
    }

    // ==================================================================

    /**
     * 从响应里提取「这个对象属于谁」的标识。
     *
     * <p>这是越权最直接的证据：请求方是 A，响应里的 owner 却是 B。
     */
    public static String extractOwner(String text) {
        // 常见的拥有者字段名
        String[] keys = {"userid", "user_id", "uid", "ownerid", "owner_id",
                "creatorid", "creator_id", "accountid", "account_id",
                "memberid", "member_id", "customerid", "customer_id"};
        String lower = text.toLowerCase();
        for (String k : keys) {
            Matcher m = Pattern.compile("\"" + k + "\"\\s*:\\s*(\"[^\"]{1,60}\"|-?\\d+)",
                    Pattern.CASE_INSENSITIVE).matcher(text);
            if (m.find()) {
                String v = m.group(1).replace("\"", "");
                return k + "=" + v;
            }
        }
        // 退一步：id 字段本身
        Matcher m = Pattern.compile("\"id\"\\s*:\\s*(\"[^\"]{1,60}\"|-?\\d+)",
                Pattern.CASE_INSENSITIVE).matcher(text);
        if (m.find()) {
            return "id=" + m.group(1).replace("\"", "");
        }
        return null;
    }

    static int statusOf(String resp) {
        if (resp == null || resp.isEmpty()) {
            return 0;
        }
        Matcher m = Pattern.compile("^HTTP/[\\d.]+\\s+(\\d{3})").matcher(resp);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }

    /**
     * 脱敏后再对比 —— 报告和界面里不该出现真实凭据。
     *
     * <p>注意：脱敏会抹掉一些值，但<b>两个响应被同等处理</b>，
     * 所以相似度比较仍然有效。
     */
    private String clean(String resp) {
        try {
            return sanitizer.sanitize(resp).cleanText;
        } catch (Throwable t) {
            return resp;
        }
    }

    /** 报告用的批量测试：一个请求 × 多个身份。 */
    public java.util.List<Result> testAll(byte[] baselineRequest,
                                          byte[] baselineResponse,
                                          Identity baselineIdentity,
                                          java.util.List<Identity> testIdentities,
                                          IHttpService service) {
        java.util.List<Result> out = new java.util.ArrayList<>();
        if (testIdentities == null) {
            return out;
        }
        for (Identity id : testIdentities) {
            out.add(test(baselineRequest, baselineResponse, baselineIdentity, id, service,
                    baselineResponse != null));
        }
        return out;
    }
}
