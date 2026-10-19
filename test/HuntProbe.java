import com.packetsentry.ai.Hypothesis;
import com.packetsentry.ai.HuntingEngine;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 「AI 挖洞」的规则闸门测试。
 *
 * <h3>这个套件要证明的事</h3>
 * 功能的价值不在「AI 能提出多少假设」，而在<b>它提不出不该提的东西</b>。
 * 所以这里逐条构造用户定义的<b>五类坏报告</b>，断言闸门全部拦住。
 */
public class HuntProbe {

    private static int pass = 0;
    private static int fail = 0;

    private static void check(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  [PASS] " + label); }
        else { fail++; System.out.println("  [FAIL] " + label); }
    }

    /** 造一条「正常」的假设置，方便各条测试只改一处。 */
    private static Hypothesis base(String title) {
        return new Hypothesis(
                title,
                "/api/order/{id}", "GET",
                "响应里出现别人的订单号 1002，且与请求的 1001 不一致",
                Arrays.asList(
                        "用账号 A 的 Cookie 请求 GET /api/order/1002",
                        "对比返回体里的 orderId 与 receiver 是否属于账号 B"),
                "若返回 200 且 body 含账号 B 的 receiver，则证实越权读取",
                "可读取任意其他用户的订单，含金额与收件人",
                Hypothesis.Confidence.HIGH);
    }

    public static void main(String[] a) {
        System.out.println("============================================================");
        System.out.println(" AI 挖洞：五类坏报告必须全部被拦住");
        System.out.println("============================================================");

        // ---------- 0. 基线：一条合格的假设 ----------
        System.out.println("\n  [基线] 合格假设要通过（但它仍是 PROPOSED，不能直接进报告）");
        Hypothesis good = base("订单越权读取");
        Hypothesis.Verdict v0 = good.gate();
        System.out.println("    " + v0.oneLine());
        check("合格的假设只卡在状态（未证实）", v0.rejected.size() == 1
                && v0.rejected.get(0).startsWith("文字幻觉体"));
        good.status = Hypothesis.Status.CONFIRMED;
        good.humanNote = "已用 A 的令牌请求 1002，返回 B 的收件人，截图 2 张";
        System.out.println("    人工标记已证实后：" + good.gate().oneLine());
        check("⭐ 人工证实 + 留了记录 → 完全通过", good.gate().pass());
        check("promotable() 与 gate().pass() 一致", good.promotable());

        // ---------- 1. 文字幻觉体 ----------
        System.out.println("\n  [①] 文字幻觉体：AI 提出但没人验证");
        Hypothesis h1 = base("疑似越权");
        // 状态保持 PROPOSED
        Hypothesis.Verdict v1 = h1.gate();
        System.out.println("    " + v1.oneLine());
        check("⭐ 未证实的假设被拒",
                v1.rejected.stream().anyMatch(s -> s.startsWith("文字幻觉体")));
        check("未证实的不 promote", !h1.promotable());

        // ---------- 2. 时空错位型 ----------
        System.out.println("\n  [②] 时空错位型：引用了抓包里不存在的接口");
        Set<String> known = new HashSet<>();
        known.add("/api/order/{id}");
        known.add("/api/user/profile");
        String aiOut = ""
                + "## 假设: 旧版接口未下线可以未授权访问\n"
                + "路由: GET /api/internal/v1/legacy/export\n"
                + "依据: 响应里没有鉴权头也返回了数据\n"
                + "步骤:\n"
                + "1. GET /api/internal/v1/legacy/export 不带 Cookie\n"
                + "2. 观察是否返回 200\n"
                + "判据: 若返回 200 且 body 含数据则证实\n"
                + "影响: 可导出全部订单\n"
                + "可信度: 高\n";
        HuntingEngine.ParseResult pr = HuntingEngine.parse(aiOut, known);
        System.out.println("    解析出 " + pr.hypotheses.size() + " 条，丢弃 "
                + pr.dropped.size() + " 条");
        for (String d : pr.dropped) System.out.println("      丢弃：" + d);
        check("⭐ 编造的路由被丢弃", pr.hypotheses.isEmpty());
        check("丢弃原因提到时空错位",
                pr.dropped.stream().anyMatch(s -> s.contains("时空错位")));

        // ---------- 3. 拼贴怪 ----------
        System.out.println("\n  [③] 拼贴怪：依据只有文档");
        Hypothesis h3 = base("参数注入");
        Hypothesis h3b = new Hypothesis(
                h3.title, h3.route, h3.method,
                "官方文档里提到该参数支持 SQL 语句拼接，理论上可以注入",
                h3.testSteps, h3.expected, h3.impact, Hypothesis.Confidence.MEDIUM);
        h3b.status = Hypothesis.Status.CONFIRMED;
        h3b.humanNote = "测过";
        Hypothesis.Verdict v3 = h3b.gate();
        System.out.println("    " + v3.oneLine());
        check("⭐ 纯文档依据被拒（拼贴怪）",
                v3.rejected.stream().anyMatch(s -> s.startsWith("拼贴怪")));

        // ---------- 4. 薛定谔漏洞 ----------
        System.out.println("\n  [④] 薛定谔漏洞：没有可证伪的判据");
        Hypothesis h4 = new Hypothesis(
                "可能有注入", "/api/order/{id}", "GET",
                "响应里的 id 参数看起来没过滤",
                Arrays.asList("1. 改一下 id 试试", "2. 看看结果"),
                "可能会报错",
                "可能导致数据泄露",
                Hypothesis.Confidence.LOW);
        h4.status = Hypothesis.Status.CONFIRMED;
        h4.humanNote = "测过";
        Hypothesis.Verdict v4 = h4.gate();
        System.out.println("    " + v4.oneLine());
        check("⭐ 不可证伪的判据被拒（薛定谔漏洞）",
                v4.rejected.stream().anyMatch(s -> s.startsWith("薛定谔漏洞")));

        // 步骤不足
        Hypothesis h4b = new Hypothesis(
                "可能有注入", "/api/order/{id}", "GET",
                "响应里的 id 参数看起来没过滤",
                Arrays.asList("改一下 id"),           // 只有 1 步
                "若返回 500 则证实",
                "可读取他人订单",
                Hypothesis.Confidence.LOW);
        h4b.status = Hypothesis.Status.CONFIRMED;
        h4b.humanNote = "测过";
        check("⭐ 步骤不足 2 步也被拒",
                h4b.gate().rejected.stream().anyMatch(s -> s.contains("步骤不足")));

        // ---------- 5. 量子态危害 ----------
        System.out.println("\n  [⑤] 量子态危害：影响空泛");
        Hypothesis h5 = new Hypothesis(
                "订单越权", "/api/order/{id}", "GET",
                "响应出现别人的订单号",
                Arrays.asList("GET /api/order/1002 用 A 的令牌", "看返回体的 receiver"),
                "若返回 200 且含 B 的收件人则证实",
                "可能导致用户信息泄露",              // ← 空泛
                Hypothesis.Confidence.HIGH);
        h5.status = Hypothesis.Status.CONFIRMED;
        h5.humanNote = "测过";
        Hypothesis.Verdict v5 = h5.gate();
        System.out.println("    " + v5.oneLine());
        check("⭐ 空泛影响被拒（量子态危害）",
                v5.rejected.stream().anyMatch(s -> s.startsWith("量子态危害")));

        // 「待验证」应当被接受（诚实占位优于编造）
        Hypothesis h5b = new Hypothesis(
                "订单越权", "/api/order/{id}", "GET",
                "响应出现别人的订单号",
                Arrays.asList("GET /api/order/1002 用 A 的令牌", "看返回体的 receiver"),
                "若返回 200 且含 B 的收件人则证实",
                "待验证",
                Hypothesis.Confidence.HIGH);
        h5b.status = Hypothesis.Status.CONFIRMED;
        h5b.humanNote = "测过";
        check("⭐ 写「待验证」是允许的（鼓励诚实而非编造）",
                h5b.gate().pass());

        // ---------- 6. 标记已证实但没留记录 ----------
        System.out.println("\n  [⑥] 标了已证实却没留人工记录");
        Hypothesis h6 = base("订单越权");
        h6.status = Hypothesis.Status.CONFIRMED;
        // humanNote 留空
        Hypothesis.Verdict v6 = h6.gate();
        System.out.println("    " + v6.oneLine());
        check("⭐ 已证实但无验证记录 → 不算通过",
                !v6.pass() && v6.missing.stream().anyMatch(s -> s.contains("人工验证记录")));

        // ---------- 7. 解析器：正常输出要能解析 ----------
        System.out.println("\n  [⑦] 解析器：合格的 AI 输出要能解析出来");
        String okOut = ""
                + "## 假设: 订单接口水平越权\n"
                + "路由: GET /api/order/{id}\n"
                + "依据: 观测到 /api/order/{id} 返回体含 orderId 字段，且请求参数只有数字 id\n"
                + "步骤:\n"
                + "1. 用账号 A 的 Cookie 请求 GET /api/order/1002\n"
                + "2. 对比返回体 orderId 与 receiver 是否属于 B\n"
                + "判据: 若返回 200 且 body 含 B 的收件人则证实\n"
                + "影响: 可读取任意其他用户的订单与收件信息\n"
                + "可信度: 高\n";
        HuntingEngine.ParseResult pr2 = HuntingEngine.parse(okOut, known);
        System.out.println("    解析出 " + pr2.hypotheses.size() + " 条");
        check("合格输出被解析成 1 条", pr2.hypotheses.size() == 1);
        if (pr2.hypotheses.size() == 1) {
            Hypothesis p = pr2.hypotheses.get(0);
            System.out.println("    标题：" + p.title);
            System.out.println("    路由：" + p.method + " " + p.route);
            System.out.println("    步骤数：" + p.testSteps.size());
            check("⭐ 状态被强制成 PROPOSED（AI 不能自称已验证）",
                    p.status == Hypothesis.Status.PROPOSED);
            check("步骤解析出 2 步", p.testSteps.size() == 2);
            check("可信度解析成 HIGH", p.confidence == Hypothesis.Confidence.HIGH);
            check("⭐ 这条假设还没有人工确认 → 不能进报告", !p.promotable());
        }

        // ---------- 8. 解析器：模型乱说时丢光 ----------
        System.out.println("\n  [⑧] 解析器：模型不按格式输出就全丢");
        HuntingEngine.ParseResult pr3 = HuntingEngine.parse(
                "这个接口可能有越权，建议修复一下。", known);
        check("⭐ 没有格式块的输出被全丢", pr3.hypotheses.isEmpty());
        check("丢弃原因说明了原因", !pr3.dropped.isEmpty());

        HuntingEngine.ParseResult pr4 = HuntingEngine.parse(null, known);
        check("null 输入安全返回空", pr4.hypotheses.isEmpty());

        // ---------- 9. 业务地图 ----------
        System.out.println("\n  [⑨] 路径归一化（同一条接口的不同 ID 应归成一条）");
        check("订单 1 与 1002 归一成同一路由",
                HuntingEngine.normalize("/api/order/1")
                        .equals(HuntingEngine.normalize("/api/order/1002")));
        check("version 段不被当成 id",
                HuntingEngine.normalize("/api/v1/order/5").contains("v1"));
        check("query 被剥掉",
                !HuntingEngine.normalize("/api/order/1?a=b").contains("?"));
        List<String> pn = HuntingEngine.paramNames("/api/search?q=x&page=2");
        check("参数名提取正确", pn.equals(Arrays.asList("q", "page")));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
