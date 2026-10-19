import com.packetsentry.ai.Hypothesis;
import com.packetsentry.ai.LocalHunter;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.sanitize.Sanitizer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 本地规则挖洞的测试。
 *
 * <h3>要证明两件事</h3>
 * <ol>
 *   <li><b>该命中的要命中</b>：越权、未授权、篡改、分页、调试泄露五类线索</li>
 *   <li><b>不该命中的别乱报</b>：干净的流量和静态资源不该产出线索</li>
 * </ol>
 * 第二条比第一条重要 —— 一个只会乱报的工具，用户两天就不看了。
 */
public class LocalHuntProbe {

    private static int pass = 0;
    private static int fail = 0;
    private static final Sanitizer SAN = new Sanitizer();

    private static void check(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  [PASS] " + label); }
        else { fail++; System.out.println("  [FAIL] " + label); }
    }

    private static int seq = 1;

    /** 造一条请求记录。 */
    private static PacketRecord req(String method, String path, String brief) {
        return new PacketRecord(seq++, 0, true, method, "t.example.com", path, 0,
                "text/html", 0, null, SAN.sanitize(brief == null ? "" : brief),
                brief, "sig" + seq, false, false, "测试", null, null, null, null);
    }

    /** 造一条请求记录，带响应内容（用 brief 承载脱敏文本）。 */
    private static PacketRecord reqWithResp(String method, String path,
                                            String brief, String respBody) {
        return new PacketRecord(seq++, 0, true, method, "t.example.com", path, 200,
                "application/json", respBody.length(), null, SAN.sanitize(respBody),
                brief, "sig" + seq, false, false, "测试", null, null, null, null);
    }

    private static List<Hypothesis> find(LocalHunter.Result r, String keyword) {
        List<Hypothesis> out = new ArrayList<>();
        for (Hypothesis h : r.hypotheses) {
            if (h.title.contains(keyword)) {
                out.add(h);
            }
        }
        return out;
    }

    public static void main(String[] a) {
        System.out.println("============================================================");
        System.out.println(" 本地规则挖洞：该命中的命中，不该命中的别乱报");
        System.out.println("============================================================");

        // ---------- 规则 1：对象 ID 越权 ----------
        System.out.println("\n  [规则 1] 路径带可变 ID 段");
        List<PacketRecord> l1 = Arrays.asList(
                req("GET", "/api/order/1001", "Cookie: SESSION=abc"),
                req("GET", "/api/order/1002", "Cookie: SESSION=abc"));
        LocalHunter.Result r1 = LocalHunter.hunt(l1);
        System.out.println("    产出 " + r1.hypotheses.size() + " 条：" + r1.ruleHits);
        List<Hypothesis> idor = find(r1, "对象级越权");
        check("⭐ 命中对象级越权", !idor.isEmpty());
        if (!idor.isEmpty()) {
            Hypothesis h = idor.get(0);
            check("路由是归一化后的模板", h.route.contains("{id}"));
            check("依据引用了观测到的 ID", h.basis.contains("1001") || h.basis.contains("1002"));
            check("给了 2 步验证", h.testSteps.size() == 2);
            check("判据可证伪（含「若…则」）", h.expected.contains("若"));
            // ⚠️ 关键：产出的必须还是待验证
            check("⭐ 状态仍是待验证（规则不能自己盖章）",
                    h.status == Hypothesis.Status.PROPOSED);
            check("⭐ 因此还不能进报告", !h.promotable());
        }

        // ---------- 规则 2：未授权 ----------
        System.out.println("\n  [规则 2] 请求没带认证");
        List<PacketRecord> l2 = Arrays.asList(
                req("GET", "/api/user/detail", "GET /api/user/detail HTTP/1.1（无 Cookie）"));
        LocalHunter.Result r2 = LocalHunter.hunt(l2);
        System.out.println("    产出 " + r2.hypotheses.size() + " 条：" + r2.ruleHits);
        check("⭐ 命中未授权访问", !find(r2, "未授权访问").isEmpty());

        // 带认证的不该命中
        LocalHunter.Result r2b = LocalHunter.hunt(Arrays.asList(
                req("GET", "/api/user/detail", "Cookie: SESSION=abc")));
        check("⭐ 带了 Cookie 就不提未授权假设（不误报）",
                find(r2b, "未授权访问").isEmpty());

        // ---------- 规则 4：参数篡改 ----------
        System.out.println("\n  [规则 3] 金额/数量类参数");
        List<PacketRecord> l4 = Arrays.asList(
                req("POST", "/api/order/create?amount=100&quantity=1",
                        "Cookie: SESSION=abc"));
        LocalHunter.Result r4 = LocalHunter.hunt(l4);
        System.out.println("    产出 " + r4.hypotheses.size() + " 条：" + r4.ruleHits);
        check("⭐ 命中参数篡改线索", !find(r4, "参数篡改").isEmpty());
        if (!find(r4, "参数篡改").isEmpty()) {
            check("标题带出了参数名",
                    find(r4, "参数篡改").get(0).title.contains("amount")
                            || find(r4, "参数篡改").get(0).title.contains("quantity"));
        }

        // ---------- 规则 5：分页上限 ----------
        System.out.println("\n  [规则 4] 分页 + 每页数量");
        List<PacketRecord> l5 = Arrays.asList(
                req("GET", "/api/user/list?page=1&size=20", "Cookie: SESSION=abc"));
        LocalHunter.Result r5 = LocalHunter.hunt(l5);
        System.out.println("    产出 " + r5.hypotheses.size() + " 条：" + r5.ruleHits);
        check("⭐ 命中分页上限线索", !find(r5, "分页上限").isEmpty());

        // 只有 page 没有 size 不该命中
        LocalHunter.Result r5b = LocalHunter.hunt(Arrays.asList(
                req("GET", "/api/user/list?page=1", "Cookie: SESSION=abc")));
        check("⭐ 只有 page 没有 size 时不提分页假设（不误报）",
                find(r5b, "分页上限").isEmpty());

        // ---------- 规则 6：调试信息泄露 ----------
        System.out.println("\n  [规则 5] 响应里有堆栈");
        List<PacketRecord> l6 = Arrays.asList(
                reqWithResp("GET", "/api/user/info", "Cookie: SESSION=abc",
                        "{\"error\":\"java.lang.NullPointerException\\n"
                                + "    at com.example.UserService.get(UserService.java:42)\"}"));
        LocalHunter.Result r6 = LocalHunter.hunt(l6);
        System.out.println("    产出 " + r6.hypotheses.size() + " 条：" + r6.ruleHits);
        check("⭐ 命中调试信息泄露", !find(r6, "调试信息泄露").isEmpty());

        // ---------- 规则 3：身份信息回显 ----------
        System.out.println("\n  [规则 6] 响应里回显身份信息");
        List<PacketRecord> l3 = Arrays.asList(
                reqWithResp("GET", "/api/user/profile", "Cookie: SESSION=abc",
                        "{\"email\":\"a@b.com\",\"phone\":\"13800000000\"}"));
        LocalHunter.Result r3 = LocalHunter.hunt(l3);
        System.out.println("    产出 " + r3.hypotheses.size() + " 条：" + r3.ruleHits);
        check("⭐ 命中身份信息回显", !find(r3, "身份信息").isEmpty());

        // ---------- 反面：干净流量 ----------
        System.out.println("\n  [反面] 干净的流量不该乱报");
        List<PacketRecord> clean = Arrays.asList(
                req("GET", "/api/user/profile", "Cookie: SESSION=abc"),
                req("GET", "/api/order/list", "Cookie: SESSION=abc"),
                req("POST", "/api/auth/login", "Content-Type: application/json"));
        LocalHunter.Result rc = LocalHunter.hunt(clean);
        System.out.println("    产出 " + rc.hypotheses.size() + " 条：" + rc.ruleHits);
        check("干净流量产出的线索很少（≤2 条）", rc.hypotheses.size() <= 2);
        check("不把 /api/user/profile 误报成越权（无 ID 段）",
                find(rc, "对象级越权").isEmpty());

        // ---------- 反面：静态资源 ----------
        System.out.println("\n  [反面] 静态资源不该被当成 API");
        List<PacketRecord> staticRes = Arrays.asList(
                req("GET", "/static/js/main-es2015.a1b2.js", ""),
                req("GET", "/images/logo.png", ""));
        LocalHunter.Result rs = LocalHunter.hunt(staticRes);
        System.out.println("    产出 " + rs.hypotheses.size() + " 条");
        check("⭐ 静态资源不产出任何线索", rs.hypotheses.isEmpty());

        // ---------- 空输入 ----------
        System.out.println("\n  [边界] 空输入");
        check("null 安全", LocalHunter.hunt(null).hypotheses.isEmpty());
        check("空列表安全", LocalHunter.hunt(new ArrayList<>()).hypotheses.isEmpty());

        // ---------- 产出的假设都要过结构性检查 ----------
        System.out.println("\n  [一致性] 所有产出的假设都要有六要素的结构");
        int structural = 0;
        for (LocalHunter.Result rr : Arrays.asList(r1, r2, r3, r4, r5, r6)) {
            for (Hypothesis h : rr.hypotheses) {
                if (!h.route.isEmpty() && !h.basis.isEmpty()
                        && h.testSteps.size() >= 2 && !h.expected.isEmpty()
                        && !h.impact.isEmpty()) {
                    structural++;
                }
            }
        }
        int totalHyps = r1.hypotheses.size() + r2.hypotheses.size()
                + r3.hypotheses.size() + r4.hypotheses.size()
                + r5.hypotheses.size() + r6.hypotheses.size();
        System.out.println("    共 " + totalHyps + " 条，结构完整 " + structural + " 条");
        check("⭐ 全部产出的结构都完整（步骤≥2、判据非空）",
                structural == totalHyps && totalHyps > 0);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
