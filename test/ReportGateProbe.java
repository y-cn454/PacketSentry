import com.packetsentry.report.ReportGate;

public class ReportGateProbe {
    static int pass = 0, fail = 0;
    static void check(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  [PASS] " + label); }
        else { fail++; System.out.println("  [FAIL] " + label); }
    }
    public static void main(String[] a) {
        System.out.println("============================================================");
        System.out.println(" 报告准入：黄金六要素 + 五类拒收");
        System.out.println("============================================================");

        // ---- 反面样本：典型的「三句话垃圾报告」----
        String bad = "某接口可能存在越权，可能导致用户信息泄露，建议修复。";
        ReportGate.Result rb = ReportGate.check(null, bad);
        System.out.println("\n  [反面样本] " + bad);
        System.out.println("  结论：" + rb.oneLine());
        check("垃圾报告不可提交", !rb.submittable());
        check("识别出「量子态危害」", rb.rejected.contains(ReportGate.Reject.QUANTUM_IMPACT));
        check("识别出「薛定谔漏洞」（无观测）",
                rb.rejected.contains(ReportGate.Reject.SCHRODINGER_POC));
        check("缺目标与版本", rb.missing.contains(ReportGate.Element.TARGET_VERSION));
        check("缺完整复现步骤", rb.missing.contains(ReportGate.Element.REPRO_STEPS));

        // ---- 正面样本：一份合格的报告 ----
        String good = String.join("\n",
            "# 越权读取他人订单",
            "## 漏洞 URL",
            "https://target.example.com/api/order/1001",
            "",
            "## 版本",
            "Spring Boot 2.7.3",
            "",
            "## 复现步骤",
            "已实测：用账号 A 的 Cookie 请求账号 B 的订单 ID。",
            "请求：",
            "GET /api/order/1002 HTTP/1.1",
            "Host: target.example.com",
            "Cookie: SESSION=***",
            "",
            "响应：",
            "HTTP/1.1 200 OK",
            "Content-Type: application/json",
            "{\"orderId\":1002,\"amount\":899,\"receiver\":\"张*\"}",
            "",
            "## 影响",
            "可读取任意其他用户的订单，含金额与收件人信息，实测返回 1 条完整记录。",
            "",
            "## 证据",
            "截图 2 张（含地址栏与时间），Cookie 已脱敏。");
        ReportGate.Result rg = ReportGate.check(null, good);
        System.out.println("\n  [正面样本] 结论：" + rg.oneLine());
        check("合格报告可提交", rg.submittable());
        check("六要素齐全", rg.missing.isEmpty());
        check("未命中拒收形态", rg.rejected.isEmpty());

        // ---- 单独验证每一类拒收能被抓到 ----
        check("抓「文字幻觉体」", ReportGate.check(null,
                "根据经验，这个接口一般来说可能存在未授权访问，建议排查。")
                .rejected.contains(ReportGate.Reject.AI_HALLUCINATION));
        check("抓「拼贴怪」", ReportGate.check(null,
                "官方文档里提到该参数支持注入，理论上可以执行命令。")
                .rejected.contains(ReportGate.Reject.SDK_PASTE));
        check("抓「时空错位型」", ReportGate.check(null,
                "该接口已下线，但推测仍可通过旧路径访问。")
                .rejected.contains(ReportGate.Reject.DEAD_API));

        System.out.println();
        System.out.println("  ⭐ 关键设计：拒收形态是硬门槛，缺要素是软门槛");
        ReportGate.Result soft = ReportGate.check(null,
                "https://a.com/api/x 已实测，可读取他人数据，返回 1 条记录。");
        System.out.println("    只有软门槛缺失时：submittable=" + soft.submittable()
                + " pass=" + soft.pass());

        System.out.println();
        System.out.println(ReportGate.checklist());

        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}