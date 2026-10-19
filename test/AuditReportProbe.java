import com.packetsentry.audit.CodeAudit;
import com.packetsentry.core.Config;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.report.ReportGenerator;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 代码审计 + 漏洞报告生成 实测。
 *
 * <h3>重点验证「三态」设计</h3>
 * 这是本功能最容易做错的地方：只报「有 / 没有」会让人误以为「没报就是安全」。
 * 所以三态都要有正例和反例：
 * <ul>
 *   <li>🔴 有发现 —— 挖到硬编码密钥/危险DOM/接口路径</li>
 *   <li>🟡 有可能 —— 没挖到但存在攻击面，必须给出试的方向</li>
 *   <li>⚪ 无     —— 纯静态内容，明确说「无」</li>
 *   <li>➖ 不适用 —— 图片/二进制</li>
 * </ul>
 */
public class AuditReportProbe {

    private static int pass = 0;
    private static int fail = 0;

    private static void check(String label, boolean ok) {
        if (ok) {
            pass++;
            System.out.println("  [PASS] " + label);
        } else {
            fail++;
            System.out.println("  [FAIL] " + label);
        }
    }

    private static String resp(String ct, String body) {
        return "HTTP/1.1 200 OK\r\nContent-Type: " + ct + "\r\n\r\n" + body;
    }

    private static boolean hasCategory(CodeAudit.Result r, String cat) {
        return r.findings.stream().anyMatch(f -> f.category.contains(cat));
    }

    public static void main(String[] args) {
        CodeAudit audit = new CodeAudit();

        System.out.println("============================================================");
        System.out.println(" 一、代码审计 —— 🔴 有发现");
        System.out.println("============================================================");

        // 硬编码密钥
        CodeAudit.Result r1 = audit.audit("GET /static/app.js HTTP/1.1\r\nHost: t\r\n\r\n",
                resp("application/javascript",
                        "var cfg={apiKey:\"AKIAIOSFODNN7EXAMPLE\",endpoint:\"/api/v1/user\"};"));
        System.out.println("  ① 硬编码密钥 → " + r1.verdict.label);
        r1.findings.forEach(f -> System.out.println("      " + f));
        check("检出硬编码凭据", hasCategory(r1, "硬编码凭据"));
        check("结论为「有发现」", r1.verdict == CodeAudit.Verdict.FOUND);
        check("证据已脱敏（不含完整密钥）",
                r1.findings.stream().noneMatch(f -> f.evidence != null
                        && f.evidence.contains("AKIAIOSFODNN7EXAMPLE")));

        // 危险 DOM
        CodeAudit.Result r2 = audit.audit("GET /s.js HTTP/1.1\r\nHost: t\r\n\r\n",
                resp("application/javascript",
                        "document.getElementById('x').innerHTML = location.hash.substring(1);"));
        System.out.println();
        System.out.println("  ② 危险 DOM → " + r2.verdict.label);
        r2.findings.forEach(f -> System.out.println("      " + f));
        check("检出危险 DOM 操作", hasCategory(r2, "危险DOM操作"));

        // 前端权限判断
        CodeAudit.Result r3 = audit.audit("GET /a.js HTTP/1.1\r\nHost: t\r\n\r\n",
                resp("application/javascript",
                        "if (user.role === 'admin') { showAdminPanel(); }"));
        System.out.println();
        System.out.println("  ③ 前端权限判断 → " + r3.verdict.label);
        r3.findings.forEach(f -> System.out.println("      " + f));
        check("检出前端权限判断", hasCategory(r3, "前端权限判断"));

        // 接口路径
        CodeAudit.Result r4 = audit.audit("GET /m.js HTTP/1.1\r\nHost: t\r\n\r\n",
                resp("application/javascript",
                        "fetch('/api/v1/admin/users');fetch('/api/v1/export/order');"
                                + "fetch('/internal/debug/status');"));
        System.out.println();
        System.out.println("  ④ 接口路径泄露 → " + r4.verdict.label);
        r4.findings.forEach(f -> System.out.println("      " + f));
        check("检出接口路径泄露", hasCategory(r4, "接口路径泄露"));

        // 注释线索
        CodeAudit.Result r5 = audit.audit("GET / HTTP/1.1\r\nHost: t\r\n\r\n",
                resp("text/html",
                        "<html><!-- TODO: remove test account admin/admin123 before release --></html>"));
        System.out.println();
        System.out.println("  ⑤ 注释线索 → " + r5.verdict.label);
        r5.findings.forEach(f -> System.out.println("      " + f));
        check("检出注释线索", hasCategory(r5, "注释线索"));

        // Source Map
        CodeAudit.Result r6 = audit.audit("GET /app.js HTTP/1.1\r\nHost: t\r\n\r\n",
                resp("application/javascript", "var a=1;\n//# sourceMappingURL=app.js.map"));
        System.out.println();
        System.out.println("  ⑥ Source Map → " + r6.verdict.label);
        r6.findings.forEach(f -> System.out.println("      " + f));
        check("检出 Source Map 泄露", hasCategory(r6, "Source Map"));

        // postMessage 无 origin 校验
        CodeAudit.Result r7 = audit.audit("GET /p.js HTTP/1.1\r\nHost: t\r\n\r\n",
                resp("application/javascript",
                        "window.addEventListener('message', function(e){ eval(e.data); });"));
        System.out.println();
        System.out.println("  ⑦ postMessage → " + r7.verdict.label);
        r7.findings.forEach(f -> System.out.println("      " + f));
        check("检出 postMessage 监听", hasCategory(r7, "postMessage"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 二、代码审计 —— 🟡 有可能（没挖到但要给方向）");
        System.out.println("============================================================");

        CodeAudit.Result p1 = audit.audit("GET /api/order?id=1 HTTP/1.1\r\nHost: t\r\n\r\n",
                resp("application/json", "{\"orderId\":1001,\"amount\":199,\"status\":\"paid\"}"));
        System.out.println("  干净的 JSON 接口 → " + p1.verdict.label);
        p1.hypotheses.forEach(h -> System.out.println("      · " + h));
        check("JSON 接口结论为「有可能」", p1.verdict == CodeAudit.Verdict.POSSIBLE);
        check("给出了具体可试的方向（不是空话）", p1.hypotheses.size() >= 2);
        check("方向里提到批量赋值或越权",
                p1.hypotheses.stream().anyMatch(h -> h.contains("批量赋值") || h.contains("越权")
                        || h.contains("别人")));

        CodeAudit.Result p2 = audit.audit("GET /page HTTP/1.1\r\nHost: t\r\n\r\n",
                resp("text/html", "<html><body><h1>Hello</h1></body></html>"));
        System.out.println();
        System.out.println("  干净的 HTML 页面 → " + p2.verdict.label);
        p2.hypotheses.forEach(h -> System.out.println("      · " + h));
        check("HTML 页面结论为「有可能」并给出 XSS / 备份文件方向",
                p2.verdict == CodeAudit.Verdict.POSSIBLE
                        && p2.hypotheses.stream().anyMatch(h -> h.contains("XSS")));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 三、代码审计 —— ⚪ 无 / ➖ 不适用");
        System.out.println("============================================================");

        CodeAudit.Result n1 = audit.audit("GET /img.png HTTP/1.1\r\nHost: t\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\u0089PNG\r\n\u001a\n");
        System.out.println("  图片 → " + n1.verdict.label + "（" + n1.nothingReason + "）");
        check("图片判为「不适用」", n1.verdict == CodeAudit.Verdict.NOT_APPLICABLE);

        CodeAudit.Result n2 = audit.audit("GET /x HTTP/1.1\r\nHost: t\r\n\r\n",
                "HTTP/1.1 204 No Content\r\n\r\n");
        check("空响应判为「不适用」", n2.verdict == CodeAudit.Verdict.NOT_APPLICABLE);

        CodeAudit.Result n3 = audit.audit("GET /ping HTTP/1.1\r\nHost: t\r\n\r\n",
                resp("text/plain", "ok"));
        System.out.println("  极短文本 → " + n3.verdict.label);
        check("过短内容判为「无」而不是「安全」", n3.verdict == CodeAudit.Verdict.NOTHING);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 四、报告生成 —— 本地骨架（六段结构）");
        System.out.println("============================================================");

        // 构造几条记录
        List<PacketRecord> targets = new ArrayList<>();
        targets.add(fakeRecord(1, "GET", "shop.example.com", "/api/order/1001",
                "GET /api/order/1001?uid=1002 HTTP/1.1\r\nHost: shop.example.com\r\n\r\n",
                com.packetsentry.detect.LocalRules.Level.MEDIUM));
        targets.add(fakeRecord(2, "POST", "shop.example.com", "/api/order/pay",
                "POST /api/order/pay HTTP/1.1\r\nHost: shop.example.com\r\n\r\n{\"price\":100}",
                com.packetsentry.detect.LocalRules.Level.HIGH));

        Config cfg = new Config();
        cfg.srcPlatform = "某SRC";
        ReportGenerator gen = new ReportGenerator();
        String skeleton = gen.buildSkeleton(targets, cfg);
        System.out.println(skeleton);

        check("骨架含「漏洞 URL / IP」段", skeleton.contains("一、漏洞 URL / IP"));
        check("骨架含「风险评级」段", skeleton.contains("二、风险评级"));
        check("骨架含「危害说明」段", skeleton.contains("三、危害说明"));
        check("骨架含「资产证明」段", skeleton.contains("四、资产证明"));
        check("骨架含「渗透路径」段", skeleton.contains("五、渗透路径"));
        check("骨架含「修复建议」段", skeleton.contains("六、修复建议"));
        check("URL 带上了路径参数（?uid=1002）", skeleton.contains("uid=1002"));
        check("标注了定级依据（平台名）", skeleton.contains("某SRC"));
        check("给出了资产证明的具体方式", skeleton.contains("WHOIS") || skeleton.contains("备案"));
        check("提醒了通用漏洞要给 CVE", skeleton.contains("CVE"));
        check("本地定级取到最高等级（高危）", skeleton.contains("高危"));

        // 无平台规则时也要能出
        Config cfg2 = new Config();
        String sk2 = gen.buildSkeleton(targets, cfg2);
        check("未提供平台规则也能生成骨架", sk2.contains("一、漏洞 URL / IP"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    /** 造一条记录（跳过管道，直接构造）。 */
    private static PacketRecord fakeRecord(int seq, String method, String host, String path,
                                           String req, com.packetsentry.detect.LocalRules.Level lv) {
        byte[] reqB = req.getBytes(StandardCharsets.UTF_8);
        byte[] respB = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}")
                .getBytes(StandardCharsets.UTF_8);

        List<com.packetsentry.detect.LocalRules.Issue> issues = new ArrayList<>();
        if (lv != com.packetsentry.detect.LocalRules.Level.NONE) {
            String name = (lv == com.packetsentry.detect.LocalRules.Level.HIGH)
                    ? "金额可篡改线索" : "ID可预测线索";
            // Issue 的签名是 (Level, name, detail, evidence) —— 四个参数
            issues.add(new com.packetsentry.detect.LocalRules.Issue(lv, name,
                    "测试用发现", "证据X"));
        }

        return new PacketRecord(seq, 1, false, method, host, path, 200, "application/json",
                respB.length, null, null, "brief", method + " " + host + path, false, false,
                "测试作用", issues, reqB, respB, null);
    }
}
