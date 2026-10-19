import com.packetsentry.core.Config;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.core.RealtimePipe;
import com.packetsentry.detect.LocalRules;
import com.packetsentry.detect.PiiScanner;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 本地业务规则引擎 + 宏观业务地图 实测。
 *
 * <p>验证两件事：
 * <ol>
 *   <li><b>作用推断</b>是否合理（零成本替代 AI 判定）</li>
 *   <li><b>漏洞检测</b>是否真能抓到东西（尤其是密码明文回显、CORS 反射）</li>
 * </ol>
 */
public class LocalRulesProbe {

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

    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println(" 一、作用推断（本地字典，零成本）");
        System.out.println("============================================================");

        String[][] cases = {
                {"GET", "/api/user/self", "获取用户信息"},
                {"GET", "/api/notice/list", "获取通知"},
                {"GET", "/api/page_content", "获取首页内容"},
                {"GET", "/static/js/app.js", "加载静态资源"},
                {"GET", "/api/token", "获取令牌"},
                {"POST", "/api/login", "登录"},
                {"GET", "/api/checkin/record", "查询签到记录"},
                {"GET", "/api/user/group", "获取用户分组"},
                {"GET", "/api/audit/log", "查询审计日志"},
                {"POST", "/api/upload", "文件上传"},
                {"POST", "/api/decrypt", "加解密"},
                {"GET", "/api/order/1001", "订单"},
                {"GET", "/admin/config", "管理接口"},
                {"DELETE", "/api/thing/9", "删除数据"},
                {"GET", "/something/unknown", "读取数据"},
                // 最长匹配优先的验证用例
                {"GET", "/api/audit/log", "查询审计日志"},
                {"GET", "/api/login_record", "查询登录记录"},
                {"POST", "/api/token/refresh", "刷新令牌"},
                // 特权命名空间优先的验证用例
                {"GET", "/admin/config", "管理接口"},
                {"GET", "/api/admin/user/list", "管理接口"},
        };

        int okPurpose = 0;
        for (String[] c : cases) {
            String got = LocalRules.inferPurpose(c[0], c[1]);
            boolean ok = got.equals(c[2]);
            if (ok) {
                okPurpose++;
            }
            System.out.printf("  %-6s %-30s → %-14s %s%n",
                    c[0], c[1], got, ok ? "" : ("期望 " + c[2]));
        }
        System.out.println();
        check("作用推断全部命中（" + cases.length + "/" + cases.length + "）",
                okPurpose == cases.length);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 二、漏洞检测（本地规则，零成本）");
        System.out.println("============================================================");

        // ---- 密码明文回显 ----
        String req1 = "POST /api/login HTTP/1.1\r\nHost: x.com\r\n\r\n"
                + "{\"username\":\"admin\",\"password\":\"P@ssw0rd!2026\"}";
        String resp1 = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + "{\"msg\":\"ok\",\"debug\":\"P@ssw0rd!2026\"}";
        List<LocalRules.Issue> i1 = LocalRules.detect(req1, resp1, null);
        System.out.println("  ① 密码明文回显");
        i1.forEach(x -> System.out.println("     " + x));
        check("检出「密码明文回显」（高危）",
                i1.stream().anyMatch(x -> x.name.equals("密码明文回显") && x.level == LocalRules.Level.HIGH));

        // ---- Authorization 回显 ----
        String req2 = "GET /api/user/self HTTP/1.1\r\nHost: x.com\r\n"
                + "Authorization: Bearer abcdefghijklmnop1234\r\n\r\n";
        String resp2 = "HTTP/1.1 200 OK\r\n\r\n{\"token\":\"abcdefghijklmnop1234\"}";
        List<LocalRules.Issue> i2 = LocalRules.detect(req2, resp2, null);
        System.out.println("  ② Authorization 回显");
        i2.forEach(x -> System.out.println("     " + x));
        check("检出「Authorization回显」（中危）",
                i2.stream().anyMatch(x -> x.name.equals("Authorization回显")));

        // ---- CORS 反射 ----
        String req3 = "GET /api/data HTTP/1.1\r\nHost: x.com\r\nOrigin: https://evil.example.com\r\n\r\n";
        String resp3 = "HTTP/1.1 200 OK\r\n"
                + "Access-Control-Allow-Origin: https://evil.example.com\r\n"
                + "Access-Control-Allow-Credentials: true\r\n\r\n{}";
        List<LocalRules.Issue> i3 = LocalRules.detect(req3, resp3, null);
        System.out.println("  ③ CORS 反射 + 允许凭据");
        i3.forEach(x -> System.out.println("     " + x));
        check("检出「CORS反射」（高危）",
                i3.stream().anyMatch(x -> x.name.equals("CORS反射") && x.level == LocalRules.Level.HIGH));

        // ---- CORS 只反射不带凭据 → 不应报 ----
        String resp3b = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.example.com\r\n\r\n{}";
        List<LocalRules.Issue> i3b = LocalRules.detect(req3, resp3b, null);
        check("只反射不带凭据时不误报",
                i3b.stream().noneMatch(x -> x.name.equals("CORS反射")));

        // ---- Cookie 属性缺失 ----
        String resp4 = "HTTP/1.1 200 OK\r\nSet-Cookie: SESSION=abc123; Path=/\r\n\r\n";
        List<LocalRules.Issue> i4 = LocalRules.detect("GET / HTTP/1.1\r\nHost: x.com\r\n\r\n", resp4, null);
        System.out.println("  ④ Cookie 属性缺失");
        i4.forEach(x -> System.out.println("     " + x));
        check("检出「Cookie属性缺失」",
                i4.stream().anyMatch(x -> x.name.equals("Cookie属性缺失")));

        // ---- SQL 报错 ----
        String resp5 = "HTTP/1.1 500 Internal Server Error\r\n\r\n"
                + "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version";
        List<LocalRules.Issue> i5 = LocalRules.detect("GET /api/q?id=1' HTTP/1.1\r\nHost: x.com\r\n\r\n", resp5, null);
        System.out.println("  ⑤ SQL 报错泄露");
        i5.forEach(x -> System.out.println("     " + x));
        check("检出「SQL报错泄露」",
                i5.stream().anyMatch(x -> x.name.equals("SQL报错泄露")));

        // ---- 目录遍历 ----
        String resp6 = "HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:";
        List<LocalRules.Issue> i6 = LocalRules.detect("GET /?file=../../etc/passwd HTTP/1.1\r\nHost: x.com\r\n\r\n", resp6, null);
        System.out.println("  ⑥ 敏感文件泄露");
        i6.forEach(x -> System.out.println("     " + x));
        check("检出「敏感文件泄露」（严重）",
                i6.stream().anyMatch(x -> x.level == LocalRules.Level.CRITICAL));

        // ---- 敏感路径可访问 ----
        String resp7 = "HTTP/1.1 200 OK\r\n\r\n{\"env\":\"prod\"}";
        List<LocalRules.Issue> i7 = LocalRules.detect("GET /.env HTTP/1.1\r\nHost: x.com\r\n\r\n", resp7, null);
        System.out.println("  ⑦ 敏感路径可访问");
        i7.forEach(x -> System.out.println("     " + x));
        check("检出「敏感路径可访问」",
                i7.stream().anyMatch(x -> x.name.equals("敏感路径可访问")));

        // ---- 内网 IP ----
        String resp8 = "HTTP/1.1 200 OK\r\n\r\n{\"backend\":\"192.168.1.50:8080\"}";
        List<LocalRules.Issue> i8 = LocalRules.detect("GET /api/status HTTP/1.1\r\nHost: x.com\r\n\r\n", resp8, null);
        System.out.println("  ⑧ 内网地址泄露");
        i8.forEach(x -> System.out.println("     " + x));
        check("检出「内网地址泄露」",
                i8.stream().anyMatch(x -> x.name.equals("内网地址泄露")));

        // ---- 干净包不应误报 ----
        String cleanReq = "GET /api/product/1001 HTTP/1.1\r\nHost: shop.com\r\n\r\n";
        String cleanResp = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=x; HttpOnly; Secure\r\n\r\n{\"name\":\"book\"}";
        List<LocalRules.Issue> i9 = LocalRules.detect(cleanReq, cleanResp, null);
        System.out.println("  ⑨ 干净报文（不应误报）");
        if (i9.isEmpty()) {
            System.out.println("     无发现 ✓");
        } else {
            i9.forEach(x -> System.out.println("     " + x));
        }
        check("干净报文不误报", i9.isEmpty());

        // ---- 汇总显示 ----
        check("summarize 对空列表返回「无」", "无".equals(LocalRules.summarize(i9)));
        check("worst 对空列表返回 NONE", LocalRules.worst(i9) == LocalRules.Level.NONE);
        check("summarize 取最严重的一条",
                LocalRules.summarize(i1).contains("高危"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 三、宏观业务地图（把几百个包收敛成接口清单）");
        System.out.println("============================================================");

        Config cfg = new Config();
        RealtimePipe pipe = new RealtimePipe(() -> cfg);
        pipe.start();

        // 模拟一个真实系统：静态资源 + 多模块接口 + 重复调用
        String host = "ai.example.com";
        addMany(pipe, host, "GET", "/static/js/app.js");
        addMany(pipe, host, "GET", "/static/css/main.css");
        addMany(pipe, host, "GET", "/api/user/self");
        addMany(pipe, host, "GET", "/api/page_content");
        addMany(pipe, host, "GET", "/api/notice/list");
        addMany(pipe, host, "GET", "/api/user/group");
        addMany(pipe, host, "GET", "/api/audit/log");
        addMany(pipe, host, "GET", "/api/checkin/record");
        addMany(pipe, host, "POST", "/api/login");
        addMany(pipe, host, "POST", "/api/decrypt");
        addMany(pipe, host, "GET", "/api/task/list");
        // 另一个域名，验证过滤
        addMany(pipe, "other.com", "GET", "/api/thing");

        sleep(1500);

        LocalRules.BusinessMap map = pipe.buildBusinessMap(host);
        System.out.println();
        System.out.println(map.toPromptText());

        check("业务地图排除了静态资源", map.entries.stream()
                .noneMatch(e -> e.pathTemplate.contains("/static/")));
        check("业务地图只含目标域名", map.entries.size() > 5);
        check("业务模块分布非空", !map.byPurpose.isEmpty());
        check("接口清单文本可用于 AI（含域名与清单）",
                map.toPromptText().contains(host) && map.toPromptText().contains("接口清单"));

        System.out.println("  业务地图收敛效果：");
        System.out.printf("    处理报文 %d 个 → 接口条目 %d 个（压缩 %.0f%%）%n",
                pipe.processedCount(), map.entries.size(),
                pipe.processedCount() == 0 ? 0
                        : 100.0 * (1 - (double) map.entries.size() / pipe.processedCount()));

        // 成本：一次宏观调用
        int inTokens = com.packetsentry.core.CostTracker.estimateTokens(map.toPromptText());
        com.packetsentry.core.CostTracker cost = new com.packetsentry.core.CostTracker();
        cost.setPricing(com.packetsentry.core.CostTracker.DEEPSEEK_FLASH);
        double macro = cost.estimatePerPacketCny(300, inTokens, 1500);
        System.out.printf("    一次宏观 AI 调用：输入 %d tokens，预估 ¥%.4f%n", inTokens, macro);
        check("一次宏观调用成本在 ¥0.05 以内", macro < 0.05);

        pipe.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    /** 提交 n 次同样的请求（模拟重复调用）。 */
    private static void addMany(RealtimePipe pipe, String host, String method, String path) {
        // 不重复太多次，避免测试太慢；3 次足以验证去重生效
        for (int i = 0; i < 3; i++) {
            StringBuilder sb = new StringBuilder();
            sb.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
            sb.append("Host: ").append(host).append("\r\n");
            sb.append("Authorization: Bearer tok").append(i).append("abcdefghijklmnop\r\n");
            if ("POST".equals(method)) {
                sb.append("Content-Type: application/json\r\n\r\n");
                sb.append("{\"username\":\"admin\",\"password\":\"Secret").append(i).append("!\"}");
            } else {
                sb.append("\r\n");
            }
            String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    + "Set-Cookie: sid=abc; HttpOnly; Secure\r\n\r\n{\"ok\":true}";
            pipe.submit(b(sb.toString()), b(resp), 1, true, new Object(), null);
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
