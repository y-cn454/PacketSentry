import com.packetsentry.core.Config;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.core.RealtimePipe;
import com.packetsentry.sanitize.Sanitizer;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 第六轮排查：<b>语义正确性</b> —— 不崩，但「结果对不对」。
 *
 * <h3>为什么这一轮最容易被忽略</h3>
 * 前五轮测的都是「会不会挂、会不会错乱」。这一轮测的是
 * <b>「程序跑得好好的，但给出的答案是错的」</b> ——
 * 这种缺陷不会报错、不会崩溃，只会让用户<b>错过漏洞</b>，
 * 而且用户完全察觉不到。
 *
 * <p>重点查三件事：
 * <ol>
 *   <li><b>去重是否误合并</b>：把两个真正不同的接口认成一个 →
 *       后一个永远不被分析 → 漏漏洞</li>
 *   <li><b>脱敏是否真的脱干净</b>：这是安全关键，漏一个就是真实数据泄露</li>
 *   <li><b>界面各处的结论是否自洽</b>：表格、明细、报告说的应该是同一件事</li>
 * </ol>
 */
public class SemanticProbe {

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

    private static byte[] resp() {
        return b("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}");
    }

    /**
     * 提交一批请求，返回「被判定为重复的比例」。
     *
     * <p>提交 N 条，其中不重复的会被记为 worth，重复的记为 dup。
     * 返回 {不重复数, 重复数}。
     */
    private static long[] submitAll(Config cfg, String... requests) {
        RealtimePipe p = new RealtimePipe(() -> cfg);
        p.start();
        for (String r : requests) {
            p.submit(b(r), resp(), 1, true, new Object(), null);
        }
        sleep(400 + requests.length * 30L);
        long[] out = {p.worthCount(), p.duplicateCount()};
        p.stop();
        return out;
    }

    public static void main(String[] args) {
        Config cfg = new Config();
        cfg.sanitizeEnabled = true;
        cfg.scanEnabled = true;

        System.out.println("============================================================");
        System.out.println(" 第六轮 · A：去重是否误合并（漏漏洞的关键）");
        System.out.println("============================================================");

        // ---- 1. 应该被合并的（同结构不同实例）----
        long[] r1 = submitAll(cfg,
                "GET /api/user/1001 HTTP/1.1\r\nHost: s.com\r\n\r\n",
                "GET /api/user/2002 HTTP/1.1\r\nHost: s.com\r\n\r\n",
                "GET /api/user/9999 HTTP/1.1\r\nHost: s.com\r\n\r\n");
        System.out.println("  /api/user/{不同数字} ×3 → 不重复 " + r1[0] + "，重复 " + r1[1]);
        check("同一接口的不同 ID 被正确合并（1 个不重复 + 2 个重复）",
                r1[0] == 1 && r1[1] == 2);

        // ---- 2. 方法不同不该合并 ----
        long[] r2 = submitAll(cfg,
                "GET /api/thing HTTP/1.1\r\nHost: s.com\r\n\r\n",
                "POST /api/thing HTTP/1.1\r\nHost: s.com\r\n\r\n");
        System.out.println("  GET /api/thing + POST /api/thing → 不重复 " + r2[0]);
        check("不同 HTTP 方法不合并", r2[0] == 2);

        // ---- 3. query 值不同但参数名相同 → 应合并 ----
        long[] r3 = submitAll(cfg,
                "GET /api/list?id=1 HTTP/1.1\r\nHost: s.com\r\n\r\n",
                "GET /api/list?id=2 HTTP/1.1\r\nHost: s.com\r\n\r\n");
        System.out.println("  /api/list?id=1 与 ?id=2 → 不重复 " + r3[0]);
        check("query 值不同、参数名相同 → 合并", r3[0] == 1);

        // ---- 4. query 参数名不同 → 不该合并 ----
        long[] r4 = submitAll(cfg,
                "GET /api/list?id=1 HTTP/1.1\r\nHost: s.com\r\n\r\n",
                "GET /api/list?name=a HTTP/1.1\r\nHost: s.com\r\n\r\n");
        System.out.println("  /api/list?id=1 与 ?name=a → 不重复 " + r4[0]);
        check("query 参数名不同 → 不合并", r4[0] == 2);

        // ---- 5. 静态资源 chunk 编号 → 应合并（且都是低价值）----
        long[] r5 = submitAll(cfg,
                "GET /static/chunk1.js HTTP/1.1\r\nHost: s.com\r\n\r\n",
                "GET /static/chunk600.js HTTP/1.1\r\nHost: s.com\r\n\r\n");
        System.out.println("  /static/chunk1.js 与 chunk600.js → 不重复 " + r5[0]);
        check("静态资源 chunk 编号归一化（低价值，不计入不重复）", r5[0] == 0);

        // ---- 6. ⭐ API 版本号不该合并 ----
        //    这是本轮最关键的怀疑点：DIGIT_RUN 会把 v1/v2 都变成 v{n}，
        //    于是 v2 的接口永远不会被分析 —— 用户会漏掉 v2 上的漏洞。
        long[] r6 = submitAll(cfg,
                "GET /api/v1/admin/users HTTP/1.1\r\nHost: s.com\r\n\r\n",
                "GET /api/v2/admin/users HTTP/1.1\r\nHost: s.com\r\n\r\n",
                "GET /api/v3/admin/users HTTP/1.1\r\nHost: s.com\r\n\r\n");
        System.out.println("  /api/v1|v2|v3/admin/users → 不重复 " + r6[0] + "，重复 " + r6[1]);
        check("⭐ API 版本号 v1/v2/v3 不被合并（否则 v2/v3 永远不会被分析）",
                r6[0] == 3);

        // ---- 7. 单复数 / 大小写路径不该合并 ----
        long[] r7 = submitAll(cfg,
                "GET /api/User HTTP/1.1\r\nHost: s.com\r\n\r\n",
                "GET /api/user HTTP/1.1\r\nHost: s.com\r\n\r\n");
        System.out.println("  /api/User 与 /api/user → 不重复 " + r7[0]);
        check("路径大小写不同 → 不合并（可能是不同路由）", r7[0] == 2);

        // ---- 8. 不同主机不该合并 ----
        long[] r8 = submitAll(cfg,
                "GET /api/x HTTP/1.1\r\nHost: a.com\r\n\r\n",
                "GET /api/x HTTP/1.1\r\nHost: b.com\r\n\r\n");
        System.out.println("  a.com/api/x 与 b.com/api/x → 不重复 " + r8[0]);
        check("不同主机的同名路径不合并", r8[0] == 2);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第六轮 · B：脱敏是否真的脱干净（安全关键）");
        System.out.println("============================================================");

        String[] secrets = {
                "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop",
                "AKIAIOSFODNN7EXAMPLE",
                "13812345678",
                "11010119900307123X",
                "6222021234567890123",
                "user@example.com",
                "password=SuperSecret123!",
                "-----BEGIN RSA PRIVATE KEY-----",
        };
        String req = "POST /api/login HTTP/1.1\r\nHost: s.com\r\n"
                + "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop\r\n"
                + "Cookie: sid=abc; token=AKIAIOSFODNN7EXAMPLE\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + "{\"phone\":\"13812345678\",\"idcard\":\"11010119900307123X\","
                + "\"bankcard\":\"6222021234567890123\",\"email\":\"user@example.com\","
                + "\"password\":\"SuperSecret123!\","
                + "\"key\":\"-----BEGIN RSA PRIVATE KEY-----\"}";

        Sanitizer sanitizer = new Sanitizer(
                Sanitizer.MaskStrategy.FULL, true, true, true);
        Sanitizer.Result sr = sanitizer.sanitize(req);
        String clean = sr.cleanText;

        boolean allMasked = true;
        for (String s : secrets) {
            // 私有密钥头这种结构词允许保留（它就是标记），其余必须被抹掉
            if (s.startsWith("-----")) {
                continue;
            }
            if (clean.contains(s)) {
                allMasked = false;
                System.out.println("    ✗ 泄露未脱敏：" + s);
            }
        }
        System.out.println("  脱敏后长度：" + req.length() + " → " + clean.length()
                + "，命中 " + sr.hits.size() + " 处");
        check("8 类敏感值全部被抹掉（不残留原文）", allMasked);

        // 反过来：结构必须保留，否则报告没法看
        check("请求行保留（脱敏不能把结构也抹掉）", clean.contains("POST /api/login"));
        check("字段名保留（否则不知道哪个字段敏感）", clean.contains("phone"));
        check("脱敏后在报告里可读（不是一片星号）", clean.length() > req.length() / 3);

        // ---- 不同掩码策略下都不许残留 ----
        boolean strategiesOk = true;
        for (Sanitizer.MaskStrategy st : Sanitizer.MaskStrategy.values()) {
            String c = new Sanitizer(st, true, true, true).sanitize(req).cleanText;
            for (String s : secrets) {
                if (s.startsWith("-----")) {
                    continue;
                }
                if (c.contains(s)) {
                    strategiesOk = false;
                    System.out.println("    ✗ 策略 " + st + " 残留：" + s);
                }
            }
        }
        check("所有掩码策略下都不残留敏感值", strategiesOk);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第六轮 · C：结论自洽（表格 / 明细 / 计数说的是同一件事）");
        System.out.println("============================================================");

        Config cfg2 = new Config();
        cfg2.sanitizeEnabled = true;
        cfg2.scanEnabled = true;
        RealtimePipe p = new RealtimePipe(() -> cfg2);
        p.start();
        // 一条有问题的 + 一条干净的
        p.submit(b("GET /backup/db.sql HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                b("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nINSERT INTO x VALUES(1);"),
                1, true, new Object(), null);
        p.submit(b("GET /api/ok HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                b("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"),
                1, true, new Object(), null);
        sleep(1200);

        List<PacketRecord> snap = p.snapshot();
        PacketRecord withIssue = null;
        for (PacketRecord r : snap) {
            if (r.statusCode == 200 && r.path.contains("db.sql")) {
                withIssue = r;
            }
        }
        check("找到带发现的记录", withIssue != null);
        if (withIssue != null) {
            check("记录里确实有发现（issues 非空）", !withIssue.issues.isEmpty());
            check("worstLevel 与 issues 一致（不是 NONE）",
                    withIssue.worstLevel.rank > 0);
            check("issueSummary 反映实际发现（含备份关键词）",
                    withIssue.issueSummary().contains("备份")
                            || withIssue.issueSummary().contains("敏感"));
            check("worthAnalyzing() 对带发现的记录为 true", withIssue.worthAnalyzing());
        }

        // 全量计数必须 >= 记录数（计数是全量，recent 是窗口）
        check("全量计数 >= recent 条数（窗口与计数不混用）",
                p.processedCount() >= snap.size());
        check("issueCount 与带发现的记录数一致",
                p.issueCount() >= 1);
        p.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第六轮 · D：成本统计的语义（不能把估算说成事实）");
        System.out.println("============================================================");

        com.packetsentry.core.CostTracker ct = new com.packetsentry.core.CostTracker();
        // 云端定价
        ct.setPricing(com.packetsentry.core.CostTracker.DEEPSEEK_FLASH);
        ct.recordCall("系统提示词", "一条报文摘要", "模型的回复内容");
        String est = ct.oneLine();
        System.out.println("  " + est);
        check("成本说明里含「估」字（不把估算说成事实）", est.contains("估"));
        check("成本说明里有具体金额", est.matches(".*[0-9].*"));

        // 本地模型 —— 必须零成本
        com.packetsentry.core.CostTracker ctLocal = new com.packetsentry.core.CostTracker();
        ctLocal.setPricing(com.packetsentry.core.CostTracker.LOCAL_FREE);
        ctLocal.recordCall("系统提示词", "一条报文摘要", "模型的回复");
        String estLocal = ctLocal.oneLine();
        System.out.println("  " + estLocal);
        check("本地模型成本为 0", ctLocal.costCny() == 0.0);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
