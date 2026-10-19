import com.packetsentry.core.AccessControlTester;
import com.packetsentry.core.Identity;

import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * 越权判定逻辑实测。
 *
 * <p>这里不发包 —— 只测「给定两个响应，判定是否正确」。
 * 因为判定逻辑才是最容易出错、也最需要验证的部分：
 * <b>误报会浪费研究时间，漏报会漏掉真漏洞</b>。
 *
 * <p>四类场景必须区分开：
 * <ol>
 *   <li>越权    换身份仍拿到同一份数据</li>
 *   <li>有防护  换身份被拒</li>
 *   <li>各取各  A 拿 A 的、B 拿 B 的（正常，不能误报）</li>
 *   <li>拿不准  需人工看</li>
 * </ol>
 */
public class AccessControlProbe {

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

    private static void checkEq(String label, Object got, Object want) {
        boolean ok = got == null ? want == null : got.equals(want);
        if (ok) {
            pass++;
            System.out.println("  [PASS] " + label);
        } else {
            fail++;
            System.out.println("  [FAIL] " + label + "　得到 " + got + "，期望 " + want);
        }
    }

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println(" 一、身份凭据替换（越权测试的核心操作）");
        System.out.println("============================================================");

        String raw = "GET /api/order/5001 HTTP/1.1\r\n"
                + "Host: shop.example.com\r\n"
                + "Cookie: SESSION=AAA111\r\n"
                + "Authorization: Bearer TOKEN_AAA\r\n"
                + "Accept: application/json\r\n"
                + "\r\n";

        Identity idB = new Identity("用户B")
                .header("Cookie", "SESSION=BBB222")
                .header("Authorization", "Bearer TOKEN_BBB");

        String out = new String(idB.apply(raw.getBytes(StandardCharsets.UTF_8), true),
                StandardCharsets.UTF_8);
        System.out.println("  替换后的请求：");
        for (String line : out.split("\r\n")) {
            System.out.println("    " + line);
        }
        System.out.println();

        check("Cookie 被替换成 B 的", out.contains("Cookie: SESSION=BBB222"));
        check("Authorization 被替换成 B 的", out.contains("Authorization: Bearer TOKEN_BBB"));
        check("A 的凭据已消失", !out.contains("AAA111") && !out.contains("TOKEN_AAA"));
        check("请求行未被改动（只换身份这一个变量）", out.startsWith("GET /api/order/5001 HTTP/1.1"));
        check("无关头保持原样（Accept）", out.contains("Accept: application/json"));
        check("Host 未被改动", out.contains("Host: shop.example.com"));

        // 缺少目标头时应新增
        String rawNoCookie = "GET /x HTTP/1.1\r\nHost: h\r\n\r\n";
        String out2 = new String(idB.apply(rawNoCookie.getBytes(StandardCharsets.UTF_8), true),
                StandardCharsets.UTF_8);
        check("原请求没有该头时能新增", out2.contains("Cookie: SESSION=BBB222")
                && out2.contains("Authorization: Bearer TOKEN_BBB"));

        // 大小写不敏感
        String rawLower = "GET /x HTTP/1.1\r\nHost: h\r\ncookie: OLD\r\n\r\n";
        String out3 = new String(idB.apply(rawLower.getBytes(StandardCharsets.UTF_8), true),
                StandardCharsets.UTF_8);
        check("头名大小写不敏感", out3.contains("SESSION=BBB222") && !out3.contains("OLD"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 二、判定逻辑（四类场景必须区分开）");
        System.out.println("============================================================");

        // ---------- 场景 1：越权 ----------
        String base1 = "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"orderId\":5001,\"userId\":1001,\"amount\":100,\"status\":\"paid\"}";
        String test1 = "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"orderId\":5001,\"userId\":1001,\"amount\":100,\"status\":\"paid\"}";
        double vs1 = AccessControlTester.valueSimilarity(base1, test1);
        double ss1 = AccessControlTester.structureSimilarity(base1, test1);
        AccessControlTester.Verdict v1 = AccessControlTester.judge(200, 200, ss1, vs1);
        System.out.printf("  ① 越权场景   结构 %.0f%%  值 %.0f%%  → %s%n", ss1 * 100, vs1 * 100, v1);
        checkEq("完全相同的响应 → 疑似越权", v1, AccessControlTester.Verdict.VULNERABLE);

        // ---------- 场景 2：有防护 ----------
        String test2 = "HTTP/1.1 403 Forbidden\r\n\r\n{\"error\":\"forbidden\"}";
        AccessControlTester.Verdict v2 = AccessControlTester.judge(200, 403, 0.2, 0.1);
        System.out.printf("  ② 有防护     200 → 403          → %s%n", v2);
        checkEq("403 → 有访问控制", v2, AccessControlTester.Verdict.PROTECTED);

        AccessControlTester.Verdict v2b = AccessControlTester.judge(200, 401, 0.2, 0.1);
        checkEq("401 → 有访问控制", v2b, AccessControlTester.Verdict.PROTECTED);

        AccessControlTester.Verdict v2c = AccessControlTester.judge(200, 404, 0.2, 0.1);
        checkEq("404 → 有访问控制", v2c, AccessControlTester.Verdict.PROTECTED);

        // ---------- 场景 3：各取各的数据（关键 —— 不能误报） ----------
        String base3 = "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"id\":1001,\"name\":\"Alice\",\"email\":\"alice@corp.com\",\"dept\":\"研发\"}";
        String test3 = "HTTP/1.1 200 OK\r\n\r\n"
                + "{\"id\":1002,\"name\":\"Bob\",\"email\":\"bob@corp.com\",\"dept\":\"市场\"}";
        double vs3 = AccessControlTester.valueSimilarity(base3, test3);
        double ss3 = AccessControlTester.structureSimilarity(base3, test3);
        AccessControlTester.Verdict v3 = AccessControlTester.judge(200, 200, ss3, vs3);
        System.out.printf("  ③ 各取各的   结构 %.0f%%  值 %.0f%%  → %s%n", ss3 * 100, vs3 * 100, v3);
        checkEq("结构像但值不同 → 各取各的（不误报越权）", v3, AccessControlTester.Verdict.SEPARATE);
        check("  且值相似度确实低（<35%）", vs3 < 0.35);

        // ---------- 场景 4：部分重合 → 需人工 ----------
        String base4 = "HTTP/1.1 200 OK\r\n\r\n{\"id\":1001,\"name\":\"Alice\",\"role\":\"user\"}";
        String test4 = "HTTP/1.1 200 OK\r\n\r\n{\"id\":1001,\"name\":\"Alice\",\"role\":\"admin\"}";
        double vs4 = AccessControlTester.valueSimilarity(base4, test4);
        double ss4 = AccessControlTester.structureSimilarity(base4, test4);
        AccessControlTester.Verdict v4 = AccessControlTester.judge(200, 200, ss4, vs4);
        System.out.printf("  ④ 部分重合   结构 %.0f%%  值 %.0f%%  → %s%n", ss4 * 100, vs4 * 100, v4);
        check("部分重合不直接判越权（保守）",
                v4 == AccessControlTester.Verdict.INCONCLUSIVE
                        || v4 == AccessControlTester.Verdict.VULNERABLE);

        // ---------- 边界 ----------
        AccessControlTester.Verdict v5 = AccessControlTester.judge(200, 500, 0.9, 0.9);
        checkEq("测试请求 5xx → 拿不准（不误报）", v5, AccessControlTester.Verdict.INCONCLUSIVE);

        AccessControlTester.Verdict v6 = AccessControlTester.judge(200, 0, 0, 0);
        checkEq("无响应 → 拿不准", v6, AccessControlTester.Verdict.INCONCLUSIVE);

        // ---------- 拥有者提取 ----------
        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 三、拥有者标识提取（越权最直接的证据）");
        System.out.println("============================================================");

        String owner1 = AccessControlTester.extractOwner(
                "{\"orderId\":5001,\"userId\":1001,\"amount\":100}");
        System.out.println("  {\"userId\":1001,...}  →  " + owner1);
        checkEq("能从 userId 提取", owner1, "userid=1001");

        String owner2 = AccessControlTester.extractOwner("{\"user_id\":\"1001\"}");
        checkEq("能从 user_id 提取", owner2, "user_id=1001");

        String owner3 = AccessControlTester.extractOwner("{\"id\":87,\"name\":\"x\"}");
        checkEq("退化到 id 字段", owner3, "id=87");

        String owner4 = AccessControlTester.extractOwner("{\"name\":\"x\"}");
        checkEq("无标识返回 null", owner4, null);

        // ---------- 相似度函数本身 ----------
        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 四、相似度函数");
        System.out.println("============================================================");

        Set<String> a = AccessControlTester.structureTokens("{\"a\":1,\"b\":2}");
        Set<String> b = AccessControlTester.structureTokens("{\"a\":1,\"b\":9}");
        System.out.println("  结构 token（值不同）：" + a + " / " + b);
        check("结构提取忽略值差异", a.equals(b));

        Set<String> va = AccessControlTester.valueTokens("{\"a\":1,\"b\":2}");
        Set<String> vb = AccessControlTester.valueTokens("{\"a\":1,\"b\":9}");
        check("值提取包含具体值", va.contains("1") && va.contains("2") && !va.equals(vb));

        check("空集 Jaccard = 1.0",
                AccessControlTester.jaccard(new java.util.HashSet<>(), new java.util.HashSet<>()) == 1.0);
        check("一方为空 = 0.0",
                AccessControlTester.jaccard(java.util.Set.of("x"), new java.util.HashSet<>()) == 0.0);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 五、身份展示脱敏（身份本身就是凭据）");
        System.out.println("============================================================");
        Identity idLong = new Identity("测试").header("Cookie",
                "SESSION=abcdefghijklmnopqrstuvwxyz123456");
        String desc = idLong.describe();
        System.out.println("  " + desc);
        check("长凭据被脱敏", desc.contains("…") && !desc.contains("klmnopqrstuvwxyz"));
        Identity idShort = new Identity("测试").header("X", "abc");
        check("短凭据显示为 ****", idShort.describe().contains("****"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
