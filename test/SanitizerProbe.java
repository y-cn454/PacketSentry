import com.packetsentry.sanitize.Sanitizer;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Sanitizer 的实测工具。
 *
 * 用一段真实的、带各种凭据的报文，验证：
 *   1. 三层规则都命中
 *   2. 原文里的敏感值一个都没漏出去（逐条断言）
 *   3. 非敏感内容原样保留（不能把 AI 需要的信息也抹了）
 */
public class SanitizerProbe {

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

    public static void main(String[] args) throws Exception {
        // 造一个"最坏情况"的请求：JWT、会话 Cookie、密码、手机号、身份证、银行卡、私钥
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                + ".eyJzdWIiOiIxMDA4NiIsInJvbGUiOiJ1c2VyIiwiZXhwIjoxNzkzMDAwMDAwfQ"
                + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        String raw = String.join("\r\n",
                "POST /backstage/auth/login HTTP/1.1",
                "Host: ywt.example.edu.cn",
                "User-Agent: Mozilla/5.0",
                "Content-Type: application/json; charset=UTF-8",
                "Authorization: Bearer " + jwt,
                "Cookie: SESSION=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6; csrftoken=deadbeefcafe1234",
                "X-Csrf-Token: 7f3a9b2c8d1e4f5a6b7c8d9e0f1a2b3c",
                "",
                "{",
                "  \"username\": \"admin\",",
                "  \"password\": \"P@ssw0rd!2026\",",
                "  \"phone\": \"13812345678\",",
                "  \"id_card\": \"110101199003074518\",",
                "  \"bank_card\": \"6222021234567890123\",",
                "  \"note\": \"测试账号，联系邮箱 zhang.san@example.com\",",
                "  \"tenant\": \"main\",",
                "  \"remember\": true",
                "}");

        Sanitizer san = new Sanitizer();
        Sanitizer.Result r = san.sanitize(raw);

        System.out.println("============================================================");
        System.out.println(" 脱敏前（原文，%d 字符）".formatted(raw.length()));
        System.out.println("============================================================");
        System.out.println(raw);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 脱敏后（将要外发给 AI 的内容，%d 字符）".formatted(r.cleanText.length()));
        System.out.println("============================================================");
        System.out.println(r.cleanText);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 命中报告");
        System.out.println("============================================================");
        for (Sanitizer.Hit h : r.hits) {
            System.out.println("  " + h);
        }
        System.out.println();
        System.out.println("  摘要      " + r.summary());
        System.out.println("  字节变化  " + raw.length() + " → " + r.cleanText.length()
                + "  (省 " + r.bytesSaved() + ")");

        // ---------------- 断言：原文敏感值一个都不能出现 ----------------
        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 泄露检查 —— 原文里的敏感值必须一个都不出现");
        System.out.println("============================================================");

        String[] secrets = {
                jwt,
                "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                "deadbeefcafe1234",
                "7f3a9b2c8d1e4f5a6b7c8d9e0f1a2b3c",
                "P@ssw0rd!2026",
                "13812345678",
                "110101199003074518",
                "6222021234567890123",
                "zhang.san@example.com",
        };
        for (String s : secrets) {
            check("未泄露: " + (s.length() > 28 ? s.substring(0, 28) + "..." : s),
                    !r.cleanText.contains(s));
        }

        // ---------------- 断言：AI 需要的上下文必须保留 ----------------
        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 保留检查 —— AI 需要的信息不能被误伤");
        System.out.println("============================================================");
        String[] keep = {
                "POST /backstage/auth/login HTTP/1.1",
                "Host: ywt.example.edu.cn",
                "Content-Type: application/json",
                "\"username\": \"admin\"",     // 用户名不算凭据，保留；且格式必须原样
                "\"tenant\": \"main\"",        // 同上：验证格式没被重建吃掉
                "\"remember\": true",          // 布尔值不能被当字符串抹
                "1381",                        // KEEP_EDGES 保留的手机号前缀
        };
        for (String s : keep) {
            check("保留: " + s, r.cleanText.contains(s));
        }

        // ---------------- 边界：超短值不能被 KEEP_EDGES 漏掉 ----------------
        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 边界测试");
        System.out.println("============================================================");
        check("短密码全掩（<=8 字符）",
                Sanitizer.mask("abc123", Sanitizer.MaskStrategy.KEEP_EDGES).equals("****"));
        check("长密码保留首尾",
                Sanitizer.mask("P@ssw0rd!2026", Sanitizer.MaskStrategy.KEEP_EDGES).equals("P@ss****2026"));
        check("FULL 策略",
                Sanitizer.mask("anything", Sanitizer.MaskStrategy.FULL).equals("<REDACTED>"));
        check("TYPE_ONLY 策略",
                Sanitizer.mask("anything", Sanitizer.MaskStrategy.TYPE_ONLY, "<JWT>").equals("<JWT>"));
        check("HASH 策略可复现",
                Sanitizer.mask("x", Sanitizer.MaskStrategy.HASH)
                        .equals(Sanitizer.mask("x", Sanitizer.MaskStrategy.HASH)));

        // form 编码
        Sanitizer.Result f = san.sanitize("POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
                + "user=admin&password=secret123&phone=13900001111&keep=yes");
        check("form: 密码被抹", !f.cleanText.contains("secret123"));
        check("form: 手机号被抹", !f.cleanText.contains("13900001111"));
        check("form: 非敏感字段保留", f.cleanText.contains("keep=yes") && f.cleanText.contains("user=admin"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=%d  FAIL=%d".formatted(pass, fail));
        System.out.println("============================================================");

        System.exit(fail == 0 ? 0 : 1);
    }
}
