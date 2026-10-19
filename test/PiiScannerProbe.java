import com.packetsentry.detect.PiiScanner;

/**
 * PiiScanner 实测 —— 验证"本地就能说清楚这个包里有什么"。
 *
 * 重点验证三件事：
 *   1. 能不能准确分类（严重度 + 类型 + 位置）
 *   2. JWT 能不能本地解码出 role / exp（不发 AI 就能得到测试线索）
 *   3. 已过期 / 仍有效的判断对不对
 */
public class PiiScannerProbe {

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

    public static void main(String[] args) {
        // 一个尚未过期的 JWT（exp 设在 2099 年）
        String fresh = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
                + ".eyJzdWIiOiIxMDA4NiIsInJvbGUiOiJhZG1pbiIsImlzcyI6Imh0dHBzOi8veXd0LmV4YW1wbGUuZWR1LmNuIiwiZXhwIjo0MDcwOTA4ODAwfQ"
                + ".ZmFrZXNpZ25hdHVyZWZha2VzaWduYXR1cmU";
        // 一个早已过期的 JWT（exp 设在 2020 年）
        String stale = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                + ".eyJzdWIiOiI5OTkiLCJyb2xlIjoidXNlciIsImV4cCI6MTU3NzgzNjgwMH0"
                + ".c2lnbmF0dXJl";

        String raw = String.join("\r\n",
                "POST /api/v1/order HTTP/1.1",
                "Host: shop.example.com",
                "Content-Type: application/json",
                "Authorization: Bearer " + fresh,
                "X-Legacy-Token: " + stale,
                "X-Api-Key: AKIAIOSFODNN7EXAMPLE",
                "",
                "{",
                "  \"receiver\": \"张三\",",
                "  \"mobile\": \"13812345678\",",
                "  \"idCard\": \"110101199003074518\",",
                "  \"cardNo\": \"6222021234567890123\",",
                "  \"email\": \"zhangsan@example.com\",",
                "  \"amount\": 199",
                "}");

        PiiScanner scanner = new PiiScanner();
        PiiScanner.Report r = scanner.scan(raw);

        System.out.println("============================================================");
        System.out.println(" 本地扫描报告（全程无网络调用）");
        System.out.println("============================================================");
        for (PiiScanner.Finding f : r.findings) {
            System.out.println("  " + f.describe());
        }
        System.out.println();
        System.out.println("  结论  " + r.headline());
        System.out.println("  最严重 " + r.worst());

        if (!r.jwts.isEmpty()) {
            System.out.println();
            System.out.println("============================================================");
            System.out.println(" JWT 本地解码（不验签，只看结构）");
            System.out.println("============================================================");
            for (PiiScanner.JwtInfo j : r.jwts) {
                System.out.println("  " + j.pretty().replace("\n", "\n  "));
                System.out.println();
            }
        }

        // ---------------- 断言 ----------------
        System.out.println("============================================================");
        System.out.println(" 断言");
        System.out.println("============================================================");

        check("发现 PEM/AWS/JWT 等 CRITICAL 或 HIGH 项", r.worst() != null
                && r.worst().ordinal() <= PiiScanner.Severity.HIGH.ordinal());
        check("检出 JWT", r.findings.stream().anyMatch(f -> "JWT".equals(f.kind)));
        check("检出 AWS 密钥", r.findings.stream().anyMatch(f -> "AWS访问密钥".equals(f.kind)));
        check("检出身份证", r.findings.stream().anyMatch(f -> "中国大陆身份证".equals(f.kind)));
        check("检出手机号", r.findings.stream().anyMatch(f -> "中国大陆手机号".equals(f.kind)));
        check("检出邮箱", r.findings.stream().anyMatch(f -> "邮箱".equals(f.kind)));
        check("检出密码字段规则（本例无 password，不应误报）",
                r.findings.stream().noneMatch(f -> "疑似密码字段".equals(f.kind)));

        check("JWT 解码出 2 个", r.jwts.size() == 2);

        boolean freshValid = r.jwts.stream().anyMatch(j -> !j.isExpired() && "admin".equals(j.role()));
        boolean staleExpired = r.jwts.stream().anyMatch(j -> j.isExpired() && "user".equals(j.role()));
        check("识别出未过期 JWT 且 role=admin", freshValid);
        check("识别出已过期 JWT 且 role=user", staleExpired);

        check("位置定位到 Authorization",
                r.findings.stream().anyMatch(f -> "Authorization".equals(f.location)));
        check("位置定位到 body.idCard",
                r.findings.stream().anyMatch(f -> "body.idCard".equals(f.location)));
        check("普通数字金额不被当银行卡（19 位才匹配）",
                r.findings.stream().noneMatch(f -> "银行卡号".equals(f.kind) && f.length < 16));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=%d  FAIL=%d".formatted(pass, fail));
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
