import com.packetsentry.core.Config;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.core.RealtimePipe;
import com.packetsentry.detect.LocalRules;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 业务逻辑线索引擎实测。
 *
 * <h3>为什么要单独测</h3>
 * 逻辑漏洞是 SRC 里最值钱的方向，而它<b>不能靠看单个报文发现</b> ——
 * 必须看一串报文的统计特征。这个引擎是新东西，也是很容易做错的东西：
 * <ul>
 *   <li>报太多 → 噪音，用户还是看不到信号</li>
 *   <li>报太少 → 等于没有</li>
 *   <li>报错了 → 用户按错误线索白测半天</li>
 * </ul>
 * 所以每一条都要有「该报」和「不该报」两个方向的验证。
 */
public class LogicHintsProbe {

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

    /** 从一条记录的 issues 里找某个线索。 */
    private static boolean hasHint(PacketRecord r, String namePart) {
        return r.issues.stream().anyMatch(i -> i.name.contains(namePart));
    }

    private static String hint(PacketRecord r, String namePart) {
        return r.issues.stream()
                .filter(i -> i.name.contains(namePart))
                .map(i -> i.name + "：" + i.detail)
                .findFirst().orElse("(无)");
    }

    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] resp(String body) {
        return b("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body);
    }

    public static void main(String[] args) throws Exception {
        Config cfg = new Config();
        cfg.sanitizeEnabled = true;
        cfg.scanEnabled = true;

        System.out.println("============================================================");
        System.out.println(" 一、ID 可预测性（最重要的越权线索）");
        System.out.println("============================================================");

        // ---- 顺序 ID：应当报 ----
        RealtimePipe p1 = new RealtimePipe(() -> cfg);
        p1.start();
        for (int i = 1001; i <= 1008; i++) {
            p1.submit(b("GET /api/order/" + i + " HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n\r\n"),
                    resp("{\"orderId\":" + i + "}"), 1, true, new Object(), null);
        }
        sleep(900);
        List<PacketRecord> r1 = p1.snapshot();
        PacketRecord last1 = r1.get(r1.size() - 1);
        System.out.println("  顺序 ID 1001..1008 →");
        System.out.println("    " + hint(last1, "ID可预测"));
        check("顺序小范围 ID 报出越权线索",
                r1.stream().anyMatch(r -> hasHint(r, "ID可预测")));
        p1.stop();

        // ---- 随机 ID：不应报 ----
        RealtimePipe p2 = new RealtimePipe(() -> cfg);
        p2.start();
        long[] randomIds = {8273619L, 55L, 918273L, 4L, 7712L, 663920L};
        for (long id : randomIds) {
            p2.submit(b("GET /api/order/" + id + " HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n\r\n"),
                    resp("{}"), 1, true, new Object(), null);
        }
        sleep(900);
        List<PacketRecord> r2 = p2.snapshot();
        System.out.println();
        System.out.println("  随机 ID 8273619/55/918273/4/7712/663920 →");
        System.out.println("    " + hint(r2.get(r2.size() - 1), "ID可预测"));
        check("随机大跨度 ID 不误报",
                r2.stream().noneMatch(r -> hasHint(r, "ID可预测")));
        p2.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 二、业务参数可篡改线索");
        System.out.println("============================================================");

        RealtimePipe p3 = new RealtimePipe(() -> cfg);
        p3.start();

        // 金额
        p3.submit(b("POST /api/order/create HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n"
                        + "Content-Type: application/json\r\n\r\n"
                        + "{\"sku\":\"A1\",\"price\":19900,\"quantity\":1,\"coupon\":\"NEW50\"}"),
                resp("{\"ok\":true}"), 1, true, new Object(), null);
        // 权限
        p3.submit(b("POST /api/user/update HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n"
                        + "Content-Type: application/json\r\n\r\n"
                        + "{\"nickname\":\"x\",\"role\":\"user\",\"vip\":0,\"level\":1}"),
                resp("{\"ok\":true}"), 1, true, new Object(), null);
        // 状态
        p3.submit(b("POST /api/order/submit HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n"
                        + "Content-Type: application/json\r\n\r\n"
                        + "{\"orderId\":1,\"status\":\"pending\",\"step\":2}"),
                resp("{\"ok\":true}"), 1, true, new Object(), null);
        // 归属
        p3.submit(b("GET /api/address?user_id=1001 HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n\r\n"),
                resp("{}"), 1, true, new Object(), null);
        // 无 CSRF
        p3.submit(b("POST /api/pay HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n"
                        + "Content-Type: application/json\r\n\r\n{\"orderId\":1,\"total\":1}"),
                resp("{\"ok\":true}"), 1, true, new Object(), null);

        sleep(1200);
        List<PacketRecord> r3 = p3.snapshot();
        System.out.println("  共 " + r3.size() + " 条记录，线索如下：");
        java.util.Set<String> allHints = new java.util.LinkedHashSet<>();
        for (PacketRecord r : r3) {
            for (LocalRules.Issue i : r.issues) {
                allHints.add(i.name);
                System.out.println("    " + r.path + "  →  " + i.name + "：" + i.detail);
            }
        }
        System.out.println();
        check("检出「金额可篡改线索」", allHints.stream().anyMatch(s -> s.contains("金额可篡改")));
        check("检出「权限字段可控线索」", allHints.stream().anyMatch(s -> s.contains("权限字段")));
        check("检出「状态字段可控线索」", allHints.stream().anyMatch(s -> s.contains("状态字段")));
        check("检出「归属字段可控线索」", allHints.stream().anyMatch(s -> s.contains("归属字段")));
        check("检出「无CSRF令牌线索」", allHints.stream().anyMatch(s -> s.contains("CSRF")));
        p3.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 三、可重复提交 / 频控缺失");
        System.out.println("============================================================");

        RealtimePipe p4 = new RealtimePipe(() -> cfg);
        p4.start();
        // 同一个请求重复 20 次 —— 既触发「可重复提交」也触发「频控缺失」
        for (int i = 0; i < 20; i++) {
            p4.submit(b("POST /api/coupon/receive HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n"
                            + "Content-Type: application/json\r\n\r\n{\"couponId\":\"NEW50\"}"),
                    resp("{\"ok\":true}"), 1, true, new Object(), null);
        }
        sleep(1200);
        List<PacketRecord> r4 = p4.snapshot();
        java.util.Set<String> h4 = new java.util.LinkedHashSet<>();
        for (PacketRecord r : r4) {
            for (LocalRules.Issue i : r.issues) {
                h4.add(i.name + "：" + i.detail);
            }
        }
        h4.forEach(s -> System.out.println("    " + s));
        System.out.println();
        check("检出「可重复提交线索」", h4.stream().anyMatch(s -> s.contains("可重复提交")));
        check("检出「频控缺失线索」", h4.stream().anyMatch(s -> s.contains("频控缺失")));
        p4.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 四、参数污染 / 前端校验 / 批量赋值");
        System.out.println("============================================================");

        RealtimePipe p5 = new RealtimePipe(() -> cfg);
        p5.start();
        // 参数污染
        p5.submit(b("GET /api/q?id=1&id=2 HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n\r\n"),
                resp("{}"), 1, true, new Object(), null);
        // 前端校验
        p5.submit(b("GET /profile HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n\r\n"),
                b("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                        + "<form><input name=\"age\" maxlength=\"2\" pattern=\"[0-9]+\"></form>"),
                1, true, new Object(), null);
        // 批量赋值线索（多字段）
        p5.submit(b("POST /api/profile/save HTTP/1.1\r\nHost: s.com\r\nCookie: a=1\r\n"
                        + "Content-Type: application/json\r\n\r\n"
                        + "{\"a\":1,\"b\":2,\"c\":3,\"d\":4,\"e\":5,\"f\":6,\"g\":7,\"h\":8,\"i\":9}"),
                resp("{}"), 1, true, new Object(), null);

        sleep(1200);
        List<PacketRecord> r5 = p5.snapshot();
        java.util.Set<String> h5 = new java.util.LinkedHashSet<>();
        for (PacketRecord r : r5) {
            for (LocalRules.Issue i : r.issues) {
                h5.add(i.name);
            }
        }
        r5.forEach(r -> System.out.println("    " + r.path + "  →  " + r.issueSummary()));
        System.out.println();
        check("检出「参数重复线索」", h5.stream().anyMatch(s -> s.contains("参数重复")));
        check("检出「前端校验线索」", h5.stream().anyMatch(s -> s.contains("前端校验")));
        check("检出「多字段提交线索」", h5.stream().anyMatch(s -> s.contains("多字段提交")));
        p5.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 五、不误报验证");
        System.out.println("============================================================");

        RealtimePipe p6 = new RealtimePipe(() -> cfg);
        p6.start();
        // 一个规规矩矩的只读接口，重复调用多次
        for (int i = 0; i < 6; i++) {
            p6.submit(b("GET /api/product/list?page=" + i + " HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                    resp("{\"items\":[]}"), 1, true, new Object(), null);
        }
        // 静态资源不该有任何线索
        p6.submit(b("GET /static/app.js HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                b("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar a=1;"),
                1, true, new Object(), null);
        sleep(1000);
        List<PacketRecord> r6 = p6.snapshot();
        long withHints = r6.stream().filter(r -> r.issues.stream()
                .anyMatch(i -> i.name.contains("线索"))).count();
        r6.forEach(r -> System.out.println("    " + r.path + "  →  " + r.issueSummary()));
        System.out.println();
        check("只读的分页接口 + 静态资源不产生逻辑线索", withHints == 0);
        p6.stop();

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
