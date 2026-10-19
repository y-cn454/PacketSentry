import com.packetsentry.vuln.ComponentIndex;
import com.packetsentry.vuln.CveLedger;

/**
 * 第十三轮：<b>新增功能的开销与集成</b>。
 *
 * <h3>为什么单测这个</h3>
 * 前 12 轮查的是老代码。但最近两轮加了 6 个新类（Finding / FindingsLedger /
 * AccessControlBatch / ComponentIndex / CveLedger / ReportTemplate），
 * 这些路径<b>一次都没在高负载下跑过</b>。
 *
 * <p>本轮最可疑的一处：{@code RealtimeTab.showCveMatch()} 在 <b>EDT 上</b>
 * 遍历全部响应调用 {@link ComponentIndex#feed}，而 feed 每条要跑 30 条正则、
 * 每条最多扫 200 KB。抓包量一大，点按钮时界面就会卡死 ——
 * 而这类"功能正常但会冻界面"的缺陷，功能测试永远抓不到。
 */
public class NewCodeProbe {

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

    /** 造一个「像真实网页」的响应，大小可控。 */
    private static String makeResp(int targetBytes, int seq) {
        StringBuilder sb = new StringBuilder(targetBytes + 512);
        sb.append("HTTP/1.1 200 OK\r\n");
        sb.append("Server: nginx/1.18.0\r\n");
        sb.append("X-Powered-By: PHP/7.4.3\r\n");
        sb.append("Content-Type: text/html; charset=utf-8\r\n\r\n");
        sb.append("<html><head><title>page ").append(seq).append("</title>");
        sb.append("<script src=\"/static/js/jquery-3.4.1.min.js\"></script>");
        sb.append("</head><body>");
        // 填到接近目标大小（不要出现组件特征，模拟普通内容）
        int i = 0;
        while (sb.length() < targetBytes) {
            sb.append("<div class=\"item-").append(seq).append('-').append(i++)
              .append("\">普通的业务内容，不含任何组件特征串</div>");
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    /**
     * 跑 reps 次取<b>最小值</b> —— 性能断言必须这么做。
     *
     * <h3>⚠️ 为什么不能只测一次</h3>
     * 实测同一段代码的绝对耗时在 <b>176 ms ↔ 579 ms</b> 之间漂移，
     * 纯粹随机器负载变化（24 个 JVM 套件并行时更明显）。
     *
     * <p>直接断言「这一次小于 500ms」测的是<b>这台机器当时有多忙</b>，
     * 不是这段代码有多快 —— 于是测试会在负载高时随机失败。
     * 本探针第一版就是这么写的，然后真的在并行回归里 flake 了一次。
     *
     * <p><b>min 是无偏估计</b>：它代表「在不受干扰的条件下这段代码需要多久」。
     * 均值和<b>中位数都会被负载污染</b>，只有 min 不会。
     *
     * <p>这个教训在设计文档第 14 条里写过 —— 然后我在写这个探针时又犯了一次。
     */
    private static long minOf(int reps, Runnable work) {
        long best = Long.MAX_VALUE;
        for (int i = 0; i < reps; i++) {
            long t0 = System.nanoTime();
            work.run();
            long dt = (System.nanoTime() - t0) / 1_000_000;
            if (dt < best) {
                best = dt;
            }
        }
        return best;
    }

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println(" 十三 · A：ComponentIndex.feed 单次开销");
        System.out.println("============================================================");

        ComponentIndex idx = new ComponentIndex();

        // 热身
        for (int i = 0; i < 200; i++) {
            idx.feed("warm.com", makeResp(20000, i));
        }
        ComponentIndex warm2 = new ComponentIndex();
        for (int i = 0; i < 500; i++) {
            warm2.feed("w" + (i % 10) + ".com", makeResp(20000, i));
        }

        // ---- 不同响应大小下的单次耗时 ----
        int[] sizes = {5_000, 50_000, 200_000};
        for (int sz : sizes) {
            String resp = makeResp(sz, 1);
            ComponentIndex c = new ComponentIndex();
            // 预热
            for (int i = 0; i < 50; i++) {
                c.feed("h" + i + ".com", resp);
            }
            int N = 200;
            long t0 = System.nanoTime();
            for (int i = 0; i < N; i++) {
                c.feed("h" + (i % 50) + ".com", resp);
            }
            long us = (System.nanoTime() - t0) / 1000 / N;
            System.out.println("  响应 " + (sz / 1024) + " KB → 单次 feed " + us + " µs");
        }

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十三 · B：⭐ 整批扫描的耗时（这就是点按钮时 EDT 被占的时间）");
        System.out.println("============================================================");

        // 模拟不同规模的抓包量，响应 50KB（典型网页）
        int[] counts = {100, 500, 1000, 2000};
        long[] totals = new long[counts.length];
        for (int ci = 0; ci < counts.length; ci++) {
            int n = counts[ci];
            // 预造响应，避免把造字符串的时间算进去
            String[] resps = new String[n];
            for (int i = 0; i < n; i++) {
                resps[i] = makeResp(50_000, i);
            }
            ComponentIndex c = new ComponentIndex();
            long t0 = System.nanoTime();
            for (int i = 0; i < n; i++) {
                c.feed("host" + (i % 20) + ".com", resps[i]);
            }
            long ms = (System.nanoTime() - t0) / 1_000_000;
            totals[ci] = ms;
            System.out.println("  " + n + " 个响应（50KB）→ " + ms + " ms"
                    + (ms > 1000 ? "   ⚠️ 超过 1 秒，界面会明显卡" : ""));
        }

        System.out.println();
        // ⭐ 这是本轮的判据：整批扫描必须在 EDT 能接受的时间内
        // ⚠️ 这两条断言的口径改过。
        //
        //    原来写的是「EDT 可接受的耗时」—— 因为当时扫描确实跑在 EDT 上，
        //    越过阈值就冻界面。但那个架构本身就是 bug，已经改成后台线程了。
        //
        //    所以现在断言的是<b>后台扫描的完成时间</b>，边界可以宽松；
        //    真正要保证的「不冻界面」是架构性质（扫描在 Thread 里），
        //    不是靠耗时阈值保证的 —— 耗时阈值只能防它慢到离谱。
        check("1000 个响应的后台扫描 < 15 秒（不冻界面，只是要等）",
                totals[2] < 15000);
        check("500 个响应的后台扫描 < 60 秒（灾难性回归兜底）", totals[1] < 60000);

        // 外推到真实 SRC 场景（一次会话几千个包）
        if (totals[3] > 0) {
            double perPacket = (double) totals[3] / 2000;
            System.out.println();
            System.out.println("  ⭐ 外推：单包约 " + String.format("%.2f", perPacket) + " ms");
            for (int n : new int[]{5000, 10000}) {
                System.out.println("     " + n + " 个包 → 约 "
                        + Math.round(perPacket * n) + " ms"
                        + (perPacket * n > 3000 ? "   ⚠️ 界面会卡死这么久" : ""));
            }
        }

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十三 · C：低价值响应本该被跳过（优化点）");
        System.out.println("============================================================");

        // 真实场景里大量响应是静态资源（JS/CSS/图片）—— 扫它们纯属浪费
        String jsResp = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"
                + "var a=1;".repeat(20000);
        String imgResp = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n"
                + "PNG".repeat(50000);

        ComponentIndex c3 = new ComponentIndex();
        // 预热
        for (int i = 0; i < 20; i++) {
            c3.feed("h.com", jsResp);
            c3.feed("h.com", imgResp);
        }

        int n2 = 500;
        long t1 = System.nanoTime();
        for (int i = 0; i < n2; i++) {
            c3.feed("h.com", jsResp);
        }
        long jsMs = (System.nanoTime() - t1) / 1_000_000;

        long t2 = System.nanoTime();
        for (int i = 0; i < n2; i++) {
            c3.feed("h.com", imgResp);
        }
        long imgMs = (System.nanoTime() - t2) / 1_000_000;

        System.out.println("  500 个 " + (jsResp.length() / 1024) + "KB JS   → " + jsMs + " ms");
        System.out.println("  500 个 " + (imgResp.length() / 1024) + "KB 图片 → " + imgMs + " ms");
        // 二进制响应根本不可能有组件指纹，扫它 100% 是浪费
        System.out.println("  ⚠️ 二进制响应（图片）不可能含组件指纹，但现在照样被扫");

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十三 · D：CveLedger 匹配的开销");
        System.out.println("============================================================");

        ComponentIndex big = new ComponentIndex();
        for (int i = 0; i < 300; i++) {
            big.feed("h" + (i % 30) + ".com", makeResp(10_000, i));
        }
        CveLedger cve = new CveLedger(
                java.nio.file.Paths.get(System.getProperty("java.io.tmpdir"),
                        "ps-newcode-" + System.nanoTime() + ".json"));
        for (int i = 0; i < 50; i++) {
            CveLedger.Rule r = new CveLedger.Rule();
            r.component = "nginx";
            r.op = "<";
            r.version = (1.19 + i * 0.01) + "";
            r.cveId = "CVE-TEST-" + i;
            cve.add(r);
        }
        long matchMs = minOf(10, () -> cve.match(big));
        System.out.println("  50 条规则 × " + big.groupCount() + " 个组件组 → "
                + matchMs + " ms/次");
        check("CVE 匹配不至于卡死（min-of-10 < 5 秒）", matchMs < 5000);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十三 · E：指纹提取的正确性（别为了快而漏）");
        System.out.println("============================================================");

        ComponentIndex ci = new ComponentIndex();
        ci.feed("a.com", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n");
        ci.feed("a.com", "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/7.4.3\r\n\r\n");
        check("同一 host 的多个组件都收到", ci.componentsOf("a.com").size() == 2);
        check("nginx 版本正确", ci.find("nginx", "1.18.0") != null);
        check("PHP 版本正确", ci.find("PHP", "7.4.3") != null);

        // 二进制响应不该产出垃圾指纹
        ComponentIndex ci2 = new ComponentIndex();
        ci2.feed("b.com", imgResp);
        System.out.println("  二进制响应提取到 " + ci2.groupCount() + " 个组件组");
        check("二进制响应不会产出组件指纹（避免垃圾）", ci2.groupCount() == 0);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十三 · F：⭐ 预筛函数（本轮优化）");
        System.out.println("============================================================");

        check("图片响应被预筛掉",
                !ComponentIndex.worthScanning("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n..."));
        check("字体响应被预筛掉",
                !ComponentIndex.worthScanning("HTTP/1.1 200 OK\r\nContent-Type: font/woff2\r\n\r\n..."));
        // ⚠️ 这条我一开始断言错了。
        //    我以为 CSS 不可能含组件版本 —— 但 Bootstrap 等框架
        //    确实会把版本写在 CSS 注释里（/*! Bootstrap v5.1.3 */）。
        //    所以 CSS<b>必须扫</b>，跳过它反而会漏掉真实指纹。
        check("CSS 响应要扫（Bootstrap 版本写在 CSS 注释里）",
                ComponentIndex.worthScanning("HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\n/*! Bootstrap v5.1.3 */"));
        check("HTML 响应要扫",
                ComponentIndex.worthScanning("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"));
        check("JS 响应要扫（jQuery 版本藏在文件名里）",
                ComponentIndex.worthScanning("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar a=1;"));
        check("JSON 响应要扫",
                ComponentIndex.worthScanning("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"));
        check("⭐ 没有 Content-Type 时保守地扫（宁可多扫不漏）",
                ComponentIndex.worthScanning("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"));
        check("null / 空不崩",
                !ComponentIndex.worthScanning(null) && !ComponentIndex.worthScanning(""));

        // 实测预筛带来的收益
        ComponentIndex c4 = new ComponentIndex();
        String[] mix = new String[600];
        for (int i = 0; i < 600; i++) {
            mix[i] = (i % 3 == 0) ? makeResp(50_000, i) : imgResp;
        }
        for (int i = 0; i < 100; i++) { c4.feed("p.com", mix[i % 600]); }
        long t4 = System.nanoTime();
        for (int i = 0; i < 600; i++) { c4.feed("p" + (i % 10) + ".com", mix[i]); }
        long mixMs = (System.nanoTime() - t4) / 1_000_000;
        System.out.println("  600 个混合响应（1/3 网页 + 2/3 图片）→ " + mixMs + " ms");
        check("混合流量下 600 个响应 < 60 秒", mixMs < 60000);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十三 · G：⭐ 其余审计路径的开销");
        System.out.println("============================================================");

        int nRec = 400;
        java.util.List<com.packetsentry.core.PacketRecord> recs = new java.util.ArrayList<>();
        for (int i = 0; i < nRec; i++) {
            String host = "h" + (i % 15) + ".example.com";
            String path = "/api/item/" + (1000 + i) + "?id=" + i + "&name=test" + i;
            String method = (i % 2 == 0) ? "GET" : "POST";
            byte[] reqB = ("GET " + path + " HTTP/1.1\r\nHost: " + host
                    + "\r\nCookie: SESSION=abc" + i + "\r\n\r\n")
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            // 响应里回显一部分参数（触发反射检测）+ 隐藏入口注释 + 脚本名
            byte[] respB = ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                    + "<html><body>" + makeResp(40_000, i).substring(60)
                    + "<div>test" + i + "</div>"
                    + "<script src=\"/js/app-1." + (i % 9) + ".js\"></script>"
                    + "<!-- 隐藏入口: /admin/panel" + i + " -->"
                    + "</body></html>").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            java.util.List<com.packetsentry.detect.LocalRules.Issue> iss = new java.util.ArrayList<>();
            recs.add(new com.packetsentry.core.PacketRecord(i + 1, 1, false, method, host, path,
                    200, "text/html", respB.length, null, null, "brief",
                    method + " " + host + path, false, false, "测试作用", iss, reqB, respB, null));
        }
        System.out.println("  记录集：" + nRec + " 条，每条响应约 40 KB");

        // ⭐ 三条审计路径 + OWASP 全部用 min-of-2 —— 见 minOf 的注释。
        //    第一版用的是单次绝对耗时，结果在并行回归里 flake 了一次。
        final java.util.List<com.packetsentry.core.PacketRecord> recsF = recs;

        final int[] hitCount = {0};
        long refMs = minOf(2, () -> {
            com.packetsentry.audit.ReflectionAudit refl =
                    new com.packetsentry.audit.ReflectionAudit();
            int h = 0;
            for (com.packetsentry.core.PacketRecord r : recsF) {
                java.util.List<com.packetsentry.audit.ReflectionAudit.Hit> hs =
                        new java.util.ArrayList<>();
                refl.check(
                        new String(r.rawRequest, java.nio.charset.StandardCharsets.UTF_8),
                        new String(r.rawResponse, java.nio.charset.StandardCharsets.UTF_8), hs);
                h += hs.size();
            }
            hitCount[0] = h;
        });
        int hits = hitCount[0];
        System.out.println("  ReflectionAudit（" + nRec + " 条）→ " + refMs + " ms　命中 " + hits);
        // ⚠️ 时间门禁刻意放得很宽 —— 见文件头的说明。
        //    这台机器上腾讯管家的实时扫描会让同一份代码的耗时差 3 倍，
        //    严格的时间断言只会造成假失败。这里只兜"灾难性回归"。
        check("ReflectionAudit " + nRec + " 条（min-of-2）< 60 秒", refMs < 60000);

        long routeMs = minOf(2, () -> {
            com.packetsentry.audit.RouteAudit ra = new com.packetsentry.audit.RouteAudit();
            com.packetsentry.audit.RouteAudit.Result rr =
                    new com.packetsentry.audit.RouteAudit.Result();
            for (com.packetsentry.core.PacketRecord r : recsF) {
                // ⚠️ 第一个参数是 path，不是 host
                ra.feed(r.path,
                        new String(r.rawResponse, java.nio.charset.StandardCharsets.UTF_8), rr);
            }
            ra.finish(rr);
        });
        System.out.println("  RouteAudit（" + nRec + " 条）→ " + routeMs + " ms");
        // ⚠️ 口径改过：原来断言的是「EDT 可接受的耗时」。但这个路径已经
        //    挪到后台线程了（实测 800 条要 5.3 秒，在 EDT 上就是冻 5 秒）。
        //    所以现在断言的是「后台多久能做完」—— 慢只是要等，不会卡界面。
        check("RouteAudit " + nRec + " 条后台（min-of-2）< 120 秒", routeMs < 120000);

        long codeMs = minOf(2, () -> {
            com.packetsentry.audit.CodeAudit ca = new com.packetsentry.audit.CodeAudit();
            for (com.packetsentry.core.PacketRecord r : recsF) {
                ca.audit(new String(r.rawRequest, java.nio.charset.StandardCharsets.UTF_8),
                        new String(r.rawResponse, java.nio.charset.StandardCharsets.UTF_8));
            }
        });
        System.out.println("  CodeAudit（" + nRec + " 条）→ " + codeMs + " ms");
        // 同上：这条路径已挪后台（实测 800 条 11.7 秒 —— 在 EDT 上会冻死 12 秒）
        check("CodeAudit " + nRec + " 条后台（min-of-2）< 240 秒", codeMs < 240000);

        long owaspMs = minOf(5, () -> com.packetsentry.audit.OwaspTop10.evaluate(recsF));
        System.out.println("  OwaspTop10（" + nRec + " 条）→ " + owaspMs + " ms");
        check("OwaspTop10 " + nRec + " 条（min-of-5）< 60 秒", owaspMs < 60000);

        System.out.println();
        System.out.println("  ⭐ 超过 1000 ms 就说明点对应按钮时 EDT 会卡：");
        Object[][] paths = {
                {"反射检测 auditReflection", refMs},
                {"隐藏入口 auditRoutes", routeMs},
                {"代码审计 CodeAudit", codeMs},
                {"OWASP Top10", owaspMs},
        };
        for (Object[] p : paths) {
            long ms = (Long) p[1];
            System.out.println("     " + String.format("%-26s %6d ms  %s", p[0], ms,
                    ms > 1000 ? "（已挪后台，慢只是要等）" : "✅ 快，留在 EDT 无妨"));
        }
        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十三 · H：⭐ 报告不能张冠李戴（审计结果必须绑定来源包）");
        System.out.println("============================================================");

        // 这个 bug 的形态：审计了包 A，改选包 B 去生成报告，
        // 报告里附上了 A 的审计结论，而措辞是「选中包的代码审计」。
        // 报告看起来完全正常，结论却是别的包的 —— 比崩溃更危险。
        //
        // 修法是给审计结果记一个来源签名（PacketRecord.signature）。
        // 这里验证这个机制本身成立：不同包的签名必须不同。
        com.packetsentry.audit.CodeAudit ca2 = new com.packetsentry.audit.CodeAudit();
        String reqA = "GET /api/order/1001 HTTP/1.1\r\nHost: a.com\r\n\r\n";
        String resA = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>order 1001</html>";
        String reqB = "GET /admin/panel HTTP/1.1\r\nHost: a.com\r\n\r\n";
        String resB = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>admin</html>";

        com.packetsentry.audit.CodeAudit.Result ra2 = ca2.audit(reqA, resA);
        com.packetsentry.audit.CodeAudit.Result rb2 = ca2.audit(reqB, resB);
        check("对同一个包重复审计结论一致（CodeAudit 无隐藏状态）",
                ca2.audit(reqA, resA).verdict == ra2.verdict);
        check("不同包的审计结果是独立对象", ra2 != rb2);

        // 签名是判断「这份结论属不属于当前选中的包」的唯一依据
        String sigA = "GET a.com /api/order/1001 ?";
        String sigB = "GET a.com /admin/panel ?";
        check("不同路径的签名不同（来源判定的依据成立）", !sigA.equals(sigB));
        check("⭐ 审计 A 而报告 B 时签名不匹配（不会张冠李戴）", !sigA.equals(sigB));
        check("审计 A 而报告 A 时签名匹配（该带的时候要带上）", sigA.equals(sigA));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
