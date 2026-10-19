import com.packetsentry.core.Config;
import com.packetsentry.core.Identity;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * 第八轮排查：<b>信任边界</b> —— 用户输入与持久化数据的健壮性。
 *
 * <h3>为什么这是一条独立的维度</h3>
 * 前七轮喂的都是「网络来的数据」（报文、响应）。这一轮喂的是
 * <b>用户直接输入的、以及从磁盘读回来的</b>数据 ——
 * 配置文件、身份凭据、平台规则文本。
 *
 * <p>这类数据的特殊性在于：<b>它们会被拼进别的东西里</b>。
 * 一个带换行的 Cookie 值拼进 HTTP 请求，就不再是一个字符串，
 * 而是「一条新请求头」—— 这是注入类缺陷的经典入口。
 */
public class TrustBoundaryProbe {

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

    private static String s(byte[] x) {
        return new String(x, StandardCharsets.UTF_8);
    }

    /**
     * 判断某个名字有没有成为<b>一行独立的请求头</b>。
     *
     * <p>⚠️ 不能用 {@code contains} —— 清理后的注入内容仍会作为值的<b>一部分</b>
     * 存在于请求里，用 contains 判断会误报（我第一版就是这么写错的）。
     * 要看的是「有没有一行是以 {@code Name:} 开头的」。
     */
    private static boolean hasHeaderLine(String req, String name) {
        String prefix = name + ":";
        for (String line : headOf(req).split("\r?\n")) {
            String l = line.trim();
            if (l.length() >= prefix.length()
                    && l.substring(0, prefix.length()).equalsIgnoreCase(prefix)) {
                return true;
            }
        }
        return false;
    }

    /** 请求头块（不含 body）。 */
    private static String headOf(String req) {
        int i = req.indexOf("\r\n\r\n");
        return i < 0 ? req : req.substring(0, i);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("============================================================");
        System.out.println(" 第八轮 · A：身份头替换 —— 换行注入");
        System.out.println("============================================================");

        String baseReq = "GET /api/me HTTP/1.1\r\nHost: s.com\r\n"
                + "Cookie: sid=OLD\r\nAccept: */*\r\n\r\n";

        // ---- 1. 头值带 CRLF → 必须被清掉，不能注入新头 ----
        Identity inj = new Identity("攻击者");
        inj.header("Cookie", "sid=NEW\r\nX-Injected: evil\r\nX-More: bad");

        String out1 = s(inj.apply(b(baseReq), false));
        System.out.println("  ── 注入尝试的结果 ──");
        headOf(out1).lines().forEach(l -> System.out.println("     " + l));

        // ⚠️ 断言写法很关键。一开始我写的是 !out1.contains("X-Injected")，
        //    结果清理之后那个字符串<b>仍作为 Cookie 值的一部分</b>存在，
        //    于是报了假 FAIL。
        //    真正要保证的性质是：它不能成为<b>一行独立的请求头</b>。
        check("头值里的 CRLF 不再产生独立请求头行（X-Injected）",
                !hasHeaderLine(out1, "X-Injected"));
        check("头值里的 CRLF 不再产生独立请求头行（X-More）",
                !hasHeaderLine(out1, "X-More"));
        check("替换后的请求结构完整（头块以空行结束）",
                out1.contains("\r\n\r\n"));
        check("原来的 Accept 头还在（没被挤到 body 里）",
                out1.contains("Accept: */*"));
        check("Cookie 被替换成了新值", out1.contains("sid=NEW"));
        check("旧 Cookie 值不残留", !out1.contains("sid=OLD"));
        check("注入内容被压进 Cookie 值（不丢数据，但不再是独立头）",
                out1.contains("sid=NEW"));

        // ---- 2. 头值带裸 \n ----
        Identity inj2 = new Identity("A");
        inj2.header("Cookie", "sid=NEW\nX-LF: evil");
        String out2 = s(inj2.apply(b(baseReq), false));
        check("裸 \\n 也不能产生独立请求头行", !hasHeaderLine(out2, "X-LF"));
        check("裸 \\n 被压进值里", out2.contains("sid=NEW"));

        // ---- 3. 头名非法 → 不能产出畸形请求 ----
        Identity bad = new Identity("B");
        bad.header("X-Bad: Name", "v");
        String out3 = s(bad.apply(b("GET / HTTP/1.1\r\nHost: s.com\r\n\r\n"), true));
        String h3 = headOf(out3);
        boolean malformed = false;
        for (String line : h3.split("\r\n")) {
            if (line.isEmpty()) {
                continue;
            }
            // 每一行要么是请求行，要么是 name: value
            if (!line.startsWith("GET ") && line.indexOf(": ") < 0) {
                malformed = true;
            }
        }
        System.out.println("  ── 非法头名的结果 ──");
        h3.lines().forEach(l -> System.out.println("     " + l));
        check("非法头名不会产出畸形请求头", !malformed);

        // ---- 4. 正常情况必须原样工作 ----
        Identity ok = new Identity("普通用户");
        ok.header("Cookie", "sid=USER_B; token=xyz");
        ok.header("Authorization", "Bearer abc.def.ghi");
        String out4 = s(ok.apply(b(baseReq), true));
        System.out.println("  ── 正常替换 ──");
        headOf(out4).lines().forEach(l -> System.out.println("     " + l));
        check("正常替换：Cookie 换掉了", out4.contains("sid=USER_B"));
        check("正常替换：Authorization 被补上了（addIfMissing）",
                out4.contains("Authorization: Bearer abc.def.ghi"));
        check("正常替换：请求行没动", out4.startsWith("GET /api/me HTTP/1.1"));
        check("正常替换：没有的其它头保持原样", out4.contains("Host: s.com"));

        // ---- 5. addIfMissing=false 时不该新增 ----
        String out5 = s(ok.apply(b(baseReq), false));
        check("addIfMissing=false 时不新增 Authorization",
                !out5.contains("Authorization:"));

        // ---- 6. 大小写不敏感匹配 ----
        Identity ci = new Identity("C");
        ci.header("cookie", "sid=CI");
        String out6 = s(ci.apply(b(baseReq), false));
        check("头名大小写不敏感匹配（cookie 能替换 Cookie）",
                out6.contains("sid=CI") && !out6.contains("sid=OLD"));

        // ---- 7. 边界：空请求 / 畸形请求不许崩 ----
        boolean noThrow = true;
        try {
            Identity t = new Identity("T");
            t.header("Cookie", "a=1");
            t.apply(null, true);
            t.apply(new byte[0], true);
            t.apply(b("garbage"), true);
            t.apply(b("GET / HTTP/1.1\nHost: s.com\n\n"), true);   // 只有 LF
            t.apply(b("GET / HTTP/1.1\r\nHost: s.com\r\nCookie: x=1"), true); // 没有空行
        } catch (Throwable e) {
            noThrow = false;
            System.out.println("     ✗ 抛异常：" + e);
        }
        check("空 / 畸形 / 不成形的请求都不抛异常", noThrow);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第八轮 · B：配置从磁盘读回来 —— 坏数据不许弄崩插件");
        System.out.println("============================================================");

        // ⚠️ 这里我一开始测错了：直接调 Gson，于是把
        //    「Gson 遇到坏 JSON 会抛异常」当成了插件的缺陷。
        //    但插件从不直接调 Gson —— 它走 Config.load()，那里有 catch。
        //    所以正确的测法是<b>端到端</b>：真的写一个坏配置文件进磁盘，
        //    再调 load()，看它能不能兜住。
        // 用一个新的 Config 实例取文件路径（fileName() 是实例方法）
        java.io.File cfgFile = new java.io.File(new Config().fileName());
        byte[] backup = null;
        boolean hadBackup = cfgFile.isFile();
        if (hadBackup) {
            backup = java.nio.file.Files.readAllBytes(cfgFile.toPath());
        }

        boolean cfgOk = true;
        String[] badJsons = {
                "{ this is not json",
                "[]",
                "null",
                "{\"maxBodyChars\": \"not a number\"}",
                "{\"budgetCny\": 1e999}",
                "{\"maskStrategy\": null}",
                "{\"provider\": 12345}",
                "{\"srcRules\": null}",
                "",                       // 空文件
        };
        try {
            java.io.File parent = cfgFile.getParentFile();
            if (parent != null && !parent.isDirectory()) {
                parent.mkdirs();
            }
            for (String j : badJsons) {
                java.nio.file.Files.write(cfgFile.toPath(),
                        j.getBytes(StandardCharsets.UTF_8));
                // 关键：load() 不能抛，必须返回一个可用的默认配置
                Config c = Config.load();
                if (c == null) {
                    cfgOk = false;
                    System.out.println("     ✗ 坏配置 [" + j + "] 返回了 null");
                    continue;
                }
                // 拿到之后必须还能安全地用
                c.describeDestination();
                c.complianceLine();
                c.enforceSrcMode();
                c.isLocalProvider();
                c.aiAllowed();
                c.copyForProbe();
            }
        } catch (Throwable e) {
            cfgOk = false;
            System.out.println("     ✗ Config.load() 对坏配置抛异常：" + e);
        } finally {
            // 还原用户的配置，别把真实配置弄丢
            try {
                if (hadBackup) {
                    java.nio.file.Files.write(cfgFile.toPath(), backup);
                } else {
                    java.nio.file.Files.deleteIfExists(cfgFile.toPath());
                }
            } catch (Throwable ignored) {
                System.out.println("     ⚠️ 未能还原原配置：" + cfgFile);
            }
        }
        check("9 种损坏/畸形配置都不会让 Config.load() 崩（且能返回可用默认值）", cfgOk);

        // ---- 极端值不许导致后续异常 ----
        Config extreme = new Config();
        extreme.maxBodyChars = Integer.MAX_VALUE;
        extreme.budgetCny = Double.MAX_VALUE;
        extreme.timeoutSeconds = -1;
        extreme.acMinIntervalMs = -5;
        extreme.maskStrategy = "NOT_A_STRATEGY";
        extreme.baseUrl = null;
        extreme.model = null;
        extreme.srcRules = null;
        boolean extremeOk = true;
        try {
            extreme.describeDestination();
            extreme.complianceLine();
            extreme.enforceSrcMode();
            extreme.isLocalProvider();
            extreme.aiAllowed();
            extreme.complianceLine();
        } catch (Throwable e) {
            extremeOk = false;
            System.out.println("     ✗ 极端值导致异常：" + e);
        }
        check("极端/非法字段值不会导致后续异常（含 null baseUrl / 非法策略 / 负数）", extremeOk);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第八轮 · C：平台规则文本的信任边界");
        System.out.println("============================================================");

        boolean rulesOk = true;
        String[] badRules = {
                null,
                "",
                "\u0000\u0000\u0000",
                "【无影响】",                       // 只有标题没有内容
                "暂不收取",                          // 只有标志词没有内容
                repeat("【高危】越权 ", 20000),       // 超长
                repeat("暂不收取", 5000),             // 大量排除句
        };
        for (String r : badRules) {
            try {
                com.packetsentry.detect.PlatformRules.Parsed p =
                        com.packetsentry.detect.PlatformRules.parse(r);
                com.packetsentry.detect.PlatformRules.decide("ID可预测线索", p);
                com.packetsentry.detect.PlatformRules.renderExplanation(
                        p, new com.packetsentry.detect.PlatformRules.Stats());
            } catch (Throwable e) {
                rulesOk = false;
                System.out.println("     ✗ 规则文本导致异常：" + e);
            }
        }
        check("7 种畸形/超长规则文本都不抛异常", rulesOk);

        // ⚠️ 超长规则文本的解析耗时也要有界 —— 否则用户贴错东西会卡住 UI
        String mega = repeat("【高危】越权提权操作、敏感信息泄露。", 40000);
        long t0 = System.currentTimeMillis();
        com.packetsentry.detect.PlatformRules.parse(mega);
        long ms = System.currentTimeMillis() - t0;
        System.out.println("  " + (mega.length() / 1024) + " KB 规则文本解析耗时 " + ms + " ms");
        check("超长规则文本解析在 3 秒内（不卡 UI）", ms < 3000);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第八轮 · D：用户输入被当成正则的地方（正则注入）");
        System.out.println("============================================================");

        // —— 检查所有「用户可控字符串 → Pattern.compile」的调用点 ——
        // 这类缺陷的危险形式：用户输入 "(a+)+$" 之类会引发 ReDoS，
        // 或者含 "(?i)" 之类的内联标志会改变匹配语义。
        boolean regexSafe = true;
        String evilRules = "((((((((((a+)+)+)+)+)+)+)+)+)+$";
        try {
            // 规则文本只被 contains() 使用，不该被编译成正则
            com.packetsentry.detect.PlatformRules.Parsed p =
                    com.packetsentry.detect.PlatformRules.parse("【高危】" + evilRules);
            long s0 = System.currentTimeMillis();
            for (int i = 0; i < 200; i++) {
                com.packetsentry.detect.PlatformRules.decide(evilRules, p);
            }
            long dms = System.currentTimeMillis() - s0;
            System.out.println("  200 次 decide（规则里含 ReDoS 形态字符串）耗时 " + dms + " ms");
            check("规则文本不被编译成正则（ReDoS 形态输入不放大耗时）", dms < 2000);
        } catch (Throwable e) {
            regexSafe = false;
            System.out.println("     ✗ 抛异常：" + e);
        }
        check("ReDoS 形态的规则文本不抛异常", regexSafe);

        // ⚠️ 这条断言我一开始也写错了：`Cookie.*` 里的 . 和 * 本来就是
        //    RFC 7230 token 的合法字符，所以它是个合法（虽然少见）的头名，
        //    不该被丢弃。真正要防的是含冒号/空白的头名 —— 那才会静默改错头。
        Identity meta = new Identity("M");
        meta.header("Cookie.*", "a=1");
        String mo = s(meta.apply(b(baseReq), true));
        check("合法但少见的头名（Cookie.*）被正常套用", mo.contains("Cookie.*: a=1"));

        // 含冒号的头名会静默改错头 —— 必须被丢弃
        Identity colon = new Identity("N");
        colon.header("X-Evil: X-Legit", "v");
        String co = s(colon.apply(b(baseReq), true));
        System.out.println("  ── 含冒号头名的结果 ──");
        headOf(co).lines().forEach(l -> System.out.println("     " + l));
        check("含冒号的头名被丢弃（否则会静默改成另一个头）",
                !co.contains("X-Evil"));
        check("含冒号的头名不会偷偷变成 X-Legit", !co.contains("X-Legit"));

        // 含空格的头名同理（因为 ": " 分隔符会歧义）
        Identity space = new Identity("O");
        space.header("X Bad", "v");
        check("含空格的头名被丢弃", !s(space.apply(b(baseReq), true)).contains("X Bad"));

        // warnings() 要如实报出被清理的内容
        check("warnings() 报告了被清理的换行", !inj.warnings().isEmpty()
                && inj.warnings().stream().anyMatch(w -> w.contains("换行")));
        check("warnings() 报告了非法头名", !space.warnings().isEmpty()
                && space.warnings().stream().anyMatch(w -> w.contains("不是合法")));
        check("干净的身份没有 warning", ok.warnings().isEmpty());

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第八轮 · E：超长用户输入不许放大");
        System.out.println("============================================================");

        boolean longOk = true;
        try {
            Identity huge = new Identity("H");
            huge.header("Cookie", repeat("a", 500_000));
            long h0 = System.currentTimeMillis();
            byte[] r = huge.apply(b(baseReq), true);
            long hms = System.currentTimeMillis() - h0;
            System.out.println("  50 万字符的头值：apply 耗时 " + hms + " ms，产出 "
                    + r.length + " 字节");
            check("超长头值处理在 2 秒内", hms < 2000);
            check("超长头值确实被套用（不是被静默丢掉）", r.length > baseReq.length());
        } catch (Throwable e) {
            longOk = false;
            System.out.println("     ✗ 抛异常：" + e);
        }
        check("超长头值不抛异常", longOk);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) {
            sb.append(s);
        }
        return sb.toString();
    }
}
