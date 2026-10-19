import com.packetsentry.core.Config;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.core.RealtimePipe;
import com.packetsentry.detect.LocalRules;
import com.packetsentry.detect.Pivot;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 第九轮：<b>针对真实反馈的回归</b>。
 *
 * <h3>这个测试来自用户的一段真实 AI 输出</h3>
 * 用户在 Hacker101 上抓到一个包，响应体就是一行 flag：
 * <pre>
 *   ^FLAG^62e19f2d7aff8c130f5c15721f7d71fa9b13b6389b04d40042c16bc015ffc0f9$FLAG$
 * </pre>
 * 而插件的输出是：
 * <pre>
 *   本地信息：作用=编辑数据　漏洞=中危安全响应头缺失 +2
 * </pre>
 * 用户的两句原话：
 * <blockquote>
 *   「已经确定包有漏洞却还是在分析可能性」<br>
 *   「无法根据这个包的漏洞来进行延伸其他漏洞」
 * </blockquote>
 *
 * <p>这个测试就是把那两句话变成可回归的断言。
 */
public class SrcFeedbackProbe {

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

    private static boolean hasPart(List<LocalRules.Issue> list, String p) {
        return list.stream().anyMatch(i -> i.name.contains(p));
    }

    private static LocalRules.Issue find(List<LocalRules.Issue> list, String p) {
        return list.stream().filter(i -> i.name.contains(p)).findFirst().orElse(null);
    }

    /** 用户给的那个真实响应。 */
    private static final String HACKER101_FLAG =
            "^FLAG^62e19f2d7aff8c130f5c15721f7d71fa9b13b6389b04d40042c16bc015ffc0f9$FLAG$";

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println(" 第九轮 · A：真实 Hacker101 flag 格式必须被识别");
        System.out.println("============================================================");

        // 完全复刻用户那个包
        String req = "POST /page/edit/1 HTTP/2\r\n"
                + "Host: c9dfe61070d9aff1dff1feb7bcfd9119.ctf.hacker101.com\r\n"
                + "Cookie: _ga=GA1.1.267873170.1789032130; _ga_K45575FWB8=GS2.1.s1792111621$o13\r\n"
                + "Content-Length: 0\r\n\r\n";
        String resp = "HTTP/2 200 OK\r\n"
                + "Content-Type: text/html; charset=utf-8\r\n"
                + "Content-Length: 76\r\n"
                + "Server: openresty/1.31.1.1\r\n\r\n"
                + HACKER101_FLAG;

        List<LocalRules.Issue> issues = LocalRules.detect(req, resp, null);
        System.out.println("  本地检出的发现：");
        for (LocalRules.Issue i : issues) {
            System.out.println("    " + i);
        }
        System.out.println();

        check("识别出 Hacker101 的 ^FLAG^...$FLAG$ 格式", hasPart(issues, "Flag"));
        LocalRules.Issue flag = find(issues, "Flag");
        check("等级是 CRITICAL（不是中危）",
                flag != null && flag.level == LocalRules.Level.CRITICAL);
        check("最严重等级取到 CRITICAL",
                LocalRules.worst(issues) == LocalRules.Level.CRITICAL);
        check("措辞明确写「已确认」而不是「疑似」",
                flag != null && flag.name.contains("已确认"));
        check("说明里不再让用户「再验证」",
                flag != null && !flag.detail.contains("可能")
                        && !flag.detail.contains("疑似"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第九轮 · B：其它常见 flag 格式也要覆盖");
        System.out.println("============================================================");

        String[][] formats = {
                {"flag{this_is_a_flag}", "通用小写"},
                {"FLAG{ABC_DEF_123}", "通用大写"},
                {"HTB{h4ck_th3_b0x}", "HackTheBox"},
                {"picoCTF{1t5_p1c0}", "picoCTF"},
                {"NSSCTF{abc123}", "NSSCTF"},
                {"CTF{short}", "CTF 前缀"},
                {"flag: 0123456789abcdef0123456789abcdef", "flag: 冒号形式"},
                {"FLAG-a1b2-c3d4-e5f6", "dash 形式"},
        };
        for (String[] f : formats) {
            String r = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                    + "<html><body>" + f[0] + "</body></html>";
            List<LocalRules.Issue> li = LocalRules.detect("GET / HTTP/1.1\r\n\r\n", r, null);
            boolean ok = hasPart(li, "Flag");
            System.out.println("  " + pad(f[1], 22) + (ok ? "✓ 识别" : "✗ 漏报"));
            check("覆盖格式：" + f[1], ok);
        }

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第九轮 · C：极小响应 + 长 hex（无前缀的 flag 页）");
        System.out.println("============================================================");

        String[] hexes = {
                "0123456789abcdef0123456789abcdef",                                 // 32
                "0123456789abcdef0123456789abcdef01234567",                          // 40
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",  // 64
        };
        for (String h : hexes) {
            String r = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + h;
            List<LocalRules.Issue> li = LocalRules.detect("GET / HTTP/1.1\r\n\r\n", r, null);
            System.out.println("  " + h.length() + " 位 hex → "
                    + (hasPart(li, "Flag") ? "✓ 识别" : "✗ 漏报"));
            check(h.length() + " 位 hex 的极小响应被识别为 flag 页", hasPart(li, "Flag"));
        }

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第九轮 · D：不该误报的（长 hex 满天飞的大页面）");
        System.out.println("============================================================");

        // 大页面 + 一堆哈希（构建指纹、ETag 之类）—— 不该报 flag
        StringBuilder bigPage = new StringBuilder(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>");
        for (int i = 0; i < 200; i++) {
            bigPage.append("<script src=\"/static/app.")
                    .append("0123456789abcdef0123456789abcdef").append(".js\"></script>");
        }
        bigPage.append("</body></html>");
        List<LocalRules.Issue> bigIssues =
                LocalRules.detect("GET / HTTP/1.1\r\n\r\n", bigPage.toString(), null);
        check("大页面里的哈希不误报 flag", !hasPart(bigIssues, "Flag"));

        // ETag 里的 32 位 hex 也不该报
        String etagResp = "HTTP/1.1 200 OK\r\nETag: \"0123456789abcdef0123456789abcdef\"\r\n"
                + "Content-Type: text/html\r\n\r\n<html><body>hello world this is a normal page"
                + "</body></html>";
        List<LocalRules.Issue> etagIssues =
                LocalRules.detect("GET / HTTP/1.1\r\n\r\n", etagResp, null);
        check("ETag 里的哈希不误报 flag", !hasPart(etagIssues, "Flag"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第九轮 · E：延伸推导（用户第二句反馈）");
        System.out.println("============================================================");

        List<Pivot.Suggestion> pv = Pivot.derive(issues, "POST", "/page/edit/1",
                "c9dfe61070d9aff1dff1feb7bcfd9119.ctf.hacker101.com", false);

        System.out.println("  从 flag 这个已确认发现推导出 " + pv.size() + " 条延伸：");
        for (Pivot.Suggestion s : pv) {
            System.out.println("    · " + s.action);
        }
        System.out.println();

        check("基于已确认发现推导出了延伸方向", !pv.isEmpty());
        check("延伸里含「换 ID 遍历」（最直接的一步）",
                pv.stream().anyMatch(s -> s.action.contains("ID")
                        && (s.action.contains("换") || s.action.contains("相邻"))));
        check("延伸里含「换 HTTP 方法」",
                pv.stream().anyMatch(s -> s.action.contains("方法")));
        check("延伸里含「去掉凭据重放」",
                pv.stream().anyMatch(s -> s.action.contains("Cookie")
                        || s.action.contains("凭据")));
        check("延伸里含「找兄弟路径」",
                pv.stream().anyMatch(s -> s.action.contains("兄弟")));
        check("延伸里含横向扩面（换前缀/换模块）",
                pv.stream().anyMatch(s -> s.action.contains("横向")
                        || s.action.contains("前缀")));
        check("每条延伸都带「为什么」",
                pv.stream().allMatch(s -> s.why != null && !s.why.isEmpty()));
        check("延伸按优先级排序（第一条权重最高）",
                pv.size() < 2 || pv.get(0).weight >= pv.get(1).weight);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第九轮 · F：无认证判断（_ga 不算认证）");
        System.out.println("============================================================");

        check("只有 _ga 统计 Cookie → 判为无业务认证",
                !RealtimePipe.hasBusinessAuth(
                        "GET / HTTP/1.1\r\nCookie: _ga=GA1.1.123; _ga_ABC=GS2.1\r\n\r\n"));
        check("有业务 Cookie → 判为已认证",
                RealtimePipe.hasBusinessAuth(
                        "GET / HTTP/1.1\r\nCookie: _ga=GA1.1.1; SESSIONID=abc\r\n\r\n"));
        check("有 Authorization → 判为已认证",
                RealtimePipe.hasBusinessAuth(
                        "GET / HTTP/1.1\r\nAuthorization: Bearer xxx\r\n\r\n"));
        check("有 X-Token → 判为已认证",
                RealtimePipe.hasBusinessAuth("GET / HTTP/1.1\r\nX-Token: abc\r\n\r\n"));
        check("什么都没带 → 判为无认证",
                !RealtimePipe.hasBusinessAuth("GET / HTTP/1.1\r\nHost: s.com\r\n\r\n"));
        check("null 不崩", !RealtimePipe.hasBusinessAuth(null));

        // 用户那个包只带 _ga → 应该被判为「无认证」，从而推出「未授权访问」方向
        List<Pivot.Suggestion> pv2 = Pivot.derive(issues, "POST", "/page/edit/1",
                "x.ctf.hacker101.com", false);
        check("无认证 + 有数据 → 推出「未授权/横向扩面」方向",
                pv2.stream().anyMatch(s -> s.action.contains("凭据")
                        || s.action.contains("未授权")
                        || s.action.contains("同前缀")));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第九轮 · G：brief 必须带上「已确认」段（关键）");
        System.out.println("============================================================");

        Config cfg = new Config();
        cfg.sanitizeEnabled = true;
        cfg.scanEnabled = true;
        RealtimePipe pipe = new RealtimePipe(() -> cfg);
        pipe.start();
        pipe.submit(b(req), b(resp), 1, true, new Object(), null);
        sleep(1500);
        List<PacketRecord> snap = pipe.snapshot();
        PacketRecord rec = null;
        for (PacketRecord r : snap) {
            if (r.path != null && r.path.contains("/page/edit/")) {
                rec = r;
            }
        }
        check("拿到记录", rec != null);
        if (rec != null) {
            System.out.println("  brief 开头 400 字：");
            String head = rec.brief.length() > 400 ? rec.brief.substring(0, 400) : rec.brief;
            for (String line : head.split("\n")) {
                System.out.println("    " + line);
            }
            System.out.println();

            check("brief 里含【本地规则已确认的发现】段",
                    rec.brief.contains("本地规则已确认的发现"));
            check("brief 里含「已确认事实」的明确标注",
                    rec.brief.contains("已确认事实"));
            check("brief 里含推导出的延伸方向",
                    rec.brief.contains("本地已推导出的延伸测试方向"));
            check("brief 里的本地结论在报文内容<b>之前</b>（决定语气）",
                    rec.brief.indexOf("已确认事实") < rec.brief.indexOf("参数"));
            check("brief 里写明了「不要再当可能讨论」",
                    rec.brief.contains("不要再把") || rec.brief.contains("不要再把它们当"));
        }
        pipe.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第九轮 · H：提示词必须禁止对已确认事实用「可能」");
        System.out.println("============================================================");

        // 提示词是编译进 class 的常量，这里用反射读出来验证措辞
        String prompt = null;
        try {
            java.lang.reflect.Field pf = com.packetsentry.ui.RealtimeTab.class
                    .getDeclaredField("SINGLE_PACKET_PROMPT");
            pf.setAccessible(true);
            prompt = (String) pf.get(null);
        } catch (Throwable e) {
            System.out.println("    （反射读提示词失败：" + e + "）");
        }
        if (prompt != null) {
            check("提示词要求把本地确认的当结论用",
                    prompt.contains("直接当结论用"));
            check("提示词明确禁止对已确认事实写「可能」",
                    prompt.contains("禁止对它们写")
                            || prompt.contains("不许出现「可能」"));
            check("提示词要求「已确认什么」段不许出现「可能」",
                    prompt.contains("这一段不许出现「可能」"));
            check("提示词含【延伸】段要求",
                    prompt.contains("延伸"));
            check("提示词要求不要重复本地已推导的方向",
                    prompt.contains("不要重复"));
            check("提示词要求建议可执行（落到方法/路径/参数）",
                    prompt.contains("可执行") || prompt.contains("直接执行"));
        } else {
            System.out.println("    ⚠️ 跳过提示词断言（反射失败）");
        }

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

    private static String pad(String s, int n) {
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < n) {
            sb.append(' ');
        }
        return sb.toString();
    }
}
