import com.packetsentry.audit.ReflectionAudit;

import java.util.ArrayList;
import java.util.List;

/**
 * 反射与上下文检测 实测。
 *
 * <h3>为什么这个功能必须测准</h3>
 * 它给用户的是「该用哪种注入形式」—— 用户会拿这个结论去手工验证 XSS。
 * 上下文判断错，就会让人用错形式、白试一轮，然后误判「没有 XSS」。
 *
 * <p>尤其 {@code <script>} 内外的区分很微妙：
 * 在 {@code <script>} 的<b>字符串里</b>和在<b>代码位置</b>，
 * 需要的 payload 完全不同（前者要闭合引号，后者不用）。
 * 所以这几组必须有正例和反例。
 */
public class ReflectionProbe {

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

    /** 跑一次检测，取第一个 hit。 */
    private static ReflectionAudit.Hit one(String req, String respRaw) {
        ReflectionAudit a = new ReflectionAudit();
        List<ReflectionAudit.Hit> out = new ArrayList<>();
        a.check(req, respRaw, out);
        return out.isEmpty() ? null : out.get(0);
    }

    private static String req(String pathAndQuery) {
        return "GET " + pathAndQuery + " HTTP/1.1\r\nHost: s.com\r\n\r\n";
    }

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println(" 一、上下文判定：每种上下文都要认对");
        System.out.println("============================================================");

        String v = "INJTEST99";

        // 1. HTML 文本
        ReflectionAudit.Hit h1 = one(req("/p?q=" + v),
                resp("text/html", "<html><body><div>" + v + "</div></body></html>"));
        System.out.println("  ① HTML 文本 → " + (h1 == null ? "无" : h1.context));
        check("HTML 文本上下文", h1 != null && h1.context == ReflectionAudit.Context.HTML_TEXT);

        // 2. 双引号属性内
        ReflectionAudit.Hit h2 = one(req("/p?q=" + v),
                resp("text/html", "<input value=\"" + v + "\">"));
        System.out.println("  ② 双引号属性 → " + (h2 == null ? "无" : h2.context));
        check("双引号属性上下文",
                h2 != null && h2.context == ReflectionAudit.Context.ATTR_DOUBLE);

        // 3. 单引号属性内
        ReflectionAudit.Hit h3 = one(req("/p?q=" + v),
                resp("text/html", "<input value='" + v + "'>"));
        check("单引号属性上下文",
                h3 != null && h3.context == ReflectionAudit.Context.ATTR_SINGLE);

        // 4. 无引号属性内
        ReflectionAudit.Hit h4 = one(req("/p?q=" + v),
                resp("text/html", "<a href=" + v + ">x</a>"));
        System.out.println("  ④ 无引号属性 → " + (h4 == null ? "无" : h4.context));
        check("无引号属性上下文",
                h4 != null && (h4.context == ReflectionAudit.Context.ATTR_UNQUOTED
                        || h4.context == ReflectionAudit.Context.URL_ATTR));

        // 5. URL 属性（带引号）
        ReflectionAudit.Hit h5 = one(req("/p?q=" + v),
                resp("text/html", "<a href=\"" + v + "\">x</a>"));
        System.out.println("  ⑤ URL 属性 → " + (h5 == null ? "无" : h5.context));
        check("URL 属性上下文",
                h5 != null && h5.context == ReflectionAudit.Context.URL_ATTR);

        // 6. script 块内 —— 代码位置（不在字符串里）
        ReflectionAudit.Hit h6 = one(req("/p?q=" + v),
                resp("text/html", "<script>var a=1;console.log(" + v + ");</script>"));
        System.out.println("  ⑥ script 块内（代码位置）→ " + (h6 == null ? "无" : h6.context));
        check("script 块内、字符串外",
                h6 != null && h6.context == ReflectionAudit.Context.SCRIPT_BLOCK);

        // 7. script 内 —— 双引号字符串
        ReflectionAudit.Hit h7 = one(req("/p?q=" + v),
                resp("text/html", "<script>var a=\"" + v + "\";</script>"));
        System.out.println("  ⑦ script 内双引号字符串 → " + (h7 == null ? "无" : h7.context));
        check("script 内、双引号字符串",
                h7 != null && h7.context == ReflectionAudit.Context.JS_STRING_DOUBLE);

        // 8. script 内 —— 单引号字符串
        ReflectionAudit.Hit h8 = one(req("/p?q=" + v),
                resp("text/html", "<script>var a='" + v + "';</script>"));
        check("script 内、单引号字符串",
                h8 != null && h8.context == ReflectionAudit.Context.JS_STRING_SINGLE);

        // 9. script 内 —— 模板字符串
        ReflectionAudit.Hit h9 = one(req("/p?q=" + v),
                resp("text/html", "<script>var a=`" + v + "`;</script>"));
        System.out.println("  ⑨ script 内模板字符串 → " + (h9 == null ? "无" : h9.context));
        check("script 内、模板字符串",
                h9 != null && h9.context == ReflectionAudit.Context.JS_TEMPLATE);

        // 10. 事件处理器内
        ReflectionAudit.Hit h10 = one(req("/p?q=" + v),
                resp("text/html", "<button onclick=\"go('" + v + "')\">x</button>"));
        System.out.println("  ⑩ 事件处理器 → " + (h10 == null ? "无" : h10.context));
        check("事件处理器上下文",
                h10 != null && h10.context == ReflectionAudit.Context.EVENT_HANDLER);

        // 11. HTML 注释内
        ReflectionAudit.Hit h11 = one(req("/p?q=" + v),
                resp("text/html", "<html><!-- debug: " + v + " --></html>"));
        System.out.println("  ⑪ HTML 注释 → " + (h11 == null ? "无" : h11.context));
        check("HTML 注释上下文",
                h11 != null && h11.context == ReflectionAudit.Context.HTML_COMMENT);

        // 12. style 块内
        ReflectionAudit.Hit h12 = one(req("/p?q=" + v),
                resp("text/html", "<style>.a{content:'" + v + "'}</style>"));
        System.out.println("  ⑫ style 块 → " + (h12 == null ? "无" : h12.context));
        check("style 块上下文",
                h12 != null && h12.context == ReflectionAudit.Context.STYLE_BLOCK);

        // 13. JSON 响应
        ReflectionAudit.Hit h13 = one(req("/api?q=" + v),
                resp("application/json", "{\"name\":\"" + v + "\"}"));
        System.out.println("  ⑬ JSON 响应 → " + (h13 == null ? "无" : h13.context));
        check("JSON 响应上下文",
                h13 != null && h13.context == ReflectionAudit.Context.JSON_BODY);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 二、转义情况的诚实报告（不许猜）");
        System.out.println("============================================================");

        // 值里没有危险字符 → 必须说「未知」
        ReflectionAudit.Hit e1 = one(req("/p?q=INJTEST99"),
                resp("text/html", "<div>INJTEST99</div>"));
        System.out.println("  值无危险字符 → " + e1.encodingNote);
        check("值里没有危险字符时如实说「未知」，不假装知道",
                e1.encodingNote.contains("未知"));

        // 值里有 < 且原样存活 → 必须报「原样存活」
        ReflectionAudit.Hit e2 = one(req("/p?q=AAA%3Cb%3E"),
                resp("text/html", "<div>AAA<b></div>"));
        if (e2 != null) {
            System.out.println("  值含 < 且原样 → " + e2.encodingNote);
        }
        // 用未编码的值直接提交（测试里不走 URL 解码）
        ReflectionAudit.Hit e3 = one(req("/p?q=AAA<b>x"),
                resp("text/html", "<div>AAA<b>x</div>"));
        System.out.println("  值含 < 且原样存活 → " + (e3 == null ? "无" : e3.encodingNote));
        check("观察到未转义字符时明确报「原样存活」",
                e3 != null && e3.encodingNote.contains("原样存活"));

        // 值里的 < 被编码 → 必须<b>仍然找到反射</b>，并说明是被编码回显的
        ReflectionAudit.Hit e4 = one(req("/p?q=AAA<b>x"),
                resp("text/html", "<div>AAA&lt;b&gt;x</div>"));
        System.out.println("  值含 < 但被编码 → "
                + (e4 == null ? "❌ 完全没找到（误报「无反射」）" : e4.encodingNote));
        // ⚠️ 分成两条断言，是为了把两种失败区分开：
        //    ① 压根没找到反射（这个最严重 —— 会漏掉整个参数）
        //    ② 找到了，但没说清是被编码回显的
        check("值被编码回显时仍能找到反射（不误报「无反射」）", e4 != null);
        check("并且明确说明是被编码回显的",
                e4 != null && e4.encodingNote.contains("编码"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 三、payload 形式与探针必须匹配上下文");
        System.out.println("============================================================");

        check("HTML 文本给的形式是标签型",
                ReflectionAudit.Context.HTML_TEXT.primaryPayload.contains("<"));
        check("双引号属性给的形式含转义双引号",
                ReflectionAudit.Context.ATTR_DOUBLE.primaryPayload.startsWith("\">"));
        check("script 块给的形式含 </script>",
                ReflectionAudit.Context.SCRIPT_BLOCK.primaryPayload.contains("</script>"));
        check("JS 双引号字符串给的形式含 \";",
                ReflectionAudit.Context.JS_STRING_DOUBLE.primaryPayload.startsWith("\";"));
        check("事件处理器给的是纯 JS（不含标签）",
                !ReflectionAudit.Context.EVENT_HANDLER.primaryPayload.contains("<"));
        check("每个上下文的探针都含 < > 或引号（能测出转义）",
                ReflectionAudit.Context.HTML_TEXT.probe.contains("<")
                        && ReflectionAudit.Context.ATTR_DOUBLE.probe.contains("\""));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 四、参数提取（query / form / JSON / 头 / 路径）");
        System.out.println("============================================================");

        ReflectionAudit a = new ReflectionAudit();

        // JSON body
        List<ReflectionAudit.Hit> jh = new ArrayList<>();
        a.check("POST /api HTTP/1.1\r\nHost: s.com\r\nContent-Type: application/json\r\n\r\n"
                        + "{\"nick\":\"JSONINJ77\"}",
                resp("text/html", "<div>JSONINJ77</div>"), jh);
        check("从 JSON body 提出参数",
                !jh.isEmpty() && jh.get(0).where.equals("body.nick"));

        // form body
        List<ReflectionAudit.Hit> fh = new ArrayList<>();
        a.check("POST /api HTTP/1.1\r\nHost: s.com\r\n"
                        + "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                        + "name=FORMINJ88",
                resp("text/html", "<div>FORMINJ88</div>"), fh);
        check("从 form body 提出参数",
                !fh.isEmpty() && fh.get(0).where.equals("body.name"));

        // 请求头
        List<ReflectionAudit.Hit> hh = new ArrayList<>();
        a.check("GET / HTTP/1.1\r\nHost: s.com\r\nReferer: https://reftest99.com/x\r\n\r\n",
                resp("text/html", "<a href=\"https://reftest99.com/x\">back</a>"), hh);
        check("从 Referer 头提出参数（这类头也常被回显）",
                !hh.isEmpty() && hh.get(0).where.startsWith("header."));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 五、不该报的不要报（降噪）");
        System.out.println("============================================================");

        // 太短的值
        List<ReflectionAudit.Hit> s1 = new ArrayList<>();
        a.check(req("/p?q=1"), resp("text/html", "<div>123</div>"), s1);
        check("过短的值不报（全是噪音）", s1.isEmpty());

        // 纯数字
        List<ReflectionAudit.Hit> s2 = new ArrayList<>();
        a.check(req("/p?q=12345"), resp("text/html", "<div>12345</div>"), s2);
        check("纯数字值不报", s2.isEmpty());

        // 值没出现在响应里
        List<ReflectionAudit.Hit> s3 = new ArrayList<>();
        a.check(req("/p?q=NOTREFLECTED"), resp("text/html", "<div>other</div>"), s3);
        check("值没回显就不报", s3.isEmpty());

        // 二进制响应
        List<ReflectionAudit.Hit> s4 = new ArrayList<>();
        a.check(req("/p?q=INJBINARY99"),
                "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\nINJBINARY99",
                s4);
        check("二进制响应不报（不可能有 HTML 上下文）", s4.isEmpty());

        // 同参数多次 → 计数累加，不重复报
        List<ReflectionAudit.Hit> s5 = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            a.check(req("/p?q=SAMEPARAM99"), resp("text/html", "<div>SAMEPARAM99</div>"), s5);
        }
        check("同一参数重复反射只报一条，计数累加",
                s5.size() == 1 && s5.get(0).count == 5);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 六、未闭合引号的判定（上下文的核心）");
        System.out.println("============================================================");

        check("无引号 → 0", ReflectionAudit.lastUnclosedQuote("var a=") == 0);
        check("一个双引号 → \"",
                ReflectionAudit.lastUnclosedQuote("var a=\"") == '"');
        check("已闭合的双引号 → 0",
                ReflectionAudit.lastUnclosedQuote("var a=\"x\"+") == 0);
        check("一个单引号 → '",
                ReflectionAudit.lastUnclosedQuote("var a='") == '\'');
        check("一个反引号 → `",
                ReflectionAudit.lastUnclosedQuote("var a=`") == '`');
        // ⚠️ 这条期望我一开始写错了。
        //    "var a=\"x\\\"" 这个字符串里，双引号确实<b>未闭合</b> ——
        //    因为后面那个 \" 是被转义的，不构成闭合。
        //    所以正确期望是「返回双引号」，不是我原先写的 0。
        check("未闭合 + 转义双引号 → 仍判为未闭合",
                ReflectionAudit.lastUnclosedQuote("var a=\"x\\\"") == '"');
        check("真正闭合（转义后再来一个未转义引号）→ 0",
                ReflectionAudit.lastUnclosedQuote("var a=\"x\\\"\"+") == 0);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 七、报告必须诚实说明「不能确认 XSS」");
        System.out.println("============================================================");

        List<ReflectionAudit.Hit> forReport = new ArrayList<>();
        a.check(req("/p?q=REPORTINJ99"),
                resp("text/html", "<div>REPORTINJ99</div>"), forReport);
        String rep = ReflectionAudit.render(forReport, 1);

        check("报告明确写「不下发 payload，不能确认 XSS」",
                rep.contains("不能确认 XSS") && rep.contains("不下发"));
        check("报告写明 0 网络请求", rep.contains("网络请求") && rep.contains("0"));
        check("报告给了探针", rep.contains("先发这个探针"));
        check("报告给了首选与备选形式",
                rep.contains("首选") && rep.contains("备选"));
        check("报告含纪律提醒（最小证明 / 不要外带 cookie）",
                rep.contains("最小证明") && rep.contains("不要外带 cookie"));
        check("报告提醒不要批量 fuzz", rep.contains("自动化工具"));

        // 空结果时的报告要指出「存储型仍可能」
        String emptyRep = ReflectionAudit.render(new ArrayList<>(), 10);
        check("无反射时提醒存储型/DOM XSS 仍可能",
                emptyRep.contains("存储型") && emptyRep.contains("DOM"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 八、边界（不许崩）");
        System.out.println("============================================================");

        boolean ok = true;
        try {
            ReflectionAudit b = new ReflectionAudit();
            List<ReflectionAudit.Hit> o = new ArrayList<>();
            b.check(null, null, o);
            b.check("", "", o);
            b.check("GET / HTTP/1.1\r\n\r\n", null, o);
            b.check(null, resp("text/html", "<div>x</div>"), o);
            b.check("\u0000\uFEFF", "\u0000\uFEFF", o);
            // 超长值与超长响应
            StringBuilder huge = new StringBuilder("GET /p?q=");
            for (int i = 0; i < 100; i++) {
                huge.append("BIGVALUE99");
            }
            huge.append(" HTTP/1.1\r\nHost: s.com\r\n\r\n");
            b.check(huge.toString(), resp("text/html", huge.toString()), o);
            ReflectionAudit.render(o, 1);
        } catch (Throwable e) {
            ok = false;
            System.out.println("    ✗ 抛异常：" + e);
        }
        check("null / 空 / 控制字符 / 超长 都不抛异常", ok);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
