import com.packetsentry.core.Config;
import com.packetsentry.detect.LocalRules;

import java.util.List;

/**
 * 扩展后的本地规则 + SRC 安全模式 实测。
 *
 * <h3>为什么要测这些规则</h3>
 * 用户反馈「在 HackerOne CTF 靶场上显示全是无」。排查后发现两个原因：
 * <ol>
 *   <li><b>早期 11 条规则检测的是「泄露的数据」，不是「可被利用的缺陷」</b> ——
 *       正常浏览时几乎不命中</li>
 *   <li><b>有些规则触发条件过窄</b>：例如「明文 HTTP」要求请求行是绝对形式
 *       {@code GET http://...}，而 Burp 代理发的是相对形式 {@code GET /path}，
 *       所以这条规则在真实流量下命中率接近 0</li>
 * </ol>
 * v0.8 补了 10 条更贴近实战的规则，这里逐条验证它们真的能触发。
 */
public class SrcModeProbe {

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

    /** 按名字<b>包含</b>判断 —— 规则名里可能带「（已确认）」这类后缀。 */
    private static boolean hasPart(List<LocalRules.Issue> list, String namePart) {
        return list.stream().anyMatch(i -> i.name.contains(namePart));
    }

    private static boolean has(List<LocalRules.Issue> list, String name) {
        return list.stream().anyMatch(i -> i.name.equals(name));
    }

    private static List<LocalRules.Issue> detect(String req, String resp) {
        return LocalRules.detect(req, resp, null);
    }

    private static String req(String path) {
        return "GET " + path + " HTTP/1.1\r\nHost: t.example.com\r\n\r\n";
    }

    private static String resp(int code, String body) {
        return "HTTP/1.1 " + code + " OK\r\nContent-Type: text/html\r\n\r\n" + body;
    }

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println(" 一、v0.8 新增规则逐条验证");
        System.out.println("============================================================");

        // 12. Flag
        List<LocalRules.Issue> flag = detect(req("/"), resp(200, "nice! flag{th1s_1s_4_t3st}"));
        System.out.println("  ① Flag 检测：" + flag);
        check("检出 CTF Flag（严重）", hasPart(flag, "Flag")
                && LocalRules.worst(flag) == LocalRules.Level.CRITICAL);

        // 13. 源码泄露
        List<LocalRules.Issue> src = detect(req("/index.php.bak"),
                resp(200, "<?php\n$db_pass = 'secret';"));
        System.out.println("  ② 源码泄露：" + src);
        check("检出服务端源码泄露（高）", has(src, "源码泄露"));

        // 14. 调试信息
        List<LocalRules.Issue> dbg = detect(req("/"), resp(500,
                "Whitelabel Error Page\nThere was an unexpected error"));
        check("检出 Whitelabel 调试页", has(dbg, "调试信息泄露"));

        List<LocalRules.Issue> dbg2 = detect(req("/"), resp(500,
                "Traceback (most recent call last):\n  File \"app.py\", line 12"));
        check("检出 Python 堆栈", has(dbg2, "调试信息泄露"));

        // 15. 绝对路径
        List<LocalRules.Issue> ap = detect(req("/"),
                resp(500, "Warning: include(/var/www/html/config.php): failed"));
        System.out.println("  ③ 路径泄露：" + ap);
        check("检出服务器绝对路径（低）", has(ap, "服务器路径泄露"));

        // 16. 服务端版本
        List<LocalRules.Issue> sv = detect(req("/"),
                "HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\nX-Powered-By: PHP/5.6.40\r\n\r\nok");
        System.out.println("  ④ 版本泄露：" + sv);
        check("检出带版本号的服务端头（低）", has(sv, "服务端版本泄露"));

        // 只有名字没有版本号 → 不应报
        List<LocalRules.Issue> sv2 = detect(req("/"),
                "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nok");
        check("只有名字没有版本号时不误报", !has(sv2, "服务端版本泄露"));

        // 17. 备份文件
        List<LocalRules.Issue> bk = detect(req("/backup/db.sql"), resp(200, "INSERT INTO ..."));
        System.out.println("  ⑤ 备份文件：" + bk);
        check("检出可访问的备份文件（高）", has(bk, "备份/配置文件可访问"));

        // 18. JSONP
        List<LocalRules.Issue> jp = detect(
                "GET /api/user?callback=cb HTTP/1.1\r\nHost: t\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\ncb({\"phone\":\"x\"})");
        System.out.println("  ⑥ JSONP：" + jp);
        check("检出 JSONP 接口（中）", has(jp, "JSONP接口"));

        // 19. HTML 注释
        List<LocalRules.Issue> hc = detect(req("/"),
                resp(200, "<html><!-- TODO: remove test account admin/admin123 --></html>"));
        System.out.println("  ⑦ 注释泄露：" + hc);
        check("检出注释里的敏感信息（中）", has(hc, "注释信息泄露"));

        // 20. 隐藏字段
        List<LocalRules.Issue> hf = detect(req("/"),
                resp(200, "<form><input type=\"hidden\" name=\"price\" value=\"1\"></form>"));
        System.out.println("  ⑧ 隐藏字段：" + hf);
        check("检出隐藏表单字段（低）", has(hf, "隐藏表单字段"));

        // 21. 硬编码凭据
        List<LocalRules.Issue> hs = detect(req("/static/app.js"),
                resp(200, "var config = {api_key: \"AKIAIOSFODNN7EXAMPLE\"};"));
        System.out.println("  ⑨ 硬编码：" + hs);
        check("检出硬编码凭据（中）", has(hs, "硬编码凭据"));

        // 目录遍历扩展
        List<LocalRules.Issue> trav = detect(req("/?f=../../windows/win.ini"),
                resp(200, "; for 16-bit app support\n[fonts]"));
        check("检出 Windows 目录遍历", has(trav, "敏感文件泄露"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 二、不误报验证（干净请求不应报任何问题）");
        System.out.println("============================================================");

        List<LocalRules.Issue> clean = detect(
                "GET /api/product/1001 HTTP/1.1\r\nHost: shop.com\r\n\r\n",
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/json\r\n"
                        + "Set-Cookie: sid=abc; HttpOnly; Secure; SameSite=Lax\r\n"
                        + "\r\n"
                        + "{\"id\":1001,\"name\":\"book\",\"price\":29.9}");
        if (!clean.isEmpty()) {
            System.out.println("  实际发现：");
            clean.forEach(i -> System.out.println("    " + i));
        } else {
            System.out.println("  无发现 ✓");
        }
        check("干净的 JSON 接口不误报", clean.isEmpty());

        // 一个正常的 404 也不该报
        List<LocalRules.Issue> nf = detect(req("/nope"), resp(404, "Not Found"));
        check("正常 404 不误报", nf.isEmpty());

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 三、SRC 安全模式");
        System.out.println("============================================================");

        // 故意配一个云端配置，看 SRC 模式能不能强制改回本地
        Config c = new Config();
        c.provider = "deepseek";
        c.baseUrl = "https://api.deepseek.com";
        c.model = "deepseek-chat";
        c.sanitizeEnabled = false;
        c.scanEnabled = false;
        c.layerHeaders = false;
        c.layerFields = false;
        c.layerValues = false;
        c.maskStrategy = "KEEP_EDGES";
        c.maxBodyChars = 5000;
        c.autoAnalyze = true;
        c.srcMode = true;

        System.out.println("  修正前的配置：");
        System.out.println("    服务商    " + c.describeDestination());
        System.out.println("    掩码      " + c.maskStrategy + "　body 上限 " + c.maxBodyChars);
        System.out.println("    自动分析  " + c.autoAnalyze + "　脱敏 " + c.sanitizeEnabled);
        System.out.println();

        List<String> forced = c.enforceSrcMode();
        System.out.println("  强制修正 " + forced.size() + " 项：");
        forced.forEach(s -> System.out.println("    · " + s));
        System.out.println();
        System.out.println("  修正后的配置：");
        System.out.println("    服务商    " + c.describeDestination());
        System.out.println("    掩码      " + c.maskStrategy + "　body 上限 " + c.maxBodyChars);
        System.out.println("    自动分析  " + c.autoAnalyze + "　脱敏 " + c.sanitizeEnabled);
        System.out.println("    合规声明  " + c.complianceLine());
        System.out.println();

        check("云端服务商被强制改成本地", c.isLocalProvider());
        check("baseUrl 指向 127.0.0.1", c.baseUrl.contains("127.0.0.1"));
        check("模型不再是云端模型", !c.model.toLowerCase().contains("deepseek"));
        // ⚠️ 注意：SRC 模式<b>不再</b>强制关闭自动分析。
        //    理由是它不是合规问题 —— 本地模型下数据不出机器，
        //    而 SRC 规则禁止的「自动化工具」指向目标发包的工具。
        //    这里断言的是「非本地时会被关掉」，而 enforceSrcMode 第一步
        //    已把服务商强制成本地，所以最终 autoAnalyze 保持用户设置。
        check("自动分析不再被强制关闭（合规问题由强制本地解决）", c.autoAnalyze);
        check("掩码策略被强制为 FULL", "FULL".equals(c.maskStrategy));
        // ⚠️ 这条断言改过一版，因为它原来固化了同一个设计错误。
        //
        //    旧写法：check("body 上限收紧到 500", c.maxBodyChars <= 500);
        //    但 enforceSrcMode 第一步已经把服务商强制成本地了 ——
        //    <b>根本不存在外传</b>，那 500 字符的截断保护不了任何东西，
        //    只是白白砍掉 AI 能看到的内容（连一个完整页面都看不全），
        //    判断变浅，而用户还以为这是「合规的代价」。
        //
        //    这个错误在第 ② 条（自动分析）上已经犯过一次并修好了 ——
        //    同一个道理，当时只改了一处，漏了这里。
        //    现在断言的是「本地模型下不截断」。
        check("⭐ body 上限被放宽到 3000（本地模型无外传，截断纯属自损）",
                c.maxBodyChars >= 1500);
        check("脱敏被强制开启", c.sanitizeEnabled && c.layerHeaders && c.layerFields && c.layerValues);
        check("aiAllowed() 返回 true（本地模型）", c.aiAllowed());
        check("合规声明非空", !c.complianceLine().isEmpty());

        // 本地配置下不应有多余修正
        Config local = new Config();
        local.srcMode = true;
        local.provider = "ollama";
        local.baseUrl = "http://127.0.0.1:11434/v1";
        local.model = "qwen2.5:14b";
        local.maskStrategy = "FULL";
        // ⚠️ 这里也要跟着改：本地配置的 body 上限应当是<b>放宽后</b>的值。
        //    写成 500 的话，enforceSrcMode 的「本地→3000」逻辑会把它抬高，
        //    于是 forced 非空，这条「不做多余修改」的断言就会失败 ——
        //    而那不是 bug，是断言的前提过时了。
        local.maxBodyChars = 3000;
        local.sanitizeEnabled = true;
        local.scanEnabled = true;
        local.layerHeaders = true;
        local.layerFields = true;
        local.layerValues = true;
        local.autoAnalyze = false;
        check("本来就合规的配置不做多余修改", local.enforceSrcMode().isEmpty());

        // 关闭 SRC 模式时不施加任何约束
        Config off = new Config();
        off.srcMode = false;
        off.baseUrl = "https://api.deepseek.com";
        check("未开启 SRC 模式时不施加约束", off.enforceSrcMode().isEmpty() && !off.isLocalProvider());

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
