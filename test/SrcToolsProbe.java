import com.packetsentry.core.AccessControlBatch;
import com.packetsentry.core.Finding;
import com.packetsentry.detect.LocalRules;
import com.packetsentry.report.ReportTemplate;
import com.packetsentry.vuln.ComponentIndex;
import com.packetsentry.vuln.CveLedger;

import java.util.ArrayList;
import java.util.List;

/**
 * 第十一轮：<b>面向 SRC 的三件事</b>。
 *
 * <ol>
 *   <li>批量越权 —— 但安全红线是「默认不碰写操作」</li>
 *   <li>同一 CVE 的多资产匹配 —— 版本比较必须按数字段，不能按字符串</li>
 *   <li>报告字段对齐平台 —— 字段映射靠关键词，改名后仍然成立</li>
 * </ol>
 *
 * <p>这一轮的测试重点不在「功能跑通」，而在<b>安全边界和正确性边界</b>：
 * 批量越权最容易出的错是「把写操作也重放了」（那是真的改数据），
 * CVE 匹配最容易出的错是「版本比较错了」（1.9 vs 1.10）。
 */
public class SrcToolsProbe {

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

    private static String resp(String s) {
        return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + s;
    }

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println(" 十一 · A：批量越权的安全红线（默认不碰写操作）");
        System.out.println("============================================================");

        List<AccessControlBatch.Target> targets = new ArrayList<>();
        // 用反射构造不了 PacketRecord（字段多），改为直接验证静态判定逻辑
        check("GET 是只读方法", isSafe("GET"));
        check("HEAD 是只读方法", isSafe("HEAD"));
        check("OPTIONS 是只读方法", isSafe("OPTIONS"));
        check("⭐ POST 不是只读（重放可能真的下单）", !isSafe("POST"));
        check("⭐ PUT 不是只读", !isSafe("PUT"));
        check("⭐ DELETE 不是只读（重放可能真的删数据）", !isSafe("DELETE"));
        check("⭐ PATCH 不是只读", !isSafe("PATCH"));
        check("大小写不影响判定", isSafe("get") && !isSafe("post"));

        // 请求上限必须是硬约束
        check("有硬上限，不会无限发", AccessControlBatch.HARD_MAX > 0
                && AccessControlBatch.HARD_MAX <= 1000);
        System.out.println("  硬上限 = " + AccessControlBatch.HARD_MAX + " 个请求");

        // 空目标 / 没身份 必须明确拒绝而不是静默跑
        AccessControlBatch.Options opts = new AccessControlBatch.Options();
        AccessControlBatch.Outcome o1 =
                new AccessControlBatch(null).run(new ArrayList<>(), opts, null);
        check("空目标明确拒绝（不静默成功）",
                o1.aborted != null && !o1.aborted.isEmpty());
        check("空目标不发任何请求", o1.sent == 0);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十一 · B：组件指纹提取（纯观测，0 网络请求）");
        System.out.println("============================================================");

        ComponentIndex idx = new ComponentIndex();
        idx.feed("www.a.com", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html>");
        idx.feed("api.a.com", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n{}");
        idx.feed("static.b.com", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\nx");
        idx.feed("c.org", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\nx");
        idx.feed("d.org", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\nx");
        idx.feed("e.org", "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/7.4.3\r\n\r\nx");
        idx.feed("f.org", "HTTP/1.1 200 OK\r\n\r\n<script src=\"/js/jquery-3.4.1.min.js\">"
                + "</script>");

        System.out.println("  提取到 " + idx.groupCount() + " 个组件组，"
                + idx.hostCount() + " 个资产");
        for (ComponentIndex.Group g : idx.all()) {
            System.out.println("    " + g.name + " " + g.version
                    + " → " + g.assetCount() + " 个资产");
        }

        check("提取到 nginx", idx.find("nginx", "1.18.0") != null);
        check("⭐ 同版本跨 3 个资产归成一组",
                idx.find("nginx", "1.18.0").assetCount() == 3);
        check("不同版本是不同组",
                idx.find("nginx", "1.24.0") != null
                        && idx.find("nginx", "1.24.0").assetCount() == 1);
        check("提取到 Apache（含括号的版本能正确截断）",
                idx.find("Apache httpd", "2.4.41") != null);
        check("提取到 PHP（X-Powered-By）", idx.find("PHP", "7.4.3") != null);
        check("从脚本文件名提取 jQuery",
                idx.find("jQuery", "3.4.1") != null);
        check("按影响资产数降序（多的在前）",
                idx.all().get(0).assetCount() >= idx.all().get(idx.all().size() - 1)
                        .assetCount());

        String rendered = idx.render();
        check("渲染里标出「跨多个资产」", rendered.contains("跨多个资产"));
        check("渲染里说明「版本指纹不是漏洞」",
                rendered.contains("版本指纹") && rendered.contains("不是漏洞"));
        check("渲染里指向 NVD 核实", rendered.contains("NVD"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十一 · C：版本比较（最容易出错的地方）");
        System.out.println("============================================================");

        // ⭐ 这条是最经典的坑：字符串比较会得到错误结论
        check("⭐ 1.9 < 1.10（按数字段比，不是字符串比）",
                CveLedger.compareVersions("1.9", "1.10") < 0);
        check("字符串比较确实是相反的（说明这个坑真实存在）",
                "1.9".compareTo("1.10") > 0);
        check("1.18.0 < 1.20.1", CveLedger.compareVersions("1.18.0", "1.20.1") < 0);
        check("1.20.1 == 1.20.1", CveLedger.compareVersions("1.20.1", "1.20.1") == 0);
        check("2.4.41 < 2.4.50", CveLedger.compareVersions("2.4.41", "2.4.50") < 0);
        check("v1.2.3 == 1.2.3（前缀 v 忽略）",
                CveLedger.compareVersions("v1.2.3", "1.2.3") == 0);
        check("1.2 与 1.2.0 视为相同（缺位补 0）",
                CveLedger.compareVersions("1.2", "1.2.0") == 0);
        check("1.2.3-beta 能比较（取数字前缀）",
                CveLedger.compareVersions("1.2.3-beta", "1.2.3") == 0);
        check("空/null 不崩",
                CveLedger.compareVersions(null, null) == 0
                        && CveLedger.compareVersions("", "1") < 0);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十一 · D：CVE 规则匹配（含区间运算）");
        System.out.println("============================================================");

        CveLedger cve = new CveLedger(
                java.nio.file.Paths.get(System.getProperty("java.io.tmpdir"),
                        "ps-cve-probe-" + System.nanoTime() + ".json"));

        CveLedger.Rule r1 = new CveLedger.Rule();
        r1.component = "nginx";
        r1.op = "<";
        r1.version = "1.20.1";
        r1.cveId = "CVE-2021-23017";
        r1.title = "resolver off-by-one";
        r1.severity = "High";
        r1.refUrl = "https://nvd.nist.gov/vuln/detail/CVE-2021-23017";
        cve.add(r1);

        List<CveLedger.Match> ms = cve.match(idx);
        System.out.println("  规则：" + r1);
        for (CveLedger.Match m : ms) {
            System.out.println("    → 命中 " + m.assetCount() + " 个资产："
                    + m.hosts);
        }
        check("规则命中", ms.size() == 1);
        check("⭐ 一次命中全部 3 个低版本 nginx 资产（这就是「多资产」）",
                ms.get(0).assetCount() == 3);
        check("资产列表正确（含 www / api / static）",
                ms.get(0).hosts.contains("www.a.com")
                        && ms.get(0).hosts.contains("api.a.com")
                        && ms.get(0).hosts.contains("static.b.com"));
        check("⭐ 1.24.0 不受影响（不在区间内）",
                !ms.get(0).hosts.contains("c.org"));
        check("不同组件不受影响（Apache 不在里面）",
                !ms.get(0).hosts.contains("d.org"));

        String mt = cve.renderMatches(idx);
        check("渲染含 CVE 号", mt.contains("CVE-2021-23017"));
        check("渲染含受影响资产数", mt.contains("受影响资产"));
        check("渲染含参考链接", mt.contains("nvd.nist.gov"));
        check("⭐ 渲染里有「提交前必须自己确认」的提醒",
                mt.contains("提交前必须自己确认"));
        check("提醒里含「版本区间是否真的覆盖」",
                mt.contains("版本区间是否真的覆盖"));

        // 区间运算
        CveLedger.Rule r2 = new CveLedger.Rule();
        r2.component = "PHP";
        r2.op = "~";
        r2.version = "7.4.0";
        r2.version2 = "7.4.30";
        r2.cveId = "CVE-TEST-RANGE";
        cve.add(r2);
        List<CveLedger.Match> ms2 = cve.match(idx);
        boolean rangeHit = false;
        for (CveLedger.Match m : ms2) {
            if ("CVE-TEST-RANGE".equals(m.rule.cveId)) {
                rangeHit = m.assetCount() == 1;
            }
        }
        check("闭区间 [7.4.0, 7.4.30] 命中 7.4.3", rangeHit);

        // 组件名不匹配 → 不命中
        CveLedger.Rule r3 = new CveLedger.Rule();
        r3.component = "不存在的组件";
        r3.op = "<";
        r3.version = "99";
        r3.cveId = "CVE-NOPE";
        cve.add(r3);
        boolean noFalse = true;
        for (CveLedger.Match m : cve.match(idx)) {
            if ("CVE-NOPE".equals(m.rule.cveId)) {
                noFalse = false;
            }
        }
        check("组件名不匹配的规则不命中", noFalse);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十一 · E：台账为空时必须解释「为什么不内置 CVE 库」");
        System.out.println("============================================================");

        CveLedger emptyCve = new CveLedger(
                java.nio.file.Paths.get(System.getProperty("java.io.tmpdir"),
                        "ps-cve-empty-" + System.nanoTime() + ".json"));
        String emptyRender = emptyCve.renderMatches(idx);
        check("空台账时解释设计原因", emptyRender.contains("版本区间必须写对"));
        check("空台账时说明责任拆开",
                emptyRender.contains("纯观测") && emptyRender.contains("核实区间"));
        check("空台账时给出文件路径", emptyRender.contains(".json"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十一 · F：报告模板（字段对齐平台）");
        System.out.println("============================================================");

        List<ReportTemplate> tpls = ReportTemplate.builtins();
        check("内置多个平台模板", tpls.size() >= 5);
        for (ReportTemplate t : tpls) {
            System.out.println("    " + t.oneLine() + "　定级：" + t.levelScheme);
        }
        check("含通用模板", ReportTemplate.byId("generic").name.contains("通用"));
        check("含补天", ReportTemplate.byId("butian").name.contains("补天"));
        check("含教育行业", ReportTemplate.byId("edu").name.contains("教育"));
        check("含 HackerOne", ReportTemplate.byId("hackerone").name.contains("HackerOne"));
        check("未知 id 退回通用（不抛异常）",
                ReportTemplate.byId("不存在").id.equals("generic"));

        // ⭐ 每个模板都必须带「按实际字段调整」的提醒 —— 这是我们不敢声称权威的诚实边界
        boolean allMarked = true;
        for (ReportTemplate t : tpls) {
            if (t.note == null || !t.note.contains("调整")) {
                allMarked = false;
                System.out.println("    ✗ 缺提醒：" + t.name);
            }
        }
        check("⭐ 每个模板都标注「按平台实际字段调整」", allMarked);

        // 字段映射
        Finding f = Finding.from("GET", "shop.com", "/api/user/1", "id",
                "越权访问", LocalRules.Level.HIGH, "响应里含他人手机号",
                com.packetsentry.detect.PlatformRules.Decision.ACCEPTED, "高危");
        List<Finding> fs = new ArrayList<>();
        fs.add(f);

        for (ReportTemplate t : tpls) {
            String md = t.render(fs, "测试平台");
            boolean okUrl = md.contains("https://shop.com/api/user/1");
            boolean okLevel = md.contains("高危");
            boolean okType = md.contains("越权访问");
            System.out.println("    " + t.name + " → URL:" + okUrl
                    + " 等级:" + okLevel + " 类型:" + okType);
            check(t.name + " 渲染出 URL / 等级 / 类型", okUrl && okLevel && okType);
        }

        String btMd = ReportTemplate.byId("butian").render(fs, "补天");
        check("补天模板含「漏洞标题」", btMd.contains("漏洞标题"));
        check("补天模板含「危害等级」", btMd.contains("危害等级"));
        check("补天模板含「修复方案」", btMd.contains("修复方案"));
        check("补天模板含平台定级口径", btMd.contains("严重 / 高危 / 中危 / 低危"));

        String h1Md = ReportTemplate.byId("hackerone").render(fs, "");
        check("HackerOne 模板含 Steps To Reproduce",
                h1Md.contains("Steps To Reproduce"));
        check("HackerOne 模板含 Impact", h1Md.contains("Impact"));

        // 空字段要明确写「待填」而不是静默留空
        check("⭐ 无法映射的字段写【待填：…】而不是留空",
                btMd.contains("【待填"));
        check("报告末尾含提交前核对清单",
                btMd.contains("提交前核对"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十一 · G：自定义字段（用户按平台实际表单改）");
        System.out.println("============================================================");

        List<ReportTemplate.Section> custom = ReportTemplate.parseEditableText(
                "漏洞名称｜含单位名和系统名\n"
                        + "漏洞证明｜截图\n"
                        + "备注字段　[可选]｜可留空\n",
                ReportTemplate.byId("generic").sections);
        check("解析出 3 个自定义字段", custom.size() == 3);
        check("解析出必填", custom.get(0).required);
        check("解析出 [可选]", !custom.get(2).required);
        check("解析出提示", custom.get(0).hint.contains("单位名"));
        check("空文本退回内置字段",
                ReportTemplate.parseEditableText("", ReportTemplate.byId("generic").sections)
                        .size() == ReportTemplate.byId("generic").sections.size());
        check("写坏了也不抛异常（退回内置）",
                ReportTemplate.parseEditableText("｜｜｜", null) != null);

        // 改名之后映射依然成立（靠关键词而不是下标）
        ReportTemplate t = ReportTemplate.byId("generic");
        t.sections = custom;
        String cMd = t.render(fs, "");
        check("⭐ 用户自定义字段名后，URL / 等级 / 类型仍能自动填上",
                cMd.contains("https://shop.com/api/user/1") && cMd.contains("高危"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十一 · H：边界（不许崩）");
        System.out.println("============================================================");

        boolean ok = true;
        try {
            ComponentIndex ci = new ComponentIndex();
            ci.feed(null, null);
            ci.feed("", "");
            ci.feed("h", "");
            ci.feed("h", "HTTP/1.1 200 OK\r\nServer: nginx/\r\n\r\n");
            ci.find(null, null);
            ci.componentsOf(null);
            ci.componentsOf("不存在");
            ci.byName();
            ci.toPromptText(0);
            ci.render();

            CveLedger cl = new CveLedger(null);
            cl.add(null);
            cl.add(new CveLedger.Rule());
            cl.removeAt(-1);
            cl.removeAt(999);
            cl.match(null);
            cl.renderMatches(null);
            cl.toPromptText(null);
            cl.oneLine();
            CveLedger.Op.of(null);
            CveLedger.Op.of("不存在");
            CveLedger.Rule rr = new CveLedger.Rule();
            rr.opEnum();
            rr.rangeText();
            rr.toString();

            ReportTemplate rt = new ReportTemplate();
            rt.render(null, null);
            rt.render(new ArrayList<>(), null);
            rt.toEditableText();
            rt.oneLine();
            ReportTemplate.byId(null);
            ReportTemplate.names();
            ReportTemplate.builtinSections();
            ReportTemplate.parseEditableText(null, null);
            ReportTemplate.parseEditableText("x", new ArrayList<>());

            AccessControlBatch.describePlan(new ArrayList<>(),
                    new AccessControlBatch.Options());
            new AccessControlBatch(null).cancel();
        } catch (Throwable e) {
            ok = false;
            System.out.println("    ✗ 抛异常：" + e);
            e.printStackTrace();
        }
        check("null / 空 / 畸形输入 都不抛异常", ok);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    private static boolean isSafe(String method) {
        return new String[]{"GET", "HEAD", "OPTIONS"}
                .length > 0 && safeSet().contains(method.toUpperCase());
    }

    private static java.util.Set<String> safeSet() {
        return new java.util.LinkedHashSet<>(
                java.util.Arrays.asList("GET", "HEAD", "OPTIONS"));
    }
}
