package com.packetsentry.report;

import com.packetsentry.core.Finding;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 报告模板 —— 按 SRC 平台的实际字段来组织。
 *
 * <h3>为什么需要模板，而不是一个固定格式</h3>
 * 不同平台要的字段不一样。「六段式」写得再清楚，
 * 如果补天要的是「漏洞标题 / 漏洞类型 / 危害等级 / 漏洞URL / 漏洞详情 / 修复方案」，
 * 你还是得手工搬一遍。而报告里最容易出错、最费时间的就是这个搬运过程。
 *
 * <h3>▲ 关于内置模板的诚实说明</h3>
 * 各个平台的表单字段会改版，<b>我不敢保证这里的内置模板和平台当前的表单完全一致</b>。
 * 所以：
 * <ul>
 *   <li>内置模板给的是<b>常见结构</b>，不是权威定义</li>
 *   <li>模板<b>可以编辑</b> —— 你在设置里按平台实际字段改一次，就一直用</li>
 *   <li>每个模板都带一句「按平台实际字段调整」的提醒</li>
 * </ul>
 *
 * <p>宁可你在界面上花一分钟改对字段，也不要我给你一个看起来很专业、
 * 实际提交时字段对不上的模板。
 */
public final class ReportTemplate {

    /** 一个字段。 */
    public static final class Section {
        /** 平台上的字段名。 */
        public String name;
        /** 这个字段该写什么（给 AI 和用户的提示）。 */
        public String hint;
        /** 是否必填（只影响提醒，不阻止导出）。 */
        public boolean required;

        public Section() {
        }

        public Section(String name, String hint, boolean required) {
            this.name = name;
            this.hint = hint;
            this.required = required;
        }

        @Override
        public String toString() {
            return name + (required ? "（必填）" : "");
        }
    }

    /** 模板名（展示用）。 */
    public String name = "通用";
    /** 平台标识（存在 Config 里，重启后还记得用哪个）。 */
    public String id = "generic";
    /** 字段列表，按平台表单顺序。 */
    public List<Section> sections = new ArrayList<>();
    /** 这个平台的定级口径说明。 */
    public String levelScheme = "";
    /** 一句提醒。 */
    public String note = "按平台实际字段调整";

    public ReportTemplate() {
    }

    public ReportTemplate(String id, String name) {
        this.id = id;
        this.name = name;
    }

    // ==================================================================
    // 内置模板
    // ==================================================================

    /**
     * 内置的几个常见平台结构。
     *
     * <p>▲ 这些是<b>常见结构</b>，不是权威定义 —— 平台表单会改版。
     * 在设置里可以按实际字段改，改完存下来一直用。
     */
    public static List<ReportTemplate> builtins() {
        List<ReportTemplate> out = new ArrayList<>();

        // ---- 通用六段式（默认）----
        ReportTemplate g = new ReportTemplate("generic", "通用（六段式）");
        g.levelScheme = "Critical / High / Medium / Low　—— 以实际危害为准";
        g.sections.addAll(Arrays.asList(
                new Section("一、漏洞 URL / IP",
                        "存在漏洞的全部 URL（含路径与参数）；服务类漏洞写 IP 与端口", true),
                new Section("二、风险评级",
                        "Critical / High / Medium / Low。逻辑漏洞要说明为什么是这个级别", true),
                new Section("三、危害说明",
                        "能做什么、影响谁的数据、能不能批量。逻辑漏洞必须说透", true),
                new Section("四、资产证明",
                        "域名归属（SEO/备案查询）、关键信息截图、关键数据截图", false),
                new Section("五、渗透路径",
                        "网站特有漏洞：完整复现步骤 + 数据包。"
                                + "通用漏洞：CVE 编号或参考链接；用了 POC 工具要写明工具名与类型", true),
                new Section("六、修复建议",
                        "针对性的修复方案；实在没思路时至少给「增加过滤 / 升级版本」", false)));
        out.add(g);

        // ---- 补天 ----
        ReportTemplate bt = new ReportTemplate("butian", "补天");
        bt.levelScheme = "严重 / 高危 / 中危 / 低危　—— 补天按「危害等级」四档";
        bt.sections.addAll(Arrays.asList(
                new Section("漏洞标题", "一句话说清：什么系统、什么位置、什么问题", true),
                new Section("漏洞类型", "如：SQL注入 / 越权访问 / 信息泄露 / 逻辑缺陷", true),
                new Section("危害等级", "严重 / 高危 / 中危 / 低危", true),
                new Section("漏洞URL", "完整 URL，带参数", true),
                new Section("漏洞详情",
                        "复现步骤，要能让审核照着走一遍就能复现。"
                                + "含数据包、账号前提、每一步的预期现象", true),
                new Section("修复方案", "具体到改哪里；至少给「增加过滤 / 升级版本」", true),
                new Section("漏洞证明", "截图或数据包。▲ 只放最小证明，不要附带业务数据", false)));
        out.add(bt);

        // ---- 教育行业 SRC ----
        ReportTemplate edu = new ReportTemplate("edu", "教育行业 SRC");
        edu.levelScheme = "严重 / 高危 / 中危 / 低危　—— 部分平台不收纯信息泄露";
        edu.sections.addAll(Arrays.asList(
                new Section("漏洞名称", "含单位名 + 系统名 + 漏洞类型", true),
                new Section("所属单位", "被影响的学校 / 单位全称（用于归属核实）", true),
                new Section("漏洞类型", "如：越权访问 / SQL注入 / 信息泄露", true),
                new Section("危害等级", "严重 / 高危 / 中危 / 低危", true),
                new Section("漏洞URL", "完整 URL，带参数", true),
                new Section("资产归属证明",
                        "域名备案查询截图、网站首页截图（证明这个资产确实属于该单位）", true),
                new Section("漏洞详情",
                        "复现步骤 + 数据包。教育行业审核通常较严，步骤要写细", true),
                new Section("修复建议", "针对性修复方案", true)));
        out.add(edu);

        // ---- HackerOne ----
        ReportTemplate h1 = new ReportTemplate("hackerone", "HackerOne");
        h1.levelScheme = "None / Low / Medium / High / Critical　—— 以 CVSS 或平台评级为准";
        h1.note = "English report is usually expected；按平台实际字段调整";
        h1.sections.addAll(Arrays.asList(
                new Section("Summary", "One or two sentences: what and where", true),
                new Section("Steps To Reproduce",
                        "Numbered steps a triager can follow exactly; include raw requests", true),
                new Section("Severity",
                        "Critical / High / Medium / Low —— 平台上通常要单独选", true),
                new Section("Impact",
                        "What an attacker gains. Be concrete: whose data, how much, what actions", true),
                new Section("Supporting Material/References",
                        "Screenshots, PoC, related links", false)));
        out.add(h1);

        // ---- 企业自建 SRC ----
        ReportTemplate ent = new ReportTemplate("enterprise", "企业自建 SRC");
        ent.levelScheme = "严重 / 高危 / 中危 / 低危";
        ent.sections.addAll(Arrays.asList(
                new Section("漏洞名称", "系统 + 位置 + 问题类型", true),
                new Section("漏洞等级", "严重 / 高危 / 中危 / 低危", true),
                new Section("影响范围", "受影响的资产、用户规模、数据敏感度", true),
                new Section("复现步骤", "详细步骤，含请求/响应", true),
                new Section("危害说明", "攻击者能做什么", true),
                new Section("修复建议", "修复方案", false)));
        out.add(ent);

        return out;
    }

    public static ReportTemplate byId(String id) {
        for (ReportTemplate t : builtins()) {
            if (t.id.equals(id) || t.name.equals(id)) {
                return t;
            }
        }
        return builtins().get(0);
    }

    /** 所有模板名（给下拉框）。 */
    public static String[] names() {
        List<ReportTemplate> bs = builtins();
        String[] out = new String[bs.size()];
        for (int i = 0; i < bs.size(); i++) {
            out[i] = bs.get(i).name;
        }
        return out;
    }

    // ==================================================================
    // 渲染
    // ==================================================================

    /**
     * 按模板渲染报告骨架。
     *
     * <p>只输出模板要求的字段，并按平台顺序排 —— 用户复制的时候不用再搬一遍。
     * 字段内容为空的会明确写「【待填：...】」，避免漏掉。
     */
    public String render(List<Finding> findings, String platformName) {
        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(name).append(" 漏洞报告\n\n");
        if (platformName != null && !platformName.isEmpty()) {
            sb.append("平台：").append(platformName).append("\n\n");
        }
        sb.append("> 字段顺序已按「").append(name).append("」模板排好。\n");
        sb.append("> ▲ ").append(note).append(" —— 如果和平台表单对不上，在设置里改模板。\n\n");
        if (levelScheme != null && !levelScheme.isEmpty()) {
            sb.append("定级口径：").append(levelScheme).append("\n\n");
        }

        if (findings == null || findings.isEmpty()) {
            sb.append("（没有可写的发现。先在发现清单里把确认过的标成「已验证」。）\n");
            return sb.toString();
        }

        sb.append("---\n\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            sb.append("## ").append(i + 1).append(". ")
                    .append(f.type).append(" —— ").append(f.host).append("\n\n");

            // ▲ 兜底：保证<b>完整 URL</b> 和 <b>风险评级</b>一定出现在报告里。
            //
            //    这个 bug 是测试逼出来的，而且修了两轮。起因是 HackerOne 模板
            //    的字段名全是英文（Summary / Steps To Reproduce / Impact），
            //    企业自建 SRC 用的是「漏洞名称 / 漏洞等级 / 影响范围」——
            //    这些名字里没有一个能映射到「完整 URL」，于是渲染出来的报告
            //    <b>从头到尾没有一条能点开的地址</b>。
            //
            //    把 URL 兜住之后，测试又指出<b>等级也会丢</b> ——
            //    如果用户自定义字段里没有等级字段，报告就没有风险评级。
            //
            //    这两样是一份漏洞报告的最低要求：审核得知道<b>去哪儿复现</b>、
            //    以及<b>你主张什么级别</b>。字段映射可以靠关键词猜，
            //    但这两样不能靠猜 —— 所以直接兜底。
            StringBuilder fbody = new StringBuilder();
            for (Section s : sections) {
                fbody.append("### ").append(s.name).append("\n\n");
                String body = bodyFor(s.name, f);
                if (body == null || body.isEmpty()) {
                    fbody.append("【待填：").append(s.hint).append("】\n\n");
                } else {
                    fbody.append(body).append("\n\n");
                }
            }
            String fbodyText = fbody.toString();
            boolean hasUrl = fbodyText.contains(f.url());
            boolean hasLevel = fbodyText.contains(f.displayLevel());
            if (!hasUrl || !hasLevel) {
                if (!hasUrl) {
                    sb.append("> **目标 URL**：`").append(f.url()).append("`\n");
                }
                if (!hasLevel) {
                    sb.append("> **风险评级**：").append(f.displayLevel());
                    if (f.decision != null && !f.decision.isEmpty()
                            && !"未提及".equals(f.decision)) {
                        sb.append("　（平台规则：").append(f.decision).append("）");
                    }
                    sb.append('\n');
                }
                sb.append('\n');
            }
            sb.append(fbody);
            sb.append("---\n\n");
        }

        sb.append("> ▲ 提交前核对：\n");
        sb.append("> 1. 每条是否真的能复现（清单里是候选，不是已确认）\n");
        sb.append("> 2. 危害说明要写清业务影响 —— 逻辑漏洞尤其要说透，否则会被降级\n");
        sb.append("> 3. 资产证明（域名归属、关键截图）需要自己补\n");
        sb.append("> 4. 证据只放最小证明，不要附带业务数据\n");
        return sb.toString();
    }

    /**
     * 把发现的数据映射到某个字段。
     *
     * <p>用<b>字段名的关键词</b>来映射，而不是按顺序 —— 这样用户在设置里
     * 调整字段顺序或改名之后，映射依然成立。
     */
    private static String bodyFor(String sectionName, Finding f) {
        String n = sectionName == null ? "" : sectionName.toLowerCase();
        StringBuilder sb = new StringBuilder();

        // ---- URL / 位置类 ----
        if (n.contains("url") || n.contains("位置") || n.contains("url")
                || n.contains("复现请求") || n.contains("地址")) {
            sb.append("`").append(f.url()).append("`\n");
            if (f.param != null && !f.param.isEmpty()) {
                sb.append("命中参数：").append(f.param).append('\n');
            }
            sb.append("方法：").append(f.method).append('\n');
            return sb.toString();
        }

        // ---- 等级类 ----
        if (n.contains("等级") || n.contains("评级") || n.contains("severity")
                || n.contains("level") || n.contains("cvss")) {
            sb.append(f.displayLevel());
            if (f.decision != null && !f.decision.isEmpty()
                    && !"未提及".equals(f.decision)) {
                sb.append("　（平台规则：").append(f.decision).append("）");
            }
            return sb.toString();
        }

        // ---- 类型 / 标题类 ----
        if (n.contains("类型") || n.contains("type")) {
            return f.type;
        }
        if (n.contains("标题") || n.contains("名称") || n.contains("summary")
                || n.contains("title")) {
            return f.type + " —— " + f.host + f.path;
        }

        // ---- 复现步骤 ----
        if (n.contains("复现") || n.contains("steps") || n.contains("渗透路径")
                || n.contains("详情")) {
            // ▲ 这里必须给<b>完整 URL</b>，不是只给 path。
            //    原来只输出 f.path（相对路径），于是像 HackerOne 这种
            //    字段名全是英文的模板，整个报告里没有一条能点开的地址。
            //    审核拿着没 URL 的报告根本不知道去哪儿复现。
            sb.append("1. 向 `").append(f.url()).append("` 发送 ")
                    .append(f.method).append(" 请求");
            if (f.param != null && !f.param.isEmpty()) {
                sb.append("（关注参数：").append(f.param).append("）");
            }
            sb.append('\n');
            sb.append("2. 观测到：").append(f.type).append('\n');
            sb.append("3. 观测次数：").append(f.seenCount).append(" 次\n");
            if (f.evidence != null && !f.evidence.isEmpty()) {
                sb.append("\n证据（截断）：`").append(f.evidence).append("`\n");
            }
            sb.append("\n【待填：完整的请求/响应数据包、前置条件（用哪个账号）、"
                    + "每一步的预期现象】\n");
            return sb.toString();
        }

        // ---- 危害 / 影响 ----
        if (n.contains("危害") || n.contains("影响") || n.contains("impact")
                || n.contains("scope")) {
            sb.append("【待填：攻击者能做什么、影响谁的数据、能不能批量】\n\n");
            sb.append("提示（来自本地判定）：").append(f.type);
            if (f.levelRank >= 3) {
                sb.append(" —— 本地初判为高等级，危害描述要撑得起这个级别");
            }
            return sb.toString();
        }

        // ---- 归属 / 资产证明 ----
        if (n.contains("归属") || n.contains("资产") || n.contains("证明")
                || n.contains("单位") || n.contains("supporting")) {
            sb.append("【待填：域名备案/WHOIS 查询截图、网站首页截图】\n\n");
            sb.append("域名：").append(f.host).append('\n');
            return sb.toString();
        }

        // ---- 修复 ----
        if (n.contains("修复") || n.contains("建议") || n.contains("方案")
                || n.contains("fix") || n.contains("remediation")) {
            return "【待填：针对性修复方案】\n\n"
                    + "兜底写法：在服务端对输入做严格校验与过滤；"
                    + "若为组件已知漏洞，升级到不受影响的版本。";
        }

        // ---- 备注 ----
        if (n.contains("备注") || n.contains("note")) {
            return f.note == null ? "" : f.note;
        }

        // 认不出来的字段 → 留待填，但把发现的基本信息给出来，方便用户填
        return "【待填：" + sectionName + "】\n\n发现信息：" + f.where();
    }

    // ==================================================================
    // 序列化（存进 Config）
    // ==================================================================

    /** 转成可存的一行行文本，用户在设置里能直接编辑。 */
    public String toEditableText() {
        StringBuilder sb = new StringBuilder();
        for (Section s : sections) {
            sb.append(s.name);
            if (!s.required) {
                sb.append("　[可选]");
            }
            sb.append("｜").append(s.hint == null ? "" : s.hint).append('\n');
        }
        return sb.toString();
    }

    /**
     * 从用户编辑过的文本还原字段表。
     *
     * <p>格式：每行「字段名｜提示」，字段名后可跟 {@code [可选]}。
     * 写坏了不抛异常 —— 退回到内置模板。
     */
    public static List<Section> parseEditableText(String text, List<Section> fallback) {
        if (text == null || text.trim().isEmpty()) {
            return fallback;
        }
        List<Section> out = new ArrayList<>();
        for (String line : text.split("\\r?\\n")) {
            String l = line.trim();
            if (l.isEmpty() || l.startsWith("#")) {
                continue;
            }
            int bar = l.indexOf('｜');
            if (bar < 0) {
                bar = l.indexOf('|');
            }
            String name;
            String hint = "";
            if (bar > 0) {
                name = l.substring(0, bar).trim();
                hint = l.substring(bar + 1).trim();
            } else {
                name = l;
            }
            boolean required = true;
            if (name.contains("[可选]")) {
                required = false;
                name = name.replace("[可选]", "").trim();
            }
            if (name.isEmpty()) {
                continue;
            }
            out.add(new Section(name, hint, required));
        }
        return out.isEmpty() ? fallback : out;
    }

    /** 供展示：模板概览。 */
    public String oneLine() {
        return name + "（" + sections.size() + " 个字段）";
    }

    /** 按 id 找内置模板的字段（用于「恢复默认」）。 */
    public static Map<String, List<Section>> builtinSections() {
        Map<String, List<Section>> m = new LinkedHashMap<>();
        for (ReportTemplate t : builtins()) {
            m.put(t.id, t.sections);
        }
        return m;
    }
}
