package com.packetsentry.report;

import com.packetsentry.audit.CodeAudit;
import com.packetsentry.core.Config;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.detect.LocalRules;
import com.packetsentry.llm.LlmClient;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 漏洞报告生成器 —— 按渗透测试报告结构产出。
 *
 * <h3>报告结构（固定六段）</h3>
 * <ol>
 *   <li><b>漏洞 URL / IP</b> —— 全部存在问题的 URL，含路径参数</li>
 *   <li><b>风险评级</b> —— Critical / High / Medium / Low，
 *       优先按用户提供的 SRC 平台规则判，没有规则时用内置标准</li>
 *   <li><b>危害说明</b> —— 讲清危害，逻辑漏洞尤其要说透</li>
 *   <li><b>资产证明</b> —— 证明资产属于目标单位</li>
 *   <li><b>渗透路径</b> —— 完整复现步骤；通用漏洞给 CVE / 参考链接</li>
 *   <li><b>修复建议</b></li>
 * </ol>
 *
 * <h3>▲ 一个刻意的设计：本地先产出骨架，AI 只做补充</h3>
 * 报告里有些内容<b>只能来自本地事实</b>（URL、参数、本地规则结论、
 * 审计证据），不能靠 AI 编。所以流程是：
 * <pre>
 *   本地引擎  →  产出确定的骨架（URL / 证据 / 本地定级）
 *   AI        →  补充「危害说明」「渗透路径」「修复建议」这些需要表述的部分
 *   本地      →  把两者拼成完整报告
 * </pre>
 * 这样即使 AI 不可用，报告仍然可用（只是表述部分留空待填）；
 * 也避免了 AI 把 URL、参数这类事实写错。
 */
public final class ReportGenerator {

    /** 报告六段的小标题。 */
    public static final String[] SECTIONS = {
            "一、漏洞 URL / IP",
            "二、风险评级",
            "三、危害说明",
            "四、资产证明",
            "五、渗透路径",
            "六、修复建议",
    };

    private final LlmClient llm = new LlmClient();

    // ==================================================================
    // 本地骨架
    // ==================================================================

    /**
     * 生成报告的本地骨架（不联网）。
     *
     * @param targets 本次报告的报文集合
     * @param cfg     配置（取 SRC 平台规则）
     */
    public String buildSkeleton(List<PacketRecord> targets, Config cfg) {
        StringBuilder sb = new StringBuilder();
        String ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        sb.append("═══════════════════════════════════════════════════\n");
        sb.append(" 漏洞报告（本地引擎生成骨架）\n");
        sb.append(" 生成时间：").append(ts).append('\n');
        sb.append(" 目标数量：").append(targets.size()).append(" 个请求\n");
        if (cfg != null && cfg.srcPlatform != null && !cfg.srcPlatform.trim().isEmpty()) {
            sb.append(" 定级依据：").append(cfg.srcPlatform).append(" 的规则\n");
        }
        sb.append("═══════════════════════════════════════════════════\n\n");

        // ---------- 一、URL / IP ----------
        sb.append("【").append(SECTIONS[0]).append("】\n");
        Set<String> urls = new LinkedHashSet<>();
        Set<String> hosts = new LinkedHashSet<>();
        for (PacketRecord r : targets) {
            String scheme = "https";
            String u = scheme + "://" + nvl(r.host) + nvl(r.path);
            if (r.rawRequest != null) {
                String req = new String(r.rawRequest, java.nio.charset.StandardCharsets.UTF_8);
                String q = queryOf(req);
                if (!q.isEmpty()) {
                    u += "?" + q;
                }
                if (req.startsWith("GET http://") || req.startsWith("POST http://")) {
                    u = u.replaceFirst("^https", "http");
                }
            }
            // 加上完整路径参数 —— 报告里必须能让复核者原样重现
            urls.add(u + "    [" + nvl(r.method) + "]");
            hosts.add(nvl(r.host));
        }
        for (String u : urls) {
            sb.append("  · ").append(u).append('\n');
        }
        if (hosts.size() == 1) {
            sb.append("\n  目标主机：").append(hosts.iterator().next()).append('\n');
        } else {
            sb.append("\n  涉及主机：").append(String.join("、", hosts)).append('\n');
        }

        // ---------- 二、风险评级 ----------
        sb.append("\n【").append(SECTIONS[1]).append("】\n");
        LocalRules.Level worst = LocalRules.Level.NONE;
        List<String> allIssues = new ArrayList<>();
        for (PacketRecord r : targets) {
            for (LocalRules.Issue i : r.issues) {
                if (i.level.rank > worst.rank) {
                    worst = i.level;
                }
                allIssues.add(i.level.label + "危 " + i.name + "（" + i.detail + "）");
            }
        }
        sb.append("  本地引擎定级：").append(worst.label).append("危");
        if (worst == LocalRules.Level.NONE) {
            sb.append("（本地规则未发现问题）");
        }
        sb.append('\n');
        if (!allIssues.isEmpty()) {
            sb.append("  依据：\n");
            for (String s : new LinkedHashSet<>(allIssues)) {
                sb.append("    · ").append(s).append('\n');
            }
        }
        if (cfg != null && cfg.srcRules != null && !cfg.srcRules.trim().isEmpty()) {
            sb.append("  ▲ 最终等级请按平台规则确认（规则已提供给 AI，见下方定级说明）\n");
        }

        // ---------- 三、危害说明（待 AI 补）----------
        sb.append("\n【").append(SECTIONS[2]).append("】\n");
        sb.append("  （待补充）\n");

        // ---------- 四、资产证明 ----------
        sb.append("\n【").append(SECTIONS[3]).append("】\n");
        sb.append("  需要自行补充证明材料，常见方式：\n");
        sb.append("    · 域名归属：WHOIS / ICP 备案查询 / SEO 查询平台的结果截图\n");
        sb.append("    · 网站关键信息截图（页面标题、版权信息、公司名）\n");
        sb.append("    · 网站关键数据截图（接口返回里能识别归属的字段）\n");
        sb.append("    · 注意：不要把真实用户数据放进报告，只放能证明归属的最小信息\n");

        // ---------- 五、渗透路径 ----------
        sb.append("\n【").append(SECTIONS[4]).append("】\n");
        int idx = 1;
        for (PacketRecord r : targets) {
            sb.append("  ").append(idx++).append(". ").append(nvl(r.method)).append(' ')
                    .append(nvl(r.host)).append(nvl(r.path)).append('\n');
            sb.append("     本地判定：").append(r.purpose).append("　")
                    .append(r.issues.isEmpty() ? "无本地发现" : r.issueSummary()).append('\n');
            if (!r.issues.isEmpty()) {
                for (LocalRules.Issue i : r.issues) {
                    sb.append("       · ").append(i.level.label).append("危 ")
                            .append(i.name).append("：").append(i.detail).append('\n');
                    if (i.evidence != null && !i.evidence.isEmpty()) {
                        sb.append("         证据：").append(i.evidence).append('\n');
                    }
                }
            }
            sb.append("     （完整请求 / 响应数据包请从 Burp 导出后附在报告里）\n");
        }
        sb.append("\n  通用漏洞（框架 / 中间件 / 组件）的写法：\n");
        sb.append("    · 给出 CVE 编号 或 官方公告 / 参考链接\n");
        sb.append("    · 说明使用了哪个 POC 工具及漏洞类型\n");

        // ---------- 六、修复建议（待 AI 补）----------
        sb.append("\n【").append(SECTIONS[5]).append("】\n");
        sb.append("  （待补充）\n");

        return sb.toString();
    }

    // ==================================================================
    // AI 补充
    // ==================================================================

    /** 报告生成的系统提示词。 */
    private static final String REPORT_SYSTEM_PROMPT =
            "你是一名资深渗透测试工程师，正在撰写一份提交给厂商 SRC 的漏洞报告。\n"
                    + "\n"
                    + "规则：\n"
                    + "1. 只使用用户提供的事实。不要编造 URL、参数、响应内容、CVE 编号。\n"
                    + "2. 如果事实不足以支撑某段内容，明确写「需补充：……」而不是猜测。\n"
                    + "3. 凭据类值已被脱敏（如 abcd****wxyz），这是正常的，不要试图还原。\n"
                    + "4. 分开写「已确认的事实」和「待验证的推测」。\n"
                    + "5. 用中文。语气专业、克制，不要夸张。\n"
                    + "6. 如果本地引擎只给出了「可能性」而没有确认漏洞，"
                    + "报告必须写明这是<b>待验证</b>的方向，不能写成已确认漏洞 —— "
                    + "提交不存在的漏洞会被平台扣分。\n";

    /**
     * 用 AI 补齐「危害说明」和「修复建议」。
     *
     * @param skeleton 本地骨架
     * @param cfg      配置
     * @return AI 返回的补充内容；失败时返回错误说明（不抛异常）
     */
    public LlmClient.Reply enrich(String skeleton, Config cfg) {
        StringBuilder user = new StringBuilder();
        user.append("以下是一份漏洞报告的本地骨架，含 URL、参数、本地规则结论与审计证据。\n");
        user.append("请补齐两段内容，严格按下面的格式输出，不要重复骨架里的其他部分：\n\n");
        user.append("【危害说明】\n");
        user.append("  讲清这个漏洞的危害。如果是逻辑漏洞（越权、金额篡改、状态绕过等），\n");
        user.append("  要说清楚<b>能做什么</b>、<b>影响谁</b>、<b>影响范围多大</b>。\n");
        user.append("  如果是 SQL 注入 / XSS 这类传统漏洞，也要说明具体能造成什么后果。\n\n");
        user.append("【渗透路径补充】\n");
        user.append("  给出可复现的分步操作（本地骨架里已有部分，你只补充缺的步骤）。\n");
        user.append("  通用漏洞给 CVE 编号或参考链接；用了 POC 工具要说明工具名和漏洞类型。\n\n");
        user.append("【修复建议】\n");
        user.append("  按优先级给出具体建议，不要只写「增加过滤」「升级版本」这种空话；\n");
        user.append("  但如果没有更具体的信息，也要说明「需结合代码确认」。\n\n");

        if (cfg != null && cfg.srcRules != null && !cfg.srcRules.trim().isEmpty()) {
            user.append("══════ 目标平台的漏洞评级规则（用户提供）══════\n");
            user.append(cfg.srcRules.trim()).append('\n');
            user.append("══════════════════════════════════════════════\n\n");
            user.append("请<b>按上面的平台规则</b>重新确认风险等级，并在【危害说明】开头"
                    + "明确写出「建议评级：Critical / High / Medium / Low（依据：规则的哪一条）」。\n");
            user.append("如果规则里没有对应条款，说明「规则未覆盖，建议按通用标准定级」。\n\n");
        } else {
            user.append("（用户未提供平台规则，请按通用标准给出 Critical/High/Medium/Low 的建议评级，"
                    + "并说明依据。）\n\n");
        }

        user.append("══════ 本地骨架 ══════\n");
        user.append(skeleton);

        return llm.chat(cfg, REPORT_SYSTEM_PROMPT, user.toString());
    }

    // ==================================================================

    static String queryOf(String reqRaw) {
        int q = reqRaw.indexOf('?');
        if (q < 0) {
            return "";
        }
        int sp = reqRaw.indexOf(' ', q);
        return sp > q ? reqRaw.substring(q + 1, sp) : reqRaw.substring(q + 1);
    }

    private static String nvl(String s) {
        return s == null ? "" : s;
    }

    /** 把代码审计结果并入报告骨架的「危害说明」区（作为事实输入）。 */
    public static String auditDigest(List<CodeAudit.Result> audits) {
        if (audits == null || audits.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (CodeAudit.Result r : audits) {
            sb.append(CodeAudit.toPromptText(r)).append('\n');
        }
        return sb.toString();
    }
}
