package com.packetsentry.audit;

import com.packetsentry.core.PacketRecord;
import com.packetsentry.detect.LocalRules;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * OWASP Top 10:2025 覆盖度视图。
 *
 * <h3>这个类解决的是什么问题</h3>
 * 用户常问「能不能检测 OWASP Top 10 的漏洞」。诚实的答案是
 * <b>不能，而且结构上就不能</b> —— OWASP Top 10 是「漏洞类别」，
 * 被动观察只能看到「痕迹」。
 *
 * <p>与其假装覆盖全部，不如<b>把每一类的真实覆盖情况说清楚</b>：
 * <ul>
 *   <li>本工具能检测到什么程度（好 / 部分 / 不能）</li>
 *   <li>从当前流量里已经发现了哪些相关线索</li>
 *   <li><b>检测不到的部分该用什么办法</b> —— 这才是最有价值的信息</li>
 * </ul>
 *
 * <h3>为什么要明确标出「不能」</h3>
 * 一个只说「已覆盖」的工具会让人误以为「没报就是安全」。
 * 明确标出「这类我测不了，你得用 sqlmap / 手工测」，
 * 才能让用户把精力放到对的地方。
 */
public final class OwaspTop10 {

    /** 本工具对某类漏洞的覆盖程度。 */
    public enum Coverage {
        /** 规则覆盖较好，被动流量能发现。 */
        GOOD("√ 可检测", "被动流量就能发现"),
        /** 能看到线索，但确认需要主动测试。 */
        PARTIAL("▲ 部分", "能看到线索，确认需主动测试"),
        /** 被动观察结构上就看不到。 */
        NONE("× 不能", "被动观察看不到，必须主动测试");

        public final String label;
        public final String note;

        Coverage(String label, String note) {
            this.label = label;
            this.note = note;
        }
    }

    /** 一类 OWASP 漏洞。 */
    public static final class Category {
        public final String id;
        public final String name;
        public final Coverage coverage;
        /** 本工具从当前流量里发现的线索。 */
        public final List<String> hits = new ArrayList<>();
        /** 检测不到的部分该怎么做。 */
        public final String howToTest;
        /** 本工具哪些规则对应这一类。 */
        public final String ourRules;

        Category(String id, String name, Coverage c, String howToTest, String ourRules) {
            this.id = id;
            this.name = name;
            this.coverage = c;
            this.howToTest = howToTest;
            this.ourRules = ourRules;
        }
    }

    // ==================================================================

    /**
     * 按当前流量里的发现，生成 OWASP Top 10 覆盖度报告。
     *
     * @param records 当前会话的记录
     */
    public static List<Category> evaluate(List<PacketRecord> records) {
        List<Category> out = new ArrayList<>();

        // ---- A01:2025 越权（连续 4 次第 1，40 个 CWE；SSRF 已并入本类）----
        Category a01 = new Category("A01:2025", "越权 / 访问控制失效（Broken Access Control）",
                Coverage.PARTIAL,
                "本工具能做：\n"
                        + "  · 逻辑线索里的 ID可预测 / 归属字段可控 / 权限字段可控，"
                        + "直接指出哪些接口该测越权\n"
                        + "  · 「越权测试」用另一个身份的凭据重放，自动对比响应\n"
                        + "  · 代码审计里的「前端权限判断」—— 前端判权限说明服务端可能没判\n"
                        + "做不了的：\n"
                        + "  · 需要你注册两个账号并配置身份\n"
                        + "  · 最终判定要人工看，工具只给信号\n"
                        + "  · SSRF 已并入本类，但它必须主动测试（见下方说明）",
                "逻辑线索（ID可预测/归属字段/权限字段）+ 越权测试 + 前端权限判断");
        collectPurpose(a01, records, "ID可预测", "归属字段", "权限字段");
        out.add(a01);

        // ---- A02:2025 安全配置错误（从 #5 升到 #2，涨幅最大）----
        Category a02 = new Category("A02:2025", "安全配置错误（Security Misconfiguration）",
                Coverage.GOOD,
                "2025 版把这一类从第 5 位提到第 2 位，涨幅最大 —— "
                        + "因为云 / 容器 / 微服务让配置面急剧变大。\n\n"
                        + "这是本工具覆盖最好的一类：调试页、堆栈、版本泄露、"
                        + "备份文件、敏感路径、目录列表、Source Map、"
                        + "以及 2025 版新增的<b>安全响应头缺失</b>检测。\n\n"
                        + "仍需手工看的：云存储策略、默认口令、CORS 配置面。",
                "安全响应头缺失 / 调试信息 / 版本泄露 / 备份文件 / 敏感路径 / "
                        + "服务器路径 / Source Map / CORS反射 / 明文HTTP / Cookie属性");
        collectPurpose(a02, records, "安全响应头", "调试信息", "版本泄露", "备份",
                "敏感路径", "服务器路径", "Source Map", "CORS", "明文HTTP", "Cookie属性");
        out.add(a02);

        // ---- A03:2025 软件供应链缺陷（★ 全新，5 个 CWE）----
        Category a03 = new Category("A03:2025", "软件供应链缺陷（Software Supply Chain Failures）",
                Coverage.PARTIAL,
                "★ 2025 新增类别。对应 SolarWinds、Log4Shell、依赖混淆这类攻击 —— "
                        + "攻击供应链比直接打应用更容易。\n\n"
                        + "本工具能做：\n"
                        + "  · 发现页面从外部域加载脚本且<b>没有 integrity 校验</b>\n"
                        + "  · 从 JS 里识别前端组件与版本（供你去查有没有已知漏洞）\n"
                        + "  · 代码审计里的硬编码凭据、Source Map 泄露\n"
                        + "做不了的：\n"
                        + "  · <b>本插件没有 CVE / SCA 库</b>，判不了某个依赖有无已知漏洞\n"
                        + "  · 依赖混淆、构建管线完整性、构件签名 —— 这些在源码 / CI 层，不在流量里\n\n"
                        + "拿到版本号后自己查：NVD / 组件官方安全公告 / SBOM 工具。",
                "第三方脚本无完整性校验 / 组件版本指纹 / 硬编码凭据 / Source Map 泄露");
        collectPurpose(a03, records, "第三方脚本", "组件版本", "硬编码凭据", "Source Map");
        out.add(a03);

        // ---- A04:2025 加密失败（2→4，仍在高位）----
        Category a04 = new Category("A04:2025", "加密失败（Cryptographic Failures）",
                Coverage.PARTIAL,
                "本工具能做：\n"
                        + "  · 发现明文 HTTP 传输\n"
                        + "  · 发现 Cookie 缺 HttpOnly / Secure / SameSite\n"
                        + "  · 从 JS 里看有没有硬编码密钥\n"
                        + "  · 缺 HSTS（在「安全响应头缺失」里）\n"
                        + "做不了的：\n"
                        + "  · TLS 配置、证书链、加密套件强弱（用 testssl.sh / ssllabs）\n"
                        + "  · 密码存储方式、密钥管理（要看源码或数据库）",
                "明文HTTP / Cookie属性缺失 / 硬编码凭据 / 安全响应头缺失(HSTS)");
        collectPurpose(a04, records, "明文HTTP", "Cookie属性", "硬编码凭据", "安全响应头");
        out.add(a04);

        // ---- A05:2025 注入（3→5，但依然最常被实际利用）----
        Category a05 = new Category("A05:2025", "注入（Injection）",
                Coverage.NONE,
                "排名从第 3 降到第 5 —— 那是参数化查询普及的成果，"
                        + "但 OWASP 数据集里它仍对应 <b>27.4 万个缺陷</b>，"
                        + "而且是实战中被利用最多的类别之一。\n\n"
                        + "本工具只能检测响应里的报错特征（SQL 错误、堆栈），"
                        + "那要求<b>已经有人注入了</b>。\n\n"
                        + "真正的注入测试必须主动构造 payload：\n"
                        + "  · SQL 注入：sqlmap / 手工加单引号看报错\n"
                        + "  · XSS：在参数里试 \"'<>，看是否被原样输出\n"
                        + "  · 命令注入：试 ; | ` $( )\n"
                        + "  · 模板注入：试 {{7*7}} ${7*7}\n\n"
                        + "本工具的价值是：<b>把可疑参数挑出来</b>，告诉你哪些地方值得注入。",
                "错误细节泄露 / SQL报错（仅检测报错，不检测注入点）");
        collectPurpose(a05, records, "错误细节", "SQL报错");
        out.add(a05);

        // ---- A06:2025 不安全设计（4→6）----
        Category a06 = new Category("A06:2025", "不安全设计（Insecure Design）",
                Coverage.PARTIAL,
                "本工具能做：\n"
                        + "  · 逻辑线索里的「金额可篡改」「数量可篡改」「状态字段可控」"
                        + "直接指向设计缺陷\n"
                        + "  · 「可重复提交」「频控缺失」指向幂等与限流设计问题\n"
                        + "做不了的：\n"
                        + "  · 判定设计是否真的不安全 —— 要结合业务规则人工判断\n"
                        + "  · 并发竞争（需同时发多个请求）",
                "逻辑线索（金额/数量/状态/可重复提交/频控缺失）");
        collectPurpose(a06, records, "金额可篡改", "数量可篡改", "状态字段",
                "可重复提交", "频控缺失");
        out.add(a06);

        // ---- A07:2025 认证失败（改名，去掉「识别」）----
        Category a07 = new Category("A07:2025", "认证失败（Authentication Failures）",
                Coverage.PARTIAL,
                "2025 版改了名，去掉「识别」，更聚焦认证机制本身"
                        + "（凭据处理、会话管理、MFA 缺口）。\n\n"
                        + "本工具能做：\n"
                        + "  · 发现改状态请求缺 CSRF 令牌\n"
                        + "  · 分析 JWT（alg / exp / role，可本地解码）\n"
                        + "  · 发现 Cookie 缺安全属性\n"
                        + "  · 发现登录接口可高频调用（频控缺失）\n"
                        + "做不了的：\n"
                        + "  · 密码策略强度、账号锁定、暴力破解（要主动跑字典）\n"
                        + "  · 会话固定 / 会话过期 / MFA 绕过 / 密码重置逻辑",
                "无CSRF令牌 / JWT凭证 / Cookie属性缺失 / 频控缺失");
        collectPurpose(a07, records, "CSRF", "JWT", "Cookie属性", "频控缺失");
        out.add(a07);

        // ---- A08:2025 软件「或」数据完整性失败（轻微改名）----
        Category a08 = new Category("A08:2025", "软件或数据完整性失败（Software or Data Integrity Failures）",
                Coverage.PARTIAL,
                "2025 版把「和」改成「或」—— 强调软件完整性与数据完整性是"
                        + "各自独立的关注点，任一出问题都算本类。\n\n"
                        + "本工具能做：\n"
                        + "  · Source Map 泄露（能还原源码）\n"
                        + "  · 前端硬编码凭据\n"
                        + "  · 第三方脚本缺 integrity 校验（与 A03 重叠）\n"
                        + "做不了的：\n"
                        + "  · 不安全的反序列化（要看数据格式和代码）\n"
                        + "  · 供应链投毒、自动更新机制缺陷",
                "Source Map 泄露 / 硬编码凭据 / 第三方脚本无完整性校验");
        collectPurpose(a08, records, "Source Map", "硬编码凭据", "第三方脚本");
        out.add(a08);

        // ---- A09:2025 日志与告警失败（改名：监控→告警）----
        Category a09 = new Category("A09:2025", "安全日志与告警失败（Security Logging and Alerting Failures）",
                Coverage.NONE,
                "2025 版把「监控」改成<b>「告警」</b>，强调："
                        + "只记录不告警等于没发现攻击。\n\n"
                        + "这一类<b>被动观察完全看不到</b>，因为它描述的是"
                        + "「服务端有没有记录和告警」。\n\n"
                        + "唯一验证方式是主动发攻击流量，然后看：\n"
                        + "  · 你的账号有没有被踢下线 / 被锁定\n"
                        + "  · 有没有收到告警邮件 / 短信\n"
                        + "  · 有没有被 WAF 拦\n\n"
                        + "▲ 这个测试会触发告警。做之前先确认目标授权范围。",
                "（无）");
        out.add(a09);

        // ---- A10:2025 异常情况处理不当（★ 全新，24 个 CWE）----
        Category a10 = new Category("A10:2025", "异常情况处理不当（Mishandling of Exceptional Conditions）",
                Coverage.PARTIAL,
                "★ 2025 新增类别。OWASP 调查中 <b>50% 的受访者把它列为第一关注</b>，"
                        + "但 CVE 库里几乎没有记录 —— 因为它只在压力 / 异常条件下才暴露，"
                        + "标准 SAST/DAST 扫不到。\n\n"
                        + "含 24 个 CWE，重点是：\n"
                        + "  · <b>CWE-209</b> 错误消息里含敏感信息\n"
                        + "  · <b>CWE-636</b> fail-open（出错时不拒绝反而放行）\n"
                        + "  · CWE-476 空指针解引用\n\n"
                        + "★ 本工具能做（错误响应本来就在流量里）：\n"
                        + "  · 检测 8 种技术栈的内部错误细节泄露（PHP/Java/Python/Node/.NET/Go/Ruby/SQL）\n"
                        + "  · 检测 <b>fail-open 迹象</b>：状态码 2xx 却同时出现错误关键词和业务数据\n"
                        + "做不了的：\n"
                        + "  · 资源耗尽、超时、下游故障下的行为（需故障注入 / 混沌工程）\n"
                        + "  · 空指针等代码级缺陷",
                "错误细节泄露 / 疑似fail-open / 调试信息泄露");
        collectPurpose(a10, records, "错误细节", "fail-open", "调试信息");
        out.add(a10);

        return out;
    }
    // ==================================================================

    /** 从记录的本地规则/逻辑线索里挑出指定名称的发现。 */
    private static void collectPurpose(Category c, List<PacketRecord> records, String... keywords) {
        Set<String> seen = new LinkedHashSet<>();
        for (PacketRecord r : records) {
            for (LocalRules.Issue i : r.issues) {
                for (String k : keywords) {
                    if (i.name.contains(k)) {
                        String line = i.name + "　" + r.method + " " + r.host + r.path;
                        if (seen.add(line) && seen.size() <= 12) {
                            c.hits.add(line);
                        }
                    }
                }
            }
        }
    }

    /** 代码审计类的发现（存在记录里时不重复跑审计）。 */
    private static void collectAudit(Category c, List<PacketRecord> records, String keyword) {
        // 代码审计是按需触发的，结果不落在 PacketRecord 上，所以这里只做占位说明
        // —— 保持诚实：没跑过就不假装有结果
    }

    // ==================================================================

    /** 生成给用户看的覆盖度报告。 */
    public static String render(List<Category> cats, int totalRecords) {
        StringBuilder sb = new StringBuilder();
        sb.append("══════════ OWASP Top 10:2025 覆盖度 ══════════\n\n");
        sb.append("会话记录 ").append(totalRecords).append(" 条\n\n");
        sb.append("说明：本工具是<b>被动流量分析器</b>，只能看到流经代理的内容。\n");
        sb.append("      OWASP Top 10 是「漏洞类别」，被动观察只能看到「痕迹」，\n");
        sb.append("      所以下面明确标出每一类的真实覆盖程度 —— 不假装全覆盖。\n\n");
        sb.append("2025 版变化：A02 安全配置错误从 #5 升到 #2（涨幅最大）；\n");
        sb.append("            A03 软件供应链缺陷、A10 异常处理不当 为★全新类别；\n");
        sb.append("            原 A10 SSRF 已并入 A01 越权。\n\n");

        int good = 0;
        int partial = 0;
        int none = 0;
        for (Category c : cats) {
            switch (c.coverage) {
                case GOOD:
                    good++;
                    break;
                case PARTIAL:
                    partial++;
                    break;
                default:
                    none++;
            }
        }
        sb.append("覆盖统计：可检测 ").append(good)
                .append(" 类　部分 ").append(partial)
                .append(" 类　不能 ").append(none).append(" 类\n\n");

        for (Category c : cats) {
            sb.append("───────────────────────────────────────────────\n");
            sb.append(c.id).append("  ").append(c.name).append('\n');
            sb.append("覆盖度  ").append(c.coverage.label)
                    .append("　").append(c.coverage.note).append('\n');
            sb.append("对应规则 ").append(c.ourRules).append('\n');

            if (!c.hits.isEmpty()) {
                sb.append("本次发现的线索：\n");
                for (String h : c.hits) {
                    sb.append("  · ").append(h).append('\n');
                }
            } else {
                sb.append("本次发现的线索：无\n");
            }

            sb.append("怎么做：\n");
            for (String line : c.howToTest.split("\n")) {
                sb.append("  ").append(line).append('\n');
            }
            sb.append('\n');
        }

        sb.append("───────────────────────────────────────────────\n");
        sb.append("▲ 重要：\n");
        sb.append("  · 标「不能」的两类：\n");
        sb.append("      A05:2025 注入（要主动构造 payload）\n");
        sb.append("      A09:2025 日志告警（要主动发攻击流量看是否被记录）\n");
        sb.append("    本工具<b>结构上无法检测</b>，必须用主动工具或手工验证。\n");
        sb.append("  · 标「部分」的类别只能给你<b>线索和方向</b>，不能给结论。\n");
        sb.append("  · 只有 A02:2025（安全配置错误）覆盖较好 —— 那类问题本就适合被动发现。\n");
        sb.append("    它恰好是 2025 版升幅最大的一类（#5 → #2）。\n");
        sb.append("  · 「没发现」不等于「安全」—— 这一点请务必记住。\n");
        return sb.toString();
    }

    /** 汇总成给 AI 的文本（生成报告时带上）。 */
    public static String toPromptText(List<Category> cats) {
        StringBuilder sb = new StringBuilder();
        sb.append("OWASP Top 10 覆盖度（由被动流量分析得出）：\n");
        for (Category c : cats) {
            sb.append("  ").append(c.id).append(' ').append(c.name)
                    .append("　覆盖度：").append(c.coverage.label);
            if (!c.hits.isEmpty()) {
                sb.append("　线索：").append(String.join("；", c.hits));
            }
            sb.append('\n');
        }
        return sb.toString();
    }
}
