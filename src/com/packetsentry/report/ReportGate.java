package com.packetsentry.report;

import com.packetsentry.core.Finding;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 报告准入闸门 —— 「黄金六要素」+ 五类拒收形态。
 *
 * <h3>为什么要有这个</h3>
 * SRC / 众测里最伤信誉的不是"挖不到漏洞"，而是<b>提交了一份站不住的报告</b>：
 * 平台判误报 → 账号降权 → 严重时封号。而一份站不住的报告往往长这样：
 * <pre>
 *   「某接口可能存在越权，可能导致用户信息泄露，建议修复」
 * </pre>
 * 三句话没有一个可验证的事实 —— 没有 URL、没有版本、没有复现步骤、
 * 没有实际观测到的东西、影响是猜的。
 *
 * <h3>黄金六要素（缺一不可）</h3>
 * <ol>
 *   <li><b>目标与版本</b> —— 精确 URL/IP + 组件版本。不接受「最新版」「未知」。</li>
 *   <li><b>完整复现步骤</b> —— 请求/响应原文都在，别人能照着做出来。</li>
 *   <li><b>明确观测结果</b> —— PoC 有输出 / 有崩溃 / 拿到了不该拿的数据。</li>
 *   <li><b>具体影响描述</b> —— 说清"拿到什么、能做什么"。不接受「可能导致风险」。</li>
 *   <li><b>人工实测确认</b> —— 手动复现过，不是 AI 生成或文档推演。</li>
 *   <li><b>完整证据</b> —— 截图含地址栏与时间，脱敏后仍能判断。</li>
 * </ol>
 *
 * <h3>五类拒收形态</h3>
 * <ol>
 *   <li>AI 一键生成、未经人工复现的「<b>文字幻觉体</b>」</li>
 *   <li>调用已下线 / 未开放 API 的「<b>时空错位型</b>」</li>
 *   <li>截取 SDK 文档片段强行脑补的「<b>拼贴怪</b>」</li>
 *   <li>PoC 无输出、无崩溃、无权限提升的「<b>薛定谔漏洞</b>」</li>
 *   <li>影响描述空泛如「可能导致风险」的「<b>量子态危害</b>」</li>
 * </ol>
 *
 * <p><b>设计边界：</b>这是<b>写报告时的自检清单</b>，不是"漏洞是否成立"的判定。
 * 它只回答「这份报告够不够格提交」，不回答「这个漏洞是不是真的」——
 * 后者只能靠人。
 */
public final class ReportGate {

    private ReportGate() {
    }

    // ==================================================================
    // 黄金六要素
    // ==================================================================

    /** 报告必须具备的六个要素。 */
    public enum Element {
        TARGET_VERSION("目标与版本", "精确 URL/IP + 组件版本（不接受「最新版」「未知」）"),
        REPRO_STEPS("完整复现步骤", "请求与响应原文都在，别人能照做"),
        OBSERVED_RESULT("明确观测结果", "有输出 / 有崩溃 / 拿到了不该拿的数据"),
        CONCRETE_IMPACT("具体影响描述", "说清拿到什么、能做什么（不接受「可能导致风险」）"),
        MANUAL_VERIFIED("人工实测确认", "手动复现过，不是 AI 生成或文档推演"),
        COMPLETE_EVIDENCE("完整证据", "截图含地址栏与时间，脱敏后仍能判断");

        public final String label;
        public final String hint;

        Element(String label, String hint) {
            this.label = label;
            this.hint = hint;
        }
    }

    // ==================================================================
    // 五类拒收形态
    // ==================================================================

    /** 会被直接打回的五类报告。 */
    public enum Reject {
        AI_HALLUCINATION("文字幻觉体",
                "AI 一键生成、未经人工复现。特征是大量「根据经验」「通常」「一般来说」而无可验证事实"),
        DEAD_API("时空错位型",
                "引用了已下线或未开放的 API / 接口"),
        SDK_PASTE("拼贴怪",
                "把 SDK 文档片段当证据，没有在自己的目标上实测"),
        SCHRODINGER_POC("薛定谔漏洞",
                "PoC 无输出、无崩溃、无权限提升 —— 说了有洞但观测不到任何变化"),
        QUANTUM_IMPACT("量子态危害",
                "影响描述空泛如「可能导致风险」，不说具体拿到什么");

        public final String label;
        public final String hint;

        Reject(String label, String hint) {
            this.label = label;
            this.hint = hint;
        }
    }

    // ==================================================================
    // 检测规则
    // ==================================================================

    /** 空泛影响的典型措辞 —— 出现这些且没有具体宾语，就算「量子态危害」。 */
    private static final Pattern VAGUE_IMPACT = Pattern.compile(
            "(?:可能|也许|或许|大概|预计)(?:会)?(?:导致|造成|引发|带来|影响)"
                    + "|存在(?:一定的?)?(?:安全)?(?:风险|隐患)"
                    + "|可能(?:被|会)?(?:利用|攻击|绕过)"
                    + "|建议(?:尽快)?(?:修复|加固|整改)\\s*$");

    /** 具体影响的标志 —— 有这些说明真的说清了后果。 */
    private static final Pattern CONCRETE_IMPACT_MARK = Pattern.compile(
            "(?:读取|获取|拿到|下载|导出|修改|删除|绕过|登录|接管|提权|执行)"
                    + "|\\d+\\s*(?:条|名|个|万|千)(?:用户|记录|订单|账号)?"
                    + "|(?:任意|全部|其他用户|他人)(?:数据|信息|订单|账号)");

    /** 幻觉体措辞 —— 缺少实测支撑时的典型话术。 */
    private static final Pattern HALLUCINATION_MARK = Pattern.compile(
            "(?:根据经验|一般来说|通常情况|理论上|按惯例|应该是|推测|猜测|据了解)"
                    + "|(?:参考|依据).{0,10}(?:文档|教程|文章)");

    /** 已完成实测的标志。 */
    private static final Pattern VERIFIED_MARK = Pattern.compile(
            "(?:已实测|实测|复现成功|已验证|抓包确认|手动验证|亲自复现|回显|返回|响应中)");

    /** 版本号的形态。 */
    private static final Pattern VERSION_TOKEN = Pattern.compile(
            "\\bv?\\d+\\.\\d+(?:\\.\\d+)?\\b"
                    + "|\\b(?:Spring|Tomcat|Nginx|Apache|WebLogic|Shiro|Fastjson|Log4j|Struts2)"
                    + "\\s*\\d");

    /** 版本模糊的措辞。 */
    private static final Pattern VAGUE_VERSION = Pattern.compile(
            "(?:最新版|未知版本|版本未知|不确定版本|若干版本|某版本)");

    /** 已下线 / 未开放 API 的提示措辞。 */
    private static final Pattern DEAD_API_MARK = Pattern.compile(
            "(?:已下线|已废弃|deprecated|已停止服务|未开放|灰度中|内测接口|已移除)");

    /** 文档片段而非实测的提示。 */
    private static final Pattern SDK_DOC_MARK = Pattern.compile(
            "(?:官方文档|SDK 文档|开发手册|API 文档|帮助中心|接口说明)"
                    + "(?:中|里)?(?:提到|说明|写道|描述)");

    /** 请求/响应的结构标志。 */
    private static final Pattern HTTP_BLOCK = Pattern.compile(
            "(?m)^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\s+\\S+\\s+HTTP/\\d"
                    + "|(?m)^HTTP/\\d(?:\\.\\d)?\\s+\\d{3}");

    /** 观测结果的标志（PoC 真的产生了变化）。 */
    private static final Pattern OBSERVED_MARK = Pattern.compile(
            "(?:状态码|HTTP)\\s*[:：]?\\s*200|\\b200\\s*OK"
                    + "|(?:返回|响应).{0,12}(?:包含|含有|出现|泄露)"
                    + "|(?:越权|未授权).{0,12}(?:可|能)?(?:读取|访问|获取)"
                    + "|(?:崩溃|Crash|OOM|500)");

    // ==================================================================
    // 结果
    // ==================================================================

    /** 闸门结论。 */
    public static final class Result {
        /** 缺失的要素（空 = 六要素齐全）。 */
        public final List<Element> missing = new ArrayList<>();
        /** 命中拒收形态（空 = 没有明显问题）。 */
        public final List<Reject> rejected = new ArrayList<>();
        /** 每一类命中的具体依据（给人看的，不是判决）。 */
        public final List<String> notes = new ArrayList<>();

        public boolean pass() {
            return rejected.isEmpty() && missing.isEmpty();
        }

        /** 能不能提交：拒收形态是硬门槛，缺要素是软门槛。 */
        public boolean submittable() {
            return rejected.isEmpty();
        }

        /** 一句话结论。 */
        public String oneLine() {
            if (pass()) {
                return "√ 六要素齐全，未命中拒收形态 —— 可以提交";
            }
            if (!rejected.isEmpty()) {
                return "× 命中 " + rejected.size() + " 类拒收形态，建议重写"
                        + (missing.isEmpty() ? "" : "；另缺 " + missing.size() + " 个要素");
            }
            return "▲ 六要素缺 " + missing.size() + " 个 —— 补齐后再提交";
        }

        /** 给人看的分条说明。 */
        public String render() {
            StringBuilder sb = new StringBuilder();
            sb.append("══════════ 报告准入检查 ══════════\n");
            sb.append(oneLine()).append("\n\n");

            if (!rejected.isEmpty()) {
                sb.append("── 命中拒收形态（硬门槛，必须改）──\n");
                for (Reject r : rejected) {
                    sb.append("  × 【").append(r.label).append("】").append(r.hint).append('\n');
                }
                sb.append('\n');
            }
            if (!missing.isEmpty()) {
                sb.append("── 缺失要素（软门槛，补齐更好）──\n");
                for (Element e : missing) {
                    sb.append("  ▲ ").append(e.label).append("：").append(e.hint).append('\n');
                }
                sb.append('\n');
            }
            if (!notes.isEmpty()) {
                sb.append("── 判断依据 ──\n");
                for (String n : notes) {
                    sb.append("  · ").append(n).append('\n');
                }
                sb.append('\n');
            }
            sb.append("提示：「黄金六要素」是自检清单，不是漏洞是否成立的判定。\n");
            sb.append("      它只回答「够不够格提交」，成立与否只能靠你自己实测。\n");
            return sb.toString();
        }

        /** 给 AI 看的短文本（让 AI 帮忙补缺，而不是替它编）。 */
        public String toPromptText() {
            StringBuilder sb = new StringBuilder();
            sb.append("【报告准入检查结果】\n");
            sb.append(oneLine()).append('\n');
            for (Reject r : rejected) {
                sb.append("  命中拒收形态：").append(r.label).append(" —— ").append(r.hint).append('\n');
            }
            for (Element e : missing) {
                sb.append("  缺失要素：").append(e.label).append(" —— ").append(e.hint).append('\n');
            }
            sb.append("⚠️ 请只补充<b>已知事实</b>的表述；不知道的信息请写「待补」，不要编造。\n");
            return sb.toString();
        }
    }

    // ==================================================================
    // 检查
    // ==================================================================

    /**
     * 检查一段报告文本 / 一条发现是否够格提交。
     *
     * @param f          发现（可空；为空时只看文本）
     * @param reportText 报告正文（通常是 ReportTemplate 渲染出来的东西）
     */
    public static Result check(Finding f, String reportText) {
        Result out = new Result();
        String text = reportText == null ? "" : reportText;
        String lower = text.toLowerCase();

        // ---------- 要素 ① 目标与版本 ----------
        boolean hasUrl = f != null && f.url() != null && !f.url().isEmpty() && text.contains(f.url());
        if (!hasUrl) {
            // 文本里出现了 URL 形态也算
            hasUrl = text.contains("http://") || text.contains("https://") || text.contains("/api/");
        }
        boolean hasVersion = VERSION_TOKEN.matcher(text).find();
        boolean vagueVersion = VAGUE_VERSION.matcher(text).find();
        if (!hasUrl) {
            out.missing.add(Element.TARGET_VERSION);
            out.notes.add("没找到目标 URL/IP —— 平台的定位与去重都依赖它");
        } else if (!hasVersion) {
            out.missing.add(Element.TARGET_VERSION);
            out.notes.add("有目标但没有版本号 —— 平台无法判断适用性，也会被判「版本模糊」");
        } else if (vagueVersion) {
            out.missing.add(Element.TARGET_VERSION);
            out.rejected.add(Reject.DEAD_API);
            out.notes.add("版本写成「最新版/未知」这类 —— 判为版本模糊");
        }

        // ---------- 要素 ② 完整复现步骤 ----------
        Matcher mb = HTTP_BLOCK.matcher(text);
        int httpBlocks = 0;
        while (mb.find()) {
            httpBlocks++;
        }
        // 请求 + 响应至少要两块（一条请求行、一条状态行）
        if (httpBlocks < 2) {
            out.missing.add(Element.REPRO_STEPS);
            out.notes.add("请求/响应原文不足（找到 " + httpBlocks + " 个 HTTP 区块，至少要请求 + 响应各一块）"
                    + " —— 判为「PoC 半截」");
        }

        // ---------- 要素 ③ 明确观测结果 ----------
        if (!OBSERVED_MARK.matcher(text).find()) {
            out.missing.add(Element.OBSERVED_RESULT);
            out.rejected.add(Reject.SCHRODINGER_POC);
            out.notes.add("没有任何「观测到了什么」的描述（状态码/回显/越权读取/崩溃）"
                    + " —— 判为「薛定谔漏洞」");
        }

        // ---------- 要素 ④ 具体影响 ----------
        boolean concrete = CONCRETE_IMPACT_MARK.matcher(text).find();
        boolean vague = VAGUE_IMPACT.matcher(text).find();
        if (!concrete) {
            out.missing.add(Element.CONCRETE_IMPACT);
            if (vague) {
                out.rejected.add(Reject.QUANTUM_IMPACT);
                out.notes.add("影响描述是「可能导致风险」这类空泛措辞，且没有说清拿到什么"
                        + " —— 判为「量子态危害」");
            } else {
                out.notes.add("没有具体影响描述 —— 平台会认为「影响不明」而降级");
            }
        }

        // ---------- 要素 ⑤ 人工实测 ----------
        if (!VERIFIED_MARK.matcher(text).find()) {
            out.missing.add(Element.MANUAL_VERIFIED);
            if (HALLUCINATION_MARK.matcher(text).find()) {
                out.rejected.add(Reject.AI_HALLUCINATION);
                out.notes.add("出现「根据经验/一般来说/理论上」这类话术而缺少实测表述"
                        + " —— 判为「文字幻觉体」");
            } else {
                out.notes.add("没写明「已手动复现」—— 平台更信任明确标注实测的报告");
            }
        }

        // ---------- 要素 ⑥ 完整证据 ----------
        // 用"明确提到证据"来判断，不数截图张数（插件不知道用户截了几张）
        boolean hasEvidence = text.contains("截图")
                || text.contains("证据")
                || text.contains("复现步骤")
                || lower.contains("evidence");
        if (!hasEvidence) {
            out.missing.add(Element.COMPLETE_EVIDENCE);
            out.notes.add("没有提到任何截图 / 证据 —— 判为「截图半张」风险");
        }

        // ---------- 额外：文档拼贴 ----------
        if (SDK_DOC_MARK.matcher(text).find() && !VERIFIED_MARK.matcher(text).find()) {
            if (!out.rejected.contains(Reject.SDK_PASTE)) {
                out.rejected.add(Reject.SDK_PASTE);
                out.notes.add("只引用了「官方文档里说」而没有在自己目标上实测 —— 判为「拼贴怪」");
            }
        }

        // ---------- 额外：明确写了已下线 ----------
        if (DEAD_API_MARK.matcher(text).find() && !VERIFIED_MARK.matcher(text).find()) {
            if (!out.rejected.contains(Reject.DEAD_API)) {
                out.rejected.add(Reject.DEAD_API);
                out.notes.add("文中出现「已下线/未开放/deprecated」—— 判为「时空错位型」");
            }
        }

        return out;
    }

    /** 六要素清单（写报告时的对照表）。 */
    public static String checklist() {
        StringBuilder sb = new StringBuilder();
        sb.append("══════════ 报告准入 · 黄金六要素 ══════════\n\n");
        int i = 1;
        for (Element e : Element.values()) {
            sb.append("  ").append(i++).append(". ").append(e.label).append('\n');
            sb.append("     ").append(e.hint).append("\n\n");
        }
        sb.append("── 会被直接打回的五类 ──\n\n");
        for (Reject r : Reject.values()) {
            sb.append("  × ").append(r.label).append('\n');
            sb.append("     ").append(r.hint).append("\n\n");
        }
        sb.append("不再接受：截图半张、PoC 半截、版本模糊、影响玄学。\n");
        return sb.toString();
    }
}
