package com.packetsentry.ai;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 一条「待验证的漏洞假设」。
 *
 * <h2>⚠️ 这个类里最重要的是它的设计哲学</h2>
 *
 * <p>本插件<b>不使用「AI 发现了漏洞」这个表述</b>，因为它做不到。
 * AI 读一遍 HTTP 流量能做的事情只有一件：<b>提出可验证的假设</b>。
 * 真正的确认必须由人在授权目标上发请求、看响应。
 *
 * <p>如果让 AI 直接输出「发现越权漏洞」，那 100% 就是用户定义的
 * <b>「文字幻觉体」</b>：AI 一键生成、未经人工复现。
 *
 * <p>所以这里有一个硬约束：{@link Status#CONFIRMED} <b>只能由人设置</b>。
 * AI 返回的结果一律是 {@link Status#PROPOSED}。
 * 而 {@link Gate} 会拒掉任何没有 CONFIRMED 的假设 —— 它进不了报告。
 *
 * <h2>它如何天然满足「五类拒收」</h2>
 * <table border="1">
 *   <tr><th>拒收形态</th><th>本类怎么挡住</th></tr>
 *   <tr><td>文字幻觉体</td>
 *       <td>AI 无权设为 CONFIRMED；未确认的假设不能进报告</td></tr>
 *   <tr><td>时空错位型</td>
 *       <td>{@link #route} 必须能在真实流量里找到，否则闸门拒收</td></tr>
 *   <tr><td>拼贴怪</td>
 *       <td>{@link #basis} 必须引用<b>观测到的</b>具体片段，不能只说「文档里提到」</td></tr>
 *   <tr><td>薛定谔漏洞</td>
 *       <td>{@link #expected} 必须可证伪；{@link #testSteps} 必须能照着做</td></tr>
 *   <tr><td>量子态危害</td>
 *       <td>{@link #impact} 必须有具体宾语，不接受「可能导致风险」</td></tr>
 * </table>
 */
public final class Hypothesis {

    /** 假设的生命周期。 */
    public enum Status {
        /** AI 刚提出，未验证。 */
        PROPOSED("待验证"),
        /** 人正在测。 */
        TESTING("验证中"),
        /** 人已实测证实 —— <b>只有人能设这个状态</b>。 */
        CONFIRMED("已证实"),
        /** 测过了，不成立。 */
        REJECTED("已否定");

        public final String label;

        Status(String label) {
            this.label = label;
        }
    }

    /** AI 自评的可信度 —— 只是排序提示，不是结论。 */
    public enum Confidence {
        LOW("低"), MEDIUM("中"), HIGH("高");

        public final String label;

        Confidence(String label) {
            this.label = label;
        }
    }

    // ==================================================================
    // 黄金六要素的字段载体
    // ==================================================================

    /** 假设标题（一句话说清猜的是什么）。 */
    public final String title;
    /** 对应哪条真实路由 —— 必须来自抓包，用于挡「时空错位型」。 */
    public final String route;
    /** HTTP 方法。 */
    public final String method;
    /**
     * 依据：观测到的<b>具体证据</b>（响应片段 / 参数 / 行为差异）。
     *
     * <p>挡「拼贴怪」——不能只说「官方文档提到该参数支持注入」。
     */
    public final String basis;
    /**
     * 可执行的测试步骤（至少 2 步，含具体请求）。
     *
     * <p>挡「薛定谔漏洞」——没有步骤就没法证伪。
     */
    public final List<String> testSteps;
    /**
     * 什么现象算证实（必须可证伪）。
     *
     * <p>挡「薛定谔漏洞」——「可能会越权」不是判据，「A 的令牌拿到 B 的订单」
     * 才是判据。
     */
    public final String expected;
    /**
     * 若成立，具体影响是什么。
     *
     * <p>挡「量子态危害」——必须有具体宾语（拿到什么数据、能做什么操作）。
     * 未知时应当写「待验证」而不是编一个。
     */
    public final String impact;
    /** AI 自评可信度。 */
    public final Confidence confidence;

    /** 当前状态。AI 只能给 PROPOSED。 */
    public Status status = Status.PROPOSED;

    /** 人工验证记录：测了什么、看到什么。 */
    public String humanNote = "";

    public Hypothesis(String title, String route, String method, String basis,
                      List<String> testSteps, String expected, String impact,
                      Confidence confidence) {
        this.title = nz(title);
        this.route = nz(route);
        this.method = nz(method);
        this.basis = nz(basis);
        this.testSteps = testSteps == null ? new ArrayList<>() : new ArrayList<>(testSteps);
        this.expected = nz(expected);
        this.impact = nz(impact);
        this.confidence = confidence == null ? Confidence.LOW : confidence;
    }

    private static String nz(String s) {
        return s == null ? "" : s.trim();
    }

    // ==================================================================
    // 闸门
    // ==================================================================

    /** 一个假设为什么过不了闸门。 */
    public static final class Verdict {
        /** 缺失的要素（人话描述）。 */
        public final List<String> missing = new ArrayList<>();
        /** 命中的拒收形态（用 ReportGate 里同一套名字）。 */
        public final List<String> rejected = new ArrayList<>();
        /** 判断依据。 */
        public final List<String> notes = new ArrayList<>();

        public boolean pass() {
            return missing.isEmpty() && rejected.isEmpty();
        }

        public String oneLine() {
            if (pass()) {
                return "√ 这条假设够格写进报告";
            }
            if (!rejected.isEmpty()) {
                return "× 命中 " + rejected.size() + " 类拒收形态：" + String.join("、", rejected);
            }
            return "▲ 还缺 " + missing.size() + " 个要素：" + String.join("、", missing);
        }

        public String render() {
            StringBuilder sb = new StringBuilder();
            sb.append(oneLine()).append('\n');
            for (String r : rejected) {
                sb.append("  × ").append(r).append('\n');
            }
            for (String m : missing) {
                sb.append("  ▲ ").append(m).append('\n');
            }
            for (String n : notes) {
                sb.append("  · ").append(n).append('\n');
            }
            return sb.toString();
        }
    }

    /** 空泛影响的措辞 —— 命中且无具体宾语就是「量子态危害」。 */
    private static final Pattern VAGUE_IMPACT = Pattern.compile(
            "(?:可能|也许|或许|大概|预计)(?:会)?(?:导致|造成|引发|带来|影响)"
                    + "|存在(?:一定的?)?(?:安全)?(?:风险|隐患)"
                    + "|可能(?:被|会)?(?:利用|攻击|绕过)");

    /** 具体影响的标志。 */
    private static final Pattern CONCRETE_IMPACT = Pattern.compile(
            "(?:读取|获取|拿到|下载|导出|修改|删除|绕过|登录|接管|提权|执行|遍历)"
                    + "|\\d+\\s*(?:条|名|个|万|千)"
                    + "|(?:任意|全部|其他用户|他人)(?:数据|信息|订单|账号|文件)");

    /** 可证伪的判据标志。 */
    private static final Pattern FALSIFIABLE = Pattern.compile(
            "(?:若|如果|当).{0,40}(?:则|就|即|说明|表示)"
                    + "|(?:返回|响应|状态码|HTTP)\\s*.{0,12}\\d{3}"
                    + "|(?:包含|出现|未出现|不包含|缺少|变成)"
                    + "|(?:对比|与.{0,10}相比|差异)");

    /** 文档/教程口吻 —— 单独的「文档里提到」不构成依据。 */
    private static final Pattern DOC_ONLY = Pattern.compile(
            "(?:官方文档|SDK 文档|开发手册|API 文档|帮助中心|接口说明|教程|文章)"
                    + "(?:中|里)?(?:提到|说明|写道|描述|介绍)");

    /**
     * 观测性依据的标志（引用抓到的具体东西）。
     *
     * <h3>⚠️ 这里刻意只放<b>观测动词</b>和<b>真实请求行</b>，不放名词</h3>
     * 第一版把「参数」「头」「body」也列了进来，结果：
     * <pre>
     *   依据 = "官方文档里提到该<b>参数</b>支持 SQL 拼接"
     * </pre>
     * 因为含「参数」二字，被判成"有观测"，于是<b>拼贴怪漏过了闸门</b>。
     *
     * <p>名词谁都能写，动词才表示真的看了。所以现在只认：
     * 响应 / 返回 / 回显 / 抓包 / 观测 / 实测 / 请求，
     * 或者一条字面意义上的 HTTP 请求行。
     */
    private static final Pattern OBSERVED_BASIS = Pattern.compile(
            "(?:响应|返回|回显|抓包|观测|实测|请求)"
                    + "|\\b\\d{100,}\\b"
                    + "|(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\s+/");

    /**
     * 检查这条假设够不够格写进报告。
     *
     * <p>判据是<b>能否被证伪</b>，而不是「听起来像不像真的」。
     * 一条说得再像的假设，只要没有可执行的验证步骤和明确的判据，
     * 写进报告就是给平台送误报。
     */
    public Verdict gate() {
        Verdict v = new Verdict();

        // ---- ① 状态：必须人已证实的 ----
        //
        // ⚠️ 这是<b>最重要</b>的一条，也是挡「文字幻觉体」的唯一有效手段：
        //    AI 只能产出 PROPOSED，而 PROPOSED 永远进不了报告。
        if (status != Status.CONFIRMED) {
            v.rejected.add("文字幻觉体：状态是「" + status.label
                    + "」，不是「已证实」 —— AI 提出的假设不算发现");
        }

        // ---- ② 路由必须来自真实流量（由调用方回填，这里只看非空） ----
        if (route.isEmpty()) {
            v.rejected.add("时空错位型：没指明对应哪条真实路由");
        }
        if (method.isEmpty()) {
            v.missing.add("HTTP 方法（GET/POST/…）");
        }

        // ---- ③ 依据必须是观测，不能是文档 ----
        if (basis.isEmpty()) {
            v.missing.add("依据（观测到的具体证据）");
        } else {
            boolean docOnly = DOC_ONLY.matcher(basis).find()
                    && !OBSERVED_BASIS.matcher(basis).find();
            if (docOnly) {
                v.rejected.add("拼贴怪：依据只有「文档里提到」，没有在真实目标上观测到的东西");
            } else if (!OBSERVED_BASIS.matcher(basis).find()) {
                v.missing.add("依据里缺少可核对的观测对象（响应片段 / 参数 / 状态码）");
            }
        }

        // ---- ④ 测试步骤：可执行 ----
        if (testSteps.size() < 2) {
            v.rejected.add("薛定谔漏洞：可执行步骤不足 2 步（现在是 "
                    + testSteps.size() + " 步）");
        } else {
            // 至少一步要提到具体请求或参数，否则「步骤」只是废话
            boolean hasConcrete = false;
            for (String s : testSteps) {
                if (OBSERVED_BASIS.matcher(s).find()) {
                    hasConcrete = true;
                    break;
                }
            }
            if (!hasConcrete) {
                v.missing.add("步骤里要有具体请求（方法 + 路径 / 参数 / 载荷）");
            }
        }

        // ---- ⑤ 判据可证伪 ----
        if (expected.isEmpty()) {
            v.rejected.add("薛定谔漏洞：没说什么现象算证实");
        } else if (!FALSIFIABLE.matcher(expected).find()) {
            v.rejected.add("薛定谔漏洞：判据不可证伪（「可能越权」不是判据，"
                    + "「A 的令牌拿到 B 的订单」才是）");
        }

        // ---- ⑥ 影响必须具体 ----
        if (impact.isEmpty()) {
            v.missing.add("影响描述");
        } else if (VAGUE_IMPACT.matcher(impact).find()
                && !CONCRETE_IMPACT.matcher(impact).find()) {
            v.rejected.add("量子态危害：影响只有「可能导致风险」这类空泛措辞，"
                    + "没说清拿到什么、能做什么");
        } else if (!impact.contains("待验证")
                && !CONCRETE_IMPACT.matcher(impact).find()) {
            v.missing.add("影响里缺少具体对象（拿到什么数据 / 能做什么操作），"
                    + "未知请写「待验证」");
        }

        // ---- 人工验证必须留记录 ----
        if (status == Status.CONFIRMED && humanNote.trim().isEmpty()) {
            v.missing.add("人工验证记录（测了什么、看到什么）—— 标了「已证实」就要留下依据");
        }

        return v;
    }

    /** 是否够格写进报告。 */
    public boolean promotable() {
        return gate().pass();
    }

    // ==================================================================
    // 展示
    // ==================================================================

    /** 一行摘要（列表用）。 */
    public String oneLine() {
        return "[" + confidence.label + "·" + status.label + "] " + title;
    }

    /** 完整卡片（详情用）。 */
    public String render() {
        StringBuilder sb = new StringBuilder();
        sb.append("┌─ ").append(title).append('\n');
        sb.append("│ 路由　").append(method).append(' ').append(route).append('\n');
        sb.append("│ 可信度 ").append(confidence.label)
                .append("　状态 ").append(status.label).append('\n');
        sb.append("│ 依据　").append(basis).append('\n');
        sb.append("│ 验证步骤\n");
        for (int i = 0; i < testSteps.size(); i++) {
            sb.append("│   ").append(i + 1).append(". ").append(testSteps.get(i)).append('\n');
        }
        sb.append("│ 判据　").append(expected).append('\n');
        sb.append("│ 影响　").append(impact).append('\n');
        if (!humanNote.trim().isEmpty()) {
            sb.append("│ 人工记录 ").append(humanNote).append('\n');
        }
        Verdict v = gate();
        sb.append("│ ").append(v.oneLine()).append('\n');
        sb.append("└─");
        return sb.toString();
    }

    /** 渲染成报告里的 Markdown 段（只在 promotable 时用）。 */
    public String toMarkdown(int index) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n### ").append(index).append(". ").append(title).append('\n');
        sb.append("- 路由：`").append(method).append(' ').append(route).append("`\n");
        sb.append("- 依据：").append(basis).append('\n');
        sb.append("- 验证步骤：\n");
        for (int i = 0; i < testSteps.size(); i++) {
            sb.append("  ").append(i + 1).append(". ").append(testSteps.get(i)).append('\n');
        }
        sb.append("- 判定依据：").append(expected).append('\n');
        sb.append("- 影响：").append(impact).append('\n');
        if (!humanNote.trim().isEmpty()) {
            sb.append("- 人工验证：").append(humanNote).append('\n');
        }
        return sb.toString();
    }

    /** 给 AI 的提示文本（让它按同样格式补充或复核）。 */
    public String toPromptText() {
        return "【假设】" + title + "\n"
                + "路由：" + method + " " + route + "\n"
                + "依据：" + basis + "\n"
                + "步骤：" + String.join(" / ", testSteps) + "\n"
                + "判据：" + expected + "\n"
                + "影响：" + impact + "\n"
                + "状态：" + status.label + "\n";
    }
}
