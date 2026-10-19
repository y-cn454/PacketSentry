package com.packetsentry.detect;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SRC 平台收录规则解析器 —— 决定「这条发现该不该显示」。
 *
 * <h3>为什么需要它</h3>
 * 每个 SRC 平台的收录范围都不一样。同一个「内网 IP 泄露」：
 * <ul>
 *   <li>有的平台算低危收</li>
 *   <li>有的平台明确写在「无影响」里不收</li>
 * </ul>
 * 用户在 SRC 模式下只想看到「平台会收的」，但这个判断不能靠程序猜 ——
 * 所以让用户把规则原文贴进来，这里做解析。
 *
 * <h3>▲ 规则里有「收」也有「不收」，必须双向判断</h3>
 * 实测过一份真实规则（新东方 SRC V4.0），它同时包含：
 * <pre>
 *   【低危】…普通越权操作…（不涉及用户敏感信息）     ← 收
 *   【无影响】…内网 IP 地址/域名泄露…                ← 不收
 *   暂不收取…"无回显的SSRF漏洞"及"CSRF漏洞"           ← 不收
 * </pre>
 * 只做「关键词命中就放行」会把不收的也显示出来，所以这里把
 * <b>排除条款的优先级设得比收录条款高</b> —— 宁可少显示，不要误导。
 *
 * <h3>▲ 这是启发式解析，不是语义理解</h3>
 * 纯本地关键词匹配，会有误判。所以界面上必须标明
 * 「按规则文本启发式匹配，请自行确认」，不能让人以为这是平台官方判定。
 */
public final class PlatformRules {

    /** 一条发现相对平台规则的判定。 */
    public enum Decision {
        /** 规则里明确写了收，且没有附加条件。 */
        ACCEPTED("收"),
        /**
         * 规则收了这个大类，但带限定条件 —— 最终取决于实际危害。
         *
         * <p>典型例子：规则同时写了
         * <pre>
         *   【高危】  越权提权操作：…越权修改重要敏感信息…      ← 收
         *   【无影响】…无敏感信息的越权访问…                    ← 不收
         * </pre>
         * 那「越权」到底收不收，取决于你测出来的影响。
         * 这种必须<b>显示并标注</b>，否则用户会漏掉真正的高危越权漏洞。
         */
        CONDITIONAL("视影响"),
        /** 规则里明确写了不收（无影响 / 暂不收取 / 不在收集范围）。 */
        EXCLUDED("不收"),
        /** 规则里找不到对应条款 —— 不能替平台下结论。 */
        UNKNOWN("未提及");

        public final String label;

        Decision(String label) {
            this.label = label;
        }
    }

    /** 解析结果。 */
    public static final class Parsed {
        /** 规则原文是否为空。 */
        public boolean empty = true;
        /** 从规则里识别到的「收录」关键词。 */
        public final Set<String> includeKeywords = new LinkedHashSet<>();
        /**
         * <b>强排除</b>关键词 —— 「暂不收取 X」这类无条件排除。
         * 命中即判 EXCLUDED。
         */
        public final Set<String> strongExclude = new LinkedHashSet<>();
        /**
         * <b>弱排除</b>关键词 —— 【无影响】段落里的描述，通常带限定语
         * （如「无敏感信息的越权访问」）。
         * 与收录条款冲突时判 CONDITIONAL，而不是直接排除。
         */
        public final Set<String> weakExclude = new LinkedHashSet<>();

        /** 兼容旧名：两类排除的并集。 */
        public final Set<String> excludeKeywords = new LinkedHashSet<>();
        /** 是否识别到了「暂不收取」这类整段排除。 */
        public boolean hasGlobalExclusion = false;
        /** 解析说明（给用户看的，说明这次判断依据是什么）。 */
        public final List<String> notes = new ArrayList<>();

        public String describe() {
            if (empty) {
                return "未提供平台规则 —— 显示全部发现，定级按通用标准";
            }
            StringBuilder sb = new StringBuilder();
            sb.append("已解析平台规则：");
            sb.append("收录关键词 ").append(includeKeywords.size()).append(" 个");
            sb.append("，排除关键词 ").append(excludeKeywords.size()).append(" 个");
            if (hasGlobalExclusion) {
                sb.append("，含整段排除条款");
            }
            return sb.toString();
        }
    }

    // ==================================================================
    // 我们自己的发现名 → 规则里可能出现的说法
    //
    // 左：本插件的 finding 名称（含关键字）
    // 右：平台规则里描述这类漏洞时会用的词
    // ==================================================================

    /**
     * 剥掉规则文本里的「排除区域」，剩下的就是「收录区」。
     *
     * <p>排除区域有两类：
     * <ul>
     *   <li>{@code 【无影响】} 整段</li>
     *   <li>「暂不收取…」「不在收集范围…」这类句子（到句号 / 分号 / 换行为止）</li>
     * </ul>
     *
     * <p>▲ 为什么要先剥：如果在整篇文本里找收录关键词，
     * 【无影响】段里的词（如「密码明文传输」）会被误记成收录关键词，
     * 导致本该「不收」的类别被判成「视影响」。
     * 这个 bug 是测试逼出来的 —— 一开始「明文HTTP」怎么都判不成「不收」。
     */
    static String stripExcludedRegions(String text) {
        String region = text;

        // 反复剥：剥掉句子可能破坏段落边界、露出新的【无影响】
        for (int round = 0; round < 3; round++) {
            boolean changed = false;

            Matcher ni = NO_IMPACT_SECTION.matcher(region);
            if (ni.find()) {
                region = region.substring(0, ni.start()) + region.substring(ni.end());
                changed = true;
            }

            for (String marker : GLOBAL_EXCLUDE_MARKERS) {
                int from = 0;
                while (true) {
                    int idx = region.indexOf(marker, from);
                    if (idx < 0) {
                        break;
                    }
                    int end = idx;
                    while (end < region.length() && end - idx < 200) {
                        char ch = region.charAt(end);
                        end++;
                        if (ch == '\n' || ch == '。' || ch == '；') {
                            break;
                        }
                    }
                    region = region.substring(0, idx) + region.substring(end);
                    from = idx;
                    changed = true;
                }
            }
            if (!changed) {
                break;
            }
        }
        return region;
    }

    private static final String[][] FIXED_MAPPING = {
            // ---- 越权 ----
            {"ID可预测", "越权", "越权访问", "水平越权", "未授权访问", "遍历", "IDOR"},
            {"归属字段", "越权", "越权访问", "水平越权"},
            {"权限字段", "越权", "垂直越权", "提权", "越权提权"},
            {"前端权限", "越权", "垂直越权", "绕过认证", "前端绕过"},

            // ---- 业务逻辑 ----
            {"金额可篡改", "逻辑漏洞", "逻辑设计缺陷", "流程缺陷", "订单金额", "支付"},
            {"数量可篡改", "逻辑漏洞", "逻辑设计缺陷", "流程缺陷"},
            {"状态字段", "逻辑漏洞", "逻辑设计缺陷", "流程缺陷", "状态"},
            {"可重复提交", "逻辑漏洞", "流程缺陷", "重放"},
            {"频控缺失", "频控", "短信炸弹", "暴力破解", "限流", "频率限制"},
            {"多字段提交", "逻辑漏洞", "参数覆盖"},

            // ---- 认证 / 会话 ----
            {"无CSRF", "CSRF", "跨站请求伪造"},
            {"JWT", "JWT", "令牌", "凭证", "会话"},
            {"Cookie属性", "Cookie", "会话安全"},

            // ---- 信息泄露 ----
            {"硬编码凭据", "敏感信息泄露", "硬编码", "密钥泄露", "凭据泄露", "AKSK"},
            {"源码泄露", "源码泄露", "代码泄露", "源代码"},
            {"调试信息", "敏感信息泄露", "报错", "错误信息", "调试", "堆栈"},
            {"服务器路径", "信息泄露", "路径信息泄露", "路径泄露"},
            {"服务端版本", "信息泄露", "版本", "指纹"},
            {"内网地址", "内网", "IP地址", "域名泄露"},
            {"备份", "源码泄露", "代码备份", "备份文件", "敏感文件"},
            {"敏感路径", "未授权访问", "敏感文件", "配置泄露"},
            {"注释信息", "信息泄露", "注释", "源码泄露"},
            {"敏感文件泄露", "路径遍历", "任意文件读取", "目录遍历"},
            {"敏感字段回显", "敏感信息泄露", "用户信息泄露", "越权获取"},

            // ---- 以下条目是「跨模块契约测试」逼出来的 ----
            //
            // ▲ 契约测试会扫 LocalRules 里所有 `new Issue(...)` 的名字，
            //    检查每个名字都能在这里找到对应说法。原本有 9 个名字没有条目，
            //    后果是：SRC 模式下这些发现被判「未提及」而<b>静默隐藏</b>，
            //    用户以为是「没检测到」，实际是「被过滤掉了」。
            //
            //    → 以后每加一条新检测规则，都要顺手在这里补上对应说法。
            {"Authorization回显", "敏感信息泄露", "凭据泄露", "令牌泄露", "信息泄露"},
            {"密码明文回显", "敏感信息泄露", "明文密码", "密码泄露", "凭据泄露",
                    "信息泄露", "明文传输"},
            {"堆栈泄露", "敏感信息泄露", "报错", "错误信息", "堆栈", "信息泄露"},
            {"安全响应头缺失", "安全配置", "配置错误", "安全头", "响应头", "信息泄露"},
            {"第三方脚本无完整性校验", "供应链", "第三方", "代码完整性", "信息泄露"},
            {"疑似fail-open", "异常处理", "访问控制", "越权", "逻辑漏洞", "fail-open"},
            {"组件版本指纹", "组件", "版本", "指纹", "供应链", "信息泄露"},
            {"错误细节泄露", "敏感信息泄露", "报错", "错误信息", "调试", "信息泄露"},
            {"隐藏表单字段", "逻辑漏洞", "前端绕过", "参数篡改", "信息泄露"},
            // 「扫描已截断」是我们自己的状态说明，不是漏洞。
            // 给它映射只是不让它在 SRC 模式下凭空消失 ——
            // 用户需要知道「这次没扫全」，这比「看起来干净」重要。
            {"扫描已截断", "信息泄露"},

            // ---- 配置 ----
            {"CORS", "CORS", "跨域", "跨站资源共享"},
            {"明文HTTP", "明文传输", "HTTP传输", "传输安全"},
            {"JSONP", "JSONP", "跨域"},
            {"参数重复", "参数污染", "HPP"},
            {"硬编码", "硬编码", "密钥泄露"},

            // ---- 前端 / 代码 ----
            {"危险DOM", "XSS", "跨站脚本"},
            {"前端校验", "前端绕过", "客户端校验"},
            {"接口路径泄露", "信息泄露", "接口泄露", "API泄露"},
            {"Source Map", "源码泄露", "sourcemap"},
            {"postMessage", "postMessage", "跨域消息", "XSS"},
            {"Flag", "flag"},
            {"SQL报错", "SQL注入", "注入"},
            {"报错泄露", "报错", "信息泄露"},
    };

    // ==================================================================
    // 排除条款的识别
    // ==================================================================

    /**
     * 整段排除的标志词。
     *
     * <p>规则里出现这些词时，紧接着描述的那类漏洞就是「不收」的。
     * 例如：「暂不收取新东方旗下各个业务"无回显的SSRF漏洞"及"CSRF漏洞"」。
     */
    private static final String[] GLOBAL_EXCLUDE_MARKERS = {
            "暂不收取", "不收取", "不在收集范围", "不在收录范围",
            "不予收录", "不予奖励", "不计算", "不计分", "不记分",
            "无影响", "忽略", "不收",
    };

    /** 「无影响」这个等级段 —— 落在里面的整段都不收。 */
    private static final Pattern NO_IMPACT_SECTION = Pattern.compile(
            "(?:【无影响】|无影响[：:])([\\s\\S]{0,4000})");

    /** 「收录/等级」段落的标题。 */
    private static final Pattern LEVEL_SECTION = Pattern.compile(
            "【(严重|高危|高|中危|中|低危|低)】");

    // ==================================================================

    /**
     * 解析规则原文。
     */
    public static Parsed parse(String rulesText) {
        Parsed p = new Parsed();
        if (rulesText == null || rulesText.trim().isEmpty()) {
            return p;
        }
        p.empty = false;
        String text = rulesText.replace("\r\n", "\n");

        // ---- 0. 先把「排除区域」挖出来，后面找收录关键词时要避开它们 ----
        //
        // ▲ 这一步是踩坑后补的。原来的顺序是「先在整篇文本里找收录关键词」，
        //    但【无影响】段和「暂不收取」句里的词也会被当成收录关键词 ——
        //    结果「明文传输」出现在【无影响】里，却被记进了 includeKeywords，
        //    于是「明文HTTP」被判成「视影响」而不是「不收」。
        //
        //    正确做法：先剥掉排除区域，剩下的才是「收录区」。
        String includeRegion = stripExcludedRegions(text);

        // ---- 1. 收录关键词：<b>只在收录区里</b>找 ----
        for (String[] pair : FIXED_MAPPING) {
            for (int i = 1; i < pair.length; i++) {
                if (includeRegion.contains(pair[i])) {
                    p.includeKeywords.add(pair[i]);
                }
            }
        }

        // ---- 2. 「无影响」整段 → 里面提到的都算排除 ----
        Matcher ni = NO_IMPACT_SECTION.matcher(text);
        if (ni.find()) {
            p.hasGlobalExclusion = true;
            String section = ni.group(1);
            p.notes.add("识别到【无影响】段落，其中的类别按「不收」处理");
            for (String[] pair : FIXED_MAPPING) {
                for (int i = 1; i < pair.length; i++) {
                    if (section.contains(pair[i])) {
                        // 【无影响】段里的属于<b>弱排除</b> —— 通常带限定语
                        p.weakExclude.add(pair[i]);
                    }
                }
            }
        }

        // ---- 3. 「暂不收取 / 不收取」这类句子 → 句子里的类别算排除 ----
        for (String marker : GLOBAL_EXCLUDE_MARKERS) {
            int from = 0;
            while (true) {
                int idx = text.indexOf(marker, from);
                if (idx < 0) {
                    break;
                }
                p.hasGlobalExclusion = true;
                // 取这句话（到句号 / 换行为止）
                int end = idx;
                while (end < text.length() && end - idx < 200) {
                    char ch = text.charAt(end);
                    if (ch == '\n' || ch == '。' || ch == '；') {
                        break;
                    }
                    end++;
                }
                String sentence = text.substring(idx, end);
                for (String[] pair : FIXED_MAPPING) {
                    for (int i = 1; i < pair.length; i++) {
                        if (sentence.contains(pair[i])) {
                            // 「暂不收取 X」是无条件排除 → 强排除
                            p.strongExclude.add(pair[i]);
                        }
                    }
                }
                from = idx + marker.length();
            }
        }

        // ---- 4. 汇总 excludeKeywords（兼容旧字段）----
        p.excludeKeywords.addAll(p.strongExclude);
        p.excludeKeywords.addAll(p.weakExclude);

        // ---- 5. 冲突项不再一刀切排除 ----
        // ▲ 这里改过一次。原来的做法是「同时出现在收录和排除里 → 从收录里摘掉」，
        //    理由是「宁可少显示，不要误导提交」。但实测发现这样会漏掉真漏洞：
        //    规则同时有【高危】越权提权操作 和【无影响】无敏感信息的越权访问，
        //    一刀切会把整个「越权」排除掉 —— 而垂直越权恰恰是高危。
        //    现在改成标 CONDITIONAL（视影响），由 decide() 处理。
        Set<String> conflict = new LinkedHashSet<>(p.includeKeywords);
        conflict.retainAll(p.weakExclude);
        if (!conflict.isEmpty()) {
            p.notes.add("这些类别同时出现在收录条款与【无影响】段里，"
                    + "将标为「视影响」—— 取决于你实测到的危害："
                    + String.join("、", conflict));
        }
        if (!p.strongExclude.isEmpty()) {
            p.notes.add("无条件排除（暂不收取）：" + String.join("、", p.strongExclude));
        }
        if (!p.weakExclude.isEmpty()) {
            p.notes.add("【无影响】段里提到的类别：" + String.join("、", p.weakExclude));
        }
        return p;
    }

    // ==================================================================

    /**
     * 判定一条发现该不该显示。
     *
     * @param findingName 发现的名称（如「ID可预测线索」「金额可篡改线索」）
     * @param parsed      解析好的规则
     */
    public static Decision decide(String findingName, Parsed parsed) {
        if (parsed == null || parsed.empty) {
            return Decision.UNKNOWN;
        }
        if (findingName == null || findingName.isEmpty()) {
            return Decision.UNKNOWN;
        }

        // 找出这条发现对应的所有平台说法
        Set<String> aliases = aliasesOf(findingName);

        boolean strong = false;
        boolean weak = false;
        boolean included = false;
        for (String a : aliases) {
            if (parsed.strongExclude.contains(a)) {
                strong = true;
            }
            if (parsed.weakExclude.contains(a)) {
                weak = true;
            }
            if (parsed.includeKeywords.contains(a)) {
                included = true;
            }
        }

        // ① 无条件排除 → 不收
        if (strong) {
            return Decision.EXCLUDED;
        }
        // ② 收录 + 【无影响】都提到 → 视影响而定
        //    这是最需要小心的一档：一刀切排除会漏掉真漏洞
        if (included && weak) {
            return Decision.CONDITIONAL;
        }
        // ③ 只被收录提到 → 收
        if (included) {
            return Decision.ACCEPTED;
        }
        // ④ 只被【无影响】提到 → 不收
        if (weak) {
            return Decision.EXCLUDED;
        }
        return Decision.UNKNOWN;
    }

    /**
     * 找出插件发现名对应的平台说法集合。
     *
     * <p>public 是为了让契约测试能验证「每条检测规则都有平台映射」——
     * 缺映射的规则在 SRC 模式下会被静默隐藏，必须能自动发现。
     */
    public static Set<String> aliasesOf(String findingName) {
        Set<String> out = new LinkedHashSet<>();
        for (String[] pair : FIXED_MAPPING) {
            if (findingName.contains(pair[0])) {
                for (int i = 1; i < pair.length; i++) {
                    out.add(pair[i]);
                }
            }
        }
        return out;
    }

    // ==================================================================

    /** 过滤统计。 */
    public static final class Stats {
        public int total;
        public int accepted;
        public int conditional;
        public int excluded;
        public int unknown;
        public final Map<String, Integer> excludedNames = new LinkedHashMap<>();

        public String describe() {
            return "共 " + total + " 条发现：收 " + accepted
                    + "　视影响 " + conditional + "　不收 " + excluded
                    + "　未提及 " + unknown;
        }
    }

    /**
     * 按规则过滤一批发现的名称。
     *
     * @param findingNames 发现的名称列表
     * @param parsed       规则
     * @param keepUnknown  规则里没提到的，要不要保留
     *                     （SRC 模式下建议 false —— 只看平台明确收的）
     */
    public static Stats filter(List<String> findingNames, Parsed parsed, boolean keepUnknown) {
        Stats s = new Stats();
        if (findingNames == null) {
            return s;
        }
        for (String n : findingNames) {
            s.total++;
            Decision d = decide(n, parsed);
            switch (d) {
                case ACCEPTED:
                    s.accepted++;
                    break;
                case CONDITIONAL:
                    s.conditional++;
                    break;
                case EXCLUDED:
                    s.excluded++;
                    s.excludedNames.merge(n, 1, Integer::sum);
                    break;
                default:
                    s.unknown++;
            }
        }
        return s;
    }

    /** 生成给用户看的规则解析说明。 */
    public static String renderExplanation(Parsed p, Stats s) {
        StringBuilder sb = new StringBuilder();
        sb.append("══════════ 平台收录规则解析 ══════════\n\n");
        if (p.empty) {
            sb.append("未提供平台规则 → 显示全部发现，定级按通用标准。\n\n");
            sb.append("想只看平台收录的？到「设置」页把目标平台的\n");
            sb.append("漏洞评级规则原文贴进去即可。\n");
            return sb.toString();
        }

        sb.append(p.describe()).append("\n\n");
        sb.append("▲ 这是对规则文本的<b>本地关键词解析</b>，不是语义理解。\n");
        sb.append("   可能有误判，请对照规则原文自行确认。\n\n");

        if (!p.notes.isEmpty()) {
            sb.append("解析说明：\n");
            for (String n : p.notes) {
                sb.append("  · ").append(n).append('\n');
            }
            sb.append('\n');
        }

        sb.append("本次发现统计：").append(s.describe()).append("\n\n");

        if (!s.excludedNames.isEmpty()) {
            sb.append("被规则排除的（已隐藏）：\n");
            for (Map.Entry<String, Integer> e : s.excludedNames.entrySet()) {
                sb.append("  · ").append(e.getKey()).append("　×").append(e.getValue()).append('\n');
            }
            sb.append('\n');
        }

        sb.append("▲ 「未提及」不等于「不收」—— 只是规则里没写。\n");
        sb.append("   本模式默认只在「收」的情况下显示；想全看就把 SRC 安全模式关掉。\n");
        return sb.toString();
    }
}
