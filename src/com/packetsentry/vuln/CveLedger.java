package com.packetsentry.vuln;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.packetsentry.core.Config;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CVE 台账 —— 把「组件 + 版本区间 → CVE」这个映射记一次，自动匹配所有资产。
 *
 * <h3>▲ 为什么这里<b>不</b>内置 CVE 数据库</h3>
 * 这是刻意的设计决定，不是偷懒。
 *
 * <p>内置一个 CVE 库听起来很好，但问题是：<b>版本区间必须写对。</b>
 * 如果我记错了「nginx 1.18.0 受不受 CVE-2021-23017 影响」，
 * 而你拿去做报告提交 —— 那是一次真实的错误提交，代价比没有这个功能大得多。
 *
 * <p>所以拆开：
 * <ul>
 *   <li>{@link ComponentIndex} 做<b>纯观测</b>（提取版本、跨资产归组）—— 这部分不会错</li>
 *   <li>本类做<b>你填的映射</b>的自动应用 —— 责任边界清晰：区间是你核实的</li>
 * </ul>
 *
 * <p>填一次的价值在于<b>跨资产</b>：
 * <pre>
 *   你填：nginx &lt; 1.20.1 → CVE-2021-23017
 *   插件答：命中 4 个资产 ── www.a.com / api.a.com / static.b.com / c.org
 * </pre>
 * 否则你得在 4 个站上分别想一遍。
 *
 * <h3>怎么填</h3>
 * 界面上有入口，也可以直接编辑 {@code ~/.packetsentry/cve.json}。
 * 每条只需要：组件名 + 比较符 + 版本 + CVE 号。{@code title} 和 {@code refUrl}
 * 随你写，写清楚更好。
 */
public final class CveLedger {

    /** 版本比较符。 */
    public enum Op {
        /** 恰好等于这个版本。 */
        EQ("=", "等于"),
        /** 小于这个版本（用于「X 之前的所有版本」）。 */
        LT("<", "低于"),
        /** 小于等于。 */
        LE("<=", "低于或等于"),
        /** 大于等于（用于「从哪个版本开始受影响」）。 */
        GE(">=", "高于或等于"),
        /** 闭区间 [v1, v2]。 */
        RANGE("~", "区间");

        public final String symbol;
        public final String label;

        Op(String symbol, String label) {
            this.symbol = symbol;
            this.label = label;
        }

        public static Op of(String s) {
            if (s == null) {
                return EQ;
            }
            for (Op o : values()) {
                if (o.symbol.equals(s) || o.name().equalsIgnoreCase(s) || o.label.equals(s)) {
                    return o;
                }
            }
            return EQ;
        }
    }

    /** 一条规则 —— 用户填写。 */
    public static final class Rule {
        /** 组件名，要和 {@link ComponentIndex} 提取出的一致（如 nginx / PHP / jQuery）。 */
        public String component = "";
        public String op = "<";
        public String version = "";
        /** 区间上界（仅 RANGE 用）。 */
        public String version2 = "";
        public String cveId = "";
        public String title = "";
        public String severity = "";
        public String refUrl = "";
        public String note = "";

        public Op opEnum() {
            return Op.of(op);
        }

        /** 人读的区间描述。 */
        public String rangeText() {
            Op o = opEnum();
            if (o == Op.RANGE) {
                return version + " ≤ x ≤ " + version2;
            }
            return o.symbol + " " + version;
        }

        @Override
        public String toString() {
            return component + " " + rangeText() + "　→　" + cveId
                    + (title == null || title.isEmpty() ? "" : "（" + title + "）");
        }
    }

    /** 一条匹配结果 —— 一个 CVE 命中了哪些资产。 */
    public static final class Match {
        public final Rule rule;
        public final List<ComponentIndex.Group> groups = new ArrayList<>();
        /** 去重后的受影响资产。 */
        public final java.util.Set<String> hosts = new java.util.LinkedHashSet<>();

        Match(Rule rule) {
            this.rule = rule;
        }

        public int assetCount() {
            return hosts.size();
        }
    }

    // ==================================================================

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting().disableHtmlEscaping().create();

    private final Path file;
    private final List<Rule> rules = new ArrayList<>();
    private String lastError = "";

    public CveLedger() {
        this(defaultFile());
    }

    public CveLedger(Path file) {
        this.file = file;
        load();
    }

    public static Path defaultFile() {
        return Config.homeDir().resolve("cve.json");
    }

    public Path file() {
        return file;
    }

    public String getLastError() {
        return lastError;
    }

    public List<Rule> rules() {
        return new ArrayList<>(rules);
    }

    public int size() {
        return rules.size();
    }

    // ==================================================================

    public void load() {
        rules.clear();
        if (file == null || !Files.isRegularFile(file)) {
            return;
        }
        try {
            String json = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
            if (json.trim().isEmpty()) {
                return;
            }
            List<Rule> list = GSON.fromJson(json, new TypeToken<List<Rule>>() { }.getType());
            if (list != null) {
                for (Rule r : list) {
                    if (r != null && r.component != null && !r.component.isEmpty()) {
                        rules.add(r);
                    }
                }
            }
            lastError = "";
        } catch (Exception e) {
            // 坏文件不删 —— 用户可能想手工修
            lastError = "CVE 台账解析失败（已忽略，原文件保留）: " + e.getMessage();
        }
    }

    public String save() {
        try {
            Path parent = file.getParent();
            if (parent != null && !Files.isDirectory(parent)) {
                Files.createDirectories(parent);
            }
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.write(tmp, GSON.toJson(rules).getBytes(StandardCharsets.UTF_8));
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (Exception atomicFailed) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
            lastError = "";
            return "";
        } catch (Exception e) {
            lastError = "CVE 台账保存失败: " + e.getMessage();
            return lastError;
        }
    }

    /** 加一条（同 CVE 同组件同区间就替换）。 */
    public void add(Rule r) {
        if (r == null || r.component == null || r.component.isEmpty()) {
            return;
        }
        for (int i = 0; i < rules.size(); i++) {
            Rule old = rules.get(i);
            if (old.component.equalsIgnoreCase(r.component)
                    && old.op.equals(r.op) && old.version.equals(r.version)
                    && old.version2.equals(r.version2)) {
                rules.set(i, r);
                return;
            }
        }
        rules.add(r);
    }

    public boolean removeAt(int index) {
        if (index < 0 || index >= rules.size()) {
            return false;
        }
        rules.remove(index);
        return true;
    }

    // ==================================================================
    // 匹配
    // ==================================================================

    /**
     * 拿索引里的所有组件去跟规则表匹配。
     *
     * <p>返回的每个 Match 都带有<b>受影响的全部资产</b> —— 那就是「多资产匹配」。
     */
    public List<Match> match(ComponentIndex index) {
        List<Match> out = new ArrayList<>();
        if (index == null || rules.isEmpty()) {
            return out;
        }
        for (Rule r : rules) {
            Match m = new Match(r);
            for (ComponentIndex.Group g : index.all()) {
                if (!g.name.equalsIgnoreCase(r.component)) {
                    continue;
                }
                if (matches(r, g.version)) {
                    m.groups.add(g);
                    m.hosts.addAll(g.hosts);
                }
            }
            if (!m.groups.isEmpty()) {
                out.add(m);
            }
        }
        // 影响资产多的排前面 —— 那才是优先要处理的
        out.sort((a, b) -> b.assetCount() - a.assetCount());
        return out;
    }

    /** 版本是否落在规则区间内。 */
    static boolean matches(Rule r, String version) {
        if (version == null || version.isEmpty()) {
            return false;
        }
        int cmp = compareVersions(version, r.version);
        switch (r.opEnum()) {
            case EQ:
                return cmp == 0;
            case LT:
                return cmp < 0;
            case LE:
                return cmp <= 0;
            case GE:
                return cmp >= 0;
            case RANGE:
                return cmp >= 0 && compareVersions(version, r.version2) <= 0;
            default:
                return false;
        }
    }

    /**
     * 版本号比较。
     *
     * <p>▲ 不能直接字符串比较 —— {@code "1.9"} 按字符串比是大于 {@code "1.10"} 的，
     * 而版本号里 1.10 才是更新的那个。所以按「点分段 → 数字比较」来做。
     *
     * <p>非数字段（比如 {@code 1.18.0-beta}）取其中的数字前缀，
     * 取不到就当 0 —— 够用，而且不会因为奇怪版本号抛异常。
     */
    public static int compareVersions(String a, String b) {
        if (a == null) {
            a = "";
        }
        if (b == null) {
            b = "";
        }
        // 版本号可能带前缀（v1.2.3）
        a = a.replaceFirst("^[vV]", "");
        b = b.replaceFirst("^[vV]", "");
        String[] pa = a.split("[.\\-_]");
        String[] pb = b.split("[.\\-_]");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            long x = numAt(pa, i);
            long y = numAt(pb, i);
            if (x != y) {
                return x < y ? -1 : 1;
            }
        }
        return 0;
    }

    private static long numAt(String[] parts, int i) {
        if (i >= parts.length) {
            return 0;
        }
        String s = parts[i];
        StringBuilder digits = new StringBuilder();
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            if (c >= '0' && c <= '9') {
                digits.append(c);
            } else {
                break;
            }
        }
        if (digits.length() == 0) {
            return 0;
        }
        try {
            return Long.parseLong(digits.toString());
        } catch (NumberFormatException e) {
            // 超长数字段（理论上不会有）—— 用前 9 位
            try {
                return Long.parseLong(digits.substring(0, Math.min(9, digits.length())));
            } catch (Exception ignored) {
                return 0;
            }
        }
    }

    // ==================================================================
    // 展示
    // ==================================================================

    /** 渲染匹配结果 —— 这是「同一 CVE 的多资产」最终给用户看的东西。 */
    public String renderMatches(ComponentIndex index) {
        List<Match> ms = match(index);

        StringBuilder sb = new StringBuilder();
        sb.append("══════════ CVE × 资产 ══════════\n\n");

        if (rules.isEmpty()) {
            sb.append("台账还是空的。\n\n");
            sb.append("为什么这里不内置 CVE 库：\n");
            sb.append("  <b>版本区间必须写对。</b>如果我记错了「nginx 1.18.0 受不受某个 CVE 影响」，\n");
            sb.append("  而你拿去做报告提交 —— 那是一次真实的错误提交，比没有这个功能代价更大。\n\n");
            sb.append("所以责任拆开：\n");
            sb.append("  · 插件负责<b>纯观测</b>：提取版本、把同指纹资产归组（这部分不会错）\n");
            sb.append("  · 你负责<b>核实区间</b>：查 NVD / 官方公告，把区间填进来\n\n");
            sb.append("填一次的价值在跨资产 —— 比如填了「nginx < 1.20.1」之后，\n");
            sb.append("所有跑低版本 nginx 的站会一次全列出来，不用在 4 个站上分别想一遍。\n\n");
            sb.append("入口：界面上「CVE 匹配」按钮，或直接编辑\n  ").append(file).append('\n');
            return sb.toString();
        }

        if (ms.isEmpty()) {
            sb.append("台账里有 ").append(rules.size()).append(" 条规则，但")
                    .append("当前组件指纹<b>一个都没命中</b>。\n\n");
            sb.append("已登记的规则：\n");
            for (Rule r : rules) {
                sb.append("  · ").append(r).append('\n');
            }
            sb.append("\n可能的原因：组件名写法不一致（要跟指纹里的名字完全一样），\n");
            sb.append("或者区间填得不对。对照「代码审计 → 组件指纹」里列出的名字改。\n");
            return sb.toString();
        }

        sb.append("命中 ").append(ms.size()).append(" 个 CVE\n\n");
        for (Match m : ms) {
            sb.append("───────────────────────────────\n");
            sb.append("★ ").append(m.rule.cveId);
            if (m.rule.severity != null && !m.rule.severity.isEmpty()) {
                sb.append("　[").append(m.rule.severity).append(']');
            }
            sb.append('\n');
            if (m.rule.title != null && !m.rule.title.isEmpty()) {
                sb.append("  ").append(m.rule.title).append('\n');
            }
            sb.append("  组件      ").append(m.rule.component)
                    .append("　").append(m.rule.rangeText()).append('\n');
            sb.append("  ★ 受影响资产  ").append(m.assetCount()).append(" 个\n");
            for (String h : m.hosts) {
                sb.append("      · ").append(h).append('\n');
            }
            sb.append("  命中的具体版本  ");
            List<String> vers = new ArrayList<>();
            for (ComponentIndex.Group g : m.groups) {
                vers.add(g.version + "（" + g.assetCount() + " 站）");
            }
            sb.append(String.join("　", vers)).append('\n');
            if (m.rule.refUrl != null && !m.rule.refUrl.isEmpty()) {
                sb.append("  参考      ").append(m.rule.refUrl).append('\n');
            }
            if (m.rule.note != null && !m.rule.note.isEmpty()) {
                sb.append("  备注      ").append(m.rule.note).append('\n');
            }
            sb.append('\n');
        }

        sb.append("───────────────────────────\n");
        sb.append("▲ 提交前必须自己确认：\n");
        sb.append("  1. <b>版本区间是否真的覆盖</b>你看到的版本（去 NVD 核一遍，别信台账）\n");
        sb.append("  2. 这个 CVE <b>对这个组件是不是真的适用</b>（有的 CVE 只在特定配置下触发）\n");
        sb.append("  3. 有没有<b>实际可利用</b>的路径 —— 光有版本号，多数平台只给「低危信息泄露」\n");
        sb.append("  4. 平台是否收录「组件已知漏洞」这类（有些平台明确不收纯版本泄露）\n");
        return sb.toString();
    }

    /** 一行摘要。 */
    public String oneLine() {
        return "CVE 规则 " + rules.size() + " 条";
    }

    /** 给 AI 的文本。 */
    public String toPromptText(ComponentIndex index) {
        List<Match> ms = match(index);
        if (ms.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("【用户登记的 CVE 规则匹配结果】\n");
        sb.append("（版本区间由用户核实填写，插件只做匹配；请勿自行断言区间正确）\n");
        int n = 0;
        for (Match m : ms) {
            if (n++ >= 10) {
                break;
            }
            sb.append("  · ").append(m.rule.cveId).append("（")
                    .append(m.rule.component).append(' ').append(m.rule.rangeText())
                    .append("）影响 ").append(m.assetCount()).append(" 个资产：")
                    .append(String.join(", ", m.hosts.size() > 5
                            ? new ArrayList<>(m.hosts).subList(0, 5) : m.hosts))
                    .append(m.hosts.size() > 5 ? " 等" : "").append('\n');
        }
        return sb.toString();
    }
}
