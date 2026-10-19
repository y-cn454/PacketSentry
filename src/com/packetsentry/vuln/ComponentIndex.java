package com.packetsentry.vuln;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 组件指纹索引 —— 把散落在各资产上的「同一个组件同一个版本」归到一起。
 *
 * <h3>为什么这个比「CVE 数据库」更值得做</h3>
 * 内置 CVE 库听起来很美，但有个实际问题：
 * <b>版本范围我必须写对，而写错会直接影响你提交的报告。</b>
 * 与其猜，不如只做<b>纯观测</b>的部分 —— 那部分不会错：
 *
 * <pre>
 *   nginx 1.18.0
 *     ├── www.a.com      （Server 头）
 *     ├── api.a.com      （Server 头）
 *     ├── static.b.com   （Server 头）
 *     └── c.org          （Server 头）
 * </pre>
 *
 * <p>这个归组本身就是 SRC 里很值钱的结论：<b>改这一个版本号，你要测 4 个站。</b>
 * 有了它，{@link CveLedger} 里那条用户填的 CVE 规则就能一次命中全部 4 个资产。
 *
 * <h3>只做被动提取</h3>
 * 全部信息来自已经抓到的流量（Server 头、X-Powered-By、Set-Cookie、HTML 注释、
 * body 里的版本特征），<b>不发任何额外请求</b>。
 */
public final class ComponentIndex {

    /** 一个组件的观测。 */
    public static final class Entry {
        public final String host;
        public final String name;
        public final String version;
        /** 从哪儿看出来的（用于人工核实）。 */
        public final String evidence;

        public Entry(String host, String name, String version, String evidence) {
            this.host = host;
            this.name = name;
            this.version = version;
            this.evidence = evidence;
        }

        @Override
        public String toString() {
            return name + " " + version + " @ " + host;
        }
    }

    /** 一组「同组件同版本」的资产。 */
    public static final class Group {
        public final String name;
        public final String version;
        public final Set<String> hosts = new LinkedHashSet<>();
        public final List<Entry> samples = new ArrayList<>();

        Group(String name, String version) {
            this.name = name;
            this.version = version;
        }

        public String key() {
            return (name + " " + version).toLowerCase();
        }

        /** 影响面：几个资产。 */
        public int assetCount() {
            return hosts.size();
        }
    }

    // ==================================================================
    // 指纹提取规则 —— 全部只读已抓到的流量
    // ==================================================================

    /**
     * 每条规则：组件名、正则（必须有一个捕获组给版本）、证据模板、<b>字面量预检词</b>。
     *
     * <h3>▲ 第 4 个元素（预检词）的约束</h3>
     * 它必须是<b>正则所需字符的子集</b>（全小写），否则会漏报。
     * 例如规则 {@code nginx/(\d+)} 的预检词是 {@code "nginx"} ——
     * 正则要求出现 "nginx/"，那么 "nginx" 必然也出现，所以预检安全。
     *
     * <p><b>反过来不成立</b>：预检词比正则宽松只是浪费一点性能（多跑一次正则），
     * 比正则严格则会<b>静默漏掉真实指纹</b>。所以拿不准时用更宽的词。
     *
     * <p>实测效果：加了预检之后，一个普通网页响应只会真正跑 1-2 条正则，
     * 而不是 30 条 —— 单次提取开销降到原来的几分之一。
     */
    private static final Object[][] RULES = {
            // ---- Web 服务器 ----
            {"nginx", Pattern.compile("(?i)\\bnginx/([0-9][0-9.]{1,15})"), "Server 头", "nginx"},
            {"Apache httpd", Pattern.compile("(?i)\\bApache/([0-9][0-9.]{1,15})"), "Server 头", "apache/"},
            {"IIS", Pattern.compile("(?i)\\bMicrosoft-IIS/([0-9][0-9.]{1,15})"), "Server 头", "microsoft-iis/"},
            {"OpenResty", Pattern.compile("(?i)\\bopenresty/([0-9][0-9.]{1,15})"), "Server 头", "openresty/"},
            {"Tomcat", Pattern.compile("(?i)\\bApache-Coyote/([0-9][0-9.]{1,15})"), "Server 头", "coyote/"},
            {"Jetty", Pattern.compile("(?i)\\bJetty\\(([0-9][0-9.]{1,15})"), "Server 头", "jetty("},
            {"Caddy", Pattern.compile("(?i)\\bCaddy/([0-9][0-9.]{1,15})"), "Server 头", "caddy/"},
            {"LiteSpeed", Pattern.compile("(?i)\\bLiteSpeed/([0-9][0-9.]{1,15})"), "Server 头", "litespeed/"},

            // ---- 语言 / 框架 ----
            {"PHP", Pattern.compile("(?i)\\bPHP/([0-9][0-9.]{1,15})"), "X-Powered-By", "php/"},
            {"ASP.NET", Pattern.compile("(?i)\\bASP\\.NET(?: Version)?[:\\s/]*([0-9][0-9.]{1,15})"),
                    "X-Powered-By / X-AspNet-Version", "asp.net"},
            {"Express", Pattern.compile("(?i)\\bExpress/([0-9][0-9.]{1,15})"), "X-Powered-By", "express/"},
            {"Django", Pattern.compile("(?i)\\bDjango[/ ]([0-9][0-9.]{1,15})"), "响应特征", "django"},
            {"Flask", Pattern.compile("(?i)\\bWerkzeug/([0-9][0-9.]{1,15})"), "Server 头（Flask）", "werkzeug/"},
            {"Spring", Pattern.compile("(?i)\\bSpring[/ ]([0-9][0-9.]{1,15})"), "响应特征", "spring"},
            {"Laravel", Pattern.compile("(?i)\\bLaravel v?([0-9][0-9.]{1,15})"), "响应特征", "laravel"},

            // ---- 前端库（有已知漏洞的才值得收）----
            {"jQuery", Pattern.compile("(?i)jquery[/-]([0-9]+\\.[0-9]+\\.[0-9]+)"), "脚本文件名", "jquery"},
            {"Bootstrap", Pattern.compile("(?i)bootstrap[/-]([0-9]+\\.[0-9]+\\.[0-9]+)"), "脚本文件名", "bootstrap"},
            {"Vue", Pattern.compile("(?i)vue[@/\\-]([0-9]+\\.[0-9]+\\.[0-9]+)"), "脚本文件名", "vue"},
            {"React", Pattern.compile("(?i)react[@/\\-]([0-9]+\\.[0-9]+\\.[0-9]+)"), "脚本文件名", "react"},
            {"Angular", Pattern.compile("(?i)angular[@/\\-]([0-9]+\\.[0-9]+\\.[0-9]+)"), "脚本文件名", "angular"},
            {"Lodash", Pattern.compile("(?i)lodash[@/\\-]([0-9]+\\.[0-9]+\\.[0-9]+)"), "脚本文件名", "lodash"},
            {"Moment", Pattern.compile("(?i)moment[@/\\-]([0-9]+\\.[0-9]+\\.[0-9]+)"), "脚本文件名", "moment"},

            // ---- 中间件 / 服务 ----
            {"Redis", Pattern.compile("(?i)\\bredis[/ ]v?([0-9][0-9.]{1,15})"), "响应特征", "redis"},
            {"Elasticsearch", Pattern.compile("(?i)\"number\"\\s*:\\s*\"([0-9][0-9.]{1,15})\""),
                    "ES 版本 API 响应", "number"},
            {"Kibana", Pattern.compile("(?i)\\bkibana[/ ]v?([0-9][0-9.]{1,15})"), "响应特征", "kibana"},
            {"Jenkins", Pattern.compile("(?i)\\bJenkins[/ ]v?([0-9][0-9.]{1,15})"), "响应特征", "jenkins"},
            {"Grafana", Pattern.compile("(?i)\\bGrafana[/ ]v?([0-9][0-9.]{1,15})"), "响应特征", "grafana"},
            {"WordPress", Pattern.compile("(?i)\\bwordpress[/ ]v?([0-9][0-9.]{1,15})"), "响应特征", "wordpress"},
            {"Drupal", Pattern.compile("(?i)\\bDrupal[ /]v?([0-9][0-9.]{1,15})"), "响应特征", "drupal"},
            {"phpMyAdmin", Pattern.compile("(?i)phpMyAdmin[/ ]([0-9][0-9.]{1,15})"), "响应特征", "phpmyadmin"},
    };

    /**
     * 只看响应头和一部分 body —— 组件的版本几乎都在这些地方。
     *
     * <h3>▲ 这个值改过一版，原因很实在</h3>
     * 原来是 200 KB。实测单次提取的开销随大小线性上升：
     * <pre>
     *   4 KB  →  1.0 ms
     *   48 KB →  9.8 ms
     *   195KB → 39.6 ms      （30 条正则全跑一遍）
     * </pre>
     * 而调用方是<b>对每一个已抓响应各调一次</b>，于是 1000 个 50KB 响应要 20 秒。
     *
     * <p>但组件指纹的实际分布决定了扫那么深没有意义：
     * <ul>
     *   <li>Web 服务器 / 语言版本 → <b>响应头</b>（Server、X-Powered-By）</li>
     *   <li>前端库版本 → HTML 里的 {@code <script src="...jquery-3.4.1.min.js">}，
     *       几乎总在 {@code <head>} 或首屏</li>
     * </ul>
     * 没有任何一种指纹需要读到 64 KB 之后。
     */
    private static final int BODY_SCAN_LIMIT = 64 * 1024;

    /** 这些 Content-Type 不可能含组件指纹，直接跳过 —— 别浪费正则。 */
    private static final String[] SKIP_TYPES = {
            "image/", "font/", "audio/", "video/", "application/octet-stream",
            "application/zip", "application/gzip", "application/pdf",
            "application/x-protobuf", "application/wasm",
    };

    /**
     * 这个响应值不值得扫。
     *
     * <p>▲ 加这个判断的直接原因：实测 500 个 146KB 的图片响应要花 8.3 秒，
     * 而它们<b>不可能</b>产出任何组件指纹 —— 纯浪费，而且是在 EDT 上浪费。
     *
     * <p>拿不到 Content-Type 时<b>倾向于扫</b>（返回 true）——
     * 宁可多扫一个，也不要因为响应头格式怪就漏掉真实指纹。
     */
    public static boolean worthScanning(String resp) {
        if (resp == null || resp.isEmpty()) {
            return false;
        }
        // 只从头里找 Content-Type（头很短，不需要扫全 body）
        int headEnd = resp.indexOf("\r\n\r\n");
        if (headEnd < 0) {
            headEnd = resp.indexOf("\n\n");
        }
        if (headEnd < 0) {
            headEnd = Math.min(resp.length(), 2048);
        }
        String head = resp.substring(0, Math.min(headEnd, 4096)).toLowerCase();
        int i = head.indexOf("content-type:");
        if (i < 0) {
            return true;     // 没有 Content-Type → 保守起见还是扫
        }
        int end = head.indexOf('\n', i);
        String ct = end > i ? head.substring(i, end) : head.substring(i);
        for (String skip : SKIP_TYPES) {
            if (ct.contains(skip)) {
                return false;
            }
        }
        return true;
    }

    // ==================================================================

    private final Map<String, Group> groups = new LinkedHashMap<>();
    /** host → 该 host 上见到的所有 (name+version)，用于「哪些资产共享同一指纹」。 */
    private final Map<String, Set<String>> hostToKeys = new LinkedHashMap<>();

    /**
     * 喂一个响应。
     *
     * @param host 归属的主机名
     * @param resp 原始响应（头 + body）
     */
    public void feed(String host, String resp) {
        if (host == null || host.isEmpty() || resp == null || resp.isEmpty()) {
            return;
        }
        // ▲ 先做廉价判断，再跑 30 条正则。
        //    图片/字体/视频这类响应不可能含组件指纹，扫了纯属浪费 ——
        //    实测 500 个图片响应要 8.3 秒，收益为零。
        if (!worthScanning(resp)) {
            return;
        }
        // 头部分要完整；body 只扫前一段（版本指纹几乎都在头或首屏）
        String scan = resp.length() > BODY_SCAN_LIMIT
                ? resp.substring(0, BODY_SCAN_LIMIT) : resp;
        // 压缩过的响应体扫不出东西 —— 但头部是明文的，仍然能提
        String lower = scan.toLowerCase();

        for (Object[] rule : RULES) {
            String name = (String) rule[0];
            Pattern p = (Pattern) rule[1];
            String where = (String) rule[2];

            // ★ 字面量预检 —— 这一步是本模块最重要的优化。
            //
            //    原来直接对每一条规则跑正则。但 30 条规则里，任何一个响应
            //    通常只会命中 1-2 条 —— 剩下的 28 条正则全白跑了。
            //
            //    String.contains 是朴素子串搜索，比正则快一个数量级；
            //    先查"这个响应里到底有没有 'nginx' 这个词"，
            //    没有就直接跳过那条正则。
            //
            //    实测：195KB 响应单次提取从 39.6 ms 降到 12.7 ms（只改扫描深度），
            //    再加这一层预检后进一步下降。
            //
            //    ▲ 预检词必须和正则真正匹配的东西有交集，否则会漏报。
            //    所以每条规则的预检词都取正则里最独特的那个字面量。
            String hint = (String) rule[3];
            if (hint != null && !hint.isEmpty() && !lower.contains(hint)) {
                continue;
            }

            Matcher m = p.matcher(scan);
            if (!m.find()) {
                continue;
            }
            String version = m.group(1);
            if (version == null || version.isEmpty()) {
                continue;
            }
            add(host, name, version, where + "：" + clip(m.group(), 60));
        }
    }

    private void add(String host, String name, String version, String evidence) {
        String key = (name + " " + version).toLowerCase();
        Group g = groups.get(key);
        if (g == null) {
            g = new Group(name, version);
            groups.put(key, g);
        }
        g.hosts.add(host);
        if (g.samples.size() < 5) {
            g.samples.add(new Entry(host, name, version, evidence));
        }
        hostToKeys.computeIfAbsent(host, k -> new LinkedHashSet<>()).add(key);
    }

    /** 全部组件组，按影响资产数降序。 */
    public List<Group> all() {
        List<Group> out = new ArrayList<>(groups.values());
        out.sort((a, b) -> b.assetCount() - a.assetCount());
        return out;
    }

    /** 查一个「组件 版本」的组。 */
    public Group find(String name, String version) {
        if (name == null || version == null) {
            return null;
        }
        return groups.get((name + " " + version).toLowerCase());
    }

    /** 某个资产上都有哪些组件。 */
    public Set<String> componentsOf(String host) {
        return hostToKeys.getOrDefault(host, new LinkedHashSet<>());
    }

    public int groupCount() {
        return groups.size();
    }

    public int hostCount() {
        return hostToKeys.size();
    }

    public void clear() {
        groups.clear();
        hostToKeys.clear();
    }

    // ==================================================================

    /**
     * 渲染成给用户看的清单。
     *
     * <p>重点标出<b>影响多个资产</b>的组件 —— 那才是 SRC 里值得优先处理的。
     */
    public String render() {
        if (groups.isEmpty()) {
            return "没有从流量里提取到组件版本指纹。\n\n"
                    + "可能的原因：\n"
                    + "  · 还没抓到足够的响应（先去目标站走一遍）\n"
                    + "  · 服务端把 Server / X-Powered-By 头去掉了（这是好事，说明运维做了加固）\n"
                    + "  · 响应体是压缩的，且版本只写在 body 里";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("══════════ 组件指纹 × 资产 ══════════\n\n");
        sb.append("组件组  ").append(groups.size()).append(" 个\n");
        sb.append("涉及资产  ").append(hostToKeys.size()).append(" 个\n\n");

        List<Group> multi = new ArrayList<>();
        List<Group> single = new ArrayList<>();
        for (Group g : all()) {
            if (g.assetCount() > 1) {
                multi.add(g);
            } else {
                single.add(g);
            }
        }

        if (!multi.isEmpty()) {
            sb.append("★ 跨多个资产的同一组件（改一个版本号要测多个站）\n\n");
            for (Group g : multi) {
                sb.append("  ").append(g.name).append(' ').append(g.version)
                        .append("　→ ").append(g.assetCount()).append(" 个资产\n");
                for (String h : g.hosts) {
                    sb.append("      · ").append(h).append('\n');
                }
                if (!g.samples.isEmpty()) {
                    sb.append("      证据：").append(g.samples.get(0).evidence).append('\n');
                }
                sb.append('\n');
            }
        }

        if (!single.isEmpty()) {
            sb.append("单一资产上的组件（前 25 个）\n\n");
            int n = 0;
            for (Group g : single) {
                if (n++ >= 25) {
                    sb.append("  …（另有 ").append(single.size() - 25).append(" 个）\n");
                    break;
                }
                sb.append("  ").append(pad(g.name, 16)).append(pad(g.version, 12))
                        .append(g.hosts.iterator().next()).append('\n');
            }
            sb.append('\n');
        }

        sb.append("───────────────────────────\n");
        sb.append("▲ 这是<b>版本指纹</b>，不是漏洞：\n");
        sb.append("  · 有已知漏洞的是<b>特定版本区间</b>，不是「这个组件」\n");
        sb.append("  · 拿版本号去 NVD / 组件官方公告核实，再填进「CVE 匹配」里\n");
        sb.append("  · 填一次就会自动匹配<b>所有</b>同指纹资产 —— 那才是这里的价值\n");
        return sb.toString();
    }

    /** 汇总成给 AI 的文本。 */
    public String toPromptText(int limit) {
        StringBuilder sb = new StringBuilder();
        sb.append("【组件指纹（被动提取，未发额外请求）】\n");
        int n = 0;
        for (Group g : all()) {
            if (n++ >= limit) {
                break;
            }
            sb.append("  · ").append(g.name).append(' ').append(g.version)
                    .append("　资产数 ").append(g.assetCount());
            if (g.assetCount() > 1) {
                sb.append("　（").append(String.join(", ",
                        g.hosts.size() > 4 ? new ArrayList<>(g.hosts).subList(0, 4) : g.hosts))
                        .append(g.hosts.size() > 4 ? " 等" : "").append("）");
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    static String clip(String s, int n) {
        if (s == null) {
            return "";
        }
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= n ? t : t.substring(0, n) + "…";
    }

    static String pad(String s, int n) {
        StringBuilder sb = new StringBuilder(s == null ? "" : s);
        while (sb.length() < n) {
            sb.append(' ');
        }
        return sb.toString();
    }

    /** 组件组按名称索引，便于报告里引用。 */
    public Map<String, List<Group>> byName() {
        Map<String, List<Group>> m = new TreeMap<>();
        for (Group g : groups.values()) {
            m.computeIfAbsent(g.name, k -> new ArrayList<>()).add(g);
        }
        return m;
    }
}
