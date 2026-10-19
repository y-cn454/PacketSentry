package com.packetsentry.audit;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 路由与隐藏入口审计 —— 找「页面上没有入口，但代码里还在」的功能。
 *
 * <h3>这个类针对的是什么场景</h3>
 * 典型例子：登录页早就没有了注册按钮，但开发只是把按钮<b>注释掉</b>，
 * 路由和页面都还在 —— 直接敲 URL 依然能进。
 *
 * <p>这在 SRC 里叫「隐藏接口 / 未授权功能暴露」，是可提交的真实问题。
 *
 * <h3>▲ 前提：这只能审计<b>前端</b>源码</h3>
 * 网站主动把 JS/HTML 发给浏览器，所以前端代码本来就在你手里，
 * 「审计」它不涉及任何逆向。
 *
 * <p><b>后端源码从流量里拿不到</b> —— 除非网站自己泄露了
 * （.git / 备份文件 / Source Map / 调试接口）。发现那种泄露本身就是高危漏洞，
 * 但请注意：这时只取最小证据，不要下载整个仓库。
 *
 * <h3>▲ 路由存在 ≠ 漏洞</h3>
 * 这里给出的都是<b>候选</b>。必须手工访问确认实际影响：
 * <ul>
 *   <li>只是显示「功能已关闭」 → 不是漏洞</li>
 *   <li>真的能注册 / 无需登录就能进 → 是漏洞</li>
 *   <li>暴露了别人的数据 → 越权，危害更高</li>
 * </ul>
 */
public final class RouteAudit {

    // ==================================================================
    // 结果
    // ==================================================================

    /** 一条被发现的候选入口。 */
    public static final class Candidate {
        /** 路径。 */
        public final String path;
        /** 来源说明（哪个文件、哪种方式发现的）。 */
        public final String source;
        /** 敏感度标签：管理 / 注册 / 调试 / 测试 / 数据 / 普通。 */
        public final String tag;
        /** 为什么可疑。 */
        public final String reason;
        /** 是否在 HTML 里找到过真实链接（true = 有入口，不算隐藏）。 */
        public boolean linkedFromPage;

        Candidate(String path, String source, String tag, String reason) {
            this.path = path;
            this.source = source;
            this.tag = tag;
            this.reason = reason;
        }

        @Override
        public String toString() {
            return "[" + tag + "] " + path + "　（" + source + "）"
                    + (linkedFromPage ? "　页面有入口" : "　▲ 页面无入口");
        }
    }

    /** 审计结果。 */
    public static final class Result {
        /** JS/HTML 里提取到的全部路由。 */
        public final Set<String> allRoutes = new LinkedHashSet<>();
        /** 从 HTML 页面里看到的真实链接（有入口的）。 */
        public final Set<String> linkedRoutes = new LinkedHashSet<>();
        /** 被注释掉的代码片段。 */
        public final List<String> commentedCode = new ArrayList<>();
        /** 候选隐藏入口（在 JS 里、但页面没入口）。 */
        public final List<Candidate> hiddenCandidates = new ArrayList<>();
        /** 敏感路由（不管有没有入口，都值得看）。 */
        public final List<Candidate> sensitiveRoutes = new ArrayList<>();
        /** Source Map 地址（可能能还原原始源码）。 */
        public final Set<String> sourceMaps = new LinkedHashSet<>();
        /** 后端源码泄露迹象。 */
        public final List<String> backendLeakSigns = new ArrayList<>();
        public int auditedFiles;

        public boolean hasAnything() {
            return !hiddenCandidates.isEmpty() || !sensitiveRoutes.isEmpty()
                    || !commentedCode.isEmpty() || !sourceMaps.isEmpty()
                    || !backendLeakSigns.isEmpty();
        }
    }

    // ==================================================================
    // 模式
    // ==================================================================

    /** Vue / React / Angular 路由表里的 path 声明。 */
    private static final Pattern[] ROUTE_PATTERNS = {
            // Vue Router: { path: '/user', component: ... }
            Pattern.compile("(?i)path\\s*:\\s*[\"'](/[^\"'{}$]{1,120})[\"']"),
            // React Router: <Route path="/user" ...>
            Pattern.compile("(?i)<Route[^>]*\\bpath\\s*=\\s*[\"'](/[^\"']{1,120})[\"']"),
            // Angular: { path: 'user', ... }（无前导斜杠）
            Pattern.compile("(?i)\\{\\s*path\\s*:\\s*[\"']([a-zA-Z0-9_\\-/]{2,80})[\"']"),
            // 编程式跳转
            Pattern.compile("(?i)(?:router\\.push|navigate|redirect|href|to)\\s*\\(?\\s*[\"'](/[^\"']{1,120})[\"']"),
            // axios/fetch 的接口路径
            Pattern.compile("(?i)(?:axios|fetch|request|http)\\.?(?:get|post|put|delete)?\\s*\\(\\s*[\"'](/[^\"']{1,120})[\"']"),
            // 配置里的 routes 数组：routes: [ '/a', '/b' ]
            Pattern.compile("[\"'](/[a-zA-Z0-9_\\-/]{2,80})[\"']"),
    };

    /** HTML 里的真实链接与表单动作（有入口的证据）。 */
    private static final Pattern HTML_LINKS = Pattern.compile(
            "(?i)(?:href|action|src|data-url|data-href)\\s*=\\s*[\"']([^\"'#?]{2,160})[\"']");

    /** HTML 注释。 */
    private static final Pattern HTML_COMMENT = Pattern.compile("(?s)<!--(.*?)-->");

    /** JS 行注释与块注释。 */
    private static final Pattern JS_COMMENT = Pattern.compile(
            "(?s)//[^\\n]{0,400}|/\\*.*?\\*/");

    /** 注释里出现这些词，说明被注释掉的可能是功能代码。 */
    private static final Pattern COMMENTED_CODE_HINT = Pattern.compile(
            "(?i)<(?:a|button|input|form|div|li|span)\\b|"
                    + "router|route|navigate|push\\(|href|v-if|v-show|@click|onclick|"
                    + "register|signup|admin|manage|delete|upload|export|debug|test|"
                    + "注册|管理|删除|导出|调试|测试|后门|临时|暂不|先注释");

    /** 敏感路径关键词 → 标签。 */
    private static final String[][] SENSITIVE_KEYWORDS = {
            {"管理", "admin|manage|manager|console|backend|backstage|dashboard|"
                    + "/sys|/system|operator"},
            {"注册", "register|signup|sign-up|regist|createAccount|apply"},
            {"调试", "debug|test|dev/|develop|staging|uat|sandbox|mock"},
            {"测试", "test|demo|sample|example|temp|tmp"},
            {"数据", "export|download|backup|dump|report|list|query|search"},
            {"接口", "api/|graphql|swagger|openapi|actuator|druid"},
            {"上传", "upload|file|attach|import"},
            {"认证", "login|logout|token|oauth|sso|cas|reset|password|forget"},
    };

    /** Source Map 引用。 */
    private static final Pattern SOURCE_MAP = Pattern.compile(
            "(?i)sourceMappingURL\\s*=\\s*([^\\s*\"']+)");

    /** 后端源码泄露迹象（出现在响应内容里）。 */
    private static final Pattern[] BACKEND_LEAK = {
            Pattern.compile("(?i)\\[core\\]\\s*\\n?\\s*repositoryformatversion"),   // git config
            Pattern.compile("(?i)ref:\\s*refs/heads/"),                              // .git/HEAD
            Pattern.compile("(?i)<\\?php"),
            Pattern.compile("(?i)package\\s+[a-z][a-z0-9_.]*\\s*;"),
            Pattern.compile("(?i)(?:^|\\n)\\s*(?:public|private|protected)\\s+"
                    + "(?:static\\s+)?(?:class|void|String)\\s"),
            Pattern.compile("(?i)^\\s*def\\s+__[a-z]+__\\s*\\(|^\\s*class\\s+\\w+\\s*[:(]"),
    };

    // ==================================================================

    private final Set<String> seenRoutes = new LinkedHashSet<>();
    private final Set<String> seenCandidates = new LinkedHashSet<>();

    /**
     * 审计一个响应，累积结果。
     *
     * <p>设计成<b>累积式</b>：因为「无入口」这个判断需要先看过后端路由表
     * （JS）和真实页面（HTML），单独一个响应判断不了。
     * 所以调用方在所有响应都喂完之后，再读 {@link Result#hiddenCandidates}。
     *
     * @param path   该响应的请求路径（用于来源标注）
     * @param body   响应体
     * @param result 累积结果
     */
    public void feed(String path, String body, Result result) {
        if (body == null || body.isEmpty()) {
            return;
        }
        result.auditedFiles++;

        String lower = body.toLowerCase();
        boolean isJs = lower.contains("function ") || lower.contains("=>")
                || lower.contains("var ") || lower.contains("const ")
                || lower.contains("var(") || lower.contains("webpack");
        boolean isHtml = lower.contains("<html") || lower.contains("<!doctype")
                || lower.contains("<div") || lower.contains("<body");

        // ---- 1. 路由提取（JS 与 HTML 都可能有内联脚本）----
        for (Pattern p : ROUTE_PATTERNS) {
            Matcher m = p.matcher(body);
            while (m.find() && result.allRoutes.size() < 600) {
                String r = cleanRoute(m.group(1));
                if (r != null) {
                    result.allRoutes.add(r);
                }
            }
        }

        // ---- 2. HTML 里的真实链接（有入口的证据）----
        //
        // ▲ 关键：必须先剥掉注释再找链接。
        //
        //    这个 bug 是测试逼出来的，而且是「目的性失效」级别的：
        //    原来的写法直接在整段 HTML 上匹配 href，于是
        //    `<!-- <a href="/register">注册</a> -->` 里的链接
        //    也被算成「页面有入口」—— 结果被注释掉的注册入口
        //    恰好被判为「有入口」而过滤掉，报告显示「什么都没发现」。
        //    用户会以为是网站干净，实际是功能自己把目标藏起来了。
        if (isHtml) {
            String htmlNoComment = HTML_COMMENT.matcher(body).replaceAll(" ");
            Matcher m = HTML_LINKS.matcher(htmlNoComment);
            while (m.find() && result.linkedRoutes.size() < 600) {
                String l = cleanRoute(m.group(1));
                if (l != null) {
                    result.linkedRoutes.add(l);
                }
            }

            // ---- 3. HTML 注释里被注释掉的代码 ----
            Matcher c = HTML_COMMENT.matcher(body);
            while (c.find() && result.commentedCode.size() < 60) {
                String inner = c.group(1).trim();
                if (inner.length() >= 8 && inner.length() <= 600
                        && COMMENTED_CODE_HINT.matcher(inner).find()) {
                    result.commentedCode.add(oneLine(inner));
                }
            }
        }

        // ---- 4. JS 注释里被注释掉的代码 ----
        if (isJs) {
            Matcher c = JS_COMMENT.matcher(body);
            while (c.find() && result.commentedCode.size() < 60) {
                String inner = c.group().trim();
                if (inner.length() >= 12 && inner.length() <= 600
                        && COMMENTED_CODE_HINT.matcher(inner).find()) {
                    // 排除版权头这类噪音
                    if (!inner.contains("Copyright") && !inner.contains("@license")
                            && !inner.contains("@author")) {
                        result.commentedCode.add(oneLine(inner));
                    }
                }
            }
        }

        // ---- 5. Source Map ----
        Matcher sm = SOURCE_MAP.matcher(body);
        while (sm.find() && result.sourceMaps.size() < 20) {
            result.sourceMaps.add(sm.group(1));
        }

        // ---- 6. 后端源码泄露迹象 ----
        for (Pattern p : BACKEND_LEAK) {
            if (p.matcher(body).find() && result.backendLeakSigns.size() < 10) {
                result.backendLeakSigns.add(path + "　→　" + describeLeak(p));
                break;
            }
        }
    }

    /**
     * 所有响应喂完后调用 —— 计算隐藏入口与敏感路由。
     *
     * <p>「隐藏」的定义：出现在 JS 路由表里，但任何 HTML 页面里都没有指向它的链接。
     */
    public Result finish(Result result) {
        result.hiddenCandidates.clear();
        result.sensitiveRoutes.clear();
        seenCandidates.clear();

        for (String route : result.allRoutes) {
            boolean linked = isLinked(route, result.linkedRoutes);
            String tag = tagOf(route);
            boolean sensitive = !"普通".equals(tag);

            if (sensitive) {
                Candidate c = new Candidate(route, "JS/HTML 路由表", tag,
                        sensitiveReason(tag));
                c.linkedFromPage = linked;
                if (seenCandidates.add("S:" + route)) {
                    result.sensitiveRoutes.add(c);
                }
            }
            // 隐藏入口 = 有敏感度 且 页面没入口
            if (!linked && sensitive) {
                Candidate c = new Candidate(route, "JS/HTML 路由表", tag,
                        "页面里没有任何链接指向它，但代码里还在 —— "
                                + "可能是被注释掉入口后残留的功能");
                c.linkedFromPage = false;
                if (seenCandidates.add("H:" + route)) {
                    result.hiddenCandidates.add(c);
                }
            }
        }
        // 排序：敏感度高的排前面
        result.hiddenCandidates.sort((a, b) -> tagWeight(b.tag) - tagWeight(a.tag));
        result.sensitiveRoutes.sort((a, b) -> tagWeight(b.tag) - tagWeight(a.tag));
        return result;
    }

    // ==================================================================

    /** 判断一个路由是否在页面链接里出现过（含前缀匹配）。 */
    static boolean isLinked(String route, Set<String> linked) {
        if (linked.contains(route)) {
            return true;
        }
        for (String l : linked) {
            if (l.equals(route)) {
                return true;
            }
            // /user/1 与 /user 视为同一入口
            if (l.startsWith(route + "/") || route.startsWith(l + "/")) {
                return true;
            }
        }
        return false;
    }

    /** 清洗提取到的路由。 */
    static String cleanRoute(String raw) {
        if (raw == null) {
            return null;
        }
        String r = raw.trim();
        if (r.isEmpty()) {
            return null;
        }
        // 去掉查询串和锚点
        int q = r.indexOf('?');
        if (q > 0) {
            r = r.substring(0, q);
        }
        int h = r.indexOf('#');
        if (h > 0) {
            r = r.substring(0, h);
        }
        // 排除明显不是路由的
        if (r.length() < 2 || r.length() > 160) {
            return null;
        }
        if (r.contains("${") || r.contains("{{") || r.contains("://")) {
            return null;
        }
        if (r.startsWith("//") || r.equals("/")) {
            return null;
        }
        // 静态资源不是路由
        String low = r.toLowerCase();
        if (low.matches(".*\\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|"
                + "mp4|webp|json)$")) {
            return null;
        }
        // 排除明显的变量拼接残留
        if (r.matches(".*[/{](id|pk|uuid|" + "\\$\\{[^}]*})$")) {
            return r;   // 这类保留 —— 它们是参数化路由，有价值
        }
        return r;
    }

    /** 给路由打敏感度标签。 */
    static String tagOf(String route) {
        String r = route.toLowerCase();
        for (String[] kw : SENSITIVE_KEYWORDS) {
            if (Pattern.compile("(?i)(" + kw[1] + ")").matcher(r).find()) {
                return kw[0];
            }
        }
        return "普通";
    }

    static int tagWeight(String tag) {
        switch (tag) {
            case "管理":
                return 10;
            case "注册":
                return 9;
            case "认证":
                return 8;
            case "调试":
                return 7;
            case "上传":
                return 6;
            case "数据":
                return 5;
            case "接口":
                return 4;
            case "测试":
                return 3;
            default:
                return 1;
        }
    }

    static String sensitiveReason(String tag) {
        switch (tag) {
            case "管理":
                return "管理类路径 —— 重点测未授权访问与垂直越权";
            case "注册":
                return "注册类路径 —— 若注册功能已关闭但接口还在，是逻辑漏洞";
            case "认证":
                return "认证类路径 —— 重点测会话固定、密码重置逻辑";
            case "调试":
                return "调试/测试路径 —— 生产环境不该存在，常伴随敏感信息泄露";
            case "上传":
                return "上传类路径 —— 重点测文件类型绕过与路径穿越";
            case "数据":
                return "数据类路径 —— 重点测越权导出与批量遍历";
            case "接口":
                return "接口/文档路径 —— 常暴露完整 API 清单";
            case "测试":
                return "疑似测试残留 —— 可能有默认口令或未清理数据";
            default:
                return "";
        }
    }

    static String describeLeak(Pattern p) {
        String s = p.pattern();
        if (s.contains("repositoryformatversion")) {
            return "可能是 .git/config 泄露";
        }
        if (s.contains("refs/heads")) {
            return "可能是 .git/HEAD 泄露";
        }
        if (s.contains("php")) {
            return "响应里出现 PHP 源码";
        }
        if (s.contains("package")) {
            return "响应里出现 Java 源码";
        }
        if (s.contains("public") || s.contains("private")) {
            return "响应里出现 Java/C# 源码";
        }
        if (s.contains("def")) {
            return "响应里出现 Python 源码";
        }
        return "疑似后端源码泄露";
    }

    static String oneLine(String s) {
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= 200 ? t : t.substring(0, 200) + "…";
    }

    // ==================================================================

    /** 渲染成给用户看的报告。 */
    public static String render(Result r) {
        StringBuilder sb = new StringBuilder();
        sb.append("══════════════ 路由与隐藏入口审计 ══════════════\n\n");
        sb.append("审计文件    ").append(r.auditedFiles).append(" 个\n");
        sb.append("提取路由    ").append(r.allRoutes.size()).append(" 条\n");
        sb.append("页面有入口  ").append(r.linkedRoutes.size()).append(" 条\n");
        sb.append("▲ 网络请求  0 个（纯本地分析已有流量）\n\n");

        // ---- 隐藏入口（核心）----
        sb.append("────── ★ 疑似隐藏入口（页面无入口，代码里还在）──────\n");
        if (r.hiddenCandidates.isEmpty()) {
            sb.append("  无\n");
            sb.append("  说明：要么代码里没有敏感路由，要么它们都在页面上有入口。\n");
        } else {
            for (Candidate c : r.hiddenCandidates) {
                sb.append("  [").append(c.tag).append("] ").append(c.path).append('\n');
                sb.append("      ").append(c.reason).append('\n');
            }
        }
        sb.append('\n');

        // ---- 敏感路由（有入口的也值得看）----
        List<Candidate> linkedSensitive = new ArrayList<>();
        for (Candidate c : r.sensitiveRoutes) {
            if (c.linkedFromPage) {
                linkedSensitive.add(c);
            }
        }
        if (!linkedSensitive.isEmpty()) {
            sb.append("────── ☆ 敏感路由（页面有入口，仍值得测）──────\n");
            for (Candidate c : linkedSensitive) {
                sb.append("  [").append(c.tag).append("] ").append(c.path).append('\n');
            }
            sb.append('\n');
        }

        // ---- 被注释掉的代码 ----
        if (!r.commentedCode.isEmpty()) {
            sb.append("────── ☆ 被注释掉的代码（可能是残留功能）──────\n");
            int n = 0;
            for (String c : r.commentedCode) {
                if (n++ >= 20) {
                    sb.append("  …（还有 ").append(r.commentedCode.size() - 20).append(" 条）\n");
                    break;
                }
                sb.append("  · ").append(c).append('\n');
            }
            sb.append('\n');
        }

        // ---- Source Map ----
        if (!r.sourceMaps.isEmpty()) {
            sb.append("────── ☆ Source Map（可能能还原原始源码）──────\n");
            for (String s : r.sourceMaps) {
                sb.append("  · ").append(s).append('\n');
            }
            sb.append("  ▲ 抓取 .map 文件会向目标发一个请求。SRC 场景请自行确认是否允许。\n");
            sb.append("     若能访问，用 source-map 工具可还原出带注释的原始源码 ——\n");
            sb.append("     那才是真正意义上的「逆向出前端源码」。\n\n");
        }

        // ---- 后端源码泄露 ----
        if (!r.backendLeakSigns.isEmpty()) {
            sb.append("────── ★ 后端源码泄露迹象 ──────\n");
            for (String s : r.backendLeakSigns) {
                sb.append("  · ").append(s).append('\n');
            }
            sb.append("\n  ▲▲ 合规红线：多数 SRC 规则明确禁止「下载、保存、传播业务数据」。\n");
            sb.append("      正确做法：\n");
            sb.append("        · 只取<b>最小证据</b>证明可访问（比如 .git/HEAD 的一行内容）\n");
            sb.append("        · 绝对不要 git clone 整个仓库\n");
            sb.append("        · 报告里说明泄露存在 + 附最小证据即可\n\n");
        }

        // ---- 怎么用 ----
        sb.append("────── 怎么用这份结果 ──────\n");
        sb.append("  1. 隐藏入口逐个访问，重点看：\n");
        sb.append("       · 功能是否真的能用（能注册 / 能管理 / 能导出）\n");
        sb.append("       · 是否需要登录（无需登录 = 未授权访问）\n");
        sb.append("       · 能否看到别人的数据（= 越权，危害更高）\n");
        sb.append("  2. ▲ 路由存在 ≠ 漏洞。\n");
        sb.append("       只显示「功能已关闭」的页面<b>不是漏洞</b>，别提交。\n");
        sb.append("  3. 逐个手工确认，不要写脚本批量扫 —— 那是「自动化工具」，多数 SRC 禁止。\n\n");

        sb.append("▲ 前提说明：\n");
        sb.append("  · 这些路由来自<b>前端</b>代码（网站主动发给浏览器的），\n");
        sb.append("    不是逆向出来的后端源码 —— 后端源码从流量里拿不到。\n");
        sb.append("  · 只有网站自己泄露（.git / 备份 / Source Map）才谈得上后端源码。\n");
        return sb.toString();
    }
}
