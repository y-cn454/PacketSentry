package com.packetsentry.detect;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 本地业务规则引擎 —— 零成本的「作用推断」与「漏洞检测」。
 *
 * <h3>为什么这些不用 AI</h3>
 * 参考实现把「作用」和「漏洞」两列都交给 AI 判定，但那两件事本质上是
 * <b>模式匹配</b>，不是推理：
 * <ul>
 *   <li>{@code /api/user/self} → 「获取用户信息」—— 查字典就够</li>
 *   <li>响应体里出现请求里的 password 值 → 「密码明文回显」—— 字符串比对就够</li>
 * </ul>
 * 把它交给 AI 会有三个后果：<b>花钱、变慢、不稳定</b>（同一个包两次问可能给不同答案）。
 *
 * <p>本地规则跑一遍是<b>微秒级、零成本、结果确定</b>。
 * AI 留给它真正擅长的事：<b>从接口清单推断业务流程、找出逻辑漏洞的切入点</b>。
 *
 * <h3>本类不产生任何网络调用</h3>
 * 纯字符串运算，可以放心在抓包热路径上跑（虽然实际由后台线程调用）。
 */
public final class LocalRules {

    // ==================================================================
    // 漏洞
    // ==================================================================

    /** 漏洞等级。数值越大越严重，便于排序与着色。 */
    public enum Level {
        NONE("无", 0),
        LOW("低", 1),
        MEDIUM("中", 2),
        HIGH("高", 3),
        CRITICAL("严重", 4);

        public final String label;
        public final int rank;

        Level(String label, int rank) {
            this.label = label;
            this.rank = rank;
        }
    }

    /** 一条漏洞发现。 */
    public static final class Issue {
        public final Level level;
        public final String name;
        public final String detail;
        /** 判定依据（给用户看「为什么判成这样」）。 */
        public final String evidence;

        public Issue(Level level, String name, String detail, String evidence) {
            this.level = level;
            this.name = name;
            this.detail = detail;
            this.evidence = evidence;
        }

        /** 列表里显示的一行。 */
        public String shortLabel() {
            if (level == Level.NONE) {
                return "无";
            }
            return level.label + "危" + name;
        }

        @Override
        public String toString() {
            return "[" + level.label + "] " + name + " —— " + detail
                    + (evidence == null || evidence.isEmpty() ? "" : "（依据：" + evidence + "）");
        }
    }

    // ==================================================================
    // 作用推断
    // ==================================================================

    /** 路径关键词 → 业务作用。按「越具体越靠前」排列，先匹配到的胜出。 */
    private static final String[][] PURPOSE_RULES = {
            // 加解密 / 安全机制
            {"/decrypt", "加解密"}, {"/encrypt", "加解密"}, {"/crypto", "加解密"},
            {"/captcha", "验证码"}, {"/verify", "验证"}, {"/otp", "验证码"},
            {"/csrf", "CSRF令牌"}, {"/token", "获取令牌"}, {"/refresh", "刷新令牌"},

            // 认证
            {"/login", "登录"}, {"/logout", "登出"}, {"/signin", "登录"},
            {"/auth", "认证"}, {"/sso", "单点登录"}, {"/cas", "单点登录"},
            {"/register", "注册"}, {"/signup", "注册"}, {"/reset", "重置密码"},

            // 用户 / 权限
            {"/user/self", "获取用户信息"}, {"/user/info", "获取用户信息"},
            {"/profile", "获取用户信息"}, {"/account", "账号信息"},
            {"/user/group", "获取用户分组"}, {"/permission", "查询权限"},
            {"/role", "查询角色"}, {"/menu", "获取菜单"},

            // 首页 / 内容
            {"/page_content", "获取首页内容"}, {"/home", "获取首页"},
            {"/index", "获取首页"}, {"/dashboard", "获取仪表盘"},
            {"/notice", "获取通知"}, {"/notification", "获取通知"}, {"/announce", "获取公告"},
            {"/logo", "获取Logo"}, {"/icon", "获取图标"}, {"/banner", "获取横幅"},

            // 查询类
            {"/search", "搜索"}, {"/query", "查询"}, {"/list", "查询列表"},
            {"/checkin", "查询签到记录"}, {"/signin_record", "查询签到记录"},
            {"/log", "查询日志"}, {"/audit", "查询审计日志"}, {"/login_record", "查询登录记录"},
            {"/task", "查询任务"}, {"/job", "查询任务"}, {"/schedule", "查询任务"},
            {"/statistic", "查询统计"}, {"/report", "查询报表"},

            // 数据操作
            {"/upload", "文件上传"}, {"/download", "文件下载"}, {"/export", "导出数据"},
            {"/import", "导入数据"}, {"/delete", "删除操作"}, {"/remove", "删除操作"},
            {"/update", "更新数据"}, {"/edit", "编辑数据"}, {"/save", "保存数据"},
            {"/create", "创建数据"}, {"/add", "新增数据"},

            // 业务
            {"/order", "订单"}, {"/cart", "购物车"}, {"/pay", "支付"},
            {"/refund", "退款"}, {"/balance", "余额"}, {"/wallet", "钱包"},
            {"/address", "收货地址"}, {"/coupon", "优惠券"}, {"/points", "积分"},

            // 管理
            {"/admin", "管理接口"}, {"/manage", "管理接口"}, {"/config", "配置"},
            {"/setting", "设置"}, {"/system", "系统接口"},

            // 静态资源
            {"/static/", "加载静态资源"}, {"/assets/", "加载静态资源"},
            {"/js/", "加载脚本"}, {"/css/", "加载样式"},
            {"/img/", "加载图片"}, {"/image/", "加载图片"}, {"/font", "加载字体"},
    };

    /**
     * 特权命名空间 —— <b>优先级高于最长匹配</b>。
     *
     * <p>为什么需要单独一层：纯最长匹配在 {@code /admin/config} 上会判成「配置」
     * （因为 {@code /config} 比 {@code /admin} 长）。但对安全分析来说，
     * <b>「这是管理端点」比「它是配置功能」重要得多</b> ——
     * 前者标志权限边界，是垂直越权的首要观察目标。
     *
     * <p>同理，{@code /api/admin/user/list} 判成「管理接口」比「查询列表」更有用。
     */
    private static final String[][] NAMESPACE_RULES = {
            {"/admin", "管理接口"},
            {"/manage", "管理接口"},
            {"/backend", "后台接口"},
            {"/console", "管理控制台"},
            {"/actuator", "运维端点"},
            {"/internal", "内部接口"},
            {"/debug", "调试接口"},
    };

    /**
     * 推断一个请求「在业务上干什么」。
     *
     * <p>判定顺序：
     * <ol>
     *   <li><b>特权命名空间</b>（{@code /admin} 这类）—— 标志权限边界</li>
     *   <li><b>最长匹配</b> —— 越具体的规则胜出，不需要人工维护顺序</li>
     *   <li><b>扩展名</b> —— 静态资源兜底</li>
     *   <li><b>HTTP 方法语义</b> —— 最后兜底，比返回「未知」有用</li>
     * </ol>
     *
     * <p>▲ 第 2 条曾经是「按数组顺序先匹配先赢」，实测出现两个错判：
     * {@code /api/audit/log} 被 {@code /log} 抢走、
     * {@code /api/login_record} 被 {@code /login} 抢走。改成长尾优先后修好。
     */
    public static String inferPurpose(String method, String path) {
        String p = path == null ? "" : path.toLowerCase();
        String m = method == null ? "" : method.toUpperCase();

        // 1) 特权命名空间
        for (String[] rule : NAMESPACE_RULES) {
            if (p.contains(rule[0])) {
                return rule[1];
            }
        }

        // 2) 最长匹配
        String best = null;
        int bestLen = -1;
        for (String[] rule : PURPOSE_RULES) {
            if (p.contains(rule[0]) && rule[0].length() > bestLen) {
                best = rule[1];
                bestLen = rule[0].length();
            }
        }
        if (best != null) {
            return best;
        }

        // 3) 扩展名兜底
        if (p.endsWith(".js")) {
            return "加载脚本";
        }
        if (p.endsWith(".css")) {
            return "加载样式";
        }
        if (p.matches(".*\\.(png|jpe?g|gif|svg|webp|ico|avif)$")) {
            return "加载图片";
        }
        if (p.endsWith(".woff") || p.endsWith(".woff2") || p.endsWith(".ttf")) {
            return "加载字体";
        }

        // 按 HTTP 语义兜底 —— 比返回「未知」有用
        switch (m) {
            case "GET":
                return "读取数据";
            case "POST":
                return "提交数据";
            case "PUT":
            case "PATCH":
                return "更新数据";
            case "DELETE":
                return "删除数据";
            case "OPTIONS":
                return "预检请求";
            default:
                return "未知";
        }
    }

    // ==================================================================
    // 漏洞检测
    // ==================================================================

    private static final Pattern[] SQL_ERROR_PATTERNS = {
            Pattern.compile("(?i)SQL syntax.*MySQL"),
            Pattern.compile("(?i)Warning.*\\bmysql_"),
            Pattern.compile("(?i)ORA-\\d{5}"),
            Pattern.compile("(?i)PostgreSQL.*ERROR"),
            Pattern.compile("(?i)Microsoft OLE DB Provider for SQL Server"),
            Pattern.compile("(?i)SQLite/JDBCDriver"),
            Pattern.compile("(?i)unclosed quotation mark after the character string"),
    };

    private static final Pattern[] STACK_PATTERNS = {
            Pattern.compile("(?i)at [a-z]+\\.[a-z0-9_.]+\\([A-Za-z0-9_]+\\.java:\\d+\\)"),
            Pattern.compile("(?i)Traceback \\(most recent call last\\)"),
            Pattern.compile("(?i)Whitelabel Error Page"),
            Pattern.compile("(?i)System\\.(NullReference|InvalidOperation)Exception"),
    };

    private static final Pattern[] PATH_TRAVERSAL_PATTERNS = {
            Pattern.compile("root:x:0:0:"),
            Pattern.compile("\\[boot loader\\]"),
            Pattern.compile("(?i)\\[extensions\\]\\s*$", Pattern.MULTILINE),
            // Windows / 常见系统文件
            Pattern.compile("(?i)\\[fonts\\]"),
            Pattern.compile("(?i); for 16-bit app support"),
            Pattern.compile("(?i)\\[mci extensions\\]"),
            Pattern.compile("(?i)daemon:x:\\d+:\\d+:"),
    };

    /**
     * CTF / 靶场的 flag —— <b>强特征</b>，出现即确认，不需要附加条件。
     *
     * <h3>▲ 这里补过一次真实的漏报</h3>
     * 早期版本只认 {@code flag{...}} 和裸的 32 位 hex。结果在 Hacker101 上，
     * 响应体明明就是：
     * <pre>
     *   ^FLAG^62e19f2d7aff8c130f5c15721f7d71fa9b13b6389b04d40042c16bc015ffc0f9$FLAG$
     * </pre>
     * 却<b>一条都没命中</b> —— 因为 Hacker101 用的是 {@code ^FLAG^...$FLAG$}
     * 包住一个 <b>64 位</b> hex，两种格式都不匹配。
     *
     * <p>后果不只是漏报：本地规则本该给 CRITICAL，实际只给了「中危 安全响应头缺失」，
     * 于是 AI 拿到的等级就是错的，整段分析的语气都按「中危」来写，
     * 明明 flag 已经在手里了还在说「疑似」。
     *
     * <p><b>教训：flag 格式必须按平台逐个覆盖，不能只写「通用 {…} 形式」。</b>
     */
    private static final Pattern FLAG_PATTERN = Pattern.compile(
            // ---- Hacker101 / HackerOne：^FLAG^<hex>$FLAG$ ----
            "\\^FLAG\\^[A-Za-z0-9_+/=\\-]{6,256}\\$FLAG\\$"
                    // ---- 各类 PREFIX{...} / PREFIX[...] / PREFIX(...) ----
                    + "|(?i)\\b(?:flag|ctf|htb|hackthebox|hacker101|hackerone|picoctf|"
                    + "nssctf|buu|ctfshow|moectf|tryhackme|thm|dctf|rootme|htb|"
                    + "flag\\{|key|secret)"
                    + "\\s*[{\\[(][^}\\])]{4,256}[}\\])]"
                    // ---- flag: xxxx / flag = xxxx ----
                    + "|(?i)\\bflag\\s*[:=]\\s*[A-Za-z0-9_+/{}\\-]{6,256}"
                    // ---- FLAG-xxxx-xxxx-xxxx 破折号形式 ----
                    //      有些平台用这个。加进来成本低、误报风险也低 ——
                    //      「字面的 FLAG 后面跟一串短段」在正常页面里几乎不会出现。
                    + "|(?i)\\bFLAG-[a-z0-9]{2,12}(?:-[a-z0-9]{2,12}){1,8}\\b"
                    // ---- 32/40/64/96 位 hex —— 但**必须**出现在 flag 字样附近 ----
                    //      单独一条 [a-f0-9]{32} 会命中 MD5 / ETag / 会话 ID，
                    //      噪音太大，所以用 lookahead 绑定「附近有 flag」。
                    + "|(?is)(?=.{0,200}(?i)flag)[^\\s]{0,40}\\b[a-fA-F0-9]{32,128}\\b");

    /**
     * 极小响应体 + 长 hex —— 靶场「命中即返回 flag」的典型形态。
     *
     * <p>用户给的那个例子 {@code Content-Length: 76}，响应体就是一行 flag。
     * 这类页面没有 HTML 结构、体积极小、内容几乎全是 hex，
     * 单独判断比靠关键词更可靠。
     */
    private static final Pattern LONG_HEX_TOKEN = Pattern.compile(
            "\\b[a-fA-F0-9]{32,128}\\b");

    /** 判断一个响应是不是「极小且几乎只有一串 hex」—— 靶场 flag 页的典型形态。 */
    static boolean looksLikeFlagPage(String resp) {
        int i = resp.indexOf("\r\n\r\n");
        if (i < 0) {
            i = resp.indexOf("\n\n");
        }
        String body = (i < 0 ? resp : resp.substring(i)).trim();
        // 只对很小的响应做这个判断 —— CTF flag 页通常几十到几百字节。
        // 大页面上出现长 hex 太常见（构建哈希、指纹），不能这么判。
        if (body.isEmpty() || body.length() > 600) {
            return false;
        }
        Matcher m = LONG_HEX_TOKEN.matcher(body);
        if (!m.find()) {
            return false;
        }
        // hex 占正文比重够大，且正文里没有多少 HTML 结构
        int hexLen = m.group().length();
        long lt = body.chars().filter(c -> c == '<').count();
        return hexLen * 2 >= body.length() && lt <= 2;
    }

    /** 服务端源码泄露 —— 响应里直接出现代码。 */
    private static final Pattern[] SOURCE_LEAK_PATTERNS = {
            Pattern.compile("<\\?php\\s"),
            Pattern.compile("<%@\\s*page\\b"),
            Pattern.compile("<\\%="),
            Pattern.compile("(?m)^\\s*package\\s+[a-z][a-z0-9_.]*;\\s*$"),
            Pattern.compile("(?m)^\\s*import\\s+java\\.[a-z]"),
            Pattern.compile("(?m)^\\s*def\\s+__[a-z]+__\\s*\\("),
    };

    /** 报错 / 调试信息 —— 泄露内部结构，常是进一步利用的起点。 */
    private static final Pattern[] DEBUG_PATTERNS = {
            Pattern.compile("(?i)Whitelabel Error Page"),
            Pattern.compile("(?i)DEBUG\\s*=\\s*True"),
            Pattern.compile("(?i)Django Version:"),
            Pattern.compile("(?i)Laravel.*(Whoops|Ignition)"),
            Pattern.compile("(?i)phpinfo\\(\\)"),
            Pattern.compile("(?i)Environment Variables"),
            Pattern.compile("(?i)Traceback \\(most recent call last\\)"),
            Pattern.compile("(?i)Stack trace:.*\\n\\s*at "),
            Pattern.compile("(?i)You have an error in your SQL syntax"),
            Pattern.compile("(?i)Unclosed quotation mark"),
            Pattern.compile("(?i)java\\.sql\\.SQLException"),
            Pattern.compile("(?i)System\\.Data\\.SqlClient\\.SqlException"),
    };

    /** 绝对路径泄露 —— 暴露服务器目录结构。 */
    private static final Pattern ABS_PATH_PATTERN = Pattern.compile(
            "(?:/var/www/|/home/[a-z0-9_]+/|/usr/local/|/opt/[a-z0-9_]+/"
                    + "|[A-Z]:\\\\inetpub\\\\|[A-Z]:\\\\xampp\\\\|[A-Z]:\\\\Users\\\\[^\\\\]+\\\\)");

    /** 服务端版本泄露。 */
    private static final Pattern SERVER_VERSION_PATTERN = Pattern.compile(
            "(?im)^(?:Server|X-Powered-By|X-AspNet-Version|X-Generator):\\s*(.+)$");

    /** 备份 / 配置文件。 */
    private static final Pattern BACKUP_PATH = Pattern.compile(
            "(?i)\\.(bak|old|orig|save|swp|zip|tar\\.gz|tgz|sql|sql\\.gz|rar|7z)$"
                    + "|/(web|app)\\.config$|/config\\.(php|json|yml|yaml|xml)$"
                    + "|/backup|/\\.git/config|/\\.svn/entries|/\\.ds_store");

    /** JSONP 回调。 */
    private static final Pattern JSONP_CALLBACK = Pattern.compile(
            "(?i)[?&](callback|jsonp|cb|_callback)=([A-Za-z_$][\\w$.]{0,40})");

    /** HTML 注释里的敏感信息。 */
    private static final Pattern HTML_COMMENT_LEAK = Pattern.compile(
            "(?is)<!--.{0,400}?(password|passwd|secret|token|api[_-]?key|TODO|FIXME|hint).{0,400}?-->");

    /** 表单里的隐藏字段 —— 常见于「客户端信任」类逻辑漏洞。 */
    private static final Pattern HIDDEN_FIELD = Pattern.compile(
            "(?is)<input[^>]+type=[\"']?hidden[\"']?[^>]*>");

    /** 客户端硬编码的密钥 / 凭据。 */
    private static final Pattern HARDCODED_SECRET = Pattern.compile(
            "(?i)(api[_-]?key|secret|token|passwd|password|access[_-]?key)"
                    + "[\"'\\s:=]{1,6}[\"']([A-Za-z0-9_\\-]{16,})[\"']");

    /** 敏感路径 —— 返回 200 通常意味着不该暴露的东西暴露了。 */
    private static final Pattern SENSITIVE_PATH = Pattern.compile(
            "(?i)/\\.git/|/\\.svn/|/\\.env|/\\.ds_store|/wp-config\\.php|"
                    + "/actuator(/|$)|/swagger-ui|/v2/api-docs|/druid/|/phpinfo|"
                    + "/backup\\.|/\\.idea/|/web\\.config|/server-status");

    // ==================================================================
    // OWASP Top 10:2025 新增 / 升级类别对应的模式
    //
    // 2025 版相比 2021 版的变化（已查证）：
    //   A02 安全配置错误  从 #5 升到 #2（涨幅最大）
    //   A03 软件供应链缺陷  ★ 全新（5 个 CWE）
    //   A10 异常情况处理不当 ★ 全新（24 个 CWE，含 CWE-209 / CWE-636）
    // 下面三组模式就是为这些类别加的。
    // ==================================================================

    /**
     * A02:2025 安全配置错误（升到第 2 位）—— 关键安全响应头。
     *
     * <p>每行是 {响应头名, 缺失说明}。只在响应是 HTML 页面时检查 ——
     * API 接口不需要这些头，对它们报缺失是噪音。
     */
    private static final String[][] SECURITY_HEADERS = {
            {"Content-Security-Policy",
                    "缺 CSP：XSS 没有第二道防线，注入的脚本可任意执行"},
            {"Strict-Transport-Security",
                    "缺 HSTS：可被降级到明文 HTTP 做中间人劫持"},
            {"X-Content-Type-Options",
                    "缺 nosniff：浏览器可能按内容嗅探类型，导致 XSS"},
            {"X-Frame-Options",
                    "缺 X-Frame-Options：页面可被任意站点 iframe 嵌套（点击劫持）"},
            {"Referrer-Policy",
                    "缺 Referrer-Policy：URL 里的敏感参数可能经 Referer 泄露给第三方"},
    };

    /** A03:2025 软件供应链缺陷 —— 引用外部域的脚本。 */
    private static final Pattern EXTERNAL_SCRIPT = Pattern.compile(
            "(?is)<script[^>]+src\\s*=\\s*[\"']https?://([^\"'/]+)[^\"']*[\"'][^>]*>");

    /** 带 integrity 属性的 script/link（子资源完整性校验）。 */
    private static final Pattern HAS_INTEGRITY = Pattern.compile(
            "(?is)<(?:script|link)[^>]+integrity\\s*=\\s*[\"'][^\"']+[\"']");

    /**
     * A03:2025 从 JS 里识别前端框架与版本。
     *
     * <p>▲ 这里用的是 <b>预编译好的 Pattern</b>，不是「名字 + 正则字符串」再现场编译。
     * 教训：最初写成 {@code String[][]} + 在循环里 {@code Pattern.compile(...)}，
     * 那是<b>热路径</b>（每个报文都要跑一遍），白白浪费 CPU。
     * 实测 633KB 的 HTML 单次要 231ms，预编译后明显下降。
     */
    private static final Object[][] FRAMEWORK_FINGERPRINTS = {
            {"jQuery", Pattern.compile("(?i)jquery[.\\-@]?v?([0-9]+\\.[0-9]+\\.[0-9]+)")},
            {"Vue", Pattern.compile("(?i)\\bvue[.@\\-]?v?([0-9]+\\.[0-9]+\\.[0-9]+)")},
            {"React", Pattern.compile("(?i)\\breact[.@\\-]?v?([0-9]+\\.[0-9]+\\.[0-9]+)")},
            {"Angular", Pattern.compile("(?i)\\bangular[.@\\-]?v?([0-9]+\\.[0-9]+\\.[0-9]+)")},
            {"Bootstrap", Pattern.compile("(?i)bootstrap[.@\\-]?v?([0-9]+\\.[0-9]+\\.[0-9]+)")},
            {"Lodash", Pattern.compile("(?i)lodash[.@\\-]?v?([0-9]+\\.[0-9]+\\.[0-9]+)")},
            {"Axios", Pattern.compile("(?i)axios[.@\\-]?v?([0-9]+\\.[0-9]+\\.[0-9]+)")},
    };

    /**
     * A10:2025 异常情况处理不当 —— 错误响应里的内部细节。
     *
     * <p>对应 <b>CWE-209</b>（把敏感信息放进错误消息）。
     */
    private static final Object[][] ERROR_DETAIL_PATTERNS = {
            {"PHP", Pattern.compile("(?i)(Warning|Notice|Fatal error|Parse error):.{0,120}? on line \\d+")},
            {"Java", Pattern.compile("(?i)java\\.[a-z]+\\.\\w+(?:Exception|Error)[:\\s]")},
            {"Python", Pattern.compile("(?i)Traceback \\(most recent call last\\)")},
            {"Node", Pattern.compile("(?i)(TypeError|ReferenceError|SyntaxError):.{0,80}(\\n|\\\\n)\\s+at ")},
            {".NET", Pattern.compile("(?i)System\\.[A-Za-z.]+Exception")},
            {"Go", Pattern.compile("(?i)goroutine \\d+ \\[running\\]:")},
            {"Ruby", Pattern.compile("(?i)(NoMethodError|NameError|ActionController::)")},
            {"SQL", Pattern.compile("(?i)(You have an error in your SQL syntax|ORA-\\d{5}|SQLSTATE\\[|"
                    + "Microsoft OLE DB Provider for SQL Server)")},
    };

    /**
     * 安全响应头名 → 预编译的「有没有这个头」正则。
     *
     * <p>同样是为了避免在热路径上现场编译 —— 每处理一个 HTML 响应
     * 原本要编译 5 次正则。
     */
    private static final java.util.Map<String, Pattern> HEADER_PRESENCE = new java.util.HashMap<>();
    static {
        for (String[] sh : SECURITY_HEADERS) {
            HEADER_PRESENCE.put(sh[0], Pattern.compile("(?im)^" + Pattern.quote(sh[0]) + "\\\\s*:"));
        }
    }

    /**
     * A10:2025 fail-open 迹象（<b>CWE-636</b>：failing to fail safely）。
     *
     * <p>判断方式：状态码是 2xx，但响应体里同时出现错误关键词和业务数据字段。
     * 这意味着「服务端内部出错了，却回了成功」—— 权限校验很可能也这样被绕过。
     */
    private static final Pattern ERROR_KEYWORDS = Pattern.compile(
            "(?i)(\"?(?:error|errmsg|exception|failed|failure|异常|失败|错误)\"?\\s*[:=])"
                    + "|(?:error|exception)\\s+occurred");

    /** 业务数据字段（用来判断响应体里到底有没有真数据）。 */
    private static final Pattern BUSINESS_DATA = Pattern.compile(
            "(?i)\"(?:id|userId|orderId|name|username|account|token|data|list|items|"
                    + "records|rows|result|balance|amount|phone|email)\"\\s*:");

    /**
     * 单次扫描的字符上限（请求与响应各自）。
     *
     * <h3>为什么必须有这个上限</h3>
     * 26 条规则每条都要扫一遍整个响应体。实测 633KB 的 HTML 要 ~230ms；
     * 如果目标是 5MB 的前端 bundle，就会到 ~2 秒 ——
     * 而 {@link com.packetsentry.core.RealtimePipe} 是单线程消费队列，
     * 一个超大响应就能让后面的报文全部积压。
     *
     * <p>取 512K 字符：覆盖绝大多数真实页面（含大 JS bundle），
     * 同时把最坏情况限制在 ~200ms 量级。
     *
     * <p>▲ 截断会有漏报的可能 —— 所以截断时会在结果里说明，
     * 不假装「扫完了没发现」。
     */
    private static final int MAX_SCAN_CHARS = 512 * 1024;

    /**
     * 检测一个请求/响应对。
     *
     * @param requestRaw  原始请求（未脱敏 —— 我们要拿它比对响应里有没有回显）
     * @param responseRaw 原始响应，可为 null
     * @param scan        该报文的 PII 扫描结果，可为 null
     */
    /**
     * 检测一个报文（<b>靶场模式</b> —— flag 规则生效）。
     *
     * <p>保留这个重载是为了测试与靶场场景。实战 SRC 走
     * {@link #detect(String, String, PiiScanner.Report, boolean)} 并传 {@code false}。
     */
    public static List<Issue> detect(String requestRaw, String responseRaw, PiiScanner.Report scan) {
        return detect(requestRaw, responseRaw, scan, true);
    }

    /**
     * 检测一个报文。
     *
     * @param rangeMode 是否靶场模式。<b>false（实战 SRC）时不跑 flag 规则</b> ——
     *                  真实业务系统里不存在 flag，而「极小响应 + 长 hex」那条兜底
     *                  会误报成 CRITICAL，在 SRC 里把注意力浪费掉是有实际代价的。
     *                  详见 {@code Config.rangeMode}。
     */
    public static List<Issue> detect(String requestRaw, String responseRaw,
                                     PiiScanner.Report scan, boolean rangeMode) {
        List<Issue> out = new ArrayList<>();
        if (requestRaw == null) {
            return out;
        }

        String req = requestRaw;
        String resp = responseRaw == null ? "" : responseRaw;

        // 超长响应截断后再扫 —— 见 MAX_SCAN_CHARS 的说明。
        // 截断了要记下来，最后如实说明，不能让用户以为「全扫过了没发现」。
        boolean reqTruncated = req.length() > MAX_SCAN_CHARS;
        boolean respTruncated = resp.length() > MAX_SCAN_CHARS;
        if (reqTruncated) {
            req = req.substring(0, MAX_SCAN_CHARS);
        }
        if (respTruncated) {
            resp = resp.substring(0, MAX_SCAN_CHARS);
        }

        // 响应头与状态码 —— 很多规则只需要看头，不必扫整个 body。
        // 热路径上这个区分很重要（见 MAX_SCAN_CHARS 的说明）。
        int status = resp.startsWith("HTTP/1.") ? parseStatus(resp) : 200;
        int headEnd = resp.indexOf("\r\n\r\n");
        if (headEnd < 0) {
            headEnd = resp.indexOf("\n\n");
        }
        String respHead = headEnd > 0 ? resp.substring(0, headEnd) : resp;

        // ---- 1. 密码明文回显（高危）----
        List<String> pwdValues = extractSensitiveValues(req, "password", "passwd", "pwd");
        for (String v : pwdValues) {
            if (v.length() >= 6 && resp.contains(v)) {
                out.add(new Issue(Level.HIGH, "密码明文回显",
                        "响应体里出现了请求提交的密码原文，攻击者可通过响应直接拿到凭据",
                        "响应中含 " + mask(v)));
                break;
            }
        }

        // ---- 2. Authorization 回显（中危）----
        List<String> authValues = extractSensitiveValues(req, "authorization");
        for (String v : authValues) {
            String token = stripScheme(v);
            if (token.length() >= 12 && resp.contains(token)) {
                out.add(new Issue(Level.MEDIUM, "Authorization回显",
                        "响应体里回显了请求的认证凭据，可能被日志或前端缓存二次泄露",
                        "响应中含 " + mask(token)));
                break;
            }
        }

        // ---- 3. 敏感字段回显（中）----
        if (scan != null) {
            for (PiiScanner.Finding f : scan.findings) {
                if (f.location != null && f.location.startsWith("body.") && !resp.isEmpty()) {
                    out.add(new Issue(Level.MEDIUM, "敏感字段回显",
                            "响应体包含 " + f.kind + " 这类个人数据，注意越权与批量遍历风险",
                            f.location + " (" + f.length + " 字符)"));
                    break;
                }
            }
        }

        // ---- 4. JWT 凭证（低危）----
        if (scan != null && !scan.jwts.isEmpty()) {
            PiiScanner.JwtInfo j = scan.jwts.get(0);
            String extra = j.role() != null ? "，role=" + j.role() : "";
            String expNote = j.isExpired() ? "，已过期" : "，仍有效";
            out.add(new Issue(Level.LOW, "JWT凭证",
                    "流量里携带 JWT（alg=" + j.alg() + extra + expNote + "），"
                            + "可本地解码查看声明，重点看 role / sub 是否可篡改",
                    "共 " + scan.jwts.size() + " 个"));
        }

        // ---- 5. CORS 反射（高）----
        if (isCorsReflected(req, resp)) {
            out.add(new Issue(Level.HIGH, "CORS反射",
                    "响应按请求的 Origin 原样返回 Access-Control-Allow-Origin，"
                            + "若同时允许凭据，同站子域可跨域读取数据",
                    "Origin 被反射"));
        }

        // ---- 6. 明文 HTTP（中）----
        if (isPlainHttp(req)) {
            out.add(new Issue(Level.MEDIUM, "明文HTTP",
                    "使用 http 而非 https，流量可被中间人读取和篡改", "scheme=http"));
        }

        // ---- 7. Cookie 缺安全属性（中）----
        String cookieIssue = checkSetCookie(resp);
        if (cookieIssue != null) {
            out.add(new Issue(Level.MEDIUM, "Cookie属性缺失",
                    "Set-Cookie 缺少 HttpOnly / Secure，Cookie 可被 JS 读取或在明文信道泄露",
                    cookieIssue));
        }

        // ---- 8. 目录遍历 / 文件泄露（严重）----
        for (Pattern p : PATH_TRAVERSAL_PATTERNS) {
            if (p.matcher(resp).find()) {
                out.add(new Issue(Level.CRITICAL, "敏感文件泄露",
                        "响应内容疑似系统文件或配置文件，可能存在路径遍历",
                        p.pattern()));
                break;
            }
        }

        // ---- 9. 报错信息泄露（中）----
        for (Pattern p : SQL_ERROR_PATTERNS) {
            if (p.matcher(resp).find()) {
                out.add(new Issue(Level.MEDIUM, "SQL报错泄露",
                        "响应暴露了数据库错误信息，可能可进一步注入",
                        p.pattern()));
                break;
            }
        }
        for (Pattern p : STACK_PATTERNS) {
            if (p.matcher(resp).find()) {
                out.add(new Issue(Level.MEDIUM, "堆栈泄露",
                        "响应暴露了调用栈或框架错误页，泄露内部结构",
                        p.pattern()));
                break;
            }
        }

        // ---- 10. 敏感路径可访问（高）----
        if (SENSITIVE_PATH.matcher(req).find() && resp.startsWith("HTTP/1.")) {
            if (status == 200) {
                Matcher m = SENSITIVE_PATH.matcher(req);
                String hit = m.find() ? m.group() : "";
                out.add(new Issue(Level.HIGH, "敏感路径可访问",
                        "管理端点 / 配置文件被直接访问且返回 200", hit));
            }
        }

        // ---- 11. 响应里的绝对路径 / 内网地址（低）----
        Matcher ip = Pattern.compile(
                "\\b(?:10|172\\.(?:1[6-9]|2\\d|3[01])|192\\.168)\\.\\d{1,3}\\.\\d{1,3}\\b")
                .matcher(resp);
        if (ip.find()) {
            out.add(new Issue(Level.LOW, "内网地址泄露",
                    "响应包含内网 IP，可能帮助攻击者绘制内网拓扑", ip.group()));
        }

        // ==============================================================
        // 以下为 v0.8 新增 —— 补上「真实流量里能看出问题」的几类。
        //
        // 背景：早期 11 条规则在正常浏览时几乎不命中（用户反馈「全是无」），
        // 因为它们检测的是「泄露的数据」，而不是「可被利用的缺陷」。
        // 这几条更贴近实际能在流量里看到的信号。
        // ==============================================================

        // ---- 12. CTF flag（严重）----
        // 靶场里拿到 flag 就是解题成功 —— 这是<b>已确认的事实</b>，不是推测。
        // 所以措辞要用「已确认」，并且明确告诉用户「这个包里已经有结论了」，
        // 避免下游（AI 分析）把它当成一个「可能」来讨论。
        Matcher fm = rangeMode ? FLAG_PATTERN.matcher(resp) : null;
        if (fm != null && fm.find()) {
            String hit = fm.group();
            out.add(new Issue(Level.CRITICAL, "Flag（已确认）",
                    "响应里直接包含 flag —— 如果这是靶场，本题已解。"
                            + "这是一个<b>已确认的结论</b>，不需要再验证；"
                            + "接下来该做的是顺着这个接口找<b>同类问题</b>（见延伸建议）。",
                    hit.length() > 40 ? hit.substring(0, 40) + "…" : hit));
        } else if (rangeMode && looksLikeFlagPage(resp)) {
            // 极小的响应体里几乎只有一串长 hex —— 靶场 flag 页的典型形态。
            // 单独判断是因为有些平台会把 flag 换个前缀（或者根本不给前缀）。
            Matcher hm = LONG_HEX_TOKEN.matcher(resp);
            if (hm.find()) {
                out.add(new Issue(Level.CRITICAL, "疑似 Flag 页（已确认形态）",
                        "这是一个极小且内容几乎只有一串十六进制的响应 —— "
                                + "靶场「命中即返回 flag」的典型形态。"
                                + "即使没有 flag 前缀，也应当作已命中处理。",
                        hm.group()));
            }
        }

        // ---- 13. 服务端源码泄露（高）----
        for (Pattern p : SOURCE_LEAK_PATTERNS) {
            if (p.matcher(resp).find()) {
                out.add(new Issue(Level.HIGH, "源码泄露",
                        "响应里直接出现了服务端源代码，可能泄露逻辑、凭据与隐藏接口",
                        p.pattern()));
                break;
            }
        }

        // ---- 14. 调试 / 报错信息（中）----
        for (Pattern p : DEBUG_PATTERNS) {
            if (p.matcher(resp).find()) {
                out.add(new Issue(Level.MEDIUM, "调试信息泄露",
                        "响应暴露了调试页、环境变量或异常堆栈 —— 常是进一步利用的起点",
                        p.pattern()));
                break;
            }
        }

        // ---- 15. 绝对路径泄露（低）----
        Matcher ap = ABS_PATH_PATTERN.matcher(resp);
        if (ap.find()) {
            out.add(new Issue(Level.LOW, "服务器路径泄露",
                    "响应暴露了服务器上的绝对路径，有助于推断部署结构",
                    ap.group()));
        }

        // ---- 16. 服务端版本泄露（低）----
        // ▲ 只扫响应头 —— 版本号只可能出现在头里，扫整个 body 是纯浪费。
        //    这是热路径，每个报文都要跑一遍。
        Matcher sv = SERVER_VERSION_PATTERN.matcher(respHead);
        if (sv.find()) {
            String v = sv.group(1).trim();
            // 带版本号的才有意义；只写 "nginx" 不算泄露
            if (v.matches(".*\\d+\\.\\d+.*")) {
                String name = resp.substring(sv.start(), resp.indexOf(':', sv.start()));
                out.add(new Issue(Level.LOW, "服务端版本泄露",
                        "响应头暴露了服务端软件及版本，便于匹配已知漏洞",
                        name + ": " + (v.length() > 50 ? v.substring(0, 50) + "…" : v)));
            }
        }

        // ---- 17. 备份 / 配置文件可访问（高）----
        if (BACKUP_PATH.matcher(req).find() && parseStatus(resp) == 200) {
            Matcher bm = BACKUP_PATH.matcher(req);
            String hit = bm.find() ? bm.group() : "";
            out.add(new Issue(Level.HIGH, "备份/配置文件可访问",
                    "备份或配置文件被直接访问且返回 200，可能泄露源码或凭据", hit));
        }

        // ---- 18. JSONP 回调（中）----
        Matcher jp = JSONP_CALLBACK.matcher(req);
        if (jp.find()) {
            String ct = "";
            Matcher ctm = Pattern.compile("(?im)^Content-Type:\\s*(.+)$").matcher(resp);
            if (ctm.find()) {
                ct = ctm.group(1).trim().toLowerCase();
            }
            // 只有「JSONP 且返回可执行脚本」才构成风险
            if (ct.contains("javascript") || ct.contains("html") || resp.contains(jp.group(2) + "(")) {
                out.add(new Issue(Level.MEDIUM, "JSONP接口",
                        "接口支持 JSONP 回调且返回可执行内容，若携带敏感数据可被跨域读取",
                        jp.group(1) + "=" + jp.group(2)));
            }
        }

        // ---- 19. HTML 注释里的敏感信息（中）----
        Matcher hc = HTML_COMMENT_LEAK.matcher(resp);
        if (hc.find()) {
            String comment = hc.group();
            out.add(new Issue(Level.MEDIUM, "注释信息泄露",
                    "HTML 注释里出现敏感关键词，可能泄露测试账号、接口或内部说明",
                    comment.length() > 60 ? comment.substring(0, 60) + "…" : comment));
        }

        // ---- 20. 表单隐藏字段（低）----
        // 隐藏字段常被前端当作「可信数据」提交，是逻辑漏洞的常见入口
        Matcher hf = HIDDEN_FIELD.matcher(resp);
        if (hf.find()) {
            String tag = hf.group();
            out.add(new Issue(Level.LOW, "隐藏表单字段",
                    "存在 hidden 字段，服务端若信任其值可导致越权或价格篡改",
                    tag.length() > 70 ? tag.substring(0, 70) + "…" : tag));
        }

        // ---- 21. 客户端硬编码凭据（中）----
        Matcher hs = HARDCODED_SECRET.matcher(resp);
        if (hs.find()) {
            String key = hs.group(1);
            String val = hs.group(2);
            out.add(new Issue(Level.MEDIUM, "硬编码凭据",
                    "前端代码里出现疑似密钥的硬编码值，任何人可直接读取",
                    key + "=" + mask(val)));
        }

        // ==============================================================
        // 以下是 OWASP Top 10:2025 新增 / 升级类别的规则
        // ==============================================================

        // ---- 22. A02:2025 安全响应头缺失（中）----
        // 2025 版把「安全配置错误」从第 5 位提到第 2 位，涨幅最大。
        // 只在 HTML 页面上检查 —— API 接口不需要这些头，对它们报是噪音。
        String ctype = contentTypeOf(respHead);
        if (ctype.contains("text/html") && !isErrorStatus(status)) {
            List<String> missing = new ArrayList<>();
            for (String[] sh : SECURITY_HEADERS) {
                Pattern hp = HEADER_PRESENCE.get(sh[0]);
                if (hp == null || !hp.matcher(respHead).find()) {
                    missing.add(sh[0] + "（" + sh[1] + "）");
                }
            }
            if (!missing.isEmpty()) {
                out.add(new Issue(Level.MEDIUM, "安全响应头缺失",
                        "HTML 页面缺少 " + missing.size() + " 个关键安全响应头，"
                                + "缺少防护会让其它漏洞的利用更容易（OWASP A02:2025 安全配置错误）",
                        String.join("；", missing)));
            }
        }

        // ---- 23. A03:2025 引用外部域脚本且无完整性校验（中）----
        // 对应软件供应链缺陷：第三方 CDN 被投毒 / 被劫持时，页面会执行攻击者的代码。
        // 有 integrity 属性就能发现被篡改。
        if (ctype.contains("text/html")) {
            Matcher es = EXTERNAL_SCRIPT.matcher(resp);
            Set<String> hosts = new LinkedHashSet<>();
            int withoutSri = 0;
            while (es.find() && hosts.size() < 8) {
                String tag = es.group();
                String host = es.group(1);
                hosts.add(host);
                if (!tag.toLowerCase().contains("integrity")) {
                    withoutSri++;
                }
            }
            if (!hosts.isEmpty()) {
                boolean anySri = HAS_INTEGRITY.matcher(resp).find();
                out.add(new Issue(anySri ? Level.LOW : Level.MEDIUM, "第三方脚本无完整性校验",
                        "页面从外部域加载脚本" + (anySri ? "（部分有 integrity）" : "，且没有 integrity 校验")
                                + "。第三方域被入侵或被劫持时，页面会执行攻击者的代码"
                                + "（OWASP A03:2025 软件供应链缺陷）",
                        String.join("、", hosts) + (withoutSri > 0
                                ? "　其中 " + withoutSri + " 个无 integrity" : "")));
            }
        }

        // ---- 24. A03:2025 前端框架版本指纹（低）----
        // 拿到版本号才能去查有没有已知漏洞。本插件没有 CVE 库，
        // 所以只报「识别到的版本」，由用户自己去查。
        if (ctype.contains("javascript") || ctype.contains("text/html")) {
            List<String> fw = new ArrayList<>();
            for (Object[] fp : FRAMEWORK_FINGERPRINTS) {
                Matcher m = ((Pattern) fp[1]).matcher(resp);
                if (m.find()) {
                    fw.add(fp[0] + " " + m.group(1));
                }
                if (fw.size() >= 5) {
                    break;
                }
            }
            if (!fw.isEmpty()) {
                out.add(new Issue(Level.LOW, "组件版本指纹",
                        "识别到前端组件与版本。本插件<b>没有 CVE 库</b>，"
                                + "无法判断这些版本是否有已知漏洞 —— 请自行到 NVD / "
                                + "官方公告核对（OWASP A03:2025 软件供应链缺陷）",
                        String.join("、", fw)));
            }
        }

        // ---- 25. A10:2025 错误响应泄露内部细节（中）----
        // 对应 CWE-209。2025 版把「异常情况处理不当」列为全新的第 10 类。
        for (Object[] ep : ERROR_DETAIL_PATTERNS) {
            Matcher m = ((Pattern) ep[1]).matcher(resp);
            if (m.find()) {
                String hit = m.group().replaceAll("\\s+", " ");
                out.add(new Issue(Level.MEDIUM, "错误细节泄露",
                        "响应里包含 " + ep[0] + " 的内部错误细节（路径 / 类名 / SQL 语句），"
                                + "可用于推断技术栈与内部结构（OWASP A10:2025 / CWE-209）",
                        truncate(hit, 120)));
                break;
            }
        }

        // ---- 26.5 扫描被截断时如实说明 ----
        // 宁可告诉用户「没扫完」，也不要让他以为「扫完了没发现」。
        if (respTruncated || reqTruncated) {
            List<String> parts = new ArrayList<>();
            if (respTruncated) {
                parts.add("响应 " + responseRaw.length() + " 字符");
            }
            if (reqTruncated) {
                parts.add("请求 " + requestRaw.length() + " 字符");
            }
            out.add(new Issue(Level.LOW, "扫描已截断",
                    "内容超过单次扫描上限（" + MAX_SCAN_CHARS + " 字符），"
                            + "只扫描了前面的部分 —— <b>后面的内容可能有发现但没被检查到</b>。"
                            + "需要完整结果时请用「代码审计」按钮（它有独立的、更宽松的上限）。",
                    String.join("，", parts)));
        }

        // ---- 26. A10:2025 fail-open 迹象（高）----
        // 对应 CWE-636（failing to fail safely）。
        // 「服务端内部出错了，却回了 2xx + 业务数据」——
        // 既然错误路径不拒绝，权限校验很可能也不拒绝。
        if (status >= 200 && status < 300
                && ERROR_KEYWORDS.matcher(resp).find()
                && BUSINESS_DATA.matcher(resp).find()) {
            out.add(new Issue(Level.HIGH, "疑似fail-open",
                    "状态码是 " + status + "（成功），但响应体里同时有错误关键词和业务数据字段。"
                            + "这说明服务端内部出错时仍然返回了成功 + 数据 —— "
                            + "同样的失败处理方式很可能让权限校验在异常路径下被绕过"
                            + "（OWASP A10:2025 / CWE-636）",
                    "状态 " + status + "　响应中出现错误关键词 + 业务数据"));
        }

        return out;
    }

    // ==================================================================
    // 小工具
    // ==================================================================

    /** 取响应的 Content-Type（已去掉 charset）。 */
    static String contentTypeOf(String head) {
        Matcher m = Pattern.compile("(?im)^Content-Type:\\s*([^;\\r\\n]+)").matcher(head);
        return m.find() ? m.group(1).trim().toLowerCase() : "";
    }

    /** 响应头里有没有这个头（大小写不敏感）。 */
    static boolean containsHeader(String head, String name) {
        return Pattern.compile("(?im)^" + Pattern.quote(name) + "\\s*:").matcher(head).find();
    }

    /** 是不是错误状态码。 */
    static boolean isErrorStatus(int status) {
        return status >= 400;
    }

    static String truncate(String s, int n) {
        if (s == null) {
            return "";
        }
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }

    /** 汇总等级 —— 取最严重的一条。 */
    public static Level worst(List<Issue> issues) {
        Level w = Level.NONE;
        for (Issue i : issues) {
            if (i.level.rank > w.rank) {
                w = i.level;
            }
        }
        return w;
    }

    /** 列表「漏洞」列显示的内容。 */
    public static String summarize(List<Issue> issues) {
        if (issues == null || issues.isEmpty()) {
            return "无";
        }
        // 显示最严重的一条，多条时加计数
        Issue top = issues.get(0);
        for (Issue i : issues) {
            if (i.level.rank > top.level.rank) {
                top = i;
            }
        }
        String s = top.level.label + "危" + top.name;
        if (issues.size() > 1) {
            s += " +" + (issues.size() - 1);
        }
        return s;
    }

    // ==================================================================
    // 辅助
    // ==================================================================

    private static final Pattern JSON_KV = Pattern.compile(
            "\"([A-Za-z_][A-Za-z0-9_]*)\"\\s*:\\s*\"([^\"]{1,200})\"");
    private static final Pattern FORM_KV = Pattern.compile(
            "(?:^|&)([A-Za-z_][A-Za-z0-9_]*)=([^&\\s]{1,200})");

    /** 从请求里抽出指定字段名的值（JSON 和 form 都试）。 */
    static List<String> extractSensitiveValues(String req, String... fieldNames) {
        List<String> out = new ArrayList<>();
        int sep = req.indexOf("\r\n\r\n");
        if (sep < 0) {
            sep = req.indexOf("\n\n");
        }
        String body = sep >= 0 ? req.substring(sep) : req;

        Matcher jm = JSON_KV.matcher(body);
        while (jm.find()) {
            if (matchesAny(jm.group(1), fieldNames)) {
                out.add(jm.group(2));
            }
        }
        Matcher fm = FORM_KV.matcher(body);
        while (fm.find()) {
            if (matchesAny(fm.group(1), fieldNames)) {
                out.add(fm.group(2));
            }
        }
        // 头里的（Authorization 在头里）
        for (String line : req.split("\r?\n")) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            if (matchesAny(line.substring(0, colon).trim(), fieldNames)) {
                out.add(line.substring(colon + 1).trim());
            }
        }
        return out;
    }

    private static boolean matchesAny(String key, String... names) {
        String k = key.toLowerCase().replace("-", "").replace("_", "");
        for (String n : names) {
            if (k.equals(n.toLowerCase().replace("-", "").replace("_", ""))) {
                return true;
            }
        }
        return false;
    }

    private static String stripScheme(String v) {
        String s = v.trim();
        if (s.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return s.substring(7).trim();
        }
        if (s.regionMatches(true, 0, "Basic ", 0, 6)) {
            return s.substring(6).trim();
        }
        return s;
    }

    /** 脱敏后用于展示的片段 —— 判定依据本身也不该泄露凭据。 */
    private static String mask(String v) {
        if (v.length() <= 8) {
            return "****";
        }
        return v.substring(0, 4) + "****" + v.substring(v.length() - 4);
    }

    static boolean isCorsReflected(String req, String resp) {
        Matcher originM = Pattern.compile("(?im)^Origin:\\s*(\\S+)\\s*$").matcher(req);
        if (!originM.find()) {
            return false;
        }
        String origin = originM.group(1);
        Matcher acaoM = Pattern.compile("(?im)^Access-Control-Allow-Origin:\\s*(\\S+)\\s*$")
                .matcher(resp);
        if (!acaoM.find()) {
            return false;
        }
        String acao = acaoM.group(1);
        boolean reflected = acao.equalsIgnoreCase(origin);
        boolean creds = Pattern.compile("(?im)^Access-Control-Allow-Credentials:\\s*true")
                .matcher(resp).find();
        // 只有「反射 + 允许凭据」才构成真问题；单纯反射到 * 不危险
        return reflected && creds;
    }

    static boolean isPlainHttp(String req) {
        // 绝对形式的请求行（代理风格）：GET http://host/path
        Matcher m = Pattern.compile("^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\s+(\\w+://)")
                .matcher(req);
        if (m.find()) {
            return m.group(1).equalsIgnoreCase("http://");
        }
        // 相对形式看不出 scheme，交给 Host 头判断不可靠，返回 false 不臆断
        return false;
    }

    static String checkSetCookie(String resp) {
        List<String> problems = new ArrayList<>();
        Matcher m = Pattern.compile("(?im)^Set-Cookie:\\s*([^\\r\\n]+)").matcher(resp);
        while (m.find()) {
            String line = m.group(1).toLowerCase();
            String name = line.split("=")[0].trim();
            if (!line.contains("httponly")) {
                problems.add(name + " 缺 HttpOnly");
            }
            if (!line.contains("secure")) {
                problems.add(name + " 缺 Secure");
            }
        }
        return problems.isEmpty() ? null : String.join("、", problems);
    }

    static int parseStatus(String resp) {
        int sp = resp.indexOf(' ');
        if (sp < 0) {
            return 0;
        }
        int sp2 = resp.indexOf(' ', sp + 1);
        try {
            return Integer.parseInt(resp.substring(sp + 1, sp2 < 0 ? Math.min(resp.length(), sp + 4) : sp2));
        } catch (Exception e) {
            return 0;
        }
    }

    // ==================================================================
    // 宏观：业务地图
    // ==================================================================

    /**
     * 把一组接口汇总成「业务地图」—— 这是做<b>宏观业务流量分析</b>的输入。
     *
     * <p>它回答的是「这个系统有哪些业务模块、每个模块有哪些接口」，
     * 而不是「这一个包在干什么」。
     *
     * <p>这份地图可以直接给 AI 做一次<b>总体业务逻辑推断</b> ——
     * 一次调用覆盖整个域名，而不是每个包调一次。
     * 一个典型域名约 20-60 个接口，合成清单约 800-2000 tokens，
     * 成本约 ¥0.01-0.03，可接受。
     */
    public static final class BusinessMap {
        public final String host;
        /** 接口条目，按路径排序。 */
        public final List<Entry> entries = new ArrayList<>();
        /** 按作用分组的计数。 */
        public final Map<String, Integer> byPurpose = new LinkedHashMap<>();

        public BusinessMap(String host) {
            this.host = host;
        }

        public static final class Entry {
            public final String method;
            public final String pathTemplate;
            public final String purpose;
            public final int count;
            public final Level worst;
            public final String issues;

            public Entry(String method, String pathTemplate, String purpose, int count,
                         Level worst, String issues) {
                this.method = method;
                this.pathTemplate = pathTemplate;
                this.purpose = purpose;
                this.count = count;
                this.worst = worst;
                this.issues = issues;
            }
        }

        /** 生成给 AI 的一次性清单文本（宏观分析用）。 */
        public String toPromptText() {
            StringBuilder sb = new StringBuilder();
            sb.append("目标域名：").append(host).append('\n');
            sb.append("接口总数：").append(entries.size()).append('\n');
            sb.append('\n');
            sb.append("接口清单（方法 路径  作用  出现次数  本地已发现问题）：\n");
            for (Entry e : entries) {
                sb.append(e.method).append(' ').append(e.pathTemplate);
                sb.append("  [").append(e.purpose).append(']');
                if (e.count > 1) {
                    sb.append("  ×").append(e.count);
                }
                if (e.issues != null && !"无".equals(e.issues)) {
                    sb.append("  ▲ ").append(e.issues);
                }
                sb.append('\n');
            }
            sb.append('\n');
            sb.append("业务模块分布：\n");
            for (Map.Entry<String, Integer> kv : byPurpose.entrySet()) {
                sb.append("  ").append(kv.getKey()).append("：").append(kv.getValue()).append(" 个接口\n");
            }
            return sb.toString();
        }
    }
}
