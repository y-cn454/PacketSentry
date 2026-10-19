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
 * 反射与上下文检测 —— 为 XSS 测试定位「该用哪种注入形式」。
 *
 * <h3>▲ 先说清楚这个模块<b>不</b>做什么</h3>
 * 它<b>不下发任何 payload</b>，所以它<b>不能确认 XSS</b>。
 * 被动分析看到的永远是「正常参数值被原样回显」，看不到「注入 payload 之后会怎样」。
 *
 * <h3>它做的是另外一半，而且是更难的那一半</h3>
 * XSS 的难点不在于记住 payload，而在于判断<b>你的输入落在什么上下文里</b> ——
 * 上下文决定该用哪种形式。选错形式，再花哨的 payload 也不会执行。
 *
 * <p>所以本模块对每个参数做三件事：
 * <ol>
 *   <li><b>有没有反射</b>：参数值出现在响应里吗（以及出现几次）</li>
 *   <li><b>落在什么上下文</b>：HTML 文本 / 属性内（单引号·双引号·无引号）/
 *       JS 字符串内 / JS 裸值 / {@code <script>} 块内 / 注释内 / {@code <style>} 内 / JSON</li>
 *   <li><b>该发什么探针、该用哪种形式</b>：直接给出「填这个探针」和
 *       「照这个形式写 payload」</li>
 * </ol>
 *
 * <h3>★ 关于「哪些字符被转义」—— 这里必须诚实</h3>
 * 只有在<b>观察到的参数值本身含</b> {@code < > " ' &} 时，才能看出服务端有没有转义它们。
 * 如果值里没有这些字符，转义状态就是<b>未知</b>，不能猜。
 * 这时本模块会明确写「未知」，并告诉你要发什么探针才能测出来 ——
 * 而不是假装知道。
 */
public final class ReflectionAudit {

    /** 反射所在的上下文 —— 决定该用哪种注入形式。 */
    public enum Context {
        HTML_TEXT("HTML 文本", "标签之间",
                "<img src=x onerror=alert(1)>",
                "<script>alert(1)</script>"),
        ATTR_DOUBLE("属性内（双引号）", "value=\"...\"",
                "\"><img src=x onerror=alert(1)>",
                "\" onmouseover=\"alert(1)"),
        ATTR_SINGLE("属性内（单引号）", "value='...'",
                "'><img src=x onerror=alert(1)>",
                "' onmouseover='alert(1)"),
        ATTR_UNQUOTED("属性内（无引号）", "<a href=...>",
                " onmouseover=alert(1) ",
                "><script>alert(1)</script>"),
        URL_ATTR("URL 属性", "href / src / action",
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>"),
        SCRIPT_BLOCK("script 块内（字符串外）", "<script> ... </script>",
                "</script><script>alert(1)</script>",
                ";alert(1);//"),
        JS_STRING_DOUBLE("JS 字符串内（双引号）", "var a=\"...\"",
                "\";alert(1);//",
                "\";alert(1);var x=\""),
        JS_STRING_SINGLE("JS 字符串内（单引号）", "var a='...'",
                "';alert(1);//",
                "';alert(1);var x='"),
        JS_TEMPLATE("JS 模板字符串内", "var a=`...`",
                "${alert(1)}",
                "`;alert(1);//"),
        JS_RAW("JS 裸值（非字符串）", "var a=...",
                "alert(1)//",
                "1;alert(1)"),
        EVENT_HANDLER("事件处理器内", "onclick=\"...\"",
                "alert(1)",
                "';alert(1);//"),
        STYLE_BLOCK("style 块内", "<style> ... </style>",
                "</style><img src=x onerror=alert(1)>",
                "</style><script>alert(1)</script>"),
        HTML_COMMENT("HTML 注释内", "<!-- ... -->",
                "--><img src=x onerror=alert(1)>",
                "--><script>alert(1)</script>"),
        JSON_BODY("JSON 响应内", "application/json",
                "（服务端上下文打不了，看前端怎么用这个字段）",
                "前端若有 innerHTML / eval 才是 DOM XSS"),
        UNKNOWN("未能判定", "上下文特征不明确",
                "（先手工看一眼响应里那一段）",
                "（先手工看一眼响应里那一段）");

        public final String label;
        public final String hint;
        /** 推荐的注入形式（首选）。 */
        public final String primaryPayload;
        /** 备选形式（首选被过滤时用）。 */
        public final String altPayload;
        /** 该上下文该发的探针。 */
        public final String probe;

        Context(String label, String hint, String primaryPayload, String altPayload) {
            this.label = label;
            this.hint = hint;
            this.primaryPayload = primaryPayload;
            this.altPayload = altPayload;
            this.probe = probeFor(this);
        }

        private static String probeFor(Context c) {
            switch (c) {
                case ATTR_DOUBLE:
                    return "AAA\"<>";
                case ATTR_SINGLE:
                    return "AAA'<>";
                case ATTR_UNQUOTED:
                    return "AAA onmouseover=1 x";
                case URL_ATTR:
                    return "AAA\"<>";
                case SCRIPT_BLOCK:
                case JS_RAW:
                    return "AAA</script><>;\"'`";
                case JS_STRING_DOUBLE:
                    return "AAA\";<>//";
                case JS_STRING_SINGLE:
                    return "AAA';<>//";
                case JS_TEMPLATE:
                    return "AAA${}<>`";
                case EVENT_HANDLER:
                    return "AAA';<>//";
                case STYLE_BLOCK:
                    return "AAA</style><>";
                case HTML_COMMENT:
                    return "AAA--><>";
                default:
                    return "AAA<>\"'`&/";
            }
        }
    }

    /** 一处反射。 */
    public static final class Hit {
        /** 参数来源，如 {@code query.id} / {@code body.user.name} / {@code header.Referer}。 */
        public final String where;
        /** 参数值（截断展示，避免把长值灌进界面）。 */
        public final String value;
        /** 上下文。 */
        public Context context;
        /** 反射次数。 */
        public int count;
        /** 观察到的转义情况说明。 */
        public String encodingNote = "未知（参数值里没有 < > \" ' 这类字符，看不出有没有被转义）";
        /** 反射位置周围的片段（供人工核对）。 */
        public String snippet = "";
        /** 风险提示。 */
        public String risk = "";

        Hit(String where, String value) {
            this.where = where;
            this.value = value;
        }
    }

    // ==================================================================

    /** 值短于这个长度就不测 —— 太短的值（如 "1"）会到处都是，全是噪音。 */
    private static final int MIN_VALUE_LEN = 3;
    private static final int MAX_VALUE_LEN = 400;
    private static final int MAX_HITS = 40;
    private static final int MAX_PARAMS = 120;

    /** JSON 里的字符串型键值对。 */
    private static final Pattern JSON_KV = Pattern.compile(
            "\"([A-Za-z_][A-Za-z0-9_\\-]{0,40})\"\\s*:\\s*\"([^\"]{1,400})\"");

    /** form 键值对。 */
    private static final Pattern FORM_KV = Pattern.compile(
            "(?:^|&)([A-Za-z_][A-Za-z0-9_\\-]{0,40})=([^&\\r\\n]{1,400})");

    /** URL 类属性名 —— 这些属性里的值会被当 URL 解析。 */
    private static final String[] URL_ATTRS = {
            "href", "src", "action", "formaction", "poster",
            "background", "codebase", "cite", "longdesc", "usemap", "manifest",
    };

    /** 值得一看的请求头（这些头也会出现在页面里）。 */
    private static final String[] HEADERS_TO_CHECK = {
            "Referer", "User-Agent", "X-Forwarded-Host", "X-Forwarded-For",
            "Origin", "Accept-Language", "X-Requested-With",
    };

    // ==================================================================

    /**
     * 检测一个请求/响应对。
     *
     * @param reqRaw  原始请求
     * @param respRaw 原始响应
     * @param out     累积结果（同一参数会被合并计数）
     */
    public void check(String reqRaw, String respRaw, List<Hit> out) {
        if (reqRaw == null || respRaw == null || respRaw.isEmpty()) {
            return;
        }
        // 二进制响应不可能有 HTML 上下文
        String ct = contentTypeOf(respRaw);
        if (ct.startsWith("image/") || ct.startsWith("font/") || ct.startsWith("audio/")
                || ct.startsWith("video/") || ct.contains("octet-stream")) {
            return;
        }
        String body = bodyOf(respRaw);
        if (body.isEmpty()) {
            return;
        }

        Map<String, String> params = extractParams(reqRaw);
        int checked = 0;
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (checked++ >= MAX_PARAMS) {
                break;
            }
            String where = e.getKey();
            String value = e.getValue();
            if (value == null || value.length() < MIN_VALUE_LEN
                    || value.length() > MAX_VALUE_LEN) {
                continue;
            }
            // 纯数字 / 纯空白 不值得测
            if (value.matches("^[0-9\\s]+$")) {
                continue;
            }
            // ▲ 不能只搜原始值。
            //
            //    这个 bug 是测试逼出来的，而且会造成<b>误报「没有反射」</b>：
            //    服务端把 < 编码成 &lt; 之后，原始值就永远搜不到 ——
            //    这个参数会被判成「无反射」而整个漏掉。但它其实<b>被反射了</b>，
            //    只是被编码了；而「被编码」恰恰是判断能不能打的关键信号。
            //
            //    所以原始值搜不到时，再试几种常见编码形态。
            int idx = body.indexOf(value);
            String encodingFound = null;
            if (idx < 0) {
                for (Map.Entry<String, String> ev : encodedVariants(value).entrySet()) {
                    int at = body.indexOf(ev.getValue());
                    if (at >= 0) {
                        idx = at;
                        encodingFound = ev.getKey();
                        break;
                    }
                }
            }
            if (idx < 0) {
                continue;
            }
            if (out.size() >= MAX_HITS) {
                // 已经够了 —— 但同参数的计数还是要更新
                Hit existing = find(out, where, value);
                if (existing != null) {
                    existing.count++;
                }
                continue;
            }

            Hit h = find(out, where, value);
            if (h == null) {
                h = new Hit(where, truncate(value, 80));
                out.add(h);
            }
            h.count++;
            // 只在第一次反射时定上下文（后续同值上下文一般相同）
            if (h.context == null) {
                h.context = detectContext(body, idx, value, ct);
                h.snippet = snippetAround(body, idx, value);
                h.encodingNote = encodingFound != null
                        ? ("▲ 参数值被「" + encodingFound + "」回显 —— "
                        + "原始字符没有原样出现，说明该字符在这个位置打不出来。"
                        + "换个字符或换个上下文仍可能，但不要在这个点硬试。")
                        : encodingNote(body, idx, value);
                h.risk = riskOf(h.context, h.encodingNote);
            }
        }
    }

    // ==================================================================
    // 上下文判定
    // ==================================================================

    /**
     * 判断反射点落在什么上下文里。
     *
     * <p>做法是从反射位置<b>往前回溯</b>，看最近的结构性标记：
     * 最近的 {@code <script} / {@code </script>} / {@code <style} / {@code <!--}
     * / 标签的 {@code <} 与 {@code >}，以及未闭合的引号。
     */
    /** public 理由同 {@link #lastUnclosedQuote}。 */
    public static Context detectContext(String body, int idx, String value, String contentType) {
        // ---- 1. 先排注释 ----
        int lastCommentOpen = body.lastIndexOf("<!--", idx);
        int lastCommentClose = body.lastIndexOf("-->", idx);
        if (lastCommentOpen >= 0 && lastCommentOpen > lastCommentClose) {
            return Context.HTML_COMMENT;
        }

        // ---- 2. 判断在不在 script / style 块内 ----
        int lastScriptOpen = body.lastIndexOf("<script", idx);
        int lastScriptClose = body.lastIndexOf("</script", idx);
        boolean inScript = lastScriptOpen >= 0 && lastScriptOpen > lastScriptClose;

        int lastStyleOpen = body.lastIndexOf("<style", idx);
        int lastStyleClose = body.lastIndexOf("</style", idx);
        boolean inStyle = lastStyleOpen >= 0 && lastStyleOpen > lastStyleClose;

        if (inScript) {
            // 在 <script> 里，进一步判断是否在字符串里
            //   从 script 开始处到反射点之间，找未闭合的引号
            String seg = body.substring(lastScriptOpen, idx);
            char open = lastUnclosedQuote(seg);
            if (open == '"') {
                return Context.JS_STRING_DOUBLE;
            }
            if (open == '\'') {
                return Context.JS_STRING_SINGLE;
            }
            if (open == '`') {
                return Context.JS_TEMPLATE;
            }
            // 没有未闭合引号 → 在代码位置，不是字符串
            return Context.SCRIPT_BLOCK;
        }

        if (inStyle) {
            return Context.STYLE_BLOCK;
        }

        // ---- 3. 判断在不在标签内部（属性区）----
        int lastLt = body.lastIndexOf('<', idx);
        int lastGt = body.lastIndexOf('>', idx);
        boolean insideTag = lastLt >= 0 && lastLt > lastGt;

        if (insideTag) {
            // 取出这个标签从 < 到反射点的片段
            String tagSeg = body.substring(lastLt, idx);

            // ▲ 判断属性名要用「最后一个 = 之前那一段」，不能拿整个剩余片段套正则。
            //
            //    这个 bug 是测试逼出来的。原来的写法是
            //      on[a-z]+\s*=\s*["']?[^"'>]*$
            //    但属性值里可能出现<b>另一种引号</b>，例如
            //      onclick="go('INJ"
            //    值里的那个单引号会打断 [^"'>]*，于是事件处理器被判成了普通属性 ——
            //    而事件处理器里该用「纯 JS」形式，普通属性里该用「闭合引号」形式，
            //    两者完全不同，判错就会让用户用错 payload。
            //
            //    改成先定位最后一个 =，再往前取属性名 —— 这样完全不关心值里有什么。
            int eq = tagSeg.lastIndexOf('=');
            if (eq > 0) {
                Matcher am = Pattern.compile("(?i)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\\s*$")
                        .matcher(tagSeg.substring(0, eq));
                if (am.find()) {
                    String attr = am.group(1).toLowerCase();
                    if (attr.startsWith("on")) {
                        return Context.EVENT_HANDLER;
                    }
                    for (String u : URL_ATTRS) {
                        if (attr.equals(u) || attr.endsWith(":" + u)) {
                            return Context.URL_ATTR;
                        }
                    }
                }
            }
            // 引号归属
            char open = lastUnclosedQuote(tagSeg);
            if (open == '"') {
                return Context.ATTR_DOUBLE;
            }
            if (open == '\'') {
                return Context.ATTR_SINGLE;
            }
            return Context.ATTR_UNQUOTED;
        }

        // ---- 4. JSON 响应 ----
        String ctLower = contentType == null ? "" : contentType.toLowerCase();
        if (ctLower.contains("json")) {
            return Context.JSON_BODY;
        }

        // ---- 5. 标签之间 = HTML 文本 ----
        if (body.trim().startsWith("{") || body.trim().startsWith("[")) {
            // 说不清是 JSON 还是 JS 字面量
            return ctLower.contains("javascript") ? Context.JS_RAW : Context.JSON_BODY;
        }
        return Context.HTML_TEXT;
    }

    /**
     * 在一段文本里找<b>未闭合</b>的引号。
     *
     * <p>从后往前扫，遇到同类引号就配对抵消。
     * 返回最后剩下的那个未闭合引号字符；没有则返回 0。
     */
    /**
     * public 是为了让测试能直接验证「未闭合引号判定」——
     * 这是上下文判定的核心，判错会导致推荐的 payload 形式完全不对。
     */
    public static char lastUnclosedQuote(String seg) {
        int dq = 0;
        int sq = 0;
        int bt = 0;
        boolean esc = false;
        for (int i = 0; i < seg.length(); i++) {
            char c = seg.charAt(i);
            if (esc) {
                esc = false;
                continue;
            }
            if (c == '\\') {
                esc = true;
                continue;
            }
            if (c == '"') {
                dq = 1 - dq;
            } else if (c == '\'') {
                sq = 1 - sq;
            } else if (c == '`') {
                bt = 1 - bt;
            }
        }
        if (dq == 1) {
            return '"';
        }
        if (sq == 1) {
            return '\'';
        }
        if (bt == 1) {
            return '`';
        }
        return 0;
    }

    /**
     * 判断观察到的值有没有被转义。
     *
     * <p>★ 这里必须诚实：只有值本身含 {@code < > " ' &} 时才能看出来，
     * 否则就是「未知」—— 不能假装知道，更不能让用户以为「没看到转义就是没转义」。
     */
    /** public 理由同 {@link #lastUnclosedQuote}。 */
    public static String encodingNote(String body, int idx, String value) {
        Set<Character> dangerous = new LinkedHashSet<>();
        for (char c : new char[]{'<', '>', '"', '\'', '&'}) {
            if (value.indexOf(c) >= 0) {
                dangerous.add(c);
            }
        }
        // 看反射出来的那一段里，这些字符是原样还是被编码
        int end = Math.min(body.length(), idx + value.length() + 20);
        String around = body.substring(idx, end);

        if (dangerous.isEmpty()) {
            return "未知 —— 这个参数值本身不含 < > \" ' & ，看不出服务端有没有转义。"
                    + "要判断必须先发一次探针。";
        }
        List<String> rawOk = new ArrayList<>();
        List<String> encoded = new ArrayList<>();
        for (char c : dangerous) {
            if (around.indexOf(c) >= 0) {
                rawOk.add(String.valueOf(c));
            }
        }
        if (around.contains("&lt;")) {
            encoded.add("<");
        }
        if (around.contains("&gt;")) {
            encoded.add(">");
        }
        if (around.contains("&quot;")) {
            encoded.add("\"");
        }
        if (around.contains("&#39;") || around.contains("&apos;")) {
            encoded.add("'");
        }
        if (around.contains("&amp;")) {
            encoded.add("&");
        }

        StringBuilder sb = new StringBuilder();
        if (!rawOk.isEmpty()) {
            sb.append("▲ 观察到这些字符原样存活：")
                    .append(String.join(" ", rawOk)).append("；");
        }
        if (!encoded.isEmpty()) {
            sb.append("观察到这些字符被编码：")
                    .append(String.join(" ", encoded)).append("；");
        }
        if (sb.length() == 0) {
            return "未知（值里有特殊字符，但反射片段里没能确认它们的形态）";
        }
        return sb.toString();
    }

    static String riskOf(Context ctx, String encodingNote) {
        boolean confirmedRaw = encodingNote != null && encodingNote.contains("原样存活");
        switch (ctx) {
            case HTML_TEXT:
            case SCRIPT_BLOCK:
            case JS_RAW:
            case ATTR_UNQUOTED:
            case EVENT_HANDLER:
                return confirmedRaw
                        ? "▲ 上下文宽松且已观察到未转义字符 —— 值得马上手工验证"
                        : "上下文宽松，值得试；转义情况待探针确认";
            case ATTR_DOUBLE:
            case ATTR_SINGLE:
            case JS_STRING_DOUBLE:
            case JS_STRING_SINGLE:
            case JS_TEMPLATE:
                return "在引号里 —— 只要能闭合引号就能打；先看引号字符有没有被转义";
            case URL_ATTR:
                return "URL 属性 —— 试 javascript: / data: ，注意前面有没有被拼 http://";
            case HTML_COMMENT:
                return "在注释里 —— 需要先闭合 --> 才能逃出来";
            case STYLE_BLOCK:
                return "在 style 里 —— 需要先闭合 </style>";
            case JSON_BODY:
                return "服务端上下文打不了；看前端有没有把它送进 innerHTML / eval";
            default:
                return "上下文不明确 —— 手工看响应里那一段";
        }
    }

    // ==================================================================
    // 参数提取
    // ==================================================================

    /** 从请求里提取「值得测反射」的参数。 */
    /** public 理由同 {@link #lastUnclosedQuote}。 */
    public static Map<String, String> extractParams(String reqRaw) {
        Map<String, String> out = new LinkedHashMap<>();
        int headEnd = reqRaw.indexOf("\r\n\r\n");
        if (headEnd < 0) {
            headEnd = reqRaw.indexOf("\n\n");
        }
        String head = headEnd > 0 ? reqRaw.substring(0, headEnd) : reqRaw;
        String body = headEnd > 0 ? reqRaw.substring(headEnd + 4) : "";

        // ---- query ----
        int q = reqRaw.indexOf('?');
        int sp = reqRaw.indexOf(' ', q > 0 ? q : 0);
        if (q > 0 && sp > q) {
            String query = reqRaw.substring(q + 1, sp);
            for (String kv : query.split("&")) {
                int eq = kv.indexOf('=');
                if (eq > 0) {
                    out.put("query." + kv.substring(0, eq), kv.substring(eq + 1));
                }
            }
        }

        // ---- path 段（有些应用把值放在路径里）----
        if (sp > 0) {
            String pathOnly = reqRaw.substring(0, sp);
            int slash = pathOnly.indexOf('/');
            if (slash > 0 && !pathOnly.contains("?")) {
                for (String seg : pathOnly.substring(slash).split("/")) {
                    if (seg.length() >= MIN_VALUE_LEN && !seg.matches("^[0-9]+$")
                            && seg.length() <= MAX_VALUE_LEN) {
                        out.put("path." + truncate(seg, 24), seg);
                    }
                }
            }
        }

        // ---- JSON body ----
        if (body.trim().startsWith("{") || body.trim().startsWith("[")) {
            Matcher m = JSON_KV.matcher(body);
            while (m.find()) {
                out.put("body." + m.group(1), m.group(2));
            }
        } else {
            // ---- form body ----
            Matcher m = FORM_KV.matcher(body);
            while (m.find()) {
                out.put("body." + m.group(1), m.group(2));
            }
        }

        // ---- 也会被回显到页面上的请求头 ----
        for (String h : HEADERS_TO_CHECK) {
            Matcher m = Pattern.compile("(?im)^" + Pattern.quote(h) + ":\\s*(.+)$")
                    .matcher(head);
            if (m.find()) {
                String v = m.group(1).trim();
                if (v.length() >= MIN_VALUE_LEN && v.length() <= MAX_VALUE_LEN) {
                    out.put("header." + h, v);
                }
            }
        }
        return out;
    }

    // ==================================================================

    private static Hit find(List<Hit> list, String where, String value) {
        for (Hit h : list) {
            if (h.where.equals(where)) {
                return h;
            }
        }
        return null;
    }

    /**
     * 把一个值按几种常见编码形态变形，用于查找「被编码的反射」。
     *
     * <p>为什么需要：服务端把 {@code <} 编码成 {@code &lt;} 之后，
     * 直接搜原始值就搜不到，参数会被误判成「没有反射」—— 但它确实反射了。
     *
     * <p>只做几种最常见的（HTML 实体 / HTML 数字实体 / URL 编码 / JS 反斜杠转义），
     * 不追求穷尽 —— 目的是「发现反射确实存在」，而不是还原服务端的编码器。
     */
    public static Map<String, String> encodedVariants(String value) {
        Map<String, String> out = new LinkedHashMap<>();
        if (value == null || value.isEmpty()) {
            return out;
        }
        boolean hasSpecial = false;
        String specials = "<>\"'&";
        for (int i = 0; i < specials.length(); i++) {
            if (value.indexOf(specials.charAt(i)) >= 0) {
                hasSpecial = true;
                break;
            }
        }
        if (!hasSpecial) {
            return out;
        }

        // ---- HTML 实体 ----
        String html = value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
        if (!html.equals(value)) {
            out.put("HTML 实体编码", html);
        }

        // ---- HTML 数字实体 ----
        String htmlNum = value.replace("<", "&#60;")
                .replace(">", "&#62;")
                .replace("\"", "&#34;")
                .replace("'", "&#39;");
        if (!htmlNum.equals(value) && !htmlNum.equals(html)) {
            out.put("HTML 数字实体编码", htmlNum);
        }

        // ---- URL 编码（只编特殊字符）----
        StringBuilder url = new StringBuilder();
        boolean urlChanged = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '<':
                    url.append("%3C");
                    urlChanged = true;
                    break;
                case '>':
                    url.append("%3E");
                    urlChanged = true;
                    break;
                case '"':
                    url.append("%22");
                    urlChanged = true;
                    break;
                case '\'':
                    url.append("%27");
                    urlChanged = true;
                    break;
                case '&':
                    url.append("%26");
                    urlChanged = true;
                    break;
                default:
                    url.append(c);
            }
        }
        if (urlChanged) {
            out.put("URL 编码", url.toString());
        }

        // ---- JS 反斜杠 / 十六进制转义（进入 JS 字符串时常见）----
        String js = value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("'", "\\'")
                .replace("<", "\\x3c")
                .replace(">", "\\x3e");
        if (!js.equals(value) && !out.containsValue(js)) {
            out.put("JS 转义编码", js);
        }
        return out;
    }

    static String contentTypeOf(String resp) {
        Matcher m = Pattern.compile("(?im)^Content-Type:\\s*([^;\\r\\n]+)").matcher(resp);
        return m.find() ? m.group(1).trim().toLowerCase() : "";
    }

    static String bodyOf(String resp) {
        int i = resp.indexOf("\r\n\r\n");
        if (i < 0) {
            i = resp.indexOf("\n\n");
        }
        return i < 0 ? "" : resp.substring(i).trim();
    }

    static String snippetAround(String body, int idx, String value) {
        int from = Math.max(0, idx - 90);
        int to = Math.min(body.length(), idx + value.length() + 90);
        String s = body.substring(from, to).replaceAll("\\s+", " ");
        return (from > 0 ? "…" : "") + s + (to < body.length() ? "…" : "");
    }

    static String truncate(String s, int n) {
        if (s == null) {
            return "";
        }
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }

    // ==================================================================

    /** 渲染成给用户看的报告。 */
    public static String render(List<Hit> hits, int packetsAudited) {
        StringBuilder sb = new StringBuilder();
        sb.append("══════════ 反射与上下文检测 ══════════\n\n");
        sb.append("审计报文  ").append(packetsAudited).append(" 个\n");
        sb.append("发现反射  ").append(hits.size()).append(" 处\n");
        sb.append("网络请求  0 个（纯本地分析已有流量）\n\n");

        sb.append("▲ 这个功能<b>不下发 payload</b>，所以它不能确认 XSS。\n");
        sb.append("   它做的是另一半、也是更难的一半：<b>判断你的输入落在什么上下文</b>。\n");
        sb.append("   上下文决定该用哪种注入形式 —— 形式选错，payload 再花哨也不会执行。\n\n");

        if (hits.isEmpty()) {
            sb.append("没有发现参数值被回显到响应里。\n\n");
            sb.append("这意味着：\n");
            sb.append("  · 反射型 XSS 基本不用看了（值都没回显）\n");
            sb.append("  · 但<b>存储型 XSS 仍然可能</b> —— 你的值存在服务端，");
            sb.append("在别的页面才显示出来。\n");
            sb.append("    要测存储型：把探针填进「个人资料 / 昵称 / 留言」这类字段，\n");
            sb.append("    然后去看<b>别的页面</b>（尤其是后台列表页）。\n");
            sb.append("  · DOM XSS 也仍然可能 —— 那要看前端 JS，用「代码审计」按钮。\n");
            return sb.toString();
        }

        // 按风险排一下：上下文宽松的排前面
        hits.sort((a, b) -> weight(b.context) - weight(a.context));

        int n = 0;
        for (Hit h : hits) {
            if (n++ >= 25) {
                sb.append("…（另有 ").append(hits.size() - 25).append(" 处未列出）\n\n");
                break;
            }
            Context c = h.context == null ? Context.UNKNOWN : h.context;
            sb.append("───────────────────────────────────────────────\n");
            sb.append("参数      ").append(h.where)
                    .append("　反射 ").append(h.count).append(" 次\n");
            sb.append("值        ").append(h.value).append('\n');
            sb.append("上下文    ").append(c.label).append("　（").append(c.hint).append("）\n");
            sb.append("转义情况  ").append(h.encodingNote).append('\n');
            sb.append("判断      ").append(h.risk).append('\n');
            sb.append('\n');
            sb.append("  → 先发这个探针，看响应里它变成什么样：\n");
            sb.append("      ").append(c.probe).append('\n');
            sb.append("    判断标准：探针里的 < > \" ' 有没有原样出现在响应里。\n");
            sb.append("    原样 → 可注入；被转成 &lt; &quot; → 这个上下文打不了。\n\n");
            sb.append("  → 确认可注入后，用这种形式：\n");
            sb.append("      首选  ").append(c.primaryPayload).append('\n');
            sb.append("      备选  ").append(c.altPayload).append('\n');
            if (h.snippet != null && !h.snippet.isEmpty()) {
                sb.append("\n  响应里的片段（人工核对用）：\n");
                sb.append("      ").append(h.snippet).append('\n');
            }
            sb.append('\n');
        }

        sb.append("───────────────────────────────────────────────\n");
        sb.append("▲ 纪律提醒：\n");
        sb.append("  · 用最小证明（alert(1) / console.log(1)），别用 alert(document.cookie)\n");
        sb.append("  · 不要在真实用户会看到的页面弹窗；存储型用只有你自己会触发的字段\n");
        sb.append("  · 不要外带 cookie、不要做蠕虫式自传播\n");
        sb.append("  · 报告里要有「响应中未编码回显」的证据，比弹窗截图更有说服力\n");
        sb.append("  · 逐个手工验证，不要写脚本批量 fuzz —— 那是「自动化工具」，多数 SRC 禁止\n");
        return sb.toString();
    }

    static int weight(Context c) {
        if (c == null) {
            return 0;
        }
        switch (c) {
            case HTML_TEXT:
            case SCRIPT_BLOCK:
            case JS_RAW:
                return 10;
            case ATTR_UNQUOTED:
            case EVENT_HANDLER:
                return 9;
            case ATTR_DOUBLE:
            case ATTR_SINGLE:
                return 8;
            case JS_STRING_DOUBLE:
            case JS_STRING_SINGLE:
            case JS_TEMPLATE:
                return 7;
            case URL_ATTR:
                return 6;
            case HTML_COMMENT:
            case STYLE_BLOCK:
                return 5;
            case JSON_BODY:
                return 4;
            default:
                return 1;
        }
    }

    /** 汇总成给 AI 的文本（生成报告时带上）。 */
    public static String toPromptText(List<Hit> hits) {
        StringBuilder sb = new StringBuilder();
        sb.append("反射与上下文检测（被动分析，未下发 payload）：\n");
        for (Hit h : hits) {
            Context c = h.context == null ? Context.UNKNOWN : h.context;
            sb.append("  ").append(h.where).append(" → 上下文：").append(c.label)
                    .append("　反射 ").append(h.count).append(" 次")
                    .append("　转义：").append(h.encodingNote).append('\n');
        }
        return sb.toString();
    }
}
