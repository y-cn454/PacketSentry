package com.packetsentry.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 测试身份 —— 越权检测的基石。
 *
 * <p>越权检测的本质是「<b>换一个身份，重放同一个请求，看还能不能拿到数据</b>」。
 * 所以必须能把一个请求里的认证凭据换成另一个身份的。
 *
 * <p>本类只描述「替换规则」，不发包、不存明文到磁盘（由调用方决定是否持久化）。
 */
public final class Identity {

    /** 身份名，如「普通用户A」「管理员」。 */
    public String name;

    /**
     * 要替换的请求头。键是头名（不区分大小写），值是完整的新值。
     *
     * <p>典型：
     * <pre>
     *   Cookie:        SESSION=xxx; token=yyy
     *   Authorization: Bearer zzz
     * </pre>
     *
     * <p>只替换列在这里的头 —— 其他头（Host / Accept / Content-Type…）
     * 保持原样，因为越权测试要尽量只改变「身份」这一个变量。
     */
    public final Map<String, String> headers = new LinkedHashMap<>();

    /** 备注，比如「从 Burp 里右键标记的」。 */
    public String note = "";

    public Identity() {
    }

    public Identity(String name) {
        this.name = name;
    }

    public Identity header(String k, String v) {
        headers.put(k, v);
        return this;
    }

    /** 这个身份有没有可用的认证信息。 */
    public boolean usable() {
        return name != null && !name.trim().isEmpty() && !headers.isEmpty();
    }

    public String describe() {
        StringBuilder sb = new StringBuilder(name == null ? "(未命名)" : name);
        sb.append("：");
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            parts.add(e.getKey() + "=" + mask(e.getValue()));
        }
        sb.append(String.join(", ", parts));
        return sb.toString();
    }

    /** 身份本身也是凭据，展示时要脱敏。 */
    static String mask(String v) {
        if (v == null) {
            return "";
        }
        String s = v.trim();
        if (s.length() <= 12) {
            return "****";
        }
        return s.substring(0, 8) + "…" + s.substring(s.length() - 4);
    }

    public Identity copy() {
        Identity c = new Identity(name);
        c.headers.putAll(headers);
        c.note = note;
        return c;
    }

    // ==================================================================

    /**
     * 把身份凭据套用到一段原始 HTTP 请求上。
     *
     * <p>这是越权测试的关键操作：<b>只替换认证头，其它一律不动</b>。
     * 这样测试才只改变「身份」一个变量，结论才可信。
     *
     * @param rawRequest 原始请求字节
     * @param addIfMissing 如果请求里没有这个头，要不要新增
     * @return 替换后的请求字节
     */
    public byte[] apply(byte[] rawRequest, boolean addIfMissing) {
        if (rawRequest == null || rawRequest.length == 0) {
            return rawRequest;
        }
        String req = new String(rawRequest, java.nio.charset.StandardCharsets.UTF_8);

        int headEnd = req.indexOf("\r\n\r\n");
        String sep = "\r\n";
        if (headEnd < 0) {
            headEnd = req.indexOf("\n\n");
            sep = "\n";
        }
        if (headEnd < 0) {
            return rawRequest;      // 报文不完整，原样返回
        }

        String head = req.substring(0, headEnd);
        String rest = req.substring(headEnd);

        // ▲ 必须用<b>清洗后</b>的头，不能用原始 headers。
        //    原始值可能含换行 —— 那会注入额外请求头或把请求结构搞坏。
        //    详见 cleanValue / cleanName 的说明。
        Map<String, String> safe = cleanedHeaders();

        // 请求行 + 头
        String[] lines = head.split("\r?\n");
        List<String> out = new ArrayList<>();
        out.add(lines.length > 0 ? lines[0] : "");      // 请求行原样保留

        java.util.Set<String> replaced = new java.util.HashSet<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon <= 0) {
                out.add(line);
                continue;
            }
            String name = line.substring(0, colon).trim();
            String match = matchKey(name, safe);
            if (match != null) {
                out.add(name + ": " + safe.get(match));
                replaced.add(match.toLowerCase());
            } else {
                out.add(line);
            }
        }

        if (addIfMissing) {
            for (Map.Entry<String, String> e : safe.entrySet()) {
                if (!replaced.contains(e.getKey().toLowerCase())) {
                    out.add(e.getKey() + ": " + e.getValue());
                }
            }
        }

        String newReq = String.join(sep, out) + rest;
        return newReq.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /** 大小写不敏感地在清洗后的头表里找匹配的头名。 */
    private String matchKey(String headerName, Map<String, String> safe) {
        for (String k : safe.keySet()) {
            if (k.equalsIgnoreCase(headerName)) {
                return k;
            }
        }
        return null;
    }

    // ==================================================================
    // 头名 / 头值的合法性 —— 信任边界
    // ==================================================================

    /**
     * RFC 7230 的 token 字符集 —— 合法的头名字符。
     *
     * <p>头名必须是 token：{@code !#$%&'*+-.^_`|} 加字母数字。
     * <b>冒号和空格都不是合法头名字符</b>。
     */
    private static final java.util.regex.Pattern HEADER_NAME =
            java.util.regex.Pattern.compile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$");

    /** 头值里不许出现的控制字符（制表符是合法 field-content，保留）。 */
    private static final java.util.regex.Pattern VALUE_CTRL =
            java.util.regex.Pattern.compile("[\\x00-\\x08\\x0A-\\x1F\\x7F]");

    /**
     * 清洗一个头值。
     *
     * <h3>▲ 为什么必须清 —— 这是个真的注入缺陷</h3>
     * 这是「信任边界」测试逼出来的，而且是本轮最严重的一个：
     * 头值直接拼进 HTTP 请求，如果值里带换行，它就不再是个值，
     * 而是<b>一条新请求头</b>。实测：
     * <pre>
     *   输入 Cookie 值  "sid=NEW\r\nX-Injected: evil"
     *   产出            Cookie: sid=NEW
     *                   X-Injected: evil        ← 注入成功
     * </pre>
     * 单独一个 {@code \n} 同样能注入。
     *
     * <p>更常见的不是恶意，而是<b>从别处复制粘贴带上了换行</b> ——
     * 那会让请求头块提前结束，后面的头全被当成 body，请求直接坏掉。
     *
     * @return 清洗后的值；null 输入返回空串
     */
    public static String cleanValue(String v) {
        if (v == null) {
            return "";
        }
        // 先把各种换行压成空格（保持可读性），再干掉其余控制字符
        String s = v.replace("\r\n", " ").replace('\r', ' ').replace('\n', ' ');
        s = VALUE_CTRL.matcher(s).replaceAll("");
        return s.trim();
    }

    /**
     * 清洗一个头名。
     *
     * <h3>▲ 为什么必须校验</h3>
     * 头名同样直接拼进请求。带冒号的名字会<b>静默改错头</b>：
     * <pre>
     *   输入头名  "X-Evil: X-Legit"
     *   产出      X-Evil: X-Legit: v
     *   服务端看到的是头 X-Evil = "X-Legit: v"
     *   —— 而不是用户以为的 X-Legit
     * </pre>
     * 带换行的头名则可以直接注入。
     *
     * @return 合法的头名；不合法时返回 null（调用方应丢弃并提示）
     */
    public static String cleanName(String n) {
        if (n == null) {
            return null;
        }
        String s = n.replace("\r", "").replace("\n", "").replace("\u0000", "").trim();
        return HEADER_NAME.matcher(s).matches() ? s : null;
    }

    /** 这个头名合法吗。 */
    public static boolean isValidName(String n) {
        return cleanName(n) != null;
    }

    /**
     * 检查本身份里有没有需要清洗的东西，返回给用户看的警告。
     *
     * <p>给界面用：用户粘完凭据后立刻告诉他「这个值里有换行，已清理」，
     * 而不是默默改掉、或者把坏请求发出去。
     */
    public List<String> warnings() {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            String k = e.getKey();
            String v = e.getValue();
            if (cleanName(k) == null) {
                out.add("头名「" + safeShow(k) + "」不是合法 HTTP 头名，将被忽略"
                        + "（合法头名只能含字母数字和 !#$%&'*+-.^_`|~）");
            } else if (!k.equals(cleanName(k))) {
                out.add("头名「" + safeShow(k) + "」含多余空白，已清理为「"
                        + cleanName(k) + "」");
            }
            if (v != null && !v.equals(cleanValue(v))) {
                out.add("头「" + safeShow(k) + "」的值里含换行或控制字符，"
                        + "已清理（否则会注入额外请求头 / 破坏请求结构）");
            }
        }
        return out;
    }

    /** 把不可见字符显示成可见形式，避免日志里看不出问题。 */
    static String safeShow(String s) {
        if (s == null) {
            return "";
        }
        String t = s.replace("\r", "\\r").replace("\n", "\\n")
                .replace("\u0000", "\\0");
        return t.length() <= 60 ? t : t.substring(0, 60) + "…";
    }

    /**
     * 清洗后的头 —— 真正会被套用到请求上的那一份。
     *
     * <p>非法头名会被<b>丢弃</b>（不是静默改造），因为改造成什么名字都不对。
     */
    public Map<String, String> cleanedHeaders() {
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            String name = cleanName(e.getKey());
            if (name == null) {
                continue;
            }
            out.put(name, cleanValue(e.getValue()));
        }
        return out;
    }
}
