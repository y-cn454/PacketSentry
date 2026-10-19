package com.packetsentry.sanitize;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PacketSentry 脱敏引擎 —— 把 Burp 报文处理成"可以安全交给 AI"的文本。
 *
 * <p>设计出发点：作者 AIPacketHunter 的 {@code buildPacketBrief()} 把
 * Authorization / Cookie / Set-Cookie 整行（含值）和请求 body 原样外发，
 * 全局没有任何脱敏逻辑。对渗透测试工具来说这是不可接受的：
 * 你抓的每个包都带着客户或学校的凭据。
 *
 * <p>本类分三层处理，逐层收紧：
 * <ol>
 *   <li><b>头层</b>：按头名白名单命中就掩码值</li>
 *   <li><b>字段层</b>：按 Content-Type 解析 body，按字段名掩码</li>
 *   <li><b>值层</b>：不依赖字段名的正则识别（手机号 / 身份证 / 银行卡 / JWT / 云密钥）</li>
 * </ol>
 *
 * <p>不变量：<b>本类不产生任何网络调用，不写任何文件。</b>
 * 它只做字符串变换，所以可以放心在任何地方调用。
 */
public final class Sanitizer {

    /** 掩码策略。默认 KEEP_EDGES —— 既能防泄露，又能让人/模型认出"这是同一个值"。 */
    public enum MaskStrategy {
        /** 保留前 4 后 4，中间用 **** 填充。默认。 */
        KEEP_EDGES,
        /** 全部替换成 &lt;REDACTED&gt;。 */
        FULL,
        /** 替换成值的 SHA-256 前 8 位（不可逆，但可比对）。 */
        HASH,
        /** 替换成类型标记，如 &lt;JWT&gt; / &lt;PHONE&gt;。 */
        TYPE_ONLY
    }

    /** 一条命中记录。用于在 UI 上告诉用户"我抹掉了什么"，而不是默默改掉。 */
    public static final class Hit {
        public final String layer;      // HEADER / FIELD / VALUE
        public final String rule;       // 命中的规则名
        public final String where;      // 位置描述，如 "Authorization" / "body.password"
        public final int originalLength;
        public final String preview;    // 掩码后的样子（本身已脱敏，可安全展示）

        Hit(String layer, String rule, String where, int originalLength, String preview) {
            this.layer = layer;
            this.rule = rule;
            this.where = where;
            this.originalLength = originalLength;
            this.preview = preview;
        }

        @Override
        public String toString() {
            return String.format("[%s] %s @ %s (%d 字符 → %s)",
                    layer, rule, where, originalLength, preview);
        }
    }

    /** 脱敏结果：处理后的文本 + 命中报告。 */
    public static final class Result {
        public final String cleanText;
        public final List<Hit> hits;
        public final int originalLength;

        Result(String cleanText, List<Hit> hits, int originalLength) {
            this.cleanText = cleanText;
            this.hits = hits;
            this.originalLength = originalLength;
        }

        public boolean hasSensitiveData() {
            return !hits.isEmpty();
        }

        public int bytesSaved() {
            return Math.max(0, originalLength - cleanText.length());
        }

        /** 给 UI 用的一句话摘要。 */
        public String summary() {
            if (hits.isEmpty()) {
                return "未发现敏感数据";
            }
            StringBuilder sb = new StringBuilder("已抹除 ").append(hits.size()).append(" 处：");
            for (int i = 0; i < hits.size() && i < 6; i++) {
                if (i > 0) {
                    sb.append("、");
                }
                sb.append(hits.get(i).rule);
            }
            if (hits.size() > 6) {
                sb.append(" 等 ").append(hits.size()).append(" 处");
            }
            return sb.toString();
        }
    }

    // ------------------------------------------------------------------
    // 第 1 层：HTTP 头白名单
    // ------------------------------------------------------------------

    /** 命中这些头名（不区分大小写、忽略前缀空格）就掩码其值。 */
    private static final String[] SENSITIVE_HEADERS = {
            "authorization", "proxy-authorization", "cookie", "set-cookie",
            "x-auth-token", "x-token", "x-access-token", "x-session-id",
            "x-csrf-token", "x-xsrf-token", "x-api-key", "api-key",
            "x-amz-security-token", "x-goog-api-key"
    };

    // ------------------------------------------------------------------
    // 第 2 层：结构化字段名
    // ------------------------------------------------------------------

    /** body 里字段名（小写）含这些子串就掩码其值。用子串匹配，覆盖 user_password 这类复合名。 */
    private static final String[] SENSITIVE_FIELD_HINTS = {
            "password", "passwd", "pwd", "secret", "token",
            "id_card", "idcard", "identity", "sfz", "shenfen",
            "bank_card", "cardno", "card_no", "creditcard", "credit_card",
            "phone", "mobile", "telephone", "tel", "msisdn",
            "email", "mail", "private_key", "privatekey",
            "apikey", "api_key", "access_key", "secret_key"
    };

    // ------------------------------------------------------------------
    // 第 3 层：值级正则（不依赖字段名）
    // ------------------------------------------------------------------

    private static final class ValueRule {
        final String name;
        final Pattern pattern;
        final String typeTag;

        ValueRule(String name, String regex, String typeTag) {
            this.name = name;
            this.pattern = Pattern.compile(regex);
            this.typeTag = typeTag;
        }
    }

    /** 按"越具体越靠前"排序 —— 先抹 JWT，再抹里面的片段。 */
    private static final ValueRule[] VALUE_RULES = {
            new ValueRule("PEM私钥",
                    "-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]{0,4000}?-----END [A-Z ]*PRIVATE KEY-----",
                    "<PRIVATE_KEY>"),
            new ValueRule("JWT",
                    "\\beyJ[A-Za-z0-9_-]{5,}\\.eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\b",
                    "<JWT>"),
            new ValueRule("AWS密钥",
                    "\\b(AKIA|ASIA)[0-9A-Z]{16}\\b",
                    "<AWS_KEY>"),
            new ValueRule("中国大陆身份证",
                    "\\b[1-9]\\d{5}(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx]\\b",
                    "<ID_CARD>"),
            new ValueRule("中国大陆手机号",
                    "\\b1[3-9]\\d{9}\\b",
                    "<PHONE>"),
            new ValueRule("银行卡号",
                    "\\b\\d{16,19}\\b",
                    "<BANK_CARD>"),
            new ValueRule("邮箱",
                    "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
                    "<EMAIL>"),
    };

    // ------------------------------------------------------------------

    private final MaskStrategy strategy;
    private final boolean headerLayer;
    private final boolean fieldLayer;
    private final boolean valueLayer;

    public Sanitizer() {
        this(MaskStrategy.KEEP_EDGES, true, true, true);
    }

    public Sanitizer(MaskStrategy strategy, boolean headerLayer, boolean fieldLayer, boolean valueLayer) {
        this.strategy = strategy == null ? MaskStrategy.KEEP_EDGES : strategy;
        this.headerLayer = headerLayer;
        this.fieldLayer = fieldLayer;
        this.valueLayer = valueLayer;
    }

    // ==================================================================
    // 入口
    // ==================================================================

    /**
     * 处理一条完整 HTTP 报文（请求或响应），返回可安全外发的文本 + 命中报告。
     *
     * @param rawMessage 原始报文（含请求行/状态行、头、空行、body）
     */
    public Result sanitize(String rawMessage) {
        List<Hit> hits = new ArrayList<>();
        if (rawMessage == null) {
            return new Result("", hits, 0);
        }
        int originalLength = rawMessage.length();

        int sep = findHeaderBodySeparator(rawMessage);
        String head;
        String body;
        if (sep < 0) {
            head = rawMessage;
            body = "";
        } else {
            head = rawMessage.substring(0, sep);
            body = rawMessage.substring(sep);
        }

        String cleanHead = headerLayer ? sanitizeHead(head, hits) : head;
        String cleanBody = body;

        if (body.length() > 0) {
            String contentType = extractHeaderValue(head, "content-type");
            cleanBody = sanitizeBody(body, contentType, hits);
        }

        // 值层作用在整体上 —— 有些敏感值出现在头里（比如自定义头塞了个手机号）
        String combined = cleanHead + cleanBody;
        if (valueLayer) {
            combined = applyValueRules(combined, hits);
        }

        return new Result(combined, hits, originalLength);
    }

    // ==================================================================
    // 第 1 层实现
    // ==================================================================

    private String sanitizeHead(String head, List<Hit> hits) {
        StringBuilder out = new StringBuilder(head.length());
        int i = 0;
        int n = head.length();
        while (i < n) {
            int lineEnd = head.indexOf('\n', i);
            if (lineEnd < 0) {
                lineEnd = n;
            }
            String line = head.substring(i, lineEnd);
            out.append(sanitizeHeaderLine(line, hits));
            if (lineEnd < n) {
                out.append('\n');
            }
            i = lineEnd + 1;
        }
        return out.toString();
    }

    private String sanitizeHeaderLine(String line, List<Hit> hits) {
        int colon = line.indexOf(':');
        if (colon <= 0) {
            return line;                     // 请求行 / 状态行 / 续行，原样保留
        }
        String name = line.substring(0, colon).trim();
        String lower = name.toLowerCase();
        if (!isSensitiveHeader(lower)) {
            return line;
        }
        String value = line.substring(colon + 1).trim();
        String masked = mask(value, MaskStrategy.KEEP_EDGES);
        hits.add(new Hit("HEADER", "敏感头", name, value.length(), masked));
        return name + ": " + masked;
    }

    private boolean isSensitiveHeader(String lowerName) {
        for (String h : SENSITIVE_HEADERS) {
            if (lowerName.equals(h)) {
                return true;
            }
        }
        return false;
    }

    // ==================================================================
    // 第 2 层实现
    // ==================================================================

    private String sanitizeBody(String body, String contentType, List<Hit> hits) {
        String ct = contentType == null ? "" : contentType.toLowerCase();

        // 按 Content-Type 选解析方式；解析失败就退回值层，不硬塞
        if (ct.contains("json") || looksLikeJson(body)) {
            return sanitizeJson(body, hits);
        }
        if (ct.contains("x-www-form-urlencoded") || looksLikeForm(body)) {
            return sanitizeForm(body, hits);
        }
        if (ct.contains("multipart/form-data")) {
            return sanitizeMultipart(body, hits);
        }
        return body;
    }

    /**
     * 只替换"值"所占的字符区间，不重建 key-value 对。
     *
     * <p>为什么强调这点：早期版本用 {@code "key":"value"} 重建整对，
     * 把原文的 {@code ": "} 空格格式吃掉了。后果是输出里被改过的字段变紧凑、
     * 没改的字段保持原样，格式不一致 —— 读起来像被谁动过手脚，
     * 也改变了原始报文的外观。现在只动值，其余字节逐字保留。
     */
    private String sanitizeJson(String body, List<Hit> hits) {
        // 只处理字符串值；数字/布尔/null 不动（免得把 "remember": true 也改坏）
        Pattern p = Pattern.compile("\"([^\"]{1,80})\"\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(body);
        StringBuilder out = new StringBuilder();
        int last = 0;
        while (m.find()) {
            String key = m.group(1);
            String val = m.group(2);
            if (!isSensitiveField(key)) {
                continue;
            }
            String maskedVal = mask(val, strategy);
            hits.add(new Hit("FIELD", "敏感字段", "body." + key, val.length(), maskedVal));
            out.append(body, last, m.start(2));   // 值之前的原文一字不动
            out.append(maskedVal);
            last = m.end(2);
        }
        out.append(body, last, body.length());
        return out.toString();
    }

    /** a=1&password=xxx&b=2 */
    private String sanitizeForm(String body, List<Hit> hits) {
        StringBuilder out = new StringBuilder(body.length());
        int i = 0;
        while (i <= body.length()) {
            int amp = body.indexOf('&', i);
            boolean lastSeg = amp < 0;
            String seg = lastSeg ? body.substring(i) : body.substring(i, amp);
            int eq = seg.indexOf('=');
            if (eq > 0) {
                String key = seg.substring(0, eq);
                String val = seg.substring(eq + 1);
                if (isSensitiveField(key)) {
                    String masked = mask(val, strategy);
                    hits.add(new Hit("FIELD", "敏感字段", "body." + key, val.length(), masked));
                    seg = key + "=" + masked;
                }
            }
            out.append(seg);
            if (lastSeg) {
                break;
            }
            out.append('&');
            i = amp + 1;
        }
        return out.toString();
    }

    /**
     * multipart：只处理 {@code name="xxx"} 后面紧跟的值。
     * 不追求完整 MIME 解析 —— 这是个安全兜底，不是 HTTP 库。
     */
    private String sanitizeMultipart(String body, List<Hit> hits) {
        Pattern p = Pattern.compile("name=\"([^\"]{1,80})\"\\s*(?:;[^\\r\\n]*)?\\r?\\n\\r?\\n([^\\r\\n]{0,400})");
        Matcher m = p.matcher(body);
        StringBuilder out = new StringBuilder();
        int last = 0;
        while (m.find()) {
            String key = m.group(1);
            String val = m.group(2);
            if (isSensitiveField(key)) {
                String masked = mask(val, strategy);
                hits.add(new Hit("FIELD", "敏感字段", "multipart." + key, val.length(), masked));
                out.append(body, last, m.start(2));
                out.append(masked);
                last = m.end(2);
            }
        }
        out.append(body, last, body.length());
        return out.toString();
    }

    private boolean isSensitiveField(String key) {
        String k = key.toLowerCase();
        for (String hint : SENSITIVE_FIELD_HINTS) {
            if (k.contains(hint)) {
                return true;
            }
        }
        return false;
    }

    // ==================================================================
    // 第 3 层实现
    // ==================================================================

    private String applyValueRules(String text, List<Hit> hits) {
        String out = text;
        for (ValueRule rule : VALUE_RULES) {
            Matcher m = rule.pattern.matcher(out);
            if (!m.find()) {
                continue;
            }
            StringBuilder sb = new StringBuilder();
            int last = 0;
            do {
                String found = m.group();
                String masked = mask(found, MaskStrategy.TYPE_ONLY, rule.typeTag);
                hits.add(new Hit("VALUE", rule.name, "内联", found.length(), masked));
                sb.append(out, last, m.start()).append(masked);
                last = m.end();
            } while (m.find());
            sb.append(out, last, out.length());
            out = sb.toString();
        }
        return out;
    }

    // ==================================================================
    // 掩码实现
    // ==================================================================

    public static String mask(String value, MaskStrategy strategy) {
        return mask(value, strategy, null);
    }

    public static String mask(String value, MaskStrategy strategy, String typeTag) {
        if (value == null || value.isEmpty()) {
            return value == null ? "" : value;
        }
        switch (strategy) {
            case FULL:
                return "<REDACTED>";
            case HASH:
                return "<" + sha256Hex(value).substring(0, 8) + ">";
            case TYPE_ONLY:
                return typeTag != null ? typeTag : "<REDACTED>";
            case KEEP_EDGES:
            default:
                // 短值全掩 —— 保留 4+4 等于没掩
                if (value.length() <= 8) {
                    return "****";
                }
                return value.substring(0, 4) + "****" + value.substring(value.length() - 4);
        }
    }

    private static String sha256Hex(String s) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return "00000000";
        }
    }

    // ==================================================================
    // 工具方法
    // ==================================================================

    /** 找头与 body 之间的空行；返回 body 起始位置，没有则 -1。 */
    private static int findHeaderBodySeparator(String msg) {
        int i = msg.indexOf("\r\n\r\n");
        if (i >= 0) {
            return i + 4;
        }
        i = msg.indexOf("\n\n");
        if (i >= 0) {
            return i + 2;
        }
        return -1;
    }

    /** 从头区取一个头的值（不区分大小写），取不到返回 null。 */
    private static String extractHeaderValue(String head, String name) {
        String target = name.toLowerCase() + ":";
        for (String line : head.split("\r?\n")) {
            String l = line.toLowerCase();
            if (l.startsWith(target)) {
                return line.substring(target.length()).trim();
            }
        }
        return null;
    }

    private static boolean looksLikeJson(String s) {
        String t = s.trim();
        return t.startsWith("{") || t.startsWith("[");
    }

    private static boolean looksLikeForm(String s) {
        String t = s.trim();
        return t.indexOf('=') > 0 && t.indexOf('\n') < 0 && t.indexOf('<') < 0;
    }
}
