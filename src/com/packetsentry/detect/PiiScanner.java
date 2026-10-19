package com.packetsentry.detect;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 本地敏感数据扫描 —— 在脱敏之前先告诉你"这个包里有什么"。
 *
 * <p>为什么要有这一步（作者没有）：用户可能根本不知道自己抓到了什么。
 * 先告警再让他决定，比默默处理更安全 —— <b>可见性就是信任</b>。
 *
 * <p>与 {@code Sanitizer} 的分工：
 * <ul>
 *   <li>Sanitizer 负责<b>改</b>（把值抹掉）</li>
 *   <li>本类负责<b>说</b>（把发现讲清楚，含严重度和过期判断）</li>
 * </ul>
 *
 * <p><b>本类不产生任何网络调用</b>。JWT 只做 Base64URL 解码，<b>不验签</b>——
 * 验签需要密钥，而且我们只想看结构，不想验证真实性。
 */
public final class PiiScanner {

    /** 严重度 —— 决定 UI 用什么颜色，以及要不要拦一下。 */
    public enum Severity {
        /** 长期凭据或私钥：泄露后果最重 */
        CRITICAL,
        /** 会话凭据、个人身份信息 */
        HIGH,
        /** 联系方式、可推断信息 */
        MEDIUM,
        /** 上下文，不算敏感 */
        INFO
    }

    /** 一条发现。 */
    public static final class Finding {
        public final Severity severity;
        public final String kind;       // 类型，如 "JWT" / "手机号"
        public final String location;   // 位置，如 "Authorization" / "body.note"
        public final int length;
        public final String detail;     // 补充说明，如 JWT 解出的 role
        public final long expiresAt;    // 仅 JWT：exp 秒级时间戳；其他为 0

        Finding(Severity severity, String kind, String location, int length, String detail, long expiresAt) {
            this.severity = severity;
            this.kind = kind;
            this.location = location;
            this.length = length;
            this.detail = detail;
            this.expiresAt = expiresAt;
        }

        /** JWT 是否已过期（需要当前时间）。 */
        public boolean isExpired() {
            return expiresAt > 0 && expiresAt * 1000L < System.currentTimeMillis();
        }

        public String describe() {
            StringBuilder sb = new StringBuilder();
            sb.append('[').append(severity).append("] ").append(kind);
            if (location != null) {
                sb.append(" @ ").append(location);
            }
            if (detail != null && !detail.isEmpty()) {
                sb.append("  ← ").append(detail);
            }
            return sb.toString();
        }

        @Override
        public String toString() {
            return describe();
        }
    }

    /** 扫描结果。 */
    public static final class Report {
        public final List<Finding> findings;
        /** JWT 解出的完整内容（已解码，供 UI 展开显示）。 */
        public final List<JwtInfo> jwts;

        Report(List<Finding> findings, List<JwtInfo> jwts) {
            this.findings = findings;
            this.jwts = jwts;
        }

        public boolean isEmpty() {
            return findings.isEmpty();
        }

        public Severity worst() {
            Severity w = null;
            for (Finding f : findings) {
                if (w == null || f.severity.ordinal() < w.ordinal()) {
                    w = f.severity;
                }
            }
            return w;
        }

        /** 给 UI 的一句话结论。 */
        public String headline() {
            if (findings.isEmpty()) {
                return "未发现敏感数据";
            }
            Map<Severity, Integer> bySev = new LinkedHashMap<>();
            for (Finding f : findings) {
                bySev.merge(f.severity, 1, Integer::sum);
            }
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<Severity, Integer> e : bySev.entrySet()) {
                if (sb.length() > 0) {
                    sb.append("，");
                }
                sb.append(e.getKey()).append(' ').append(e.getValue()).append(" 项");
            }
            return findings.size() + " 项发现（" + sb + "）";
        }
    }

    /** 本地解出的 JWT 结构。 */
    public static final class JwtInfo {
        public final String raw;
        public final Map<String, Object> header;
        public final Map<String, Object> payload;
        public final String location;

        JwtInfo(String raw, Map<String, Object> header, Map<String, Object> payload, String location) {
            this.raw = raw;
            this.header = header;
            this.payload = payload;
            this.location = location;
        }

        public String alg() {
            Object a = header.get("alg");
            return a == null ? "?" : String.valueOf(a);
        }

        public long exp() {
            Object e = payload.get("exp");
            if (e instanceof Number) {
                return ((Number) e).longValue();
            }
            return 0;
        }

        /** 已过期？没有 exp 声明时一律算"未过期"（不臆断）。 */
        public boolean isExpired() {
            long e = exp();
            return e > 0 && e * 1000L < System.currentTimeMillis();
        }

        public String role() {
            Object r = payload.get("role");
            if (r == null) {
                r = payload.get("roles");
            }
            if (r == null) {
                r = payload.get("scope");
            }
            return r == null ? null : String.valueOf(r);
        }

        /** 给 UI 展开用的可读文本。 */
        public String pretty() {
            StringBuilder sb = new StringBuilder();
            sb.append("位置   ").append(location).append('\n');
            sb.append("算法   ").append(alg()).append('\n');
            long e = exp();
            if (e > 0) {
                boolean expired = e * 1000L < System.currentTimeMillis();
                sb.append("过期   ").append(new java.util.Date(e * 1000L))
                        .append(expired ? "  ← 已过期" : "  ← 仍有效").append('\n');
            }
            String r = role();
            if (r != null) {
                sb.append("角色   ").append(r).append("   ← 测试越权时优先看这个").append('\n');
            }
            sb.append("声明   ").append(payload);
            return sb.toString();
        }
    }

    // ------------------------------------------------------------------

    private static final class Rule {
        final String kind;
        final Severity severity;
        final Pattern pattern;
        final String typeTag;

        Rule(String kind, Severity severity, String regex, String typeTag) {
            this.kind = kind;
            this.severity = severity;
            this.pattern = Pattern.compile(regex);
            this.typeTag = typeTag;
        }
    }

    private static final Rule[] RULES = {
            new Rule("PEM私钥", Severity.CRITICAL,
                    "-----BEGIN [A-Z ]*PRIVATE KEY-----", null),
            new Rule("JWT", Severity.HIGH,
                    "\\beyJ[A-Za-z0-9_-]{5,}\\.eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\b", null),
            new Rule("AWS访问密钥", Severity.CRITICAL,
                    "\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b", null),
            new Rule("中国大陆身份证", Severity.HIGH,
                    "\\b[1-9]\\d{5}(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx]\\b", null),
            new Rule("中国大陆手机号", Severity.MEDIUM,
                    "\\b1[3-9]\\d{9}\\b", null),
            new Rule("银行卡号", Severity.HIGH,
                    "\\b\\d{16,19}\\b", null),
            new Rule("邮箱", Severity.MEDIUM,
                    "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b", null),
            new Rule("疑似密码字段", Severity.HIGH,
                    "(?i)[\"']?(?:password|passwd|pwd)[\"']?\\s*[:=]\\s*[\"']?[^\"'&\\s,}]{1,64}", null),
    };

    // ------------------------------------------------------------------

    private final boolean decodeJwt;

    public PiiScanner() {
        this(true);
    }

    public PiiScanner(boolean decodeJwt) {
        this.decodeJwt = decodeJwt;
    }

    /** 扫描一条完整 HTTP 报文。纯本地，无副作用。 */
    public Report scan(String rawMessage) {
        List<Finding> findings = new ArrayList<>();
        List<JwtInfo> jwts = new ArrayList<>();
        if (rawMessage == null || rawMessage.isEmpty()) {
            return new Report(findings, jwts);
        }

        for (Rule rule : RULES) {
            Matcher m = rule.pattern.matcher(rawMessage);
            while (m.find()) {
                String found = m.group();
                String location = locate(rawMessage, m.start());

                if ("JWT".equals(rule.kind)) {
                    JwtInfo info = decodeJwt ? tryDecodeJwt(found, location) : null;
                    long exp = info == null ? 0 : info.exp();
                    String detail;
                    if (info == null) {
                        detail = "无法解码（不是标准三段式？）";
                    } else if (exp > 0 && exp * 1000L < System.currentTimeMillis()) {
                        detail = "alg=" + info.alg() + "，已过期";
                    } else {
                        String role = info.role();
                        detail = "alg=" + info.alg() + (role != null ? "，role=" + role : "")
                                + (exp > 0 ? "，仍有效" : "");
                    }
                    findings.add(new Finding(rule.severity, rule.kind, location,
                            found.length(), detail, exp));
                    if (info != null) {
                        jwts.add(info);
                    }
                } else {
                    findings.add(new Finding(rule.severity, rule.kind, location,
                            found.length(), "", 0));
                }

                // 同一处不重复计：跳过本匹配内部
                if (m.end() <= m.start()) {
                    break;
                }
            }
        }

        return new Report(findings, jwts);
    }

    /**
     * 定位一个偏移落在报文哪个部分 —— 给出 "Authorization" / "body.phone" 这类可读位置。
     * 这是"能说清在哪"的关键，只报"发现一个手机号"没有用。
     */
    static String locate(String msg, int offset) {
        int sep = msg.indexOf("\r\n\r\n");
        int sepLen = 4;
        if (sep < 0) {
            sep = msg.indexOf("\n\n");
            sepLen = 2;
        }
        int bodyStart = sep < 0 ? -1 : sep + sepLen;

        if (bodyStart >= 0 && offset >= bodyStart) {
            String body = msg.substring(bodyStart, Math.min(msg.length(), offset + 200));
            // 往上找最近的一个 "key":
            Matcher km = Pattern.compile("\"([^\"]{1,60})\"\\s*:").matcher(body);
            String lastKey = null;
            while (km.find() && km.end() <= (offset - bodyStart)) {
                lastKey = km.group(1);
            }
            return lastKey != null ? "body." + lastKey : "body";
        }

        // 在头区：往回找本行开头
        int lineStart = msg.lastIndexOf('\n', Math.max(0, offset - 1)) + 1;
        int lineEnd = msg.indexOf('\n', offset);
        if (lineEnd < 0) {
            lineEnd = msg.length();
        }
        String line = msg.substring(lineStart, lineEnd);
        int colon = line.indexOf(':');
        return colon > 0 ? line.substring(0, colon).trim() : "请求行";
    }

    /** 只做 Base64URL 解码，<b>不验签</b>。 */
    static JwtInfo tryDecodeJwt(String token, String location) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            Map<String, Object> header = parseJsonObject(b64UrlDecode(parts[0]));
            Map<String, Object> payload = parseJsonObject(b64UrlDecode(parts[1]));
            if (header == null || payload == null) {
                return null;
            }
            return new JwtInfo(token, header, payload, location);
        } catch (Exception e) {
            return null;
        }
    }

    private static String b64UrlDecode(String s) {
        String padded = s;
        int rem = padded.length() % 4;
        if (rem == 2) {
            padded += "==";
        } else if (rem == 3) {
            padded += "=";
        } else if (rem == 1) {
            return null;
        }
        byte[] raw = Base64.getUrlDecoder().decode(padded);
        return new String(raw, StandardCharsets.UTF_8);
    }

    /**
     * 极简 JSON 对象解析 —— 只处理扁平的 key:value。
     *
     * <p>这里刻意不引入 Gson：本类要能在没有依赖的情况下单独编译测试。
     * 生产代码里应该换成成熟库（见设计文档技术选型）。
     */
    static Map<String, Object> parseJsonObject(String json) {
        if (json == null) {
            return null;
        }
        String t = json.trim();
        if (!t.startsWith("{") || !t.endsWith("}")) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        String inner = t.substring(1, t.length() - 1);
        Matcher m = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"[^\"]*\"|-?\\d+(?:\\.\\d+)?|true|false|null)")
                .matcher(inner);
        while (m.find()) {
            String k = m.group(1);
            String v = m.group(2);
            if (v.startsWith("\"")) {
                out.put(k, v.substring(1, v.length() - 1));
            } else if ("true".equals(v) || "false".equals(v)) {
                out.put(k, Boolean.parseBoolean(v));
            } else if ("null".equals(v)) {
                out.put(k, null);
            } else {
                try {
                    out.put(k, v.contains(".") ? (Object) Double.parseDouble(v) : (Object) Long.parseLong(v));
                } catch (NumberFormatException e) {
                    out.put(k, v);
                }
            }
        }
        return out;
    }
}
