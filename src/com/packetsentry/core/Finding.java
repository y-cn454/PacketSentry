package com.packetsentry.core;

import com.packetsentry.detect.LocalRules;
import com.packetsentry.detect.PlatformRules;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 一条<b>发现</b> —— SRC 工作的基本单位。
 *
 * <h3>为什么需要这个类，而不是直接用「包」</h3>
 * 靶场和 SRC 的根本差异在这里：
 * <ul>
 *   <li><b>靶场</b>：拿到 flag 就结束了。分析单位是「包」</li>
 *   <li><b>SRC</b>：一个目标挖几天，最后交的是「报告」。
 *       而<b>一条发现常常跨好几个包</b> ——
 *       比如「/api/user/{id} 存在越权」，你会用 5 个不同的 ID 各发一次请求验证它。
 *       这 5 个包是<b>同一个发现</b>，不该在清单里出现 5 次</li>
 * </ul>
 *
 * <p>所以需要一层抽象：把包里的问题<b>归并成发现</b>，并记住它的状态。
 *
 * <h3>状态机 —— 这就是 SRC 的工作流</h3>
 * <pre>
 *   待验证 ──→ 已验证 ──→ 已提交 ──→ 已收录
 *      │           │           └──→ 已忽略（平台说重复/不收）
 *      │           └──→ 不收（确认平台不收录这类）
 *      └──→ 忽略（自己判断没价值）
 * </pre>
 *
 * <p>没有这个状态，挖几天下来根本记不住哪条验证过、哪条提交了。
 */
public final class Finding {

    /** 发现的生命周期状态。 */
    public enum Status {
        TODO("待验证", 0),
        VERIFIED("已验证", 1),
        SUBMITTED("已提交", 2),
        ACCEPTED("已收录", 3),
        REJECTED("已忽略", 4),
        OUT_OF_SCOPE("不收", 5),
        IGNORED("弃用", 6);

        public final String label;
        public final int code;

        Status(String label, int code) {
            this.label = label;
            this.code = code;
        }

        public static Status of(String s) {
            if (s == null) {
                return TODO;
            }
            for (Status st : values()) {
                if (st.label.equals(s) || st.name().equalsIgnoreCase(s)) {
                    return st;
                }
            }
            return TODO;
        }

        /** 已经交出去了吗（用于报告统计）。 */
        public boolean isDelivered() {
            return this == SUBMITTED || this == ACCEPTED;
        }

        /** 还算「活跃」吗（未提交、也没被否掉）。 */
        public boolean isOpen() {
            return this == TODO || this == VERIFIED;
        }
    }

    // ==================================================================
    // 字段（直接暴露为 public —— 这些是纯数据，Gson 也靠它序列化）
    // ==================================================================

    /** 稳定指纹 —— <b>去重的唯一依据</b>。由 host + 方法 + 规范化路径 + 类型 组成。 */
    public String id = "";

    public String host = "";
    public String method = "";
    /** 原始路径（含真实 ID），用于复现。 */
    public String path = "";
    /** 规范化路径（ID 段换成 {n}），用于把同一接口的多次观测并成一条。 */
    public String normPath = "";
    /** 涉及的参数名（可空）。 */
    public String param = "";

    /** 漏洞类型（本插件的规则名）。 */
    public String type = "";
    /** 本地初判等级名（严重/高危/中危/低危/提示）。 */
    public String level = "";
    public int levelRank = 0;

    /** 最小证据 —— <b>故意截断</b>。SRC 规则普遍禁止保存、传播业务数据。 */
    public String evidence = "";

    /** 生命周期状态。 */
    public String status = Status.TODO.label;
    /** 用户备注（比如「平台说重复，理由 xxx」）。 */
    public String note = "";

    /** 平台规则判定（收 / 视影响 / 不收 / 未提及）。 */
    public String decision = "";
    /** 按平台规则定级后的等级名 —— 可能被平台规则降级。 */
    public String platformLevel = "";

    public long firstSeen = 0L;
    public long lastSeen = 0L;
    /** 被观测到几次 —— 次数多说明这个点很常见，值得优先处理。 */
    public int seenCount = 0;

    // ==================================================================

    public Finding() {
    }

    /** 取状态枚举。 */
    public Status statusEnum() {
        return Status.of(status);
    }

    /** 展示用等级 —— 有平台定级就显示平台定级（那才是提交时的等级）。 */
    public String displayLevel() {
        return platformLevel != null && !platformLevel.isEmpty() ? platformLevel : level;
    }

    /** 完整 URL（用于报告「漏洞 URL」段）。 */
    public String url() {
        return "https://" + host + path;
    }

    /** 一眼能看懂的定位串。 */
    public String where() {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(' ').append(path);
        if (param != null && !param.isEmpty()) {
            sb.append("　参数 ").append(param);
        }
        return sb.toString();
    }

    /**
     * 去重指纹。
     *
     * <p>▲ 用<b>规范化路径</b>而不是原始路径 —— 这是关键。
     * {@code /api/user/1} 和 {@code /api/user/2} 是同一个接口的两次观测，
     * 如果按原始路径算指纹，清单里会堆出几百条「同一个越权问题」。
     *
     * <p>但类型要参与指纹：同一个接口上的「越权」和「信息泄露」是两条发现。
     */
    public static String fingerprint(String method, String host, String normPath, String type) {
        String m = method == null ? "GET" : method.toUpperCase();
        String h = host == null ? "" : host.toLowerCase();
        String p = normPath == null ? "" : normPath;
        // 类型只取「主干」—— 规则名后面常带「（已确认）」「线索」这类后缀，
        // 那是措辞不是类型，不该影响指纹。
        String t = type == null ? "" : type;
        t = t.replace("（已确认）", "").replace("（已观测）", "").replace("线索", "")
                .replace("（形态）", "").trim();
        return m + " " + h + " " + p + " #" + t;
    }

    /** 从一次观测构造发现。 */
    public static Finding from(String method, String host, String path, String param,
                               String type, LocalRules.Level level, String evidence,
                               PlatformRules.Decision decision, String platformLevel) {
        Finding f = new Finding();
        f.method = method == null ? "" : method.toUpperCase();
        f.host = host == null ? "" : host;
        f.path = path == null ? "" : path;
        f.normPath = normalizePath(f.path);
        f.param = param == null ? "" : param;
        f.type = type == null ? "" : type;
        f.level = level == null ? "" : level.label;
        f.levelRank = level == null ? 0 : level.rank;
        f.evidence = clip(evidence, 300);
        f.decision = decision == null ? "" : decision.label;
        f.platformLevel = platformLevel == null ? "" : platformLevel;
        f.status = Status.TODO.label;
        f.id = fingerprint(f.method, f.host, f.normPath, f.type);
        long now = System.currentTimeMillis();
        f.firstSeen = now;
        f.lastSeen = now;
        f.seenCount = 1;
        return f;
    }

    /** 把两条同一发现合并（保留更早的 firstSeen、累加次数、取更严重的等级）。 */
    public void mergeFrom(Finding other) {
        if (other == null) {
            return;
        }
        if (other.firstSeen > 0 && (firstSeen == 0 || other.firstSeen < firstSeen)) {
            firstSeen = other.firstSeen;
        }
        if (other.lastSeen > lastSeen) {
            lastSeen = other.lastSeen;
        }
        seenCount += Math.max(1, other.seenCount);
        // 等级取更严重的 —— 同一个问题在不同包里严重度可能不同，取最严重那个
        if (other.levelRank > levelRank) {
            level = other.level;
            levelRank = other.levelRank;
        }
        // 证据取更长的那个（信息更多），但有上限
        if (other.evidence != null && other.evidence.length() > evidence.length()) {
            evidence = clip(other.evidence, 300);
        }
        if ((platformLevel == null || platformLevel.isEmpty())
                && other.platformLevel != null && !other.platformLevel.isEmpty()) {
            platformLevel = other.platformLevel;
        }
        if ((decision == null || decision.isEmpty())
                && other.decision != null && !other.decision.isEmpty()) {
            decision = other.decision;
        }
        if ((param == null || param.isEmpty()) && other.param != null) {
            param = other.param;
        }
    }

    // ==================================================================
    // 路径规范化 —— 去重的关键
    // ==================================================================

    private static final Pattern UUID_SEG = Pattern.compile(
            "(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern LONG_HEX = Pattern.compile("(?i)^[0-9a-f]{16,}$");
    private static final Pattern DIGITS = Pattern.compile("^\\d+$");
    /** 版本段不能被替换成 {n} —— 否则 v1/v2 会被并成一条（这个坑踩过）。 */
    private static final Pattern VERSION_SEG =
            Pattern.compile("(?i)^(?:v|ver|version|api[-_]?v)\\d{1,4}$");

    /**
     * 把路径里的「实例标识」替换成占位符。
     *
     * <p>{@code /api/user/12345/profile} → {@code /api/user/{n}/profile}
     *
     * <p>▲ 版本段必须保留 —— {@code /api/v1/x} 和 {@code /api/v2/x} 是<b>不同接口</b>，
     * 并成一条会漏掉 v2 上的漏洞。
     */
    public static String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        String q = "";
        int qi = path.indexOf('?');
        if (qi >= 0) {
            q = path.substring(qi);
            path = path.substring(0, qi);
        }
        String[] segs = path.split("/");
        List<String> out = new ArrayList<>();
        for (String s : segs) {
            if (s.isEmpty()) {
                continue;
            }
            if (VERSION_SEG.matcher(s).matches()) {
                out.add(s);
                continue;
            }
            if (DIGITS.matcher(s).matches() || UUID_SEG.matcher(s).matches()
                    || LONG_HEX.matcher(s).matches()) {
                out.add("{n}");
                continue;
            }
            // 数字混在里面的段（如 order-123）也归一化
            String norm = s.replaceAll("\\d{2,}", "{n}");
            out.add(norm);
        }
        return "/" + String.join("/", out) + q;
    }

    static String clip(String s, int n) {
        if (s == null) {
            return "";
        }
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= n ? t : t.substring(0, n) + "…";
    }

    @Override
    public String toString() {
        return "[" + displayLevel() + "] " + type + " @ " + where()
                + "　" + status + "　×" + seenCount;
    }
}
