package com.packetsentry.core;

import com.packetsentry.detect.LocalRules;
import com.packetsentry.detect.PiiScanner;
import com.packetsentry.sanitize.Sanitizer;

/**
 * 一个被抓到的报文的完整本地画像。
 *
 * <p>纯数据对象，由 {@link RealtimePipe} 在后台线程构造。
 * <b>构造它不产生任何网络调用</b> —— 扫描和脱敏都是本地字符串运算。
 */
public final class PacketRecord {

    /** 抓包序号，从 1 开始。 */
    public final int seq;
    /** Burp 的 tool flag（Proxy / Repeater / Intruder…）。 */
    public final int toolFlag;
    public final boolean isRequest;

    public final String method;
    public final String host;
    public final String path;
    public final int statusCode;
    public final String mimeType;
    public final int size;

    /** 本地敏感数据扫描结果。 */
    public final PiiScanner.Report scan;
    /** 脱敏结果（含命中报告）。 */
    public final Sanitizer.Result sanitized;
    /** 脱敏后的摘要文本 —— 这就是将来要发给 AI 的东西。 */
    public final String brief;

    /** 业务作用，由本地规则推断（零成本）。如「获取用户信息」「加载脚本」。 */
    public final String purpose;
    /** 本地规则检出的漏洞，可能为空但不为 null。 */
    public final java.util.List<LocalRules.Issue> issues;
    /** 漏洞最严重等级，用于列表着色。 */
    public final LocalRules.Level worstLevel;

    /** 原始请求/响应 —— 用于「发到 Repeater」、响应侧分析和越权测试。 */
    public final transient byte[] rawRequest;
    public final transient byte[] rawResponse;
    /** 目标服务 —— 越权测试重放时需要。 */
    public final transient burp.IHttpService service;

    /**
     * 结构签名：方法 + 路径模板 + 参数名集合。
     * 用于去重 —— 同一个接口调用 300 次，只分析 1 次。
     */
    public final String signature;
    /** 是否为重复（之前见过同签名的包）。 */
    public final boolean duplicate;
    /** 是否被判定为不值得送 AI（静态资源等）。 */
    public final boolean lowValue;

    public PacketRecord(int seq, int toolFlag, boolean isRequest,
                        String method, String host, String path, int statusCode,
                        String mimeType, int size,
                        PiiScanner.Report scan, Sanitizer.Result sanitized, String brief,
                        String signature, boolean duplicate, boolean lowValue,
                        String purpose, java.util.List<LocalRules.Issue> issues,
                        byte[] rawRequest, byte[] rawResponse, burp.IHttpService service) {
        this.seq = seq;
        this.toolFlag = toolFlag;
        this.isRequest = isRequest;
        this.method = method;
        this.host = host;
        this.path = path;
        this.statusCode = statusCode;
        this.mimeType = mimeType;
        this.size = size;
        this.scan = scan;
        this.sanitized = sanitized;
        this.brief = brief;
        this.signature = signature;
        this.duplicate = duplicate;
        this.lowValue = lowValue;
        this.purpose = purpose == null ? "未知" : purpose;
        this.issues = issues == null ? java.util.Collections.emptyList() : issues;
        this.worstLevel = LocalRules.worst(this.issues);
        this.rawRequest = rawRequest;
        this.rawResponse = rawResponse;
        this.service = service;
    }

    /** 漏洞列的显示文本。 */
    public String issueSummary() {
        return LocalRules.summarize(issues);
    }

    /** 值不值得送 AI。三个条件同时满足才算值得。 */
    public boolean worthAnalyzing() {
        if (lowValue) {
            return false;          // 静态资源等
        }
        if (duplicate) {
            return false;          // 结构重复 —— 省 90% 的关键
        }
        return true;
    }

    /** 给列表用的一行摘要。 */
    public String oneLine() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%4d", seq)).append("  ");
        sb.append(String.format("%-6s", method == null ? "?" : method));
        sb.append(host == null ? "" : host).append(path == null ? "" : path);
        if (statusCode > 0) {
            sb.append("  → ").append(statusCode);
        }
        sb.append("  [").append(purpose).append(']');
        if (worstLevel != LocalRules.Level.NONE) {
            sb.append("  ▲ ").append(issueSummary());
        }
        if (duplicate) {
            sb.append("   [重复]");
        }
        if (lowValue) {
            sb.append("   [低价值]");
        }
        return sb.toString();
    }

    /** 风险等级，用于列表着色。 */
    public PiiScanner.Severity risk() {
        return scan == null ? null : scan.worst();
    }
}
