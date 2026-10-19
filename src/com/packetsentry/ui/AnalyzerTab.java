package com.packetsentry.ui;

import burp.IMessageEditorController;
import burp.IMessageEditorTab;

import com.packetsentry.core.Config;
import com.packetsentry.detect.PiiScanner;
import com.packetsentry.llm.LlmClient;
import com.packetsentry.sanitize.Sanitizer;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.function.Supplier;

/**
 * 报文编辑器里的 PacketSentry 面板 —— <b>整个插件的门面</b>。
 *
 * <p>打开 Burp 的报文编辑器时，会多出一个 PacketSentry 标签页。它做四件事：
 * <ol>
 *   <li><b>本地扫描</b>：立刻告诉你这个包里有什么敏感数据（<b>零网络调用</b>）</li>
 *   <li><b>脱敏预览</b>：左侧原文 / 右侧将要外发的内容，<b>改了哪里一目了然</b></li>
 *   <li><b>手动分析</b>：点按钮才发送，绝不在报文到达时自动发</li>
 *   <li><b>结果展示</b>：把模型返回的内容显示出来</li>
 * </ol>
 *
 * <p><b>关键安全约束：</b>
 * <ul>
 *   <li>{@link #setMessage} 只做本地字符串处理，不联网</li>
 *   <li>联网只发生在 {@link #runAnalysis()}，由用户点击触发</li>
 *   <li>发送前必然经过 {@link Sanitizer}，且用户可以再手工编辑外发内容</li>
 * </ul>
 */
public final class AnalyzerTab implements IMessageEditorTab {

    private final JPanel root;
    private final JLabel statusLabel;
    private final JTextArea scanArea;
    private final JTextArea previewArea;
    private final JTextArea resultArea;
    private final JButton analyzeBtn;
    private final JButton copyBtn;
    private final JCheckBox allowCriticalBox;

    private final Sanitizer sanitizer = new Sanitizer();
    private final PiiScanner scanner = new PiiScanner();
    private final LlmClient llm = new LlmClient();

    /** 配置提供者 —— 每次读取都拿最新值，这样设置改了立刻生效。 */
    private final Supplier<Config> configSupplier;

    private byte[] currentMessage;
    private boolean currentIsRequest = true;
    private PiiScanner.Report lastScan;
    private Sanitizer.Result lastSanitized;
    private volatile boolean busy = false;
    private int generation = 0;

    public AnalyzerTab(IMessageEditorController controller,
                       boolean editable,
                       Supplier<Config> configSupplier) {
        this.configSupplier = configSupplier;

        root = new JPanel(new BorderLayout(0, 4));

        // ▲ 初始化顺序有讲究：按钮的 ActionListener 会捕获 previewArea /
        // scanArea，而 Java 的确定赋值分析要求被捕获的 final 字段在 lambda
        // 创建之前就已赋值。所以文本区必须先建，按钮后建。
        scanArea = monoArea();
        scanArea.setEditable(false);
        previewArea = monoArea();
        previewArea.setToolTipText("这是将要发送的内容，可以直接编辑");
        resultArea = monoArea();
        resultArea.setEditable(false);

        // ---- 顶部：状态 + 按钮 ----
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.X_AXIS));
        top.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        analyzeBtn = new JButton("分析（发送脱敏后的内容）");
        analyzeBtn.setEnabled(false);
        analyzeBtn.addActionListener(e -> runAnalysis());

        copyBtn = new JButton("复制脱敏内容");
        copyBtn.addActionListener(e -> {
            previewArea.selectAll();
            previewArea.copy();
            previewArea.setSelectionEnd(0);
            setStatus("已复制到剪贴板");
        });

        allowCriticalBox = new JCheckBox("含 CRITICAL 时仍然发送");
        // 提示文字不用 HTML：Burp 的自定义 L&F 不保证渲染 JLabel/JToolTip 里的 HTML
        allowCriticalBox.setToolTipText(
                "默认关闭。开启后，即使本地扫描发现私钥 / 云密钥这类极高危数据，"
                        + "也允许发送（仍会脱敏）。");

        top.add(analyzeBtn);
        top.add(Box.createHorizontalStrut(6));
        top.add(copyBtn);
        top.add(Box.createHorizontalStrut(12));
        top.add(allowCriticalBox);
        top.add(Box.createHorizontalGlue());
        root.add(top, BorderLayout.NORTH);

        // ---- 中部：上=扫描+预览，下=结果 ----
        JPanel scanPanel = titled("① 本地扫描（零网络调用）", wrap(scanArea));
        JPanel previewPanel = titled("② 将要发送的内容（可编辑）", wrap(previewArea));

        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, scanPanel, previewPanel);
        topSplit.setResizeWeight(0.4);
        topSplit.setDividerLocation(320);

        JPanel resultPanel = titled("③ 分析结果", wrap(resultArea));

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, resultPanel);
        mainSplit.setResizeWeight(0.55);
        mainSplit.setDividerLocation(300);
        root.add(mainSplit, BorderLayout.CENTER);

        // ---- 底部：状态栏 ----
        statusLabel = new JLabel("就绪");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));
        root.add(statusLabel, BorderLayout.SOUTH);

        root.setPreferredSize(new Dimension(900, 520));
    }

    private static JTextArea monoArea() {
        JTextArea a = new JTextArea();
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        a.setLineWrap(false);
        a.setWrapStyleWord(false);
        return a;
    }

    private static JScrollPane wrap(JTextArea a) {
        return new JScrollPane(a);
    }

    private static JPanel titled(String title, Component body) {
        JPanel p = new JPanel(new BorderLayout());
        JLabel l = new JLabel(title);
        l.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        p.add(l, BorderLayout.NORTH);
        p.add(body, BorderLayout.CENTER);
        return p;
    }

    private void setStatus(String s) {
        statusLabel.setText(" " + s);
    }

    // ==================================================================
    // IMessageEditorTab
    // ==================================================================

    @Override
    public String getTabCaption() {
        return "PacketSentry";
    }

    @Override
    public Component getUiComponent() {
        return root;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return content != null && content.length > 0;
    }

    /**
     * Burp 在切换报文时调用。这里<b>只做本地处理</b> —— 不联网、不写文件。
     *
     * <p>之所以敢在这里做完整扫描 + 脱敏，是因为两者都是纯字符串运算，
     * 对一个几十 KB 的报文是微秒级。真正的网络调用留给用户点击。
     */
    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.currentMessage = content;
        this.currentIsRequest = isRequest;

        if (content == null || content.length == 0) {
            scanArea.setText("");
            previewArea.setText("");
            resultArea.setText("");
            analyzeBtn.setEnabled(false);
            setStatus("无内容");
            return;
        }

        Config cfg = configSupplier.get();
        String raw = new String(content, java.nio.charset.StandardCharsets.UTF_8);

        // ① 本地扫描
        if (cfg.scanEnabled) {
            lastScan = scanner.scan(raw);
            scanArea.setText(renderScan(lastScan, isRequest));
            scanArea.setCaretPosition(0);
        } else {
            lastScan = null;
            scanArea.setText("（本地扫描已在设置中关闭）");
        }

        // ② 脱敏
        if (cfg.sanitizeEnabled) {
            Sanitizer.MaskStrategy strategy = parseStrategy(cfg.maskStrategy);
            Sanitizer s = new Sanitizer(strategy, cfg.layerHeaders, cfg.layerFields, cfg.layerValues);
            lastSanitized = s.sanitize(raw);
            previewArea.setText(trimBody(lastSanitized.cleanText, cfg.maxBodyChars));
        } else {
            lastSanitized = null;
            previewArea.setText("（脱敏已在设置中关闭 —— 将发送原始报文）\n\n"
                    + trimBody(raw, cfg.maxBodyChars));
        }
        previewArea.setCaretPosition(0);

        resultArea.setText("");
        analyzeBtn.setEnabled(!busy);

        // ③ 状态栏结论
        StringBuilder st = new StringBuilder();
        if (lastScan != null && !lastScan.isEmpty()) {
            st.append(lastScan.headline());
        } else {
            st.append("未发现敏感数据");
        }
        if (lastSanitized != null && lastSanitized.hasSensitiveData()) {
            st.append("　|　已抹除 ").append(lastSanitized.hits.size()).append(" 处");
        }
        st.append("　|　").append(cfg.describeDestination());
        setStatus(st.toString());
    }

    @Override
    public byte[] getMessage() {
        // 本标签页不修改报文 —— 它只观察和建议
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        String sel = previewArea.getSelectedText();
        if (sel == null || sel.isEmpty()) {
            sel = scanArea.getSelectedText();
        }
        return sel == null ? null : sel.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ==================================================================
    // 渲染
    // ==================================================================

    private String renderScan(PiiScanner.Report r, boolean isRequest) {
        StringBuilder sb = new StringBuilder();
        sb.append("类型  ").append(isRequest ? "请求" : "响应").append('\n');
        sb.append("大小  ").append(currentMessage == null ? 0 : currentMessage.length)
                .append(" 字节\n\n");

        if (r.isEmpty()) {
            sb.append("√ 未发现敏感数据\n");
            return sb.toString();
        }

        sb.append("▲ ").append(r.headline()).append("\n");
        sb.append("最严重 ").append(r.worst()).append("\n\n");
        for (PiiScanner.Finding f : r.findings) {
            sb.append("· ").append(f.severity).append("  ").append(f.kind);
            if (f.location != null) {
                sb.append("  @ ").append(f.location);
            }
            sb.append("  (").append(f.length).append(" 字符)");
            if (f.detail != null && !f.detail.isEmpty()) {
                sb.append("\n    ").append(f.detail);
            }
            sb.append('\n');
        }

        if (!r.jwts.isEmpty()) {
            sb.append("\n── JWT 本地解码（不验签，不发网络）──\n");
            for (PiiScanner.JwtInfo j : r.jwts) {
                sb.append(j.pretty()).append("\n\n");
            }
        }
        return sb.toString();
    }

    /** 只截断 body，保留头部 —— 头部是理解上下文的关键，body 才是体积大头。 */
    static String trimBody(String msg, int maxBody) {
        if (msg == null) {
            return "";
        }
        int sep = msg.indexOf("\r\n\r\n");
        int len = 4;
        if (sep < 0) {
            sep = msg.indexOf("\n\n");
            len = 2;
        }
        if (sep < 0) {
            return msg.length() <= maxBody ? msg : msg.substring(0, maxBody) + "\n…（已截断）";
        }
        int bodyStart = sep + len;
        String head = msg.substring(0, bodyStart);
        String body = msg.substring(bodyStart);
        if (body.length() <= maxBody) {
            return msg;
        }
        return head + body.substring(0, maxBody) + "\n…（body 已截断到 " + maxBody + " 字符）";
    }

    private static Sanitizer.MaskStrategy parseStrategy(String name) {
        if (name == null) {
            return Sanitizer.MaskStrategy.KEEP_EDGES;
        }
        try {
            return Sanitizer.MaskStrategy.valueOf(name.trim().toUpperCase());
        } catch (Exception e) {
            return Sanitizer.MaskStrategy.KEEP_EDGES;
        }
    }

    // ==================================================================
    // 分析（唯一的联网路径）
    /** 套用暗色主题 —— 由 BurpExtender 在注册标签页后统一调用。 */
    public void restyle() {
        // AnalyzerTab 实现的是 IMessageEditorTab，本身不是 Component，
        // 所以要通过它持有的 root 面板来着色。
        com.packetsentry.ui.Theme.apply(root);
    }
    // ==================================================================

    private void runAnalysis() {
        if (busy) {
            return;
        }
        final Config cfg = configSupplier.get();

        // SRC 安全模式的合规闸门。
        // ▲ 真正的兜底在 LlmClient 里（fail-closed）；这里只是提前拦一下，
        //    好给出比「请求失败」更可读的提示。
        if (cfg.srcMode && !cfg.isLocalProvider()) {
            resultArea.setText("已阻止发送 —— SRC 安全模式不允许把业务数据发给非本机地址。\n\n"
                    + "当前目标：" + cfg.baseUrl + "\n\n"
                    + "多数 SRC 规则禁止向第三方披露业务数据（含用户资料）。\n"
                    + "请到「设置」页把服务商换成 Ollama / LM Studio，"
                    + "或关闭 SRC 安全模式。");
            return;
        }

        // CRITICAL 拦截：默认要求用户显式确认
        if (lastScan != null && lastScan.worst() == PiiScanner.Severity.CRITICAL
                && !allowCriticalBox.isSelected()) {
            resultArea.setText("已阻止发送。\n\n"
                    + "本地扫描发现 CRITICAL 级别的数据（私钥 / 云访问密钥等）。\n"
                    + "默认不允许把它发给 AI 服务商。\n\n"
                    + "如果确认要发：\n"
                    + "  1. 先在上方右侧手工检查并删除相关内容，或\n"
                    + "  2. 勾选「含 CRITICAL 时仍然发送」\n\n"
                    + "扫描结果：\n" + renderScan(lastScan, currentIsRequest));
            return;
        }

        final String payload = previewArea.getText();
        if (payload == null || payload.trim().isEmpty()) {
            resultArea.setText("没有可发送的内容。");
            return;
        }

        busy = true;
        analyzeBtn.setEnabled(false);
        final int myGen = ++generation;

        String dest = cfg.describeDestination();
        resultArea.setText("正在请求 " + dest + " …\n");
        setStatus("请求中…（" + dest + "）");

        // 后台线程执行 —— 绝不阻塞 EDT
        Thread t = new Thread(() -> {
            LlmClient.Reply reply = llm.chat(cfg, SYSTEM_PROMPT, payload);
            SwingUtilities.invokeLater(() -> {
                if (myGen != generation) {
                    return;                       // 用户已经切到别的报文
                }
                busy = false;
                analyzeBtn.setEnabled(true);
                if (reply.ok) {
                    resultArea.setText(reply.content);
                    resultArea.setCaretPosition(0);
                    setStatus("分析完成　|　HTTP " + reply.httpStatus
                            + "　|　" + reply.elapsedMs + " ms　|　" + dest);
                } else {
                    resultArea.setText("分析失败：\n\n" + reply.error
                            + "\n\n排查建议：\n"
                            + "  · 本地模型（Ollama / LM Studio）是否已启动？\n"
                            + "  · baseUrl 是否正确？Ollama 默认 http://127.0.0.1:11434/v1\n"
                            + "  · 云端服务商是否配置了 API Key？\n"
                            + "  · 模型名是否存在于该服务商？\n"
                            + "  · 网络是否可达？\n");
                    setStatus("分析失败：" + reply.error);
                }
            });
        }, "packetsentry-llm");
        t.setDaemon(true);                        // 不阻止 JVM 退出
        t.start();
    }

    /** 系统提示词。刻意强调"只根据给到的内容判断"，避免模型脑补。 */
    private static final String SYSTEM_PROMPT =
            "你是一名 Web 安全分析助手，正在协助一次已获授权的渗透测试。\n"
                    + "\n"
                    + "用户会给你一段 HTTP 报文的摘要。注意：\n"
                    + "1. 其中的凭据类字段已被脱敏（如 abcd****wxyz），这是正常的，不要试图还原。\n"
                    + "2. 只根据给出的内容判断，不要臆测未提供的信息。\n"
                    + "3. 区分「已观测到的事实」和「你的推测」，并明确标注。\n"
                    + "4. 不确定就说不确定。\n"
                    + "\n"
                    + "请按以下结构回答：\n"
                    + "【这个报文在做什么】一句话\n"
                    + "【关键参数】逐个说明用途，标注哪些看起来是可控输入\n"
                    + "【值得测试的方向】按优先级列出，每条给出具体理由和测试思路\n"
                    + "【已观测到的问题】只写你能从内容直接看出的\n"
                    + "【不确定的地方】\n"
                    + "\n"
                    + "用中文回答。保持简洁，不要重复报文内容。";
}
