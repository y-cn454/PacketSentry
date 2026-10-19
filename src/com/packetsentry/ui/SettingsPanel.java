package com.packetsentry.ui;

import com.packetsentry.core.Config;
import com.packetsentry.core.Identity;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.function.Supplier;

/**
 * 设置页 —— 服务商、模型、密钥、脱敏策略。
 *
 * <p>两个刻意的设计选择：
 * <ul>
 *   <li><b>预设服务商下拉框</b>而不是让用户手打 URL ——
 *       手打 URL 是配置错误的主要来源，而配置错误会让人以为"插件坏了"</li>
 *   <li><b>密钥优先用环境变量</b>。输入框里直接存明文是最后手段，
 *       且旁边有明确警告</li>
 * </ul>
 */
public final class SettingsPanel extends JPanel {

    /** 预设服务商。local=true 表示数据不出机器。 */
    /**
     * 服务商预设。
     *
     * <h3>▲ 第 6 列「当前可用模型名」是必须的</h3>
     * 这里踩过一个真实的坑：预设里 DeepSeek 的默认模型写的是 {@code deepseek-chat}，
     * 但这个名字<b>已经退役</b>了 —— 用户点了预设、填了密钥，得到的却是
     * 「模型不存在」，而错误提示还把这句混在一堆通用原因里，很难定位。
     *
     * <p>更尴尬的是：{@code CostTracker} 里的定价<b>早就是新的</b>
     * （{@code deepseek-flash} / {@code deepseek-v4-pro}），只有预设没跟着改 ——
     * 自己代码内部不一致。
     *
     * <p>所以现在把「当前可用模型名」显式写在预设里，并且在连接失败时
     * 直接把它抛给用户，而不是让他自己去查文档。
     *
     * <p><b>模型名会变</b>（DeepSeek 就变过一次），所以这一列是<b>提示</b>，
     * 不是权威 —— 最终以服务商文档为准。
     */
    private static final String[][] PRESETS = {
            // 显示名, provider id, baseUrl, 默认模型, local?, 当前可用模型名（提示）
            {"Ollama（本地，推荐）", "ollama", "http://127.0.0.1:11434/v1",
                    "qwen3:4b", "1",
                    "qwen3:4b（约 5.2GB，8GB 显存够）/ llama3.1:8b（约 4.9GB）；"
                            + "14B 档要 12GB 以上显存，装不下会掉到 1-3 tokens/秒"},
            {"LM Studio（本地）", "lmstudio", "http://127.0.0.1:1234/v1",
                    "local-model", "1", "看 LM Studio 里加载的模型"},
            {"vLLM（本地）", "vllm", "http://127.0.0.1:8000/v1",
                    "local-model", "1", "看你 vLLM 启动时指定的模型"},
            {"DeepSeek（云端）", "deepseek", "https://api.deepseek.com",
                    "deepseek-flash", "0", "deepseek-flash / deepseek-v4-pro"},
            {"通义千问（云端）", "dashscope", "https://dashscope.aliyuncs.com/compatible-mode/v1",
                    "qwen-plus", "0", "qwen-plus / qwen-max（以官方文档为准）"},
            {"智谱 GLM（云端）", "zhipu", "https://open.bigmodel.cn/api/paas/v4",
                    "glm-4", "0", "glm-4 系列（以官方文档为准）"},
            {"Kimi（云端）", "moonshot", "https://api.moonshot.cn/v1",
                    "moonshot-v1-8k", "0", "moonshot-v1 系列（以官方文档为准）"},
            {"自定义", "custom", "", "", "0", "以你的服务商文档为准"},
    };

    private final Supplier<Config> configSupplier;
    private final Runnable onSaved;

    private final JComboBox<String> providerBox = new JComboBox<>();
    private final JTextField baseUrlField = new JTextField(38);
    private final JTextField modelField = new JTextField(22);
    private final JTextField apiKeyEnvField = new JTextField(22);
    private final JPasswordField apiKeyInlineField = new JPasswordField(22);
    private final JLabel destinationLabel = new JLabel();
    private final JLabel keyWarningLabel = new JLabel();

    private final JCheckBox sanitizeBox = new JCheckBox("启用脱敏（强烈建议保持开启）");
    private final JCheckBox scanBox = new JCheckBox("启用本地扫描");
    private final JCheckBox layerHeaders = new JCheckBox("头层：按头名掩码值");
    private final JCheckBox layerFields = new JCheckBox("字段层：按字段名掩码 body");
    private final JCheckBox layerValues = new JCheckBox("值层：手机号/身份证/JWT 等正则");
    private final JComboBox<String> strategyBox = new JComboBox<>(
            new String[]{"KEEP_EDGES", "FULL", "HASH", "TYPE_ONLY"});
    private final JTextField maxBodyField = new JTextField(8);
    private final JTextField timeoutField = new JTextField(6);

    private final JTextArea logArea = new JTextArea(6, 70);
    private final JCheckBox srcModeBox = new JCheckBox("启用 SRC 安全模式（强制本地模型，数据不出本机）");
    /** 目标 SRC 平台名称 + 评级规则原文 + 署名。 */
    /**
     * 靶场模式。默认关（= 实战 SRC）。
     *
     * <p>打开后 flag 规则才生效。实战环境里真实业务系统没有 flag，
     * 开着那条规则只会产生误报 —— 详见 Config.rangeMode。
     */
    private final JCheckBox rangeModeBox =
            new JCheckBox("靶场模式（打 CTF/靶场时打开；实战 SRC 请保持关闭）");

    private final JTextField srcPlatformField = new JTextField(20);
    private final JTextArea srcRulesArea = new JTextArea(10, 60);
    private final JTextField reporterField = new JTextField(16);

    /**
     * 报告模板选择。
     *
     * <p>各平台表单字段不一样，也都会改版 —— 所以这里是「常见结构」+ 可编辑，
     * 而不是一个看起来很权威、实际可能过时的固定定义。
     */
    private final javax.swing.JComboBox<String> templateBox =
            new javax.swing.JComboBox<>(com.packetsentry.report.ReportTemplate.names());

    /** 用户编辑过的字段表（覆盖模板内置字段）。 */
    private final JTextArea reportFieldsArea = new JTextArea(7, 54);

    // ---- 越权测试 ----
    private final JTextArea acListArea = new JTextArea();
    private final JTextField acIntervalField = new JTextField(6);
    private final JCheckBox acAckBox = new JCheckBox(
            "我确认：越权测试会向目标主动发送请求，我只在已获授权的目标上使用");

    private JLabel acWarningLabel() {
        JLabel l = new JLabel("▲ 越权测试会向目标主动发包。仅在已获授权的目标上使用。");
        l.setForeground(new java.awt.Color(0xB0, 0x30, 0x30));
        return l;
    }

    private JPanel acButtonRow() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.X_AXIS));
        JButton add = new JButton("添加身份");
        add.setToolTipText("填入该身份的 Cookie 或 Authorization 头");
        add.addActionListener(e -> addIdentityDialog());
        JButton del = new JButton("删除选中");
        del.addActionListener(e -> {
            String name = javax.swing.JOptionPane.showInputDialog(this,
                    "要删除的身份名：\n\n已有：" + identityNames());
            if (name == null || name.trim().isEmpty()) {
                return;
            }
            Config c = configSupplier.get();
            c.identities.removeIf(id -> name.trim().equals(id.name));
            refreshAcList();
            log("已删除身份：" + name.trim() + "（记得点保存）");
        });
        p.add(add);
        p.add(Box.createHorizontalStrut(6));
        p.add(del);
        p.add(Box.createHorizontalGlue());
        return p;
    }

    private String identityNames() {
        Config c = configSupplier.get();
        if (c.identities == null || c.identities.isEmpty()) {
            return "（无）";
        }
        StringBuilder sb = new StringBuilder();
        for (Identity id : c.identities) {
            if (sb.length() > 0) {
                sb.append("、");
            }
            sb.append(id.name);
        }
        return sb.toString();
    }

    /**
     * 添加一个测试身份。
     *
     * <p>刻意用对话框而不是内嵌表格：身份通常只配 2-3 个，一次性填完最省事。
     */
    private void addIdentityDialog() {
        JTextField nameField = new JTextField(24);
        JTextArea headerArea = new JTextArea(6, 44);
        headerArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        headerArea.setText("Cookie: SESSION=把这里换成该身份的 Cookie\n"
                + "Authorization: Bearer 或者换成该身份的 Token");
        headerArea.setToolTipText("一行一个头，格式「头名: 值」");

        JPanel p = new JPanel(new java.awt.BorderLayout(0, 6));
        JPanel top = new JPanel();
        top.add(new JLabel("身份名"));
        top.add(nameField);
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(headerArea), BorderLayout.CENTER);
        JLabel hint = new JLabel("每行一个头，格式「头名: 值」。只会替换这些头，其它不动。");
        hint.setForeground(java.awt.Color.GRAY);
        p.add(hint, BorderLayout.SOUTH);

        int r = javax.swing.JOptionPane.showConfirmDialog(this, p,
                "添加测试身份", javax.swing.JOptionPane.OK_CANCEL_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE);
        if (r != javax.swing.JOptionPane.OK_OPTION) {
            return;
        }
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            log("身份名不能为空");
            return;
        }
        Identity id = new Identity(name);
        for (String line : headerArea.getText().split("\r?\n")) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String k = line.substring(0, colon).trim();
            String v = line.substring(colon + 1).trim();
            if (!k.isEmpty() && !v.isEmpty() && !v.startsWith("把这里换成") && !v.startsWith("或者换成")) {
                id.header(k, v);
            }
        }
        if (!id.usable()) {
            log("没有解析到有效的认证头，身份未添加");
            return;
        }

        // ▲ 把「清洗掉了什么」如实告诉用户。
        //
        //    头名/头值会被直接拼进 HTTP 请求，所以它们不能含换行 ——
        //    否则会注入额外请求头，或者让请求头块提前结束、把后面的头挤成 body。
        //    Identity 内部已经做了清洗（见 Identity.cleanValue / cleanName），
        //    但<b>默默改掉用户输入是不礼貌的</b>：他以为填的是 A，实际发出去的是 B。
        //    所以要明确说出来，并且让用户确认。
        java.util.List<String> warns = id.warnings();
        if (!warns.isEmpty()) {
            StringBuilder msg = new StringBuilder();
            msg.append("检测到你填的凭据里有需要清理的内容：\n\n");
            for (String w : warns) {
                msg.append("  · ").append(w).append('\n');
            }
            msg.append("\n为什么必须清：这些头会被直接拼进 HTTP 请求。\n");
            msg.append("值里带换行会注入额外请求头，或者让请求头块提前结束、\n");
            msg.append("把后面的头全挤成请求体 —— 请求就坏了。\n\n");
            msg.append("仍然添加这个身份吗？（清理后的版本会被保存）");
            int choice = javax.swing.JOptionPane.showConfirmDialog(this, msg.toString(),
                    "凭据里有需要清理的内容", javax.swing.JOptionPane.OK_CANCEL_OPTION,
                    javax.swing.JOptionPane.WARNING_MESSAGE);
            if (choice != javax.swing.JOptionPane.OK_OPTION) {
                log("已取消添加身份（凭据未保存）");
                return;
            }
        }

        Config c = configSupplier.get();
        c.identities.removeIf(x -> name.equals(x.name));
        c.identities.add(id);
        refreshAcList();
        log("已添加身份：" + id.describe() + "（记得点保存）");
    }

    private void refreshAcList() {
        Config c = configSupplier.get();
        StringBuilder sb = new StringBuilder();
        if (c.identities == null || c.identities.isEmpty()) {
            sb.append("（尚未配置身份）\n\n");
            sb.append("越权测试的原理：\n");
            sb.append("  用另一个身份的凭据重放同一个请求。\n");
            sb.append("  如果仍能拿到相同数据 → 访问控制可能缺失。\n\n");
            sb.append("典型配置：\n");
            sb.append("  身份一：普通用户A   Cookie: SESSION=xxx\n");
            sb.append("  身份二：普通用户B   Cookie: SESSION=yyy\n");
            sb.append("  （垂直越权再加一个低权限账号）\n");
        } else {
            for (Identity id : c.identities) {
                sb.append("· ").append(id.describe()).append('\n');
            }
            sb.append("\n共 ").append(c.identities.size()).append(" 个身份\n");
        }
        acListArea.setText(sb.toString());
        acListArea.setCaretPosition(0);
    }

    public SettingsPanel(Supplier<Config> configSupplier, Runnable onSaved) {
        this.configSupplier = configSupplier;
        this.onSaved = onSaved;

        setLayout(new BorderLayout());

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(3, 3, 3, 3);
        gc.anchor = GridBagConstraints.WEST;
        int row = 0;

        // ---- 服务商 ----
        for (String[] p : PRESETS) {
            providerBox.addItem(p[0]);
        }
        providerBox.addActionListener(e -> applyPreset());
        addRow(form, gc, row++, "服务商", providerBox);

        addRow(form, gc, row++, "Base URL", baseUrlField);
        addRow(form, gc, row++, "模型", modelField);

        destinationLabel.setFont(destinationLabel.getFont().deriveFont(Font.BOLD));
        addRow(form, gc, row++, "当前去向", destinationLabel);

        addRow(form, gc, row++, "密钥环境变量", apiKeyEnvField);
        addRow(form, gc, row++, "密钥（明文，不推荐）", apiKeyInlineField);

        keyWarningLabel.setForeground(new java.awt.Color(0xB0, 0x30, 0x30));
        addRow(form, gc, row++, "", keyWarningLabel);

        // ---- 脱敏 ----
        // ---- SRC 安全模式 ----
        addFullRow(form, gc, row++, separator("SRC 安全模式"));
        addFullRow(form, gc, row++, srcModeBox);
        addFullRow(form, gc, row++, rangeModeBox);
        JLabel srcHint = new JLabel(
                "开启后强制：本地模型 / FULL 掩码 / body≤500 / 三层全开。"
                        + "自动分析只会被默认关掉（可自行开回，本地模型下没有外传风险）");
        srcHint.setForeground(new java.awt.Color(0x55, 0x55, 0x55));
        addFullRow(form, gc, row++, srcHint);
        srcModeBox.addActionListener(e -> onSrcModeToggled());

        addFullRow(form, gc, row++, separator("脱敏策略"));
        addRow(form, gc, row++, "", sanitizeBox);        addRow(form, gc, row++, "", scanBox);
        addRow(form, gc, row++, "启用层", layerRow());
        addRow(form, gc, row++, "掩码策略", strategyBox);
        addRow(form, gc, row++, "body 上限(字符)", maxBodyField);
        addRow(form, gc, row++, "请求超时(秒)", timeoutField);

        // ---- 按钮 ----
        JButton saveBtn = new JButton("保存");
        saveBtn.addActionListener(e -> doSave());
        JButton testBtn = new JButton("测试连接");
        testBtn.setToolTipText("用当前表单里的设置发一次最小请求，验证地址 / 模型 / 密钥是否可用");
        testBtn.addActionListener(e -> doTest());
        JButton reloadBtn = new JButton("重新载入");
        reloadBtn.addActionListener(e -> loadIntoForm());
        JButton resetBtn = new JButton("恢复默认");
        resetBtn.addActionListener(e -> {
            applyToConfig(new Config(), true);
            loadIntoForm();
            log("已恢复默认（尚未保存）");
        });
        JPanel buttons = new JPanel();
        buttons.add(saveBtn);
        buttons.add(testBtn);
        buttons.add(reloadBtn);
        buttons.add(resetBtn);
        addRow(form, gc, row++, "", buttons);

        // ---- 越权测试身份 ----
        addFullRow(form, gc, row++, separator("越权测试身份"));
        addFullRow(form, gc, row++, acWarningLabel());
        addFullRow(form, gc, row++, acButtonRow());
        acListArea.setEditable(false);
        acListArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        acListArea.setRows(5);
        JScrollPane acScroll = new JScrollPane(acListArea);
        acScroll.setPreferredSize(new Dimension(600, 100));
        addFullRow(form, gc, row++, acScroll);
        addRow(form, gc, row++, "发包间隔(毫秒)", acIntervalField);

        // ---- 漏洞报告 / SRC 平台规则 ----
        addFullRow(form, gc, row++, separator("漏洞报告"));
        addRow(form, gc, row++, "SRC 平台名称", srcPlatformField);
        addRow(form, gc, row++, "报告署名", reporterField);
        addRow(form, gc, row++, "报告模板", templateBox);
        reportFieldsArea.setLineWrap(false);
        reportFieldsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        reportFieldsArea.setToolTipText(
                "每行「字段名｜提示」，字段名后可跟 [可选]。留空则用模板内置字段。"
                        + " 各平台表单会改版，按实际表单改一次即可");
        addRow(form, gc, row++, "自定义字段", new JScrollPane(reportFieldsArea));
        JLabel rulesHint = new JLabel(
                "把目标平台的漏洞评级规则<b>原文</b>贴到下面 —— 生成报告时连同规则一起发给模型，"
                        + "让它按该平台的条款定级");
        rulesHint.setForeground(new java.awt.Color(0x55, 0x55, 0x55));
        addFullRow(form, gc, row++, rulesHint);
        srcRulesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        srcRulesArea.setLineWrap(true);
        JScrollPane rulesScroll = new JScrollPane(srcRulesArea);
        rulesScroll.setPreferredSize(new Dimension(700, 180));
        addFullRow(form, gc, row++, rulesScroll);
        JLabel rulesHint2 = new JLabel(
                "留空也能用：会按通用标准（Critical / High / Medium / Low）定级，"
                        + "并在报告里注明「未提供平台规则」");
        rulesHint2.setForeground(new java.awt.Color(0x55, 0x55, 0x55));
        addFullRow(form, gc, row++, rulesHint2);
        addFullRow(form, gc, row++, acAckBox);

        add(new JScrollPane(form), BorderLayout.CENTER);

        // ---- 日志 ----
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("配置日志"));
        logPanel.add(new JScrollPane(logArea), BorderLayout.CENTER);
        logPanel.setPreferredSize(new Dimension(700, 150));
        add(logPanel, BorderLayout.SOUTH);

        // 事件：任何改动都刷新"当前去向"预览
        baseUrlField.getDocument().addDocumentListener((SimpleDocListener) this::refreshDestination);
        modelField.getDocument().addDocumentListener((SimpleDocListener) this::refreshDestination);

        loadIntoForm();
    }

    // ------------------------------------------------------------------

    private void addRow(JPanel p, GridBagConstraints gc, int row, String label, java.awt.Component field) {
        gc.gridx = 0;
        gc.gridy = row;
        gc.gridwidth = 1;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        p.add(new JLabel(label), gc);
        gc.gridx = 1;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        p.add(field, gc);
        gc.gridwidth = 1;
    }

    /**
     * 放一个跨两列的行。
     *
     * <p>▲ 这里踩过一个坑：早期版本写成
     * {@code form.add(separator("..."), span(gc, row))}，
     * 把「要放的组件」和「布局约束」搞反了 —— {@code span()} 返回的是
     * Component，却被当成 GridBagConstraints 传进去，GridBagLayout 直接抛
     * IllegalArgumentException，整个 buildUi 中断，最终 addSuiteTab 从未执行，
     * 插件在 Burp 里根本不显示。
     *
     * <p>所以这个方法收的是「要放的组件」，约束在这里就地设置。
     */
    private void addFullRow(JPanel p, GridBagConstraints gc, int row, java.awt.Component c) {
        gc.gridx = 0;
        gc.gridy = row;
        gc.gridwidth = 2;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        p.add(c, gc);
        gc.gridwidth = 1;   // 复位，避免污染后续行
        gc.weightx = 0;
    }

    private static JPanel separator(String title) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, java.awt.Color.LIGHT_GRAY));
        if (title != null && !title.isEmpty()) {
            JLabel l = new JLabel(title);
            l.setFont(l.getFont().deriveFont(Font.BOLD));
            l.setBorder(BorderFactory.createEmptyBorder(6, 0, 2, 0));
            p.add(l, BorderLayout.WEST);
        } else {
            p.setPreferredSize(new Dimension(10, 10));
        }
        return p;
    }

    private JPanel layerRow() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.X_AXIS));
        p.add(layerHeaders);
        p.add(Box.createHorizontalStrut(10));
        p.add(layerFields);
        p.add(Box.createHorizontalStrut(10));
        p.add(layerValues);
        return p;
    }

    // ------------------------------------------------------------------

    private void applyPreset() {
        int i = providerBox.getSelectedIndex();
        if (i < 0 || i >= PRESETS.length) {
            return;
        }
        String[] p = PRESETS[i];
        if (!"custom".equals(p[1])) {
            baseUrlField.setText(p[2]);
            if (modelField.getText().trim().isEmpty() || !"custom".equals(p[1])) {
                modelField.setText(p[3]);
            }
        }
        // ★ 把「当前可用模型名」显示出来。
        //
        //    加这个是因为踩过坑：预设里 DeepSeek 的默认模型曾是 deepseek-chat，
        //    而那个名字后来退役了。用户点预设 → 填密钥 → 得到「模型不存在」，
        //    却不知道正确的名字是什么。
        //    现在直接把候选名字摆在「模型」输入框的提示里。
        if (p.length > 5 && p[5] != null && !p[5].isEmpty()) {
            modelField.setToolTipText("当前可用模型名：" + p[5]
                    + "　（模型名会变，最终以服务商文档为准）");
        } else {
            modelField.setToolTipText(null);
        }
        refreshDestination();
    }

    /**
     * 刷新「当前去向」。
     *
     * <p>▲ 这里刻意<b>不用</b> HTML。早期版本写成
     * {@code setText("<html><span style='color:...'>...")}，
     * 在标准 L&amp;F 下渲染正常，但在 Burp 的自定义 LookAndFeel 下
     * 会被当<b>纯文本</b>显示出来 —— 用户看到的是一整串 HTML 源码。
     *
     * <p>颜色改用 {@link #setForeground}，任何 L&amp;F 下都成立。
     * 教训：只用 HTML 做布局/换行这类非它不可的事，别拿它做样式。
     */
    private void refreshDestination() {
        String url = baseUrlField.getText().trim();
        boolean local = url.contains("127.0.0.1") || url.contains("localhost")
                || url.contains("0.0.0.0") || url.contains("::1");
        String scope = local ? "本地（数据不出机器）" : "云端（数据会离开本机）";
        destinationLabel.setText(scope + "　→　" + (url.isEmpty() ? "（未填）" : url));
        destinationLabel.setForeground(local
                ? new java.awt.Color(0x1B, 0x7F, 0x3B)
                : new java.awt.Color(0xB0, 0x30, 0x30));
    }

    private void loadIntoForm() {
        Config c = configSupplier.get();
        // 选中匹配的预设
        int sel = PRESETS.length - 1;
        for (int i = 0; i < PRESETS.length; i++) {
            if (PRESETS[i][1].equals(c.provider)) {
                sel = i;
                break;
            }
        }
        providerBox.setSelectedIndex(sel);
        baseUrlField.setText(c.baseUrl);
        modelField.setText(c.model);
        apiKeyEnvField.setText(c.apiKeyEnv);
        apiKeyInlineField.setText(c.apiKeyInline);
        srcModeBox.setSelected(c.srcMode);
        rangeModeBox.setSelected(c.rangeMode);
        com.packetsentry.report.ReportTemplate cur =
                com.packetsentry.report.ReportTemplate.byId(c.reportTemplateId);
        templateBox.setSelectedItem(cur.name);
        reportFieldsArea.setText(c.reportFieldsOverride == null
                ? "" : c.reportFieldsOverride);
        sanitizeBox.setSelected(c.sanitizeEnabled);
        scanBox.setSelected(c.scanEnabled);
        layerHeaders.setSelected(c.layerHeaders);
        layerFields.setSelected(c.layerFields);
        layerValues.setSelected(c.layerValues);
        strategyBox.setSelectedItem(c.maskStrategy);
        maxBodyField.setText(String.valueOf(c.maxBodyChars));
        timeoutField.setText(String.valueOf(c.timeoutSeconds));

        refreshDestination();
        refreshKeyWarning();

        if (c.getLastError() != null) {
            log("载入时的提示：" + c.getLastError());
        }
        if (c.isLocalProvider()) {
            log("当前为本地服务商，报文不会离开本机。");
        }
    }

    private void refreshKeyWarning() {
        boolean hasInline = new String(apiKeyInlineField.getPassword()).trim().length() > 0;
        // 同样不用 HTML —— 单行纯文本在任何 L&F 下都可靠
        if (hasInline) {
            keyWarningLabel.setText("▲ 明文密钥会写入配置文件；建议留空，改用环境变量");
        } else {
            keyWarningLabel.setText("");
        }
    }

    /**
     * 测试连接 —— 用<b>当前表单里的值</b>（不要求先保存）发一次最小请求。
     *
     * <p>为什么这个按钮值得存在：配置错误的表现通常是「点了分析没反应 / 报个看不懂的错」，
     * 用户会以为插件坏了。让插件自己去连一次，把真实的 HTTP 状态和错误原文显示出来，
     * 比任何文档都直接。
     *
     * <p>走后台线程，不阻塞 EDT。测试用的是简短提示词，消耗可以忽略。
     */
    private void doTest() {
        Config probe = configSupplier.get().copyForProbe();
        // 用表单里的当前值，而不是已保存的值 —— 用户往往想「先测再存」
        probe.baseUrl = baseUrlField.getText().trim();
        probe.model = modelField.getText().trim();
        probe.apiKeyEnv = apiKeyEnvField.getText().trim();
        probe.apiKeyInline = new String(apiKeyInlineField.getPassword()).trim();
        probe.timeoutSeconds = parseInt(timeoutField.getText(), probe.timeoutSeconds);

        log("── 开始测试连接 ──");
        log("地址 " + (probe.baseUrl.isEmpty() ? "（空）" : probe.baseUrl));
        log("模型 " + (probe.model.isEmpty() ? "（空）" : probe.model));

        String key = probe.resolveApiKey();
        if (key == null || key.isEmpty()) {
            log("密钥 （未取到）");
            if (!probe.isLocalProvider()) {
                log("▲ 云端服务商必须有密钥。检查环境变量 "
                        + (probe.apiKeyEnv == null || probe.apiKeyEnv.isEmpty()
                        ? "（未填写变量名）" : probe.apiKeyEnv)
                        + " 是否已设置，且设置后需重启 Burp。");
                return;
            }
        } else {
            log("密钥 （已取到，" + key.length() + " 字符，只显示前 4 位：" 
                    + (key.length() >= 4 ? key.substring(0, 4) : "****") + "…）");
        }

        if (probe.baseUrl == null || probe.baseUrl.isEmpty()) {
            log("× Base URL 为空，无法测试");
            return;
        }

        final com.packetsentry.llm.LlmClient client = new com.packetsentry.llm.LlmClient();
        final Config finalProbe = probe;
        Thread t = new Thread(() -> {
            com.packetsentry.llm.LlmClient.Reply r =
                    client.chat(finalProbe, "You are a connectivity probe.",
                            "Reply with exactly: OK");
            SwingUtilities.invokeLater(() -> {
                if (r.ok) {
                    log("√ 连接成功　HTTP " + r.httpStatus + "　" + r.elapsedMs + " ms");
                    String c = r.content == null ? "" : r.content.trim().replaceAll("\\s+", " ");
                    if (c.length() > 80) {
                        c = c.substring(0, 80) + "…";
                    }
                    log("   模型回复：" + c);
                    log("   配置可用，可以去报文编辑器里点「分析」了");
                } else {
                    // ▲ 这里改过一版，原因很具体：
                    //
                    //    旧版无论什么错误，都固定打印四行「常见原因」：
                    //      · 本地模型没启动 / 密钥没生效 / 模型名不存在 / 网络不通
                    //    结果用户看到「模型名不存在」就以为是插件的诊断结论，
                    //    而<b>真正的错误在上一行，被日志框滚掉了</b>。
                    //
                    //    而且那四行里往往只有一行是对的 —— 另外三行是噪音，
                    //    反而把用户往错误方向带。
                    //
                    //    现在改成：先突出真实错误，再根据错误内容给<b>针对性</b>建议；
                    //    实在判断不出来时才列通用排查项。
                    log("");
                    log("× 连接失败：" + r.error);
                    log("   （HTTP " + r.httpStatus + "，" + r.elapsedMs + " ms）");
                    log("");
                    for (String hint : diagnose(r)) {
                        log("   " + hint);
                    }
                }
            });
        }, "packetsentry-probe");
        t.setDaemon(true);
        t.start();
    }

    /**
     * 根据真实错误给针对性排查建议。
     *
     * <p>▲ 为什么值得单独写一个方法：旧版对任何错误都固定列四行通用原因，
     * 用户看到「模型名不存在」会以为是插件的诊断结论，而真正的错误在上一行。
     * 那四行里通常只有一行是对的，另外三行把人往错方向带。
     *
     * <p>这里按 HTTP 状态码 + 错误文案关键词来判断 —— <b>能确定的才说</b>，
     * 不确定就给通用排查项，绝不假装知道。
     */
    private java.util.List<String> diagnose(com.packetsentry.llm.LlmClient.Reply r) {
        java.util.List<String> out = new java.util.ArrayList<>();
        String err = r.error == null ? "" : r.error;
        String low = err.toLowerCase();
        int st = r.httpStatus;

        // ---- 认证类 ----
        if (st == 401 || st == 403
                || low.contains("unauthorized") || low.contains("invalid api key")
                || low.contains("authentication") || low.contains("api key")) {
            out.add("→ 判断：密钥无效或没带上。");
            if (!apiKeyEnvField.getText().trim().isEmpty()) {
                out.add("  你在用环境变量 " + apiKeyEnvField.getText().trim() + "。");
                out.add("  ▲ 环境变量是在 Burp <b>启动时</b>读入的 —— 设完之后必须重启 Burp。");
                out.add("  想立刻验证：把密钥临时填到下面「密钥（明文）」框里，再测一次。");
            } else {
                out.add("  你没有填明文密钥，也没有配环境变量。");
                out.add("  填一个密钥（明文框或环境变量）再测。");
            }
            return out;
        }

        // ---- 余额 / 配额 ----
        if (st == 402 || low.contains("insufficient") || low.contains("balance")
                || low.contains("quota") || low.contains("exceeded")) {
            out.add("→ 判断：账户余额不足或超出配额。");
            out.add("  到服务商控制台充值 / 查看用量。");
            return out;
        }

        // ---- 限流 ----
        if (st == 429 || low.contains("rate limit") || low.contains("too many")) {
            out.add("→ 判断：被限流了（请求太快）。");
            out.add("  等一会再试；或把「自动分析新接口」关掉、降低分析频率。");
            return out;
        }

        // ---- 模型名 ----
        if (low.contains("model") && (low.contains("not exist") || low.contains("not found")
                || low.contains("invalid") || low.contains("unknown")
                || low.contains("does not exist") || st == 404)) {
            out.add("→ 判断：<b>模型名不对</b>（或这个服务商没有这个模型）。");
            out.add("  你填的是：" + modelField.getText().trim());
            int i = providerBox.getSelectedIndex();
            if (i >= 0 && i < PRESETS.length && PRESETS[i].length > 5) {
                out.add("  " + PRESETS[i][0] + " 当前可用：" + PRESETS[i][5]);
            }
            out.add("  ▲ 模型名会随时间变（DeepSeek 就把 deepseek-chat 换成了 deepseek-flash）。");
            out.add("  最终以服务商文档的模型列表为准。");
            return out;
        }

        // ---- 路径 / 端点 ----
        if (st == 404 || st == 405 || low.contains("not found")) {
            out.add("→ 判断：<b>地址路径不对</b>。");
            out.add("  当前会请求：" + com.packetsentry.llm.LlmClient
                    .buildEndpoint(baseUrlField.getText().trim()));
            out.add("  ▲ 本插件会自动在 Base URL 后面补 /chat/completions。");
            out.add("  所以 Base URL 应该只写到 <b>/v1</b> 为止（或服务商要求的根路径），");
            out.add("  不要自己再带上 /chat/completions —— 那会变成两层。");
            return out;
        }

        // ---- 网络 ----
        if (low.contains("超时") || low.contains("timeout")) {
            out.add("→ 判断：请求超时。");
            out.add("  当前超时设置 " + timeoutField.getText().trim() + " 秒。");
            out.add("  · 本地模型首次加载很慢 —— 先单独跑一次模型再回来测");
            out.add("  · 云端服务商偶发慢 —— 重试一次");
            out.add("  · 确实不够就调大超时");
            return out;
        }
        if (low.contains("连不上") || low.contains("connect")
                || low.contains("unknownhost") || low.contains("refused")) {
            out.add("→ 判断：<b>连不上这个地址</b>。");
            out.add("  · 本地服务商：确认 Ollama / LM Studio 正在跑，端口对得上");
            out.add("    （Ollama 默认 11434，LM Studio 默认 1234）");
            out.add("  · 云端服务商：确认网络能通，有没有走代理");
            out.add("  · 地址拼写：确认 Base URL 没写错");
            return out;
        }

        // ---- 响应格式 ----
        if (low.contains("choices")) {
            out.add("→ 判断：这个地址返回了内容，但<b>不是 OpenAI 兼容格式</b>。");
            out.add("  可能你填的是网页版地址、或是别的协议的 API。");
            out.add("  本插件需要 OpenAI 兼容的 /chat/completions 接口。");
            return out;
        }

        // ---- 显存 / 内存不足 ----
        //
        // ▲ 这个分支是<b>被一次真实事故加上的</b>：用户点「测试连接」得到
        //   HTTP 500 + cudaMalloc failed: out of memory，
        //   而旧版 diagnose() 认不出来，只回了一句
        //   「没能自动判断出原因」+ 四行通用排查项 —— 完全没有帮助。
        //
        //   实际原因链很有意思，值得记下来：
        //     ① nvidia-smi 显示 7956 MiB 空闲，ggml 也认为"能装下"
        //     ② 但 cudaMalloc 4.6 GB 仍然失败
        //     ③ 改用纯 CPU 跑，连 3.08 GB 都分配不出来
        //     ④ 查提交限制才发现：17.7 GB 上限、已提交 14 GB，只剩 3.7 GB
        //     → 根因是<b>页面文件太小</b>（被固定成 2 GB），不是显卡坏了
        //
        //   所以这个分支必须同时覆盖 GPU 和 CPU 两种 OOM 文案，
        //   并且要点出「nvidia-smi 的 free 不等于可用」这个坑。
        java.util.List<String> oom = diagnoseOom(low);
        if (oom != null) {
            out.addAll(oom);
            return out;
        }

        // ---- 判断不出来就老实说 ----
        out.add("→ 没能自动判断出原因（上面的错误信息是关键线索）。");
        out.add("  可以按这个顺序排查：");
        out.add("  1. 地址：Base URL 是否正确（本插件会补 /chat/completions）");
        out.add("  2. 密钥：环境变量要重启 Burp 才生效");
        out.add("  3. 模型：名字是否在服务商的模型列表里");
        out.add("  4. 网络：能否访问该地址（本地服务商是否在跑）");
        return out;
    }

    /**
     * 切换 SRC 安全模式。
     *
     * <p>开启时立刻在界面上把被强制的项改过来 —— 让用户<b>看见</b>发生了什么，
     * 而不是存盘后配置被悄悄改掉。
     */
    private void onSrcModeToggled() {
        Config c = configSupplier.get();
        c.srcMode = srcModeBox.isSelected();
        if (!c.srcMode) {
            log("已关闭 SRC 安全模式 —— 数据可能离开本机，请自行确认合规性");
            return;
        }
        java.util.List<String> forced = c.enforceSrcMode();
        loadIntoForm();
        log("── 已开启 SRC 安全模式 ──");
        if (forced.isEmpty()) {
            log("当前配置本来就合规，未做修改");
        } else {
            for (String s : forced) {
                log("  强制修正：" + s);
            }
        }
        log("▲ 请确认：「" + c.complianceLine() + "」");
        log("   多数 SRC 规则禁止向第三方披露业务数据 —— 云端模型会违反这一条。");
        log("");
        log("关于「自动分析」：");
        log("  它不向目标发任何请求，所以不属于 SRC 规则禁止的「自动化工具」。");
        log("  而且本模式已强制本地模型，数据不出机器，也没有外传风险。");
        log("  之所以默认关掉，是因为本地大模型每处理一个接口要 1-3 秒，");
        log("  浏览时会占满 CPU/GPU，而你未必在读那些输出。");
        log("  → 想要的话可以自己重新勾选「自动分析新接口」，合规上没问题。");
    }

    private void doSave() {
        Config c = configSupplier.get();
        applyToConfig(c, false);

        // ▲ 保存时也必须施加 SRC 硬约束。
        //    早期版本只在「开启 SRC 模式」那一下调用 enforceSrcMode()，
        //    结果用户可以在设置页把 baseUrl 改回云端、再点保存 ——
        //    配置里就变成了「SRC 模式开着 + 地址是云端」。
        //    （真正的兜底在 LlmClient 里，但这里也不该放过。）
        java.util.List<String> forced = c.enforceSrcMode();
        if (!forced.isEmpty()) {
            log("── SRC 安全模式强制修正 ──");
            for (String s : forced) {
                log("  " + s);
            }
        }

        String err = c.save();
        if (err == null) {
            log("已保存到 " + c.asFile());
            if (!forced.isEmpty()) {
                loadIntoForm();     // 把被强制改回的值显示出来，别让界面和配置不一致
            }
            if (c.isForeignProvider()) {
                log("▲ 当前服务商在境外，报文内容会离开中国大陆境内。");
            }
            if (c.apiKeyStoredInPlaintext()) {
                log("▲ API Key 以明文存储。建议改用环境变量 "
                        + (c.apiKeyEnv == null ? "" : c.apiKeyEnv) + "。");
            }
            if (onSaved != null) {
                onSaved.run();
            }
        } else {
            log("保存失败：" + err);
        }
    }

    private void applyToConfig(Config c, boolean defaults) {
        int i = providerBox.getSelectedIndex();
        if (i >= 0 && i < PRESETS.length && !defaults) {
            c.provider = PRESETS[i][1];
        }
        c.baseUrl = baseUrlField.getText().trim();
        c.model = modelField.getText().trim();
        c.apiKeyEnv = apiKeyEnvField.getText().trim();
        c.apiKeyInline = new String(apiKeyInlineField.getPassword()).trim();
        c.srcMode = srcModeBox.isSelected();
        c.rangeMode = rangeModeBox.isSelected();
        c.sanitizeEnabled = sanitizeBox.isSelected();
        c.scanEnabled = scanBox.isSelected();
        c.layerHeaders = layerHeaders.isSelected();
        c.layerFields = layerFields.isSelected();
        c.layerValues = layerValues.isSelected();
        Object st = strategyBox.getSelectedItem();
        c.maskStrategy = st == null ? "KEEP_EDGES" : st.toString();
        c.maxBodyChars = parseInt(maxBodyField.getText(), c.maxBodyChars);
        c.timeoutSeconds = parseInt(timeoutField.getText(), c.timeoutSeconds);
        c.acMinIntervalMs = parseInt(acIntervalField.getText(), (int) c.acMinIntervalMs);
        c.acAcknowledged = acAckBox.isSelected();
        c.srcPlatform = srcPlatformField.getText().trim();
        c.srcRules = srcRulesArea.getText();
        c.reporterName = reporterField.getText().trim();
        Object tsel = templateBox.getSelectedItem();
        c.reportTemplateId = com.packetsentry.report.ReportTemplate
                .byId(tsel == null ? "generic" : tsel.toString()).id;
        c.reportFieldsOverride = reportFieldsArea.getText();
    }

    private static int parseInt(String s, int fallback) {
        try {
            int v = Integer.parseInt(s.trim());
            return v > 0 ? v : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }

    /**
     * 追加一行日志。
     *
     * <p>带时间戳 —— 这个面板是<b>追加</b>的，多次「载入 / 保存」会堆在一起。
     * 没有时间戳就看不出哪条是刚才的，实测中确实造成了困惑
     * （日志里还写着「当前为本地服务商」，但界面已经切到云端了 ——
     * 那是历史记录，不是当前状态）。
     */
    private void log(String s) {
        SwingUtilities.invokeLater(() -> {
            String ts = new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date());
            logArea.append("[" + ts + "] " + s + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    /** DocumentListener 有 3 个方法，这里用接口默认方法省掉样板。 */
    private interface SimpleDocListener extends javax.swing.event.DocumentListener {
        void changed();

        @Override
        default void insertUpdate(javax.swing.event.DocumentEvent e) {
            changed();
        }

        @Override
        default void removeUpdate(javax.swing.event.DocumentEvent e) {
            changed();
        }

        @Override
        default void changedUpdate(javax.swing.event.DocumentEvent e) {
            changed();
        }
    }
    /** 套用暗色主题 —— 由 BurpExtender 在注册标签页后统一调用。 */
    public void restyle() {
        com.packetsentry.ui.Theme.apply(this);
    }


    /**
     * 显存 / 内存不足的针对性建议（静态版，便于单元测试）。
     *
     * <p>抽出来的原因：{@code diagnose(Reply)} 是实例方法且依赖多个输入框字段，
     * 没法直接测。而 OOM 这一支<b>不需要任何字段</b> —— 只看错误文案。
     *
     * @param low 已经 toLowerCase 的错误文案
     * @return 命中 OOM 时返回建议行；否则返回 {@code null}
     */
    static java.util.List<String> diagnoseOom(String low) {
        if (low == null
                || !(low.contains("out of memory") || low.contains("cudamalloc")
                || low.contains("unable to allocate") || low.contains("cpu_repack")
                || low.contains("failed to allocate") || low.contains("outofmemory"))) {
            return null;
        }
        java.util.List<String> r = new java.util.ArrayList<>();
        boolean gpuOom = low.contains("cuda") || low.contains("cudamalloc")
                || low.contains("buffer of size");

        r.add("→ 判断：<b>本机显存 / 内存不够，模型加载失败</b>。"
                + "这不是插件的问题，也不是地址或密钥的问题。");
        if (gpuOom) {
            r.add("  错误里提到了 CUDA —— 显存分配失败：");
            r.add("  · <b>nvidia-smi 显示的 free 不等于能用的量</b>。"
                    + "笔记本 WDDM 模式下桌面会占掉一块显存，");
            r.add("    而且 ggml 的「will fit」预测只算它自己那部分，"
                    + "算不到别的进程。");
        } else {
            r.add("  错误里没提 CUDA —— 是<b>系统内存</b>分配失败。");
        }
        r.add("");
        r.add("  按这个顺序查（每步都能立刻得到答案）：");
        r.add("  1. 看显存：在命令行跑 nvidia-smi，used 接近 total 就是显存满");
        r.add("  2. <b>看提交限制</b>：任务管理器 → 性能 → 内存，"
                + "看「已提交」有没顶到上限");
        r.add("     ▲ 提交限制 = 物理内存 + 页面文件。"
                + "<b>页面文件太小会让大模型完全加载不了</b>，");
        r.add("       而报错可能显示成 CUDA 分配失败，很容易误判成显卡问题。");
        r.add("  3. 换个更小的模型。实测对照（8 GB 显存的笔记本）：");
        r.add("     qwen3:8b → 需 5.3 GB 显存，2 GB 页面文件的机器上装不下");
        r.add("     qwen3:4b → 需 3.2 GB 显存，72 tokens/s，<b>推荐</b>");
        r.add("     2B 级 → 约 2 GB，更快但推理能力明显下降");
        r.add("     切到 qwen3:4b：ollama pull qwen3:4b，然后在设置里改模型名。");
        r.add("  4. 关掉吃显存/内存的程序（浏览器硬件加速、游戏、"
                + "其它已加载的模型实例）。");
        r.add("  5. 模型已经在加载时不要连按「测试连接」—— "
                + "<b>两次加载会互相抢显存</b>，第二次必然失败。");
        r.add("");
        r.add("  ▲ 本插件的模型没在显存里时，第一次请求要等它加载完；"
                + "8B 冷启动可能 10–60 秒。");

        return r;
    }
}
