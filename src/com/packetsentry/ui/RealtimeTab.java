package com.packetsentry.ui;

import burp.IBurpExtenderCallbacks;

import com.packetsentry.audit.CodeAudit;
import com.packetsentry.audit.OwaspTop10;
import com.packetsentry.audit.RouteAudit;
import com.packetsentry.audit.ReflectionAudit;
import com.packetsentry.report.ReportGate;
import com.packetsentry.report.ReportGenerator;
import com.packetsentry.core.AccessControlTester;
import com.packetsentry.core.AccessControlBatch;
import com.packetsentry.core.Config;
import com.packetsentry.core.CostTracker;
import com.packetsentry.core.Identity;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.core.RealtimePipe;
import com.packetsentry.detect.LocalRules;
import com.packetsentry.detect.PlatformRules;
import com.packetsentry.detect.Pivot;
import com.packetsentry.llm.LlmClient;
import com.packetsentry.sanitize.Sanitizer;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * 实时抓包面板 —— 宏观业务流量分析 + 单个流量分析。
 *
 * <h3>两个分析层次</h3>
 * <ul>
 *   <li><b>宏观</b>：把几百个包收敛成「业务地图」—— 这个系统有哪些模块、
 *       每个接口干什么、本地已发现什么问题。用「分析该域名」触发，
 *       可本地查看，也可一次调用 AI 做业务逻辑推断</li>
 *   <li><b>微观</b>：选中单个包 → 看请求/响应 → 送 Repeater 手工测 → 或送 AI 深挖</li>
 * </ul>
 *
 * <h3>成本设计</h3>
 * 「作用」和「漏洞」两列由<b>本地规则</b>填充（{@link LocalRules}），
 * 零成本、零网络、结果确定。AI 只用于两处：
 * 单包深挖（约 0.5 分）和整个域名的业务逻辑推断（约 ¥0.01-0.03）。
 */
public final class RealtimeTab extends JPanel {

    private final RealtimePipe pipe;
    private final CostTracker cost;
    private final Supplier<Config> configSupplier;
    private final IBurpExtenderCallbacks callbacks;
    private final LlmClient llm = new LlmClient();

    /**
     * 最近一次「AI 挖洞」产出的假设。
     *
     * <p>⚠️ 这些<b>永远</b>是待验证状态 —— AI 无权把人标记成「已证实」。
     * 只有用户在复核对话框里亲手标过，才有资格写进报告。
     */
    private java.util.List<com.packetsentry.ai.Hypothesis> lastHypotheses =
            new java.util.ArrayList<>();

    private final PacketTableModel model = new PacketTableModel();
    private final JTable table = new JTable(model);
    private final JTextArea detail = new JTextArea();
    private final JLabel statusLabel = new JLabel(" 等待抓包…");
    private final JLabel legendLabel = new JLabel();
    private final JComboBox<String> hostBox = new JComboBox<>();
    private final JCheckBox autoBox = new JCheckBox("自动分析新接口");

    /**
     * 暗色主题开关。
     *
     * <p>▲ 为什么要留这个开关：Burp 的 Look &amp; Feel 会覆盖组件颜色，
     * 在某些版本 / 系统主题组合下暗色可能显示异常。
     * 与其让用户被一个看不清的界面卡住，不如给一个一键退回原生的出口。
     */
    private final JCheckBox darkThemeBox = new JCheckBox("暗色主题", true);
    /**
     * 漏洞等级过滤。
     *
     * <p>▲ 为什么必须有：真实 SRC 目标上「服务端版本泄露」「隐藏表单字段」
     * 这类低危规则几乎每一行都命中，会把真正有价值的信号淹掉。
     * 没有过滤器时用户看到的是「一屏低危」，反而以为工具没用。
     */
    private final JComboBox<String> severityBox = new JComboBox<>();
    private javax.swing.table.TableRowSorter<PacketTableModel> sorter;
    private final JTextField budgetField = new JTextField(5);
    private final JButton macroAiBtn = new JButton("AI 业务逻辑分析");

    /** 「AI 挖洞」—— 从抓到的流量里生成可验证的假设（不是"发现漏洞"）。 */
    private final JButton huntBtn = new JButton("AI 挖洞");

    /**
     * 「本地挖洞」—— 纯规则驱动，<b>不需要任何模型</b>。
     *
     * <p>零网络、零成本，SRC 安全模式下完全可用。
     * 和 AI 版输出同一个数据模型、过同一个闸门。
     */
    private final JButton localHuntBtn = new JButton("本地挖洞");

    /** 「复核假设」—— 人在这里把假设标成已证实/已否定，并留验证记录。 */
    private final JButton reviewBtn = new JButton("复核假设");
    private final JComboBox<String> identityBox = new JComboBox<>();
    private AccessControlTester acTester;
    private final CodeAudit codeAudit = new CodeAudit();
    private final ReportGenerator reportGen = new ReportGenerator();
    /** 最近一次代码审计结果，生成报告时可能要带上。 */
    private CodeAudit.Result lastAudit;
    /**
     * {@link #lastAudit} 是对<b>哪个包</b>算出来的（用 {@link PacketRecord#signature} 标识）。
     *
     * <p>▲ 没有它就会出「报告张冠李戴」的 bug：审计了包 A、改选包 B 去生成报告，
     * 报告里会附上 A 的审计结论，而措辞是「选中包的代码审计」。
     * 报告看起来完全正常，结论却是别的包的 —— 对挖 SRC 的人比崩溃更危险。
     */
    private String lastAuditSig;

    /**
     * 解析好的 SRC 平台收录规则。
     *
     * <p>▲ 过滤放在<b>显示层</b>而不是抓包层 —— 这样开关 SRC 模式或改规则时
     * 能立刻重算，不需要重新抓包。抓包时把发现丢掉就找不回来了。
     */
    private volatile PlatformRules.Parsed platformRules = new PlatformRules.Parsed();

    /**
     * 发现清单 —— SRC 工作的载体。
     *
     * <p>这是「切合 SRC」最关键的一块。SRC 的实际形态是<b>盯着一个目标挖几天</b>，
     * 靠的是跨天累积、去重、能跟踪状态的清单，而不是「最近 500 条包」。
     * <b>包是过程，发现才是产物。</b>
     *
     * <p>在这之前的问题很实在：关掉 Burp 半天的工作就没了；
     * 同一个接口用 5 个 ID 验证越权会在列表里出现 5 次；
     * 挖到第三天记不清哪条验证过、哪条提交了。
     */
    private final com.packetsentry.core.FindingsLedger ledger =
            new com.packetsentry.core.FindingsLedger();
    /** 上次把清单写盘的时间 —— 攒着写，不必每个包都落盘。 */
    private long lastLedgerSave = 0L;

    private final List<PacketRecord> pending = new ArrayList<>();
    private final javax.swing.Timer flushTimer;
    private boolean hostBoxDirty = true;
    /** 程序正在重建域名下拉框（用来区分「程序触发」和「用户选择」）。 */
    private boolean updatingHostBox = false;
    /** 详情区是否被钉住（AI / 越权结果），钉住时不自动覆盖。 */
    private boolean detailPinned = false;

    public RealtimeTab(RealtimePipe pipe,
                       CostTracker cost,
                       Supplier<Config> configSupplier,
                       IBurpExtenderCallbacks callbacks) {
        this.pipe = pipe;
        this.cost = cost;
        this.configSupplier = configSupplier;
        this.callbacks = callbacks;

        setLayout(new BorderLayout(0, 4));

        // ---------- 第 1 行：域名过滤 + 宏观分析 ----------
        JPanel row1 = new JPanel();
        row1.setLayout(new BoxLayout(row1, BoxLayout.X_AXIS));
        row1.setBorder(BorderFactory.createEmptyBorder(4, 6, 0, 6));

        hostBox.setMaximumSize(new Dimension(280, 26));
        hostBox.setToolTipText("只显示该域名的流量；宏观分析也针对该域名");
        hostBox.addActionListener(e -> onHostSelected());
        huntBtn.setToolTipText(
                "从抓到的流量里生成可验证的漏洞假设（不是直接判定漏洞）"
                        + " —— 每条都必须过黄金六要素闸门才能进报告");
        huntBtn.addActionListener(e -> runHunting());
        localHuntBtn.setToolTipText(
                "用本地规则从流量里找线索（越权/未授权/篡改/信息泄露）"
                        + " —— 纯本地，0 网络请求，SRC 模式下也能用");
        localHuntBtn.addActionListener(e -> runLocalHunting());
        reviewBtn.setToolTipText(
                "逐条标记假设的验证结果 —— 只有「已证实」的才够格写进报告");
        reviewBtn.addActionListener(e -> reviewHypotheses());

        JButton macroLocalBtn = new JButton("本地业务地图");
        macroLocalBtn.setToolTipText("把该域名的接口汇总成业务地图（零成本，不联网）");
        macroLocalBtn.addActionListener(e -> showBusinessMap(false));

        macroAiBtn.setToolTipText("把业务地图发给 AI 做一次业务逻辑推断（约 ¥0.01-0.03，单次调用）");
        macroAiBtn.addActionListener(e -> showBusinessMap(true));

        JButton clearBtn = new JButton("清空");
        clearBtn.addActionListener(e -> {
            pipe.reset();
            cost.reset();
            model.clear();
            detail.setText("");
            hostBoxDirty = true;
            refreshStatus();
        });

        JButton routeAuditBtn = new JButton("隐藏入口");
        routeAuditBtn.setToolTipText(
                "找「页面上没有入口、但代码里还在」的路由（被注释掉的功能、残留的注册/管理入口）"
                        + " —— 纯本地分析，0 网络请求");
        // ⚠️ 这一行是补的：按钮声明了、加了 tooltip、加进了工具栏，
        //    但<b>从来没接监听器</b> —— 于是 auditRoutes() 写好了却永远不被调用，
        //    用户点了「隐藏入口」毫无反应。
        //
        //    这类 bug 特别隐蔽：界面看起来完全正常，方法也写得对，
        //    只是少了一行接线。所以现在有 RouteAuditProbe 之外，
        //    还加了一条「每个 JButton 都必须有 addActionListener」的检查。
        routeAuditBtn.addActionListener(e -> auditRoutes());

        JButton reflectBtn = new JButton("反射检测");
        reflectBtn.setToolTipText(
                "找出哪些参数值被回显到响应里，以及落在什么上下文"
                        + "（HTML文本/属性内/JS字符串内…）—— 直接告诉你该用哪种 XSS 注入形式。"
                        + " 纯本地分析，0 网络请求，不下发 payload");
        reflectBtn.addActionListener(e -> auditReflection());

        JButton domainAuditBtn = new JButton("审计该域名");
        domainAuditBtn.setToolTipText(
                "审计已抓到的该域名所有 JS/HTML —— 纯本地字符串分析，发送 0 个网络请求，不会触发 WAF");
        domainAuditBtn.addActionListener(e -> auditDomain());

        JButton owaspBtn = new JButton("OWASP Top10");
        owaspBtn.setToolTipText("按当前流量显示 OWASP Top 10 的真实覆盖度（含「本工具测不了」的明确标注）");
        owaspBtn.addActionListener(e -> showOwasp());

        row1.add(new JLabel("目标域名 "));
        row1.add(hostBox);
        row1.add(Box.createHorizontalStrut(6));
        row1.add(macroLocalBtn);
        row1.add(Box.createHorizontalStrut(4));
        row1.add(macroAiBtn);
        row1.add(Box.createHorizontalStrut(10));
        row1.add(routeAuditBtn);
        row1.add(Box.createHorizontalStrut(4));
        row1.add(reflectBtn);
        row1.add(Box.createHorizontalStrut(4));
        row1.add(domainAuditBtn);
        row1.add(Box.createHorizontalStrut(4));
        row1.add(owaspBtn);
        row1.add(Box.createHorizontalStrut(10));
        row1.add(clearBtn);
        row1.add(Box.createHorizontalGlue());

        // ★ 「发现清单」放在最右、独立分组 —— 它不是一个分析动作，
        //    而是 SRC 工作的<b>主界面</b>：盯一个目标挖几天，日常就是看这个清单。
        JButton findingsBtn = new JButton("★ 发现清单");
        findingsBtn.setToolTipText(
                "跨会话保存的发现台账 —— 自动把包里的问题归并成「发现」并去重，"
                        + "可跟踪状态（待验证/已验证/已提交/已收录/不收）、导出 Markdown 报告。"
                        + " 存于 ~/.packetsentry/findings.json");
        findingsBtn.addActionListener(e -> showFindings());
        row1.add(findingsBtn);
        row1.add(Box.createHorizontalStrut(4));

        // ★ SRC 场景的两个高频动作：批量越权、CVE 跨资产匹配
        JButton acBatchBtn = new JButton("批量越权");
        acBatchBtn.setToolTipText(
                "一次测一组接口 —— 只原样重放你已经发过的请求，不注入 payload。"
                        + " 默认只测只读方法（GET/HEAD/OPTIONS），"
                        + "写操作需二次确认（重放写操作可能真的改数据）");
        acBatchBtn.addActionListener(e -> runBatchAccessControl());
        row1.add(acBatchBtn);
        row1.add(Box.createHorizontalStrut(4));

        JButton cveBtn = new JButton("CVE 匹配");
        cveBtn.setToolTipText(
                "从已抓流量提取组件版本，把「同组件同版本」的资产归组；"
                        + " 你核实并登记 CVE 区间后，一次匹配全部同指纹资产。"
                        + " 纯被动分析，0 网络请求");
        cveBtn.addActionListener(e -> showCveMatch());
        row1.add(cveBtn);
        row1.add(localHuntBtn);
        row1.add(huntBtn);
        row1.add(reviewBtn);
        add(row1, BorderLayout.NORTH);

        // ---------- 第 2 行：微观控制 ----------
        JPanel row2 = new JPanel();
        row2.setLayout(new BoxLayout(row2, BoxLayout.X_AXIS));
        row2.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));

        autoBox.setToolTipText("只对「新接口结构」自动送分析；重复接口和静态资源跳过");
        autoBox.addActionListener(e -> onAutoChanged());

        budgetField.setText("1.0");
        budgetField.setMaximumSize(new Dimension(60, 24));
        budgetField.setToolTipText("累计预估花费超过这个金额（人民币）就停止自动分析");
        budgetField.addActionListener(e -> applyBudget());

        JButton toRepeaterBtn = new JButton("→ Repeater");
        toRepeaterBtn.setToolTipText("把选中的请求直接送到 Repeater 手工测试");
        toRepeaterBtn.addActionListener(e -> sendToRepeater());

        JButton toAiBtn = new JButton("AI 深挖选中");
        toAiBtn.setToolTipText("把选中包的脱敏内容发给 AI 做单个流量分析（约 0.5 分）");
        toAiBtn.addActionListener(e -> analyzeSelected());

        JButton pauseBtn = new JButton("暂停");
        pauseBtn.addActionListener(e -> {
            boolean p = !pipe.isPaused();
            pipe.setPaused(p);
            pauseBtn.setText(p ? "继续" : "暂停");
            refreshStatus();
        });

        // ---- 越权测试 ----
        identityBox.setMaximumSize(new Dimension(170, 26));
        identityBox.setToolTipText("用这个身份重放选中的请求，对比响应（需要先在设置页配置身份）");
        refreshIdentities();

        JButton acBtn = new JButton("越权测试");
        acBtn.setToolTipText("用选中的身份重放该请求，与基线响应对比 —— 会向目标发送 1 个额外请求");
        acBtn.addActionListener(e -> runAccessControlTest());

        severityBox.setMaximumSize(new Dimension(150, 26));
        severityBox.setToolTipText("真实目标上低危噪音很多，建议从「中危以上」看起");
        severityBox.addItem("全部");
        severityBox.addItem("低危以上");
        severityBox.addItem("中危以上");
        severityBox.addItem("高危以上");
        severityBox.addItem("仅严重");
        severityBox.addItem("仅无问题");
        severityBox.addActionListener(e -> applySeverityFilter());

        row2.add(new JLabel("显示 "));
        row2.add(severityBox);
        row2.add(Box.createHorizontalStrut(10));
        darkThemeBox.setToolTipText("关掉则交回 Burp 原生外观（若暗色在某些环境下显示异常）");
        darkThemeBox.addActionListener(e -> {
            Theme.setEnabled(darkThemeBox.isSelected());
            applyTheme();
        });
        row2.add(autoBox);
        row2.add(Box.createHorizontalStrut(10));
        row2.add(darkThemeBox);
        row2.add(Box.createHorizontalStrut(8));
        row2.add(new JLabel("预算 ¥"));
        row2.add(budgetField);
        row2.add(Box.createHorizontalStrut(12));
        JButton auditBtn = new JButton("代码审计");
        auditBtn.setToolTipText("审计选中响应里的 JS/HTML：硬编码密钥、危险DOM、接口路径、注释线索、Source Map…");
        auditBtn.addActionListener(e -> runCodeAudit());

        JButton reportBtn = new JButton("生成报告");
        reportBtn.setToolTipText("按渗透测试报告结构生成：URL / 定级 / 危害 / 资产证明 / 渗透路径 / 修复建议");
        reportBtn.addActionListener(e -> generateReport());

        row2.add(auditBtn);
        row2.add(Box.createHorizontalStrut(4));
        row2.add(reportBtn);
        row2.add(Box.createHorizontalStrut(10));
        row2.add(toRepeaterBtn);
        row2.add(Box.createHorizontalStrut(4));
        row2.add(toAiBtn);
        row2.add(Box.createHorizontalStrut(4));
        row2.add(pauseBtn);
        row2.add(Box.createHorizontalStrut(14));
        row2.add(new JLabel("以身份 "));
        row2.add(identityBox);
        row2.add(Box.createHorizontalStrut(4));
        row2.add(acBtn);
        row2.add(Box.createHorizontalGlue());

        // ---------- 表格 ----------
        table.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        table.setRowHeight(20);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);

        // 等级过滤靠 RowFilter 实现 —— 不改数据，只改显示
        sorter = new javax.swing.table.TableRowSorter<>(model);
        table.setRowSorter(sorter);
        // 选择变化只在用户点行时解除钉住；程序性变化（排序等）不碰详情区
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                refreshDetailForSelection();
            }
        });
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent ev) {
                if (table.rowAtPoint(ev.getPoint()) >= 0) {
                    onRowClicked();
                }
            }
        });
        table.setDefaultRenderer(Object.class, new RiskRenderer());
        table.setDefaultRenderer(Integer.class, new RiskRenderer());
        table.setDefaultRenderer(String.class, new RiskRenderer());

        // 列宽：路径最宽，状态/标记最窄
        int[] widths = {52, 62, 170, 330, 120, 190, 66, 52};
        for (int i = 0; i < widths.length && i < table.getColumnModel().getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        // 双击直接送 Repeater —— 最常用的动作
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent ev) {
                if (ev.getClickCount() == 2) {
                    sendToRepeater();
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(table);

        detail.setEditable(false);
        detail.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detail);
        detailScroll.setBorder(BorderFactory.createTitledBorder(
                "详情（本地扫描 + 本地规则 + 脱敏后将要发送的内容）"));

        JPanel center = new JPanel(new BorderLayout());
        center.add(tableScroll, BorderLayout.CENTER);

        // 图例
        // ▲ 刻意不用 HTML —— Burp 的自定义 LookAndFeel 不保证渲染 JLabel 里的 HTML
        //    （之前「当前去向」就因此把 HTML 源码当纯文本显示出来了）。
        legendLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        legendLabel.setText("行背景："
                + "紫=严重　红=高　橙=中　黄=低　绿=已查无问题　灰=低价值/重复"
                + "　｜　「漏洞」列圆点同色　｜　双击行送 Repeater");
        center.add(legendLabel, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, center, detailScroll);
        split.setResizeWeight(0.6);
        split.setDividerLocation(300);

        JPanel mid = new JPanel(new BorderLayout());
        mid.add(row2, BorderLayout.NORTH);
        mid.add(split, BorderLayout.CENTER);
        add(mid, BorderLayout.CENTER);

        // ---------- 底部状态 ----------
        statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));
        add(statusLabel, BorderLayout.SOUTH);

        // ---------- 批量刷新 ----------
        reloadPlatformRules();

        flushTimer = new javax.swing.Timer(400, e -> flushPending());
        flushTimer.start();

        pipe.addListener(new RealtimePipe.Listener() {
            @Override
            public void onRecord(PacketRecord r) {
                synchronized (pending) {
                    pending.add(r);
                }
                maybeAutoAnalyze(r);
            }

            @Override
            public void onOverflow(long total) {
                SwingUtilities.invokeLater(() -> statusLabel.setText(
                        " ▲ 队列溢出，已丢弃 " + total + " 个包（抓包太快，处理跟不上）"));
            }
        });

        // ▲▲ 这一行是补的，它修的是一个「暗色主题从未生效」的 bug。
        //
        //    原来的情况：darkThemeBox 默认就是勾选的（new JCheckBox("暗色主题", true)），
        //    但 applyTheme() 只挂在它的 ActionListener 上 ——
        //    而<b>复选框的初始状态不会触发 ActionListener</b>。
        //
        //    结果：界面启动后完全是 Burp 的浅色 L&F，用户看到的就是一片白。
        //    只有手动点两下复选框（关掉再打开）才会变黑 ——
        //    这也是为什么这个 bug 很容易被当成"主题在某些环境下显示异常"，
        //    而不是"主题压根没被调用"。
        //
        //    放在构造函数最末尾，是因为此时组件树已经完整 ——
        //    Theme.apply(this) 要递归遍历它。
        applyTheme();
    }

    // ==================================================================
    // 刷新
    // ==================================================================

    private void flushPending() {
        List<PacketRecord> batch;
        synchronized (pending) {
            if (pending.isEmpty()) {
                return;
            }
            batch = new ArrayList<>(pending);
            pending.clear();
        }
        model.addAll(batch);
        hostBoxDirty = true;
        refreshHostBox();
        ingestFindings(batch);
        refreshStatus();
    }

    // ==================================================================
    // 发现清单 —— 把「包里的问题」归并成「发现」
    // ==================================================================

    /**
     * 把这一批报文里的问题归集进发现清单。
     *
     * <p>关键在 {@link com.packetsentry.core.Finding#fingerprint}：
     * 同一个接口用 5 个不同的 ID 验证越权，只会产生<b>一条</b>发现（次数 +5），
     * 而不是 5 条。没有这个归并，清单两天就废了 —— 那正是「靶场思维」和
     * 「SRC 思维」的分界线。
     *
     * <p>平台规则的判定在这里一起落进去 —— 提交时的等级要以平台为准，
     * 而不是以我们本地判的为准。
     */
    private void ingestFindings(List<PacketRecord> batch) {
        PlatformRules.Parsed pr = platformRules;
        Config cfg = configSupplier.get();
        boolean rangeMode = cfg != null && cfg.rangeMode;
        int added = 0;

        for (PacketRecord r : batch) {
            if (r.lowValue || r.issues == null || r.issues.isEmpty()) {
                continue;
            }
            for (LocalRules.Issue i : r.issues) {
                if (i.level == null || i.level == LocalRules.Level.NONE) {
                    continue;
                }
                // ▲ 只有靶场模式才收 Flag。
                //    实战 SRC 里真实业务系统不存在 flag，那条规则是纯噪音 ——
                //    而且「极小响应 + 长 hex」的兜底会误报成 CRITICAL，
                //    把注意力浪费在假问题上是有实际代价的。
                boolean isFlag = i.name != null && i.name.contains("Flag");
                if (isFlag && !rangeMode) {
                    continue;
                }

                PlatformRules.Decision d = pr == null
                        ? null : PlatformRules.decide(i.name, pr);
                // 平台明确不收的就不进清单 —— 收了也不给钱，别占地方
                if (d == PlatformRules.Decision.EXCLUDED) {
                    continue;
                }

                String platLevel = i.level.label;
                if (d == PlatformRules.Decision.CONDITIONAL
                        && i.level.rank > LocalRules.Level.LOW.rank) {
                    // 平台「视影响」的：等级照报，但标注出来，
                    // 提醒用户提交时必须把危害写清楚，否则会被降级
                    platLevel = i.level.label + "（平台视影响）";
                }

                com.packetsentry.core.Finding fd = com.packetsentry.core.Finding.from(
                        r.method, r.host, r.path, primaryParam(r), i.name, i.level,
                        i.evidence, d, platLevel);
                if (ledger.upsert(fd)) {
                    added++;
                }
            }
        }

        // 攒着写盘：有新增、且距上次超过 5 秒。
        // 每个包都落盘会让抓包变卡，而清单丢几秒是可以接受的。
        long now = System.currentTimeMillis();
        if (added > 0 && now - lastLedgerSave > 5000) {
            ledger.save();
            lastLedgerSave = now;
        }
    }

    /** 从请求里取「最可能命中的参数名」，只用于清单展示。 */
    private static String primaryParam(PacketRecord r) {
        if (r.rawRequest == null) {
            return "";
        }
        String req = new String(r.rawRequest, java.nio.charset.StandardCharsets.UTF_8);
        java.util.List<String> names = new ArrayList<>();

        int q = req.indexOf('?');
        int sp = req.indexOf(' ', q > 0 ? q : 0);
        if (q > 0 && sp > q) {
            for (String kv : req.substring(q + 1, sp).split("&")) {
                int eq = kv.indexOf('=');
                if (eq > 0) {
                    names.add(kv.substring(0, eq));
                }
            }
        }

        int he = req.indexOf("\r\n\r\n");
        if (he > 0) {
            String body = req.substring(he + 4);
            java.util.regex.Matcher mj = java.util.regex.Pattern
                    .compile("\"([A-Za-z_][A-Za-z0-9_\\-]{0,30})\"\\s*:")
                    .matcher(body);
            while (mj.find() && names.size() < 8) {
                names.add(mj.group(1));
            }
            java.util.regex.Matcher mf = java.util.regex.Pattern
                    .compile("(?:^|&)([A-Za-z_][A-Za-z0-9_\\-]{0,30})=")
                    .matcher(body);
            while (mf.find() && names.size() < 8) {
                names.add(mf.group(1));
            }
        }
        if (names.isEmpty()) {
            return "";
        }
        return String.join(", ", names.subList(0, Math.min(3, names.size())));
    }

    private void refreshHostBox() {
        if (!hostBoxDirty) {
            return;
        }
        hostBoxDirty = false;

        // ▲ 重建下拉框会触发一串 ActionEvent（removeAllItems / 每个 addItem
        //    各触发一次）。早期版本的下拉框监听器直接调 refreshDetailForSelection()，
        //    结果每次刷新都把详情区覆盖成 renderDetail() ——
        //    <b>AI 分析结果刚出来就被冲掉，用户只能重新点，token 白烧</b>。
        //
        //    用这个标志让「程序重建」与「用户选择」区分开：
        //    程序重建期间不触发详情刷新。
        updatingHostBox = true;
        try {
            String sel = (String) hostBox.getSelectedItem();
            List<String> hosts = pipe.hosts();
            hostBox.removeAllItems();
            hostBox.addItem("(全部)");
            for (String h : hosts) {
                hostBox.addItem(h);
            }
            if (sel != null) {
                hostBox.setSelectedItem(sel);
            }
        } finally {
            updatingHostBox = false;
        }
    }

    /** 用户真的在下拉框里选了东西（而不是程序重建触发的事件）。 */
    private void onHostSelected() {
        if (updatingHostBox) {
            return;
        }
        // 用户主动换域名 = 明确想换内容，解除详情钉住
        detailPinned = false;
        refreshDetailForSelection();
    }

    /**
     * 把详情区钉住，不让自动刷新覆盖它。
     *
     * <p>AI 分析、越权测试这类结果<b>是要花钱的</b>，绝不能被后台的
     * 定时刷新冲掉 —— 用户重新点一次就是重新花一次钱。
     * 只有用户明确点了表格某一行，才解除钉住。
     */
    private void pinDetail(String text) {
        detailPinned = true;
        detail.setText(text);
        detail.setCaretPosition(0);
    }

    /** 追加到已钉住的详情末尾（用于补一句结论，而不覆盖正文）。 */
    private void appendPinned(String text) {
        detailPinned = true;
        detail.append(text);
        detail.setCaretPosition(detail.getDocument().getLength());
    }

    private String selectedHost() {
        Object o = hostBox.getSelectedItem();
        if (o == null || "(全部)".equals(o)) {
            return null;
        }
        return o.toString();
    }

    /**
     * 按漏洞等级过滤表格。
     *
     * <p>用 {@link javax.swing.table.TableRowSorter} 的 RowFilter 实现，
     * <b>不改动数据</b>，只是不显示 —— 切换回来立刻恢复。
     */
    private void applySeverityFilter() {
        if (sorter == null) {
            return;
        }
        Object sel = severityBox.getSelectedItem();
        String mode = sel == null ? "全部" : sel.toString();

        final LocalRules.Level min;
        final boolean onlyNone;
        switch (mode) {
            case "低危以上":
                min = LocalRules.Level.LOW;
                onlyNone = false;
                break;
            case "中危以上":
                min = LocalRules.Level.MEDIUM;
                onlyNone = false;
                break;
            case "高危以上":
                min = LocalRules.Level.HIGH;
                onlyNone = false;
                break;
            case "仅严重":
                min = LocalRules.Level.CRITICAL;
                onlyNone = false;
                break;
            case "仅无问题":
                min = LocalRules.Level.NONE;
                onlyNone = true;
                break;
            default:
                min = null;
                onlyNone = false;
        }

        if (min == null && !onlyNone) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(new javax.swing.RowFilter<PacketTableModel, Integer>() {
                @Override
                public boolean include(Entry<? extends PacketTableModel, ? extends Integer> e) {
                    PacketRecord p = e.getModel().get(e.getIdentifier());
                    if (p == null) {
                        return false;
                    }
                    // 低价值 / 重复的行只在「全部」下显示
                    if (p.lowValue || p.duplicate) {
                        return false;
                    }
                    if (onlyNone) {
                        return p.worstLevel == LocalRules.Level.NONE;
                    }
                    return p.worstLevel.rank >= min.rank;
                }
            });
        }
        int shown = table.getRowCount();
        int total = model.getRowCount();
        if (shown != total) {
            statusLabel.setText(" 显示 " + shown + " / " + total + " 行（等级过滤：" + mode + "）");
        } else {
            refreshStatus();
        }
    }

    /**
     * 重新解析平台规则并刷新过滤。
     *
     * <p>设置页保存后由 {@code BurpExtender} 调过来，让过滤立刻生效。
     */
    /**
     * 套用 / 撤销暗色主题。
     *
     * <p>关掉主题时不去「记住原来的颜色再还原」——那太脆弱。
     * 而是直接用 Burp 当前 L&F 的默认色重设一遍，这样无论用户
     * 用的是哪种 L&F 都能正确回退。
     */
    private void applyTheme() {
        if (!Theme.isEnabled()) {
            // 回退：用当前 L&F 的默认色刷一遍
            revertToLaf(this);
            revertTableToLaf();
            return;
        }
        Theme.apply(this);
        Theme.table(table);
        Theme.textArea(detail);
        Theme.base(this);
        Theme.check(darkThemeBox);
        Theme.check(autoBox);
        // ⭐ 按钮分级放在最后做。
        //
        //    为什么不逐个在 new JButton 处调用：按钮是字段式声明的，
        //    没有统一的初始化段落可以插入调用点（试过，锚点全找不到）。
        //
        //    更重要的原因：按<b>文字</b>分配级别能让"哪些动作有视觉重量"
        //    这件事集中在一处可见 —— 而不是散在 16 个 new JButton 里，
        //    将来加按钮时也不会漏掉分级。
        applyButtonHierarchy();
        table.repaint();
    }

    /**
     * 按按钮文字分配视觉级别。
     *
     * <h3>为什么需要这个</h3>
     * 旧界面里 16 个按钮长得一模一样 —— 「生成报告」和「清空」在视觉上等价，
     * 而前者是你最想让人点的、后者是不可逆的破坏性操作。
     * 全部一样的结果是<b>用户的眼睛没有落点</b>。
     *
     * <p>分级依据是<b>后果的不可逆程度</b>：
     * <ul>
     *   <li>PRIMARY —— 最终产出（生成报告）、核心价值动作（AI 分析）</li>
     *   <li>DANGER —— 不可逆或有真实副作用（清空、越权测试、批量越权）</li>
     *   <li>GHOST —— 临时开关（暂停），不需要视觉重量</li>
     *   <li>SECONDARY —— 其余全部</li>
     * </ul>
     *
     * <p>⚠️ 用 {@code equals} 精确匹配文字，不用 contains ——
     * 「越权测试」和「批量越权」如果用 contains 会互相误伤。
     */
    private void applyButtonHierarchy() {
        // 文字 → 级别。刻意只列需要偏离默认值的，其余保持 SECONDARY。
        java.util.Map<String, Theme.Btn> map = new java.util.HashMap<>();
        map.put("生成报告", Theme.Btn.PRIMARY);
        map.put("AI 业务逻辑分析", Theme.Btn.PRIMARY);
        map.put("清空", Theme.Btn.DANGER);
        map.put("越权测试", Theme.Btn.DANGER);
        map.put("批量越权", Theme.Btn.DANGER);
        map.put("暂停", Theme.Btn.GHOST);

        for (javax.swing.AbstractButton btn : Theme.buttons(this)) {
            String text = btn.getText();
            if (text == null) {
                continue;
            }
            Theme.Btn kind = map.get(text.trim());
            Theme.styleButton(btn, kind == null ? Theme.Btn.SECONDARY : kind);
        }
    }

    /** 把组件树的颜色交回当前 L&F。 */
    private void revertToLaf(java.awt.Component root) {
        try {
            javax.swing.UIDefaults u = javax.swing.UIManager.getDefaults();
            if (root instanceof javax.swing.JComponent) {
                javax.swing.JComponent jc = (javax.swing.JComponent) root;
                Object bg = u.get("Panel.background");
                Object fg = u.get("Label.foreground");
                if (jc instanceof javax.swing.JTextField || jc instanceof javax.swing.JTextArea) {
                    bg = u.get("TextField.background");
                    fg = u.get("TextField.foreground");
                } else if (jc instanceof javax.swing.JButton) {
                    bg = u.get("Button.background");
                    fg = u.get("Button.foreground");
                }
                if (bg instanceof java.awt.Color) {
                    jc.setBackground((java.awt.Color) bg);
                }
                if (fg instanceof java.awt.Color) {
                    jc.setForeground((java.awt.Color) fg);
                }
            }
            if (root instanceof java.awt.Container) {
                for (java.awt.Component c : ((java.awt.Container) root).getComponents()) {
                    revertToLaf(c);
                }
            }
        } catch (Throwable ignored) {
            // 回退失败也不该影响功能
        }
    }

    /** 表格回退到 L&F 默认外观。 */
    private void revertTableToLaf() {
        try {
            javax.swing.UIDefaults u = javax.swing.UIManager.getDefaults();
            Object bg = u.get("Table.background");
            Object fg = u.get("Table.foreground");
            if (bg instanceof java.awt.Color) {
                table.setBackground((java.awt.Color) bg);
            }
            if (fg instanceof java.awt.Color) {
                table.setForeground((java.awt.Color) fg);
            }
            table.setGridColor(javax.swing.UIManager.getColor("Table.gridColor"));
            if (table.getTableHeader() != null) {
                table.getTableHeader().setBackground(
                        javax.swing.UIManager.getColor("TableHeader.background"));
                table.getTableHeader().setForeground(
                        javax.swing.UIManager.getColor("TableHeader.foreground"));
            }
            table.repaint();
        } catch (Throwable ignored) {
            // 忽略
        }
    }
    public void reloadPlatformRules() {
        Config cfg = configSupplier.get();
        // 只有「SRC 安全模式 + 提供了规则」才过滤。
        // 不开启 SRC 模式时正常显示全部 —— 这是用户明确要求的行为。
        if (cfg.srcMode) {
            platformRules = PlatformRules.parse(cfg.srcRules);
        } else {
            platformRules = new PlatformRules.Parsed();     // empty = 不过滤
        }
        model.setIssueFilter(this::keepIssue);
        // 过滤规则变了，重新套一次等级过滤 + 重绘
        applySeverityFilter();
        model.fireTableDataChanged();
    }

    /**
     * 一条发现该不该显示。
     *
     * <p>SRC 模式 + 有规则时，<b>只显示平台明确「收」的</b>。
     * 「未提及」也不显示 —— 因为用户开这个模式的意图就是「只看能提交的」。
     */
    private boolean keepIssue(LocalRules.Issue i) {
        if (platformRules == null || platformRules.empty) {
            return true;
        }
        return PlatformRules.decide(i.name, platformRules) == PlatformRules.Decision.ACCEPTED;
    }

    /** 一条记录里「可见」的发现（已按平台规则过滤）。 */
    private List<LocalRules.Issue> visibleIssues(PacketRecord r) {
        List<LocalRules.Issue> out = new ArrayList<>();
        for (LocalRules.Issue i : r.issues) {
            if (keepIssue(i)) {
                out.add(i);
            }
        }
        return out;
    }

    /** 可见发现里的最严重等级。 */
    private LocalRules.Level visibleWorst(PacketRecord r) {
        LocalRules.Level w = LocalRules.Level.NONE;
        for (LocalRules.Issue i : r.issues) {
            if (keepIssue(i) && i.level.rank > w.rank) {
                w = i.level;
            }
        }
        return w;
    }

    /** 可见发现的汇总文本。 */
    private String visibleSummary(PacketRecord r) {
        List<LocalRules.Issue> vis = visibleIssues(r);
        if (vis.isEmpty()) {
            return "无";
        }
        LocalRules.Issue top = vis.get(0);
        for (LocalRules.Issue i : vis) {
            if (i.level.rank > top.level.rank) {
                top = i;
            }
        }
        String s = top.level.label + "危" + top.name;
        if (vis.size() > 1) {
            s += " +" + (vis.size() - 1);
        }
        return s;
    }
    /**
     * 把发现清单落盘。
     *
     * <p>Burp 卸载扩展时调用 —— 保证最后几秒新增的发现不会因为
     * 「还没到 5 秒的攒批窗口」而丢掉。
     */
    public void flushLedger() {
        try {
            ledger.save();
            lastLedgerSave = System.currentTimeMillis();
        } catch (Throwable ignored) {
            // 卸载路径上不该再抛异常
        }
    }

    /** 清单条数，给外部（状态栏/日志）用。 */
    public int findingCount() {
        return ledger.size();
    }

    private void refreshStatus() {
        Config cfg = configSupplier.get();
        StringBuilder sb = new StringBuilder(" ");
        sb.append(pipe.processedCount()).append(" 个包");
        sb.append("　接口结构 ").append(pipe.distinctStructures()).append(" 种");
        if (pipe.issueCount() > 0) {
            sb.append("　▲ 本地检出问题 ").append(pipe.issueCount()).append(" 个");
        }
        if (pipe.queuedCount() > 0) {
            sb.append("　队列 ").append(pipe.queuedCount());
        }
        if (pipe.droppedCount() > 0) {
            sb.append("　丢弃 ").append(pipe.droppedCount());
        }
        sb.append("　|　").append(cost.oneLine());
        sb.append("　|　").append(cfg.isLocalProvider() ? "本地模型" : "云端模型");
        statusLabel.setText(sb.toString());
    }

    private void refreshDetailForSelection() {
        // ▲ 详情区被钉住时（AI 结果 / 越权结果）不自动覆盖。
        //    这些结果是要花钱的，被后台刷新冲掉就等于白花。
        if (detailPinned) {
            return;
        }
        int row = table.getSelectedRow();
        if (row < 0) {
            return;
        }
        PacketRecord r = model.get(table.convertRowIndexToModel(row));
        detail.setText(renderDetail(r));
        detail.setCaretPosition(0);
    }

    /** 用户主动点击表格行 —— 这是明确的「我要看这个包」，解除钉住。 */
    private void onRowClicked() {
        detailPinned = false;
        refreshDetailForSelection();
    }

    // ==================================================================
    // 微观：选中 / 送 Repeater / AI 深挖
    // ==================================================================

    private PacketRecord selected() {
        int row = table.getSelectedRow();
        if (row < 0) {
            return null;
        }
        return model.get(table.convertRowIndexToModel(row));
    }

    /**
     * 把选中的请求送到 Repeater。
     *
     * <p>这是渗透测试里最高频的动作 ——「这个包看起来有问题，我要改一改试试」。
     * 双击表格行也能触发，减少鼠标移动。
     */
    private void sendToRepeater() {
        PacketRecord r = selected();
        if (r == null) {
            pinDetail("请先在列表里选一个包。");
            return;
        }
        if (callbacks == null) {
            pinDetail("（当前环境没有 Burp callbacks，无法发送到 Repeater）");
            return;
        }
        byte[] req = r.rawRequest;
        if (req == null || req.length == 0) {
            pinDetail("这个记录没有保存请求原文，无法发送。");
            return;
        }

        // ▲ 端口与协议必须从 Burp 给的 IHttpService 取。
        //
        //    这里原来有个<b>严重 bug</b>：第二个参数（port）传的是 r.statusCode，
        //    也就是 HTTP 状态码。于是 statusCode=200 就变成「连 200 端口」、
        //    404 变成「连 404 端口」—— 全是目标上不存在的端口，
        //    结果就是<b>送到 Repeater 的包永远没有响应</b>。
        //
        //    statusCode 是「响应码」，port 是「端口」，两个都是 int，
        //    编译器拦不住，所以这种错误只能靠人看出来。
        int port;
        String protocol;
        String host;
        if (r.service != null) {
            port = r.service.getPort();
            protocol = r.service.getProtocol();
            host = r.service.getHost() != null ? r.service.getHost() : r.host;
        } else {
            // 没有 service 时的兜底：按协议猜默认端口
            protocol = schemeOf(r);
            port = "http".equalsIgnoreCase(protocol) ? 80 : 443;
            host = r.host;
        }
        boolean useHttps = "https".equalsIgnoreCase(protocol);

        try {
            callbacks.sendToRepeater(host, port,
                    useHttps, req, "PacketSentry #" + r.seq);
        } catch (Throwable t) {
            pinDetail("发送到 Repeater 失败：" + t);
            return;
        }

        // ▲ 关键：<b>追加</b>而不是覆盖。
        //
        //    「送 Repeater」是个很轻的动作，不能把用户刚花钱拿到的 AI 分析结果冲掉 ——
        //    那会逼他重新点一次「AI 深挖」，token 白烧。
        //    所以：详情区已被钉住时只追加一行确认；否则才整体替换。
        String note = "── 已发送到 Repeater ──\n"
                + r.method + " " + host + ":" + port + "　（"
                + (useHttps ? "https" : "http") + "）　标签 PacketSentry #" + r.seq + "\n";
        if (detailPinned) {
            appendPinned("\n\n" + note);
        } else {
            pinDetail(note + "\n" + renderDetail(r));
        }
    }

    private static String schemeOf(PacketRecord r) {
        // 端口 443/8443 视为 https，其余按请求行判断
        String req = r.rawRequest == null ? "" : new String(r.rawRequest,
                java.nio.charset.StandardCharsets.UTF_8);
        if (req.startsWith("GET https://") || req.startsWith("POST https://")) {
            return "https";
        }
        return "https";     // 保守默认 —— 现代站点绝大多数是 https
    }

    private void analyzeSelected() {
        PacketRecord r = selected();
        if (r == null) {
            pinDetail("请先在列表里选一个包。");
            return;
        }
        Config cfg = configSupplier.get();

        if (r.worstLevel == LocalRules.Level.CRITICAL && !confirmCritical(r)) {
            return;
        }

        double per = cost.estimatePerPacketCny(200, CostTracker.estimateTokens(r.brief), 700);
        detail.setText("正在请求 " + cfg.describeDestination()
                + "（预估 ¥" + String.format("%.4f", per) + "）…\n\n"
                + "将要发送的内容：\n" + r.brief);
        detail.setCaretPosition(0);
        statusLabel.setText(" AI 分析中…（" + cfg.describeDestination() + "）");

        final PacketRecord rec = r;
        Thread t = new Thread(() -> {
            LlmClient.Reply reply = llm.chat(cfg, SINGLE_PACKET_PROMPT, rec.brief);
            SwingUtilities.invokeLater(() -> {
                if (reply.ok) {
                    cost.recordCall(SINGLE_PACKET_PROMPT, rec.brief, reply.content);
                    pinDetail("═══ AI 单个流量分析 ═══\n"
                            + "HTTP " + reply.httpStatus + "　" + reply.elapsedMs + " ms　"
                            + "预估 ¥" + String.format("%.4f", per) + "\n\n"
                            + reply.content
                            + "\n\n───────────────────────────\n"
                            + "本地信息：作用=" + rec.purpose
                            + "　漏洞=" + model.summaryOf(rec)
                            + "\n\n将要发送的内容：\n" + rec.brief);
                    detail.setCaretPosition(0);
                    refreshStatus();
                } else {
                    detail.setText("AI 分析失败：\n\n" + reply.error
                            + "\n\n可以用「→ Repeater」手工测试这个包。");
                }
            });
        }, "packetsentry-single");
        t.setDaemon(true);
        t.start();
    }

    private boolean confirmCritical(PacketRecord r) {
        int n = javax.swing.JOptionPane.showConfirmDialog(this,
                "本地规则在这个包里发现了严重级别的数据或问题：\n\n"
                        + model.summaryOf(r) + "\n\n"
                        + "默认不建议发送给 AI 服务商。\n"
                        + "如果确认要发（仍会脱敏），点「是」。",
                "确认发送 CRITICAL 数据", javax.swing.JOptionPane.YES_NO_OPTION,
                javax.swing.JOptionPane.WARNING_MESSAGE);
        return n == javax.swing.JOptionPane.YES_OPTION;
    }

    // ==================================================================
    // 发现清单面板
    // ==================================================================

    /**
     * 发现清单 —— SRC 的主界面。
     *
     * <h3>为什么它比「包列表」重要</h3>
     * 包列表回答的是「刚才流量里有什么」；发现清单回答的是
     * <b>「这个目标我手上有什么、哪些能交」</b> —— 那才是 SRC 每天要问的问题。
     *
     * <p>面板里做的三件事：
     * <ol>
     *   <li><b>看</b>：按等级排序的全部发现，含状态与观测次数</li>
     *   <li><b>改状态</b>：验证完标「已验证」，交了标「已提交」，平台说不收标「不收」</li>
     *   <li><b>导出</b>：把「已验证」的导成 Markdown，直接贴进平台报告框</li>
     * </ol>
     */
    private void showFindings() {
        String host = selectedHost();
        List<com.packetsentry.core.Finding> list = ledger.byHost(host);

        if (list.isEmpty()) {
            pinDetail("══════════ 发现清单 ══════════\n\n"
                    + "目标域名：" + (host == null ? "(全部)" : host) + "\n"
                    + "当前为空。\n\n"
                    + "清单是<b>自动</b>填的 —— 抓包时本地规则一旦发现问题就会归集进来，\n"
                    + "而且会<b>去重</b>：同一个接口用 5 个 ID 验证越权只算 1 条（次数 +5）。\n\n"
                    + "所以你要做的只是：<b>正常浏览目标站</b>，让流量经过代理。\n\n"
                    + "清单存在 " + ledger.file() + "\n"
                    + "关掉 Burp 也不会丢。");
            return;
        }

        // ---- 表格 ----
        String[] cols = {"等级", "类型", "位置", "状态", "次数"};
        Object[][] rows = new Object[list.size()][cols.length];
        for (int i = 0; i < list.size(); i++) {
            com.packetsentry.core.Finding f = list.get(i);
            rows[i][0] = f.displayLevel();
            rows[i][1] = f.type;
            rows[i][2] = f.method + " " + f.path
                    + (f.param.isEmpty() ? "" : "　[" + f.param + "]");
            rows[i][3] = f.status;
            rows[i][4] = f.seenCount;
        }
        javax.swing.table.DefaultTableModel tm = new javax.swing.table.DefaultTableModel(
                rows, cols) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        javax.swing.JTable tbl = new javax.swing.JTable(tm);
        tbl.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_LAST_COLUMN);
        tbl.setRowHeight(22);
        tbl.getColumnModel().getColumn(0).setPreferredWidth(130);
        tbl.getColumnModel().getColumn(1).setPreferredWidth(150);
        tbl.getColumnModel().getColumn(2).setPreferredWidth(420);
        tbl.getColumnModel().getColumn(3).setPreferredWidth(80);
        tbl.getColumnModel().getColumn(4).setPreferredWidth(50);
        tbl.setDefaultRenderer(Object.class, new FindingsRenderer(list));
        Theme.apply(tbl);
        javax.swing.JScrollPane sp = new javax.swing.JScrollPane(tbl);
        sp.setPreferredSize(new java.awt.Dimension(940, 380));

        // ---- 统计条 ----
        StringBuilder head = new StringBuilder();
        java.util.Map<String, Integer> st = ledger.statusCounts();
        head.append("目标 ").append(host == null ? "(全部)" : host)
                .append("　共 ").append(list.size()).append(" 条\n");
        for (java.util.Map.Entry<String, Integer> e : st.entrySet()) {
            if (e.getValue() > 0) {
                head.append("  ").append(e.getKey()).append(' ')
                        .append(e.getValue()).append("　");
            }
        }
        head.append("\n\n").append(ledger.nextSteps(host));

        // ---- 操作按钮 ----
        Object[] options = {
                "标为已验证", "标为已提交", "标为已收录",
                "标为不收", "标为弃用", "导出报告", "关闭",
        };
        int choice = javax.swing.JOptionPane.showOptionDialog(this,
                new Object[]{new javax.swing.JLabel(head.toString()), sp},
                "发现清单（" + ledger.oneLine() + "）",
                javax.swing.JOptionPane.DEFAULT_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE, null, options, options[6]);

        if (choice < 0 || choice == 6) {
            ledger.save();
            return;
        }

        if (choice == 5) {
            exportFindings(host);
            return;
        }

        int row = tbl.getSelectedRow();
        if (row < 0) {
            pinDetail("先在上面的表格里选中一条发现。");
            return;
        }
        com.packetsentry.core.Finding target = list.get(row);
        com.packetsentry.core.Finding.Status ns;
        switch (choice) {
            case 0:
                ns = com.packetsentry.core.Finding.Status.VERIFIED;
                break;
            case 1:
                ns = com.packetsentry.core.Finding.Status.SUBMITTED;
                break;
            case 2:
                ns = com.packetsentry.core.Finding.Status.ACCEPTED;
                break;
            case 3:
                ns = com.packetsentry.core.Finding.Status.OUT_OF_SCOPE;
                break;
            default:
                ns = com.packetsentry.core.Finding.Status.IGNORED;
        }
        String note = target.note;
        if (ns == com.packetsentry.core.Finding.Status.OUT_OF_SCOPE
                || ns == com.packetsentry.core.Finding.Status.IGNORED) {
            note = javax.swing.JOptionPane.showInputDialog(this,
                    "记一句原因（可留空）：", target.note == null ? "" : target.note);
            if (note == null) {
                note = target.note;
            }
        }
        ledger.setStatus(target.id, ns, note);
        ledger.save();
        pinDetail("══════════ 发现清单 ══════════\n\n"
                + "已更新：\n  " + target.type + " @ " + target.where()
                + "\n  → " + ns.label + (note == null || note.isEmpty() ? "" : "（" + note + "）")
                + "\n\n" + ledger.oneLine()
                + "\n\n再点「★ 发现清单」继续处理。");
    }

    /** 导出报告（按所选平台的字段模板）。 */
    private void exportFindings(String host) {
        List<com.packetsentry.core.Finding> ready = new ArrayList<>();
        for (com.packetsentry.core.Finding f : ledger.byHost(host)) {
            if (f.statusEnum() == com.packetsentry.core.Finding.Status.VERIFIED
                    || f.statusEnum() == com.packetsentry.core.Finding.Status.SUBMITTED
                    || f.statusEnum() == com.packetsentry.core.Finding.Status.ACCEPTED) {
                ready.add(f);
            }
        }
        if (ready.isEmpty()) {
            pinDetail("══════════ 导出报告 ══════════\n\n"
                    + "没有「已验证」及以上的发现。\n\n"
                    + "清单里现在有 " + ledger.toVerify().size() + " 条待验证 —— "
                    + "先在 Repeater 里确认它们真的能复现，再回来标成「已验证」。\n\n"
                    + "▲ 这一步不能省。清单里的是候选，不是已确认的漏洞；\n"
                    + "直接拿候选去提交，平台复核一跑就会发现复现不了。");
            return;
        }

        Config cfg = configSupplier.get();

        // ★ 按平台字段模板渲染 —— 字段顺序和平台表单一致，省掉手工搬运。
        //    各平台表单会改版，所以模板是可编辑的：改一次一直用。
        com.packetsentry.report.ReportTemplate tpl =
                com.packetsentry.report.ReportTemplate.byId(cfg.reportTemplateId);
        if (cfg.reportFieldsOverride != null && !cfg.reportFieldsOverride.trim().isEmpty()) {
            tpl.sections = com.packetsentry.report.ReportTemplate.parseEditableText(
                    cfg.reportFieldsOverride, tpl.sections);
        }
        String md = tpl.render(ready, cfg.srcPlatform);

        String path;
        try {
            java.nio.file.Path out = com.packetsentry.core.Config.homeDir()
                    .resolve("report-" + tpl.id + "-" + System.currentTimeMillis() + ".md");
            java.nio.file.Files.write(out, md.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            path = out.toString();
        } catch (Exception e) {
            path = "（写文件失败：" + e.getMessage() + "）";
        }

        // ⭐ 导出路径也要过报告准入闸门。
        //
        //    为什么这条路径必须有：generateReport() 生成的是「单个漏洞」的报告，
        //    而这里导出的是「发现清单」里已标记为已验证的那批 ——
        //    它们会被<b>批量</b>提交到平台。批量提交里混进一条站不住的，
        //    损失比单条更大（平台会怀疑你整批的可信度）。
        //
        //    ⚠️ 闸门只提示、不拦截：
        //       它判断不了"漏洞是否成立"，只能判断"表述够不够格"。
        //       拦下来反而可能挡住用户真正想提交的东西。
        ReportGate.Result gate = ReportGate.check(null, md);
        StringBuilder gateBlock = new StringBuilder();
        gateBlock.append("\n══════════ 报告准入检查（批量导出）══════════\n");
        gateBlock.append(gate.oneLine()).append('\n');
        if (!gate.rejected.isEmpty()) {
            gateBlock.append("\n── 命中的拒收形态（提交前请逐条改掉）──\n");
            for (ReportGate.Reject r : gate.rejected) {
                gateBlock.append("  × 【").append(r.label).append("】")
                        .append(r.hint).append('\n');
            }
        }
        if (!gate.missing.isEmpty()) {
            gateBlock.append("\n── 缺失要素 ──\n");
            for (ReportGate.Element el : gate.missing) {
                gateBlock.append("  ▲ ").append(el.label).append("：")
                        .append(el.hint).append('\n');
            }
        }
        if (!gate.notes.isEmpty()) {
            gateBlock.append("\n── 判断依据 ──\n");
            for (String n : gate.notes) {
                gateBlock.append("  · ").append(n).append('\n');
            }
        }
        gateBlock.append("\n提示：这是自检清单，不是漏洞是否成立的判定。\n");
        gateBlock.append("      批量导出时，先确保每一条都过得了这六条。\n");

        pinDetail("══════════ 导出报告 ══════════\n\n"
                + "模板：" + tpl.oneLine() + "　（" + tpl.note + "）\n"
                + "导出 " + ready.size() + " 条「已验证及以上」的发现。\n"
                + "文件：" + path + "\n\n"
                + "如果字段和平台表单对不上，到「设置 → 报告模板」改一次即可。\n"
                + gateBlock
                + "\n───────────────────────────\n"
                + md);
    }

    /** 发现清单的表格着色 —— 按等级染色，和主表一致。 */
    private final class FindingsRenderer extends javax.swing.table.DefaultTableCellRenderer {
        private final List<com.packetsentry.core.Finding> data;

        FindingsRenderer(List<com.packetsentry.core.Finding> data) {
            this.data = data;
        }

        @Override
        public java.awt.Component getTableCellRendererComponent(
                javax.swing.JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {
            java.awt.Component c = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);
            try {
                if (row >= 0 && row < data.size()) {
                    com.packetsentry.core.Finding f = data.get(row);
                    LocalRules.Level lv = levelOf(f);
                    if (isSelected) {
                        c.setBackground(Theme.BG_SELECT);
                        c.setForeground(Theme.FG_INPUT);
                    } else {
                        c.setBackground(Theme.levelRowBg(lv));
                        // 等级列本来是白字，但要能看出等级 —— 用带色文字更清楚
                        c.setForeground(column == 0 ? Theme.levelColor(lv) : Theme.FG_TEXT);
                    }
                }
            } catch (Throwable ignored) {
                // 着色失败退回默认 —— 绝不让渲染异常毁掉整个表
            }
            return c;
        }
    }

    private static LocalRules.Level levelOf(com.packetsentry.core.Finding f) {
        for (LocalRules.Level lv : LocalRules.Level.values()) {
            if (lv.label.equals(f.level)) {
                return lv;
            }
        }
        return LocalRules.Level.NONE;
    }

    // ==================================================================
    // 批量越权测试
    // ==================================================================

    /**
     * 批量越权 —— 一次测一组接口。
     *
     * <h3>▲ 为什么默认只测只读方法</h3>
     * 用身份 B 的凭据重放身份 A 的 {@code POST /order/create}，
     * 如果服务端真的执行了 —— <b>那就是真的下了一单</b>。
     * 那不是「证明漏洞」，那是「造成业务影响」，SRC 明令禁止。
     *
     * <p>所以默认只跑 GET / HEAD / OPTIONS。写操作要用户显式确认两次。
     */
    private void runBatchAccessControl() {
        Config cfg = configSupplier.get();
        if (cfg.identities == null || cfg.identities.size() < 2) {
            pinDetail("══════════ 批量越权 ══════════\n\n"
                    + "至少需要 2 个身份：一个基线（你当前登录的账号）、\n"
                    + "一个测试身份（另一个普通账号）。\n\n"
                    + "到「设置」页 → 越权测试 → 添加身份。\n"
                    + "每个身份填该账号的 Cookie 或 Authorization 头。");
            return;
        }
        if (callbacks == null) {
            pinDetail("当前环境没有 Burp callbacks，无法发包。");
            return;
        }

        Object baseSel = javax.swing.JOptionPane.showInputDialog(this,
                "选一个基线身份（通常是当前登录的账号）：",
                "批量越权 · 第 1 步", javax.swing.JOptionPane.QUESTION_MESSAGE,
                null, cfg.identities.toArray(), cfg.identities.get(0));
        if (baseSel == null) {
            return;
        }
        Identity baseline = (Identity) baseSel;

        List<Identity> others = new ArrayList<>();
        for (Identity id : cfg.identities) {
            if (id != baseline) {
                others.add(id);
            }
        }
        if (others.isEmpty()) {
            pinDetail("没有其它身份可作测试用。");
            return;
        }
        Object testSel = javax.swing.JOptionPane.showInputDialog(this,
                "选一个测试身份（另一个账号，用来验证能不能拿到它的数据）：",
                "批量越权 · 第 2 步", javax.swing.JOptionPane.QUESTION_MESSAGE,
                null, others.toArray(), others.get(0));
        if (testSel == null) {
            return;
        }
        Identity testId = (Identity) testSel;

        String host = selectedHost();
        AccessControlBatch.Options opts = new AccessControlBatch.Options();
        opts.baseline = baseline;
        opts.testIdentities = new ArrayList<>();
        opts.testIdentities.add(testId);
        opts.intervalMs = Math.max(400, cfg.acMinIntervalMs);

        List<AccessControlBatch.Target> targets = AccessControlBatch.selectTargets(
                pipe.snapshot(), host, opts);

        if (targets.isEmpty()) {
            pinDetail("目标域名：" + (host == null ? "(全部)" : host) + "\n\n"
                    + "没有可测试的接口。\n\n"
                    + "至少要满足：已抓到请求原文 + 有 service 信息（能确定目标主机）。\n"
                    + "先去目标站走一遍，再回来。");
            return;
        }

        int unsafeCount = 0;
        for (AccessControlBatch.Target t : targets) {
            if (!t.isSafeMethod()) {
                unsafeCount++;
            }
        }

        StringBuilder warn = new StringBuilder();
        warn.append(AccessControlBatch.describePlan(targets, opts));
        warn.append("\n关于「自动化」的说明：\n");
        warn.append("  本功能只原样重放你已经发过的请求，不改参数、不注入 payload，\n");
        warn.append("  用的是你自己账号的凭据。这区别于扫描器（sqlmap/xray 那类）。\n");
        warn.append("  但仍请确认目标平台规则允许，并保持保守速率。\n");
        if (unsafeCount > 0) {
            warn.append("\n★ 检测到 ").append(unsafeCount).append(" 个写操作接口，默认跳过。\n");
            warn.append("   原因：用另一个身份的凭据重放 POST/PUT/DELETE，\n");
            warn.append("   如果服务端真的执行了 —— 那是真的改了数据，不是证明漏洞。\n");
        }
        warn.append("\n开始测试？");

        int go = javax.swing.JOptionPane.showConfirmDialog(this, warn.toString(),
                "批量越权确认", javax.swing.JOptionPane.OK_CANCEL_OPTION,
                javax.swing.JOptionPane.WARNING_MESSAGE);
        if (go != javax.swing.JOptionPane.OK_OPTION) {
            pinDetail("已取消批量越权测试。");
            return;
        }

        boolean allowUnsafe = false;
        if (unsafeCount > 0) {
            int go2 = javax.swing.JOptionPane.showConfirmDialog(this,
                    "确定要测试这 " + unsafeCount + " 个写操作接口吗？\n\n"
                            + "▲ 用另一个身份的凭据重放写操作，"
                            + "如果服务端没有做权限校验，\n"
                            + "这个操作会真的被执行（下单、删除、改配置…）。\n\n"
                            + "建议：先在只读接口上确认越权存在，写操作留到最后手工测。\n\n"
                            + "仍然要测吗？",
                    "▲ 写操作确认（第二次）",
                    javax.swing.JOptionPane.YES_NO_OPTION,
                    javax.swing.JOptionPane.ERROR_MESSAGE);
            allowUnsafe = go2 == javax.swing.JOptionPane.YES_OPTION;
        }
        opts.allowUnsafeMethods = allowUnsafe;
        opts.maxRequests = 200;

        pinDetail("══════════ 批量越权（进行中）══════════\n\n"
                + "基线身份：" + baseline.name + "\n"
                + "测试身份：" + testId.name + "\n"
                + "接口数：" + targets.size() + "\n"
                + "速率：" + opts.intervalMs + " ms/次\n"
                + (allowUnsafe ? "\n★ 包含写操作 —— 请盯着进度\n" : "\n（只测只读方法）\n")
                + "\n正在发送…");
        statusLabel.setText(" 批量越权中…");

        final AccessControlBatch batch = new AccessControlBatch(callbacks);
        final AccessControlBatch.Options optsFinal = opts;
        final List<AccessControlBatch.Target> targetsFinal = targets;
        final Identity testIdentity = testId;

        Thread t = new Thread(() -> {
            AccessControlBatch.Outcome oc;
            try {
                oc = batch.run(targetsFinal, optsFinal, (done, total, cur) ->
                        SwingUtilities.invokeLater(() -> statusLabel.setText(
                                " 批量越权 " + done + "/" + total + "　" + cur)));
            } catch (Throwable e) {
                SwingUtilities.invokeLater(() -> pinDetail(
                        "批量越权出错：" + e + "\n\n已发送的请求无法撤回，"
                                + "但也不会造成额外影响（都是原样重放）。"));
                return;
            }
            final AccessControlBatch.Outcome ocFinal = oc;
            SwingUtilities.invokeLater(() -> {
                // ★ 疑似越权直接写进发现清单 —— 那才是 SRC 的产物
                int added = 0;
                for (AccessControlBatch.Hit h : ocFinal.hits) {
                    com.packetsentry.core.Finding fd = com.packetsentry.core.Finding.from(
                            h.record.method, h.record.host, h.record.path,
                            "(整条请求)", "疑似越权 · " + testIdentity.name,
                            LocalRules.Level.HIGH,
                            h.result.summaryLine(),
                            PlatformRules.Decision.UNKNOWN, LocalRules.Level.HIGH.label);
                    if (ledger.upsert(fd)) {
                        added++;
                    }
                }
                if (added > 0) {
                    ledger.save();
                }
                pinDetail(ocFinal.render()
                        + (added > 0
                        ? "\n\n已写入发现清单 " + added + " 条（状态：待验证）。\n"
                        + "点「★ 发现清单」查看。\n"
                        + "★ 记住：清单里的是候选 —— 要人工看一眼响应里"
                        + "到底有没有属于别人的数据，再标成「已验证」。"
                        : "\n\n（没有新增发现）"));
                refreshStatus();
            });
        }, "packetsentry-ac-batch");
        t.setDaemon(true);
        t.start();
    }

    // ==================================================================
    // CVE × 资产匹配
    // ==================================================================

    /**
     * 组件指纹 × CVE × 资产。
     *
     * <p>插件做纯观测：从已抓流量里提取组件版本，把同指纹资产归组。
     * CVE 区间由用户核实填写 —— 不内置 CVE 库，因为版本区间写错
     * 会直接导致一次错误的报告提交，代价比没有这个功能更大。
     *
     * <h3>▲ 扫描必须在后台线程做</h3>
     * 这一处踩过坑：原来整个扫描直接写在按钮回调里，也就是<b>跑在 EDT 上</b>。
     * 实测单次提取开销随响应大小线性上升（195KB 要 39.6 ms），
     * 而代码是对<b>每一个已抓响应</b>各调一次：
     * <pre>
     *   1000 个 50KB 响应 → 20.1 秒
     *   5000 个包         → 约 49 秒
     *   10000 个包        → 约 97 秒
     * </pre>
     * 界面会整整冻死这么久 —— 而这类「功能正常但会冻界面」的缺陷，
     * 纯功能测试永远抓不到，只有压测才发现。
     *
     * <p>现在：先在后台线程扫完，再回 EDT 弹窗。
     */
    private void showCveMatch() {
        String host = selectedHost();
        final List<PacketRecord> snap = pipe.snapshot();

        pinDetail("══════════ CVE × 资产匹配 ══════════\n\n"
                + "目标域名：" + (host == null ? "(全部)" : host) + "\n"
                + "已抓记录：" + snap.size() + " 条\n\n"
                + "正在后台提取组件指纹…\n"
                + "（扫描在后台线程做，抓包多也不会卡界面）");

        Thread t = new Thread(() -> {
            com.packetsentry.vuln.ComponentIndex index =
                    new com.packetsentry.vuln.ComponentIndex();
            int fed = 0;
            int skipped = 0;
            for (PacketRecord r : snap) {
                if (r.rawResponse == null || r.rawResponse.length == 0) {
                    continue;
                }
                if (host != null && !host.isEmpty()
                        && (r.host == null || !r.host.equalsIgnoreCase(host))) {
                    continue;
                }
                String resp = new String(r.rawResponse,
                        java.nio.charset.StandardCharsets.UTF_8);
                // 廉价预筛：图片/字体/视频不可能含组件指纹
                if (!com.packetsentry.vuln.ComponentIndex.worthScanning(resp)) {
                    skipped++;
                    continue;
                }
                index.feed(r.host, resp);
                fed++;
            }
            final int fedFinal = fed;
            final int skippedFinal = skipped;
            final com.packetsentry.vuln.ComponentIndex idxFinal = index;
            SwingUtilities.invokeLater(() -> showCveResult(idxFinal, fedFinal,
                    skippedFinal, host));
        }, "packetsentry-cve-scan");
        t.setDaemon(true);
        t.start();
    }

    /** 扫描完成后在 EDT 上展示结果。 */
    private void showCveResult(com.packetsentry.vuln.ComponentIndex index,
                               int fed, int skipped, String host) {
        if (fed == 0) {
            pinDetail("没有可分析的响应。\n\n"
                    + "目标域名：" + (host == null ? "(全部)" : host) + "\n"
                    + "跳过的非文本响应：" + skipped + " 个"
                    + "（图片/字体/视频等，不可能含组件指纹）\n\n"
                    + "先去目标站走一遍，再回来。");
            return;
        }

        com.packetsentry.vuln.CveLedger cve = new com.packetsentry.vuln.CveLedger();
        List<com.packetsentry.vuln.CveLedger.Match> ms = cve.match(index);

        String summary = cve.oneLine()
                + "　命中 " + ms.size() + " 个 CVE\n"
                + index.groupCount() + " 个组件组 / "
                + index.hostCount() + " 个资产\n"
                + "已扫描 " + fed + " 个响应（0 网络请求）"
                + (skipped > 0 ? "，跳过 " + skipped + " 个非文本响应" : "");

        String body = ms.isEmpty()
                ? (cve.size() == 0 ? index.render()
                : cve.renderMatches(index) + "\n\n" + index.render())
                : cve.renderMatches(index);

        Object[] options = {"添加 CVE 规则", "查看组件指纹", "关闭"};
        int c = javax.swing.JOptionPane.showOptionDialog(this,
                new Object[]{new javax.swing.JLabel(htmlWrap(summary)),
                        new javax.swing.JScrollPane(textArea(body, 800, 430))},
                "CVE × 资产匹配",
                javax.swing.JOptionPane.DEFAULT_OPTION,
                javax.swing.JOptionPane.PLAIN_MESSAGE, null, options, options[2]);
        if (c == 0) {
            addCveRule(index, cve);
        } else if (c == 1) {
            pinDetail(index.render());
        }
    }

    /** 加一条 CVE 规则。 */
    private void addCveRule(com.packetsentry.vuln.ComponentIndex index,
                            com.packetsentry.vuln.CveLedger cve) {
        List<com.packetsentry.vuln.ComponentIndex.Group> groups = index.all();
        if (groups.isEmpty()) {
            pinDetail("没有提取到组件指纹，无法添加规则。");
            return;
        }
        Object compSel = javax.swing.JOptionPane.showInputDialog(this,
                "选组件（这些是从你的流量里实际提取到的，选它可避免名字拼错）：",
                "添加 CVE 规则 · 1/5", javax.swing.JOptionPane.QUESTION_MESSAGE,
                null, groups.toArray(), groups.get(0));
        if (compSel == null) {
            return;
        }
        String component = ((com.packetsentry.vuln.ComponentIndex.Group) compSel).name;

        Object opSel = javax.swing.JOptionPane.showInputDialog(this, "版本条件：",
                "添加 CVE 规则 · 2/5", javax.swing.JOptionPane.QUESTION_MESSAGE,
                null, com.packetsentry.vuln.CveLedger.Op.values(),
                com.packetsentry.vuln.CveLedger.Op.LT);
        if (opSel == null) {
            return;
        }
        com.packetsentry.vuln.CveLedger.Op op =
                (com.packetsentry.vuln.CveLedger.Op) opSel;

        String ver = javax.swing.JOptionPane.showInputDialog(this,
                "版本号（例如 1.20.1）\n\n"
                        + "▲ 这个区间要你自己核实 —— 去 NVD / 组件官方公告确认。\n"
                        + "插件不内置 CVE 库，正是为了避免我记错区间导致你错误提交。",
                "");
        if (ver == null || ver.trim().isEmpty()) {
            return;
        }
        String ver2 = "";
        if (op == com.packetsentry.vuln.CveLedger.Op.RANGE) {
            ver2 = javax.swing.JOptionPane.showInputDialog(this, "区间上界版本：", "");
            if (ver2 == null) {
                return;
            }
        }

        String cveId = javax.swing.JOptionPane.showInputDialog(this,
                "CVE 编号（例如 CVE-2021-23017）：", "CVE-");
        if (cveId == null || cveId.trim().isEmpty()) {
            return;
        }

        com.packetsentry.vuln.CveLedger.Rule r =
                new com.packetsentry.vuln.CveLedger.Rule();
        r.component = component;
        r.op = op.symbol;
        r.version = ver.trim();
        r.version2 = ver2 == null ? "" : ver2.trim();
        r.cveId = cveId.trim().toUpperCase();
        r.title = nvl(javax.swing.JOptionPane.showInputDialog(this,
                "一句话说明（建议写 —— 报告里要用）：", ""));
        r.severity = nvl(javax.swing.JOptionPane.showInputDialog(this,
                "严重度（可留空；如 High / 高危）：", ""));
        r.refUrl = nvl(javax.swing.JOptionPane.showInputDialog(this,
                "参考链接（建议填 NVD 或官方公告）：", ""));

        cve.add(r);
        String err = cve.save();
        if (!err.isEmpty()) {
            pinDetail("规则保存失败：" + err);
            return;
        }
        pinDetail("══════════ CVE 规则已保存 ══════════\n\n"
                + r + "\n\n台账文件：" + cve.file() + "\n\n"
                + cve.renderMatches(index));
    }

    private static String nvl(String s) {
        return s == null ? "" : s.trim();
    }

    /** 只读文本域 + 滚动。 */
    private static javax.swing.JTextArea textArea(String text, int w, int h) {
        javax.swing.JTextArea a = new javax.swing.JTextArea(text);
        a.setEditable(false);
        a.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
        a.setCaretPosition(0);
        a.setPreferredSize(new java.awt.Dimension(w, h));
        Theme.apply(a);
        return a;
    }

    private static String htmlWrap(String s) {
        return "<html><body style='width:640px;font-family:monospace'>"
                + s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\n", "<br>")
                + "</body></html>";
    }

    // ==================================================================
    // 宏观：业务地图
    // ==================================================================

    /**
     * 展示业务地图。
     *
     * @param useAi true 表示把地图发给 AI 做业务逻辑推断（一次调用），
     *              false 表示只本地展示
     */
    private void showBusinessMap(boolean useAi) {
        String host = selectedHost();
        LocalRules.BusinessMap map = pipe.buildBusinessMap(host);

        if (map.entries.isEmpty()) {
            detail.setText("该域名下还没有可分析的接口（静态资源不计入业务地图）。");
            return;
        }

        String localView = renderBusinessMap(map);

        if (!useAi) {
            detail.setText(localView);
            detail.setCaretPosition(0);
            return;
        }

        Config cfg = configSupplier.get();
        String promptText = map.toPromptText();
        int inTokens = CostTracker.estimateTokens(promptText);
        double per = cost.estimatePerPacketCny(300, inTokens, 1500);

        detail.setText("═══ 本地业务地图 ═══\n" + localView
                + "\n\n正在请 AI 做业务逻辑推断…（" + cfg.describeDestination()
                + "，输入约 " + inTokens + " tokens，预估 ¥"
                + String.format("%.4f", per) + "）");
        detail.setCaretPosition(0);
        statusLabel.setText(" AI 业务逻辑分析中…（" + cfg.describeDestination() + "）");

        Thread t = new Thread(() -> {
            LlmClient.Reply reply = llm.chat(cfg, MACRO_PROMPT, promptText);
            SwingUtilities.invokeLater(() -> {
                if (reply.ok) {
                    cost.recordCall(MACRO_PROMPT, promptText, reply.content);
                    pinDetail("═══ AI 业务逻辑分析 ═══\n"
                            + "目标 " + map.host + "　接口 " + map.entries.size() + " 个　"
                            + "HTTP " + reply.httpStatus + "　" + reply.elapsedMs + " ms　"
                            + "预估 ¥" + String.format("%.4f", per) + "\n\n"
                            + reply.content
                            + "\n\n───────────────────────────\n"
                            + "═══ 本地业务地图（判定依据）═══\n" + localView);
                    detail.setCaretPosition(0);
                    refreshStatus();
                } else {
                    detail.setText("═══ 本地业务地图 ═══\n" + localView
                            + "\n\nAI 分析失败：" + reply.error);
                    detail.setCaretPosition(0);
                }
            });
        }, "packetsentry-macro");
        t.setDaemon(true);
        t.start();
    }

    private String renderBusinessMap(LocalRules.BusinessMap map) {
        StringBuilder sb = new StringBuilder();
        sb.append("目标域名：").append(map.host).append('\n');
        sb.append("接口数量：").append(map.entries.size()).append("（已排除静态资源）\n\n");

        sb.append("业务模块分布：\n");
        for (java.util.Map.Entry<String, Integer> kv : map.byPurpose.entrySet()) {
            sb.append("  ").append(pad(kv.getKey(), 14))
                    .append(kv.getValue()).append(" 个接口\n");
        }

        sb.append("\n接口清单：\n");
        sb.append(String.format("  %-7s %-40s %-14s %-6s %s%n",
                "方法", "路径", "作用", "次数", "本地发现"));
        sb.append("  ").append("-".repeat(100)).append('\n');
        for (LocalRules.BusinessMap.Entry e : map.entries) {
            sb.append(String.format("  %-7s %-40s %-14s %-6s %s%n",
                    e.method,
                    truncate(e.pathTemplate, 40),
                    truncate(e.purpose, 14),
                    e.count > 1 ? ("×" + e.count) : "",
                    "无".equals(e.issues) ? "" : e.issues));
        }

        // 汇总
        int withIssues = 0;
        for (LocalRules.BusinessMap.Entry e : map.entries) {
            if (!"无".equals(e.issues)) {
                withIssues++;
            }
        }
        sb.append("\n汇总：").append(map.entries.size()).append(" 个接口，其中 ")
                .append(withIssues).append(" 个有本地检出的问题\n");
        return sb.toString();
    }

    private static String pad(String s, int n) {
        StringBuilder b = new StringBuilder(s == null ? "" : s);
        while (b.length() < n) {
            b.append(' ');
        }
        return b.toString();
    }

    private static String truncate(String s, int n) {
        if (s == null) {
            return "";
        }
        return s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }

    // ==================================================================
    // 越权测试（主动发包）
    // ==================================================================

    /** 从配置刷新身份下拉框。设置页改完配置后需要重新调用。 */
    public void refreshIdentities() {
        String sel = (String) identityBox.getSelectedItem();
        identityBox.removeAllItems();
        Config cfg = configSupplier.get();
        if (cfg.identities == null || cfg.identities.isEmpty()) {
            identityBox.addItem("(未配置身份)");
            identityBox.setEnabled(false);
            return;
        }
        identityBox.setEnabled(true);
        for (Identity id : cfg.identities) {
            identityBox.addItem(id.name == null ? "(未命名)" : id.name);
        }
        if (sel != null) {
            identityBox.setSelectedItem(sel);
        }
    }

    private Identity selectedIdentity() {
        Config cfg = configSupplier.get();
        if (cfg.identities == null || cfg.identities.isEmpty()) {
            return null;
        }
        int i = identityBox.getSelectedIndex();
        if (i < 0 || i >= cfg.identities.size()) {
            return null;
        }
        return cfg.identities.get(i);
    }

    /**
     * 越权测试 —— <b>会向目标发送额外请求</b>，所以每一步都要用户确认。
     *
     * <p>安全约束（硬性）：
     * <ol>
     *   <li>必须配置了身份才可用</li>
     *   <li>每次执行前弹窗确认，并显示「将向 host 发送 1 个请求」</li>
     *   <li>未在设置页确认过「会主动发包」时，先要求确认</li>
     *   <li>发包有最小间隔，不轰目标</li>
     * </ol>
     */
    // ==================================================================
    // 代码审计
    // ==================================================================

    /**
     * 审计选中响应的前端代码。
     *
     * <p>结论分三态 —— 这是本功能的关键设计：
     * <ul>
     *   <li><b>有发现</b> —— 挖到了密钥 / 危险 DOM / 接口路径 / 注释线索等</li>
     *   <li><b>有可能</b> —— 没挖到具体东西，但存在可攻击面，列出值得试的方向</li>
     *   <li><b>无</b> —— 连可能性都没有（纯图片/二进制），明确说「无」</li>
     * </ul>
     * 只报「有 / 没有」会让人误以为「没报就是安全」。
     */
    // ==================================================================
    // 审计该域名（纯本地，0 网络请求）
    // ==================================================================
    // 隐藏入口审计（纯本地，0 网络请求）
    // ==================================================================
    // 反射与上下文检测（纯本地，0 网络请求，不下发 payload）
    // ==================================================================

    /**
     * 找出参数值被回显到哪里，以及落在什么上下文。
     *
     * <h3>▲ 这个功能不下发 payload，所以不能确认 XSS</h3>
     * 它做的是另一半，也是更难的一半：<b>判断输入落在什么上下文</b>。
     * 上下文决定该用哪种注入形式 —— 形式选错，payload 再花哨也不会执行。
     *
     * <p>对每个反射点，它会给出：
     * <ol>
     *   <li>上下文（HTML 文本 / 属性内 / JS 字符串内 / script 块内 / 注释内 …）</li>
     *   <li><b>该发什么探针</b>去测「哪些字符没被转义」</li>
     *   <li>确认可注入后<b>该用哪种形式</b>（首选 + 备选）</li>
     * </ol>
     *
     * <h3>★ 关于「转义情况」的诚实边界</h3>
     * 只有观察到的参数值本身含 {@code < > " ' &} 时，才看得出服务端有没有转义。
     * 否则就是「未知」—— 不能猜，更不能让用户以为「没看到转义就是没转义」。
     */
    private void auditReflection() {
        String host = selectedHost();
        List<PacketRecord> all = pipe.snapshot();
        ReflectionAudit audit = new ReflectionAudit();
        List<ReflectionAudit.Hit> hits = new ArrayList<>();

        int audited = 0;
        for (PacketRecord r : all) {
            if (host != null && (r.host == null || !r.host.equalsIgnoreCase(host))) {
                continue;
            }
            if (r.rawRequest == null || r.rawResponse == null) {
                continue;
            }
            String mime = r.mimeType == null ? "" : r.mimeType.toLowerCase();
            boolean looksTextual = mime.contains("html") || mime.contains("json")
                    || mime.contains("xml") || mime.contains("javascript")
                    || mime.contains("text/");
            if (!looksTextual) {
                continue;
            }
            audit.check(new String(r.rawRequest, java.nio.charset.StandardCharsets.UTF_8),
                    new String(r.rawResponse, java.nio.charset.StandardCharsets.UTF_8), hits);
            audited++;
        }

        if (audited == 0) {
            pinDetail("没有可分析的响应。\n\n"
                    + "目标域名：" + (host == null ? "(全部)" : host) + "\n"
                    + "已抓记录：" + all.size() + " 条\n\n"
                    + "先在目标站里正常走一遍（带参数访问几个页面、提交几个表单），\n"
                    + "让请求和响应经过代理，再回来点这个按钮。");
            return;
        }

        pinDetail(ReflectionAudit.render(hits, audited));
    }
    // ==================================================================

    /**
     * 找「页面上没有入口，但代码里还在」的路由。
     *
     * <h3>针对的场景</h3>
     * 登录页早就没有了注册按钮，但开发只是把按钮<b>注释掉</b>，
     * 路由和页面都还在 —— 直接敲 URL 依然能进。
     * 这在 SRC 里叫「隐藏接口 / 未授权功能暴露」，是可提交的真实问题。
     *
     * <h3>▲ 前提：这审计的是<b>前端</b>代码</h3>
     * 网站主动把 JS/HTML 发给浏览器，所以前端代码本来就在手里，
     * 「审计」它不涉及逆向。<b>后端源码从流量里拿不到</b> ——
     * 除非网站自己泄露（.git / 备份 / Source Map），那时会单独提示。
     *
     * <h3>▲ 0 网络请求</h3>
     * 只分析已经抓到的响应，不会主动去请求任何东西。
     */
    private void auditRoutes() {
        final String host = selectedHost();
        final List<PacketRecord> all = pipe.snapshot();

        // ▲ 后台线程：实测 800 条记录要 5.3 秒，跑在 EDT 上就是界面冻 5 秒。
        //    按 2000 个包外推约 13 秒。这里只把<b>结果字符串</b>算好，
        //    再由 invokeLater 回 EDT 显示 —— pinDetail 只能在 EDT 上调。
        pinDetail("══════════ 隐藏入口审计 ══════════\n\n"
                + "目标域名：" + (host == null ? "(全部)" : host) + "\n"
                + "已抓记录：" + all.size() + " 条\n\n"
                + "正在后台审计…（扫描本地缓存的 JS/HTML，0 网络请求）");

        Thread t = new Thread(() -> {
            RouteAudit audit = new RouteAudit();
            RouteAudit.Result result = new RouteAudit.Result();
            int fed = 0;
            for (PacketRecord r : all) {
                if (host != null && (r.host == null || !r.host.equalsIgnoreCase(host))) {
                    continue;
                }
                String mime = r.mimeType == null ? "" : r.mimeType.toLowerCase();
                boolean interesting = mime.contains("javascript") || mime.contains("html")
                        || mime.contains("json") || mime.contains("xml");
                // 有些站点 Content-Type 不准，按路径再兜一层
                if (!interesting && r.path != null) {
                    String p = r.path.toLowerCase();
                    interesting = p.endsWith(".js") || p.endsWith(".html")
                            || p.endsWith("/") || !p.contains(".");
                }
                if (!interesting || r.rawResponse == null) {
                    continue;
                }
                audit.feed(r.path, new String(r.rawResponse,
                        java.nio.charset.StandardCharsets.UTF_8), result);
                fed++;
            }

            if (fed == 0) {
                final int total = all.size();
                SwingUtilities.invokeLater(() -> pinDetail("没有可审计的内容。\n\n"
                        + "目标域名：" + (host == null ? "(全部)" : host) + "\n"
                        + "已抓记录：" + total + " 条\n\n"
                        + "先在目标站里正常浏览一遍（登录、点几个菜单），让 JS/HTML 经过代理，\n"
                        + "再回来点这个按钮。"));
                return;
            }

            audit.finish(result);
            final String out = RouteAudit.render(result);
            SwingUtilities.invokeLater(() -> pinDetail(out));
        }, "packetsentry-route-audit");
        t.setDaemon(true);
        t.start();
    }
    // ==================================================================

    /**
     * 审计该域名<b>已抓到</b>的所有 JS / HTML。
     *
     * <h3>▲ 这个功能发送 0 个网络请求</h3>
     * 它只是把 {@link RealtimePipe} 里已经缓存的响应挑出来做本地字符串分析。
     * <b>不会去主动抓取任何东西</b> —— 所以不会触发云 WAF / IDS，
     * 也不会给目标增加任何流量。
     *
     * <p>这是刻意的设计：很多工具的「审计该域名」是爬虫，会主动请求目标域名的
     * JS 文件，那必然在 WAF 日志里留下一串请求。这里不这么做 ——
     * 你浏览过什么，就审计什么。
     */
    private void auditDomain() {
        String host = selectedHost();
        List<PacketRecord> all = pipe.snapshot();
        List<PacketRecord> targets = new ArrayList<>();
        for (PacketRecord r : all) {
            if (host != null && (r.host == null || !r.host.equalsIgnoreCase(host))) {
                continue;
            }
            // 只看可审计的内容类型
            String mime = r.mimeType == null ? "" : r.mimeType.toLowerCase();
            if (mime.contains("javascript") || mime.contains("html") || mime.contains("json")
                    || mime.contains("xml") || mime.contains("css")) {
                targets.add(r);
            }
        }
        if (targets.isEmpty()) {
            pinDetail("没有可审计的内容。\n\n"
                    + "目标域名：" + (host == null ? "(全部)" : host) + "\n"
                    + "已抓记录：" + all.size() + " 条\n\n"
                    + "「审计该域名」只审计<b>已经抓到</b>的 JS/HTML/JSON 响应，\n"
                    + "不会主动去请求目标 —— 所以先正常浏览一遍目标站，再回来点这个按钮。");
            return;
        }

        // ▲ 后面这段必须放后台线程。
        //    实测 800 条记录要 11.7 秒 —— 跑在 EDT 上就是点一下
        //    「审计该域名」，Burp 彻底冻死近 12 秒（2000 个包约 29 秒）。
        //    上面挑 targets 的循环很便宜（只比 mime 字符串），留在 EDT 没关系。
        final List<PacketRecord> targetsF = targets;
        final int totalCount = all.size();
        pinDetail("══════════ 域名代码审计 ══════════\n\n"
                + "目标域名：" + (host == null ? "(全部)" : host) + "\n"
                + "审计对象：" + targets.size() + " 个响应\n"
                + "网络请求：0 个（纯本地分析，不会触发 WAF）\n\n"
                + "正在后台审计…");

        Thread t = new Thread(() -> {

        StringBuilder sb = new StringBuilder();
        sb.append("══════════ 域名代码审计 ══════════\n");
        sb.append("目标域名  ").append(host == null ? "(全部)" : host).append('\n');
        sb.append("审计对象  ").append(targetsF.size()).append(" 个响应\n");
        sb.append("网络请求  ").append("0 个").append("　（纯本地分析，不会触发 WAF）\n\n");

        int found = 0;
        int possible = 0;
        int nothing = 0;
        java.util.Map<String, Integer> byCategory = new java.util.LinkedHashMap<>();
        List<String> highlights = new ArrayList<>();

        for (PacketRecord r : targetsF) {
            String respRaw = r.rawResponse == null ? "" : new String(r.rawResponse,
                    java.nio.charset.StandardCharsets.UTF_8);
            String reqRaw = r.rawRequest == null ? "" : new String(r.rawRequest,
                    java.nio.charset.StandardCharsets.UTF_8);
            CodeAudit.Result a = codeAudit.audit(reqRaw, respRaw);
            switch (a.verdict) {
                case FOUND:
                    found++;
                    break;
                case POSSIBLE:
                    possible++;
                    break;
                default:
                    nothing++;
            }
            for (CodeAudit.Finding fd : a.findings) {
                byCategory.merge(fd.level.label + "危 " + fd.category, 1, Integer::sum);
                if (highlights.size() < 40) {
                    highlights.add("[" + fd.level.label + "] " + fd.category + "　"
                            + r.method + " " + r.path + "\n      "
                            + CodeAudit.truncate(fd.detail, 120)
                            + (fd.evidence == null || fd.evidence.isEmpty() ? ""
                            : "\n      证据 " + fd.evidence));
                }
            }
        }

        sb.append("── 结论分布 ──\n");
        sb.append("  ★ 有发现 ").append(found).append(" 个\n");
        sb.append("  ☆ 有可能 ").append(possible).append(" 个\n");
        sb.append("  ○ 无     ").append(nothing).append(" 个\n\n");

        if (!byCategory.isEmpty()) {
            sb.append("── 按类别汇总 ──\n");
            for (java.util.Map.Entry<String, Integer> e : byCategory.entrySet()) {
                sb.append("  ").append(e.getKey()).append("　×").append(e.getValue()).append('\n');
            }
            sb.append('\n');
        }

        if (!highlights.isEmpty()) {
            sb.append("── 发现明细 ──\n");
            for (String h : highlights) {
                sb.append("  · ").append(h).append('\n');
            }
            sb.append('\n');
        }

        sb.append("提示：\n");
        sb.append("  · 本按钮<b>没有向目标发送任何请求</b> —— 你浏览过什么就审计什么。\n");
        sb.append("  · 想审计更多内容？先在目标站里多点几个页面，让流量经过代理。\n");
        sb.append("  · 「有发现」里的接口路径，可以直接送 Repeater 逐个访问。\n");

        // 回到 EDT 再显示 —— pinDetail 触碰 Swing 组件，只能在 EDT 上调
        final String out = sb.toString();
        SwingUtilities.invokeLater(() -> pinDetail(out));

        }, "packetsentry-domain-audit");
        t.setDaemon(true);
        t.start();
    }

    // ==================================================================
    // OWASP Top 10 覆盖度
    // ==================================================================

    /**
     * 显示 OWASP Top 10 的真实覆盖度。
     *
     * <p>刻意<b>不做</b>「已覆盖全部」这种表述 —— 被动观察结构上就看不到
     * 注入 / SSRF / 日志监控这三类。明确标出来，用户才知道该用什么别的办法。
     */
    private void showOwasp() {
        List<PacketRecord> all = pipe.snapshot();
        List<OwaspTop10.Category> cats = OwaspTop10.evaluate(all);
        pinDetail(OwaspTop10.render(cats, all.size()));
    }
    private void runCodeAudit() {
        PacketRecord r = selected();
        if (r == null) {
            pinDetail("请先在列表里选一个包。");
            return;
        }
        String reqRaw = r.rawRequest == null ? "" : new String(r.rawRequest,
                java.nio.charset.StandardCharsets.UTF_8);
        String respRaw = r.rawResponse == null ? "" : new String(r.rawResponse,
                java.nio.charset.StandardCharsets.UTF_8);

        lastAudit = codeAudit.audit(reqRaw, respRaw);
        // ▲ 必须同时记下来源包 —— 否则「生成报告」时无法判断
        //    这份审计结论到底属不属于当前选中的包（会张冠李戴）。
        lastAuditSig = r.signature;

        StringBuilder sb = new StringBuilder();
        sb.append("══════════ 代码审计 ══════════\n");
        sb.append("目标    ").append(r.method).append(' ').append(r.host).append(r.path).append('\n');
        sb.append("类型    ").append(lastAudit.contentType.isEmpty() ? "(未知)"
                : lastAudit.contentType).append("　审计 ")
                .append(lastAudit.auditedBytes).append(" 字节\n");
        sb.append("结论    ").append(lastAudit.verdict.label).append('\n');
        if (lastAudit.nothingReason != null) {
            sb.append("说明    ").append(lastAudit.nothingReason).append('\n');
        }
        sb.append('\n');

        if (!lastAudit.findings.isEmpty()) {
            sb.append("── 发现 ──\n");
            for (CodeAudit.Finding f : lastAudit.findings) {
                sb.append("  [").append(f.level.label).append("] ").append(f.category).append('\n');
                sb.append("      ").append(f.detail).append('\n');
                if (f.evidence != null && !f.evidence.isEmpty()) {
                    sb.append("      证据   ").append(f.evidence).append('\n');
                }
                if (f.nextStep != null && !f.nextStep.isEmpty()) {
                    sb.append("      下一步 ").append(f.nextStep).append('\n');
                }
                sb.append('\n');
            }
        }

        if (!lastAudit.hypotheses.isEmpty()) {
            sb.append("── 没挖到具体问题，但值得尝试 ──\n");
            for (String h : lastAudit.hypotheses) {
                sb.append("  · ").append(h).append('\n');
            }
            sb.append('\n');
        }

        sb.append("提示：审计结论分三态 ——\n");
        sb.append("  ★ 有发现 = 挖到了具体东西\n");
        sb.append("  ☆ 有可能 = 没挖到，但存在可攻击面（上面列了试的方向）\n");
        sb.append("  ○ 无     = 连可能性都没有（纯静态内容）\n");
        sb.append("「无」不等于「安全」，只表示这类内容里没有可挖的东西。\n");

        pinDetail(sb.toString());
    }

    // ==================================================================
    // 漏洞报告生成
    // ==================================================================

    /**
     * 生成漏洞报告。
     *
     * <p>流程刻意做成「本地出骨架，AI 补表述」：
     * URL、参数、本地结论、审计证据这些<b>事实只能来自本地</b>，不能靠 AI 编。
     * AI 只负责「危害说明 / 渗透路径补充 / 修复建议」。
     * 这样即使 AI 不可用，报告仍可用（表述部分标注待补）。
     */
    private void generateReport() {
        Config cfg = configSupplier.get();

        List<PacketRecord> targets = new java.util.ArrayList<>();
        int[] rows = table.getSelectedRows();
        if (rows != null && rows.length > 0) {
            for (int v : rows) {
                targets.add(model.get(table.convertRowIndexToModel(v)));
            }
        } else {
            for (int v = 0; v < table.getRowCount(); v++) {
                targets.add(model.get(table.convertRowIndexToModel(v)));
            }
        }
        if (targets.isEmpty()) {
            pinDetail("没有可生成报告的内容 —— 先在列表里选中一行或几行。");
            return;
        }

        String skeleton = reportGen.buildSkeleton(targets, cfg);

        // ▲ 这个判断改过一版，修的是一个「报告张冠李戴」的 bug。
        //
        //    原来只判断 lastAudit != null 就把它拼进报告，措辞还是
        //    「附带：<b>选中包</b>的代码审计」。但 lastAudit 保存的是
        //    <b>上一次点「代码审计」按钮时那个包</b>的结果 ——
        //    和现在选中的包可以完全无关：
        //
        //      1. 选中包 A，点「代码审计」   → lastAudit = A 的结论
        //      2. 改选包 B（不同 host/path）
        //      3. 点「生成报告」             → 报告针对 B，却附上了 A 的结论
        //
        //    对挖 SRC 的人来说这比崩溃更糟：会拿着一份<b>张冠李戴的报告</b>
        //    去提交，而报告本身看起来完全正常。
        //
        //    现在用签名绑定来源包，只有选中的包里确实含那个包时才附带。
        CodeAudit.Result auditForReport = null;
        if (lastAudit != null && lastAuditSig != null) {
            for (PacketRecord t : targets) {
                if (lastAuditSig.equals(t.signature)) {
                    auditForReport = lastAudit;
                    break;
                }
            }
        }
        if (auditForReport != null) {
            skeleton += "\n── 附带：选中包的代码审计 ──\n"
                    + CodeAudit.toPromptText(auditForReport);
        }

        // ══════════════════════════════════════════════════════════════
        // 报告准入闸门 —— 黄金六要素 + 五类拒收形态
        // ══════════════════════════════════════════════════════════════
        //
        // ⚠️ 这一段放在 AI 补齐<b>之前</b>，是刻意的。
        //
        //    如果先让 AI 去"润色"，它会很自然地把缺失的信息
        //    用流畅的话补上 —— 而那正是「文字幻觉体」的来源。
        //    所以必须先用本地规则照一遍：**缺什么就说缺什么**，
        //    再决定要不要让 AI 去补（而且只补已知事实的表述）。
        //
        //    另外：闸门<b>不阻止</b>生成报告，只如实告知。
        //    它回答"够不够格提交"，不回答"漏洞是否成立" ——
        //    后者只能靠人实测。
        ReportGate.Result gate = ReportGate.check(null, skeleton);
        String gateBlock = "\n" + gate.render();

        if (!cfg.aiAllowed()) {
            pinDetail(skeleton
                    + gateBlock
                    + "\n══════════ 说明 ══════════\n"
                    + "SRC 安全模式下不允许把内容发给非本机模型，"
                    + "所以「危害说明 / 修复建议」两段没有生成。\n"
                    + "换成 Ollama / LM Studio 后可自动补齐。\n\n"
                    + "本地骨架本身已经可用 —— URL、定级依据、渗透路径要点都在上面。");
            return;
        }

        pinDetail(skeleton + gateBlock
                + "\n\n正在用 " + cfg.model + " 补齐「危害说明 / 渗透路径补充 / 修复建议」…");
        statusLabel.setText(" 报告生成中…（" + cfg.describeDestination() + "）");

        // 把闸门结论也交给 AI，并要求它<b>只补已知事实</b>，不许编
        final String sk = skeleton + "\n" + gate.toPromptText();
        Thread t = new Thread(() -> {
            com.packetsentry.llm.LlmClient.Reply reply = reportGen.enrich(sk, cfg);
            SwingUtilities.invokeLater(() -> {
                if (reply.ok) {
                    pinDetail(sk
                            + "\n══════════ AI 补充 ══════════\n"
                            + gate.render()
                            + "模型 " + cfg.model + "　HTTP " + reply.httpStatus
                            + "　" + reply.elapsedMs + " ms\n\n"
                            + reply.content
                            + "\n\n─────────────────────────────────\n"
                            + "▲ 提交前请自行核对：\n"
                            + "  · AI 补充的内容必须与实际复现一致，不一致就删掉\n"
                            + "  · 未经复现的「可能」不能写成「已确认」—— 平台会扣分\n"
                            + "  · 资产证明需要你自己截图补充\n");
                    refreshStatus();
                } else {
                    pinDetail(sk + "\n\nAI 补充失败：" + reply.error + "\n\n（本地骨架仍可用）");
                }
            });
        }, "packetsentry-report");
        t.setDaemon(true);
        t.start();
    }
    private void runAccessControlTest() {
        PacketRecord r = selected();
        if (r == null) {
            pinDetail("请先在列表里选一个包。");
            return;
        }
        Identity test = selectedIdentity();
        if (test == null) {
            detail.setText("还没有配置测试身份。\n\n"
                    + "到「设置」页 → 越权测试 → 添加身份，填写该身份的 Cookie 或 Authorization 头。\n\n"
                    + "越权测试的原理：用另一个身份的凭据重放这个请求，\n"
                    + "如果仍能拿到相同数据，说明访问控制可能缺失。");
            return;
        }
        if (r.rawRequest == null || r.rawRequest.length == 0) {
            detail.setText("这个记录没有保存请求原文，无法测试。");
            return;
        }
        if (r.service == null) {
            detail.setText("缺少目标服务信息，无法重放。");
            return;
        }

        Config cfg = configSupplier.get();
        int n = javax.swing.JOptionPane.showConfirmDialog(this,
                "即将向目标发送 1 个额外请求来完成越权测试。\n\n"
                        + "  目标    " + r.host + "\n"
                        + "  请求    " + r.method + " " + r.path + "\n"
                        + "  测试身份 " + test.name + "\n\n"
                        + "▲ 请确认你对这个目标有测试授权。\n"
                        + "   插件不会自动执行这个动作，只有你点「确定」才会发包。",
                "确认发送越权测试请求", javax.swing.JOptionPane.OK_CANCEL_OPTION,
                javax.swing.JOptionPane.WARNING_MESSAGE);
        if (n != javax.swing.JOptionPane.OK_OPTION) {
            pinDetail("已取消越权测试。");
            return;
        }

        if (acTester == null) {
            acTester = new AccessControlTester(callbacks);
        }
        acTester.minIntervalMs = cfg.acMinIntervalMs;

        detail.setText("正在以身份「" + test.name + "」重放请求…\n\n"
                + "目标 " + r.host + "\n"
                + "请求 " + r.method + " " + r.path + "\n");
        statusLabel.setText(" 越权测试中…");

        final PacketRecord rec = r;
        Thread t = new Thread(() -> {
            AccessControlTester.Result res = acTester.test(
                    rec.rawRequest, rec.rawResponse,
                    new Identity("基线（原请求凭据）"), test,
                    rec.service, rec.rawResponse != null);
            SwingUtilities.invokeLater(() -> {
                detail.setText(renderAcResult(rec, res));
                detail.setCaretPosition(0);
                statusLabel.setText(" 越权测试完成：" + res.verdict.label);
                // 把结论记进记录，方便列表里回看
                if (res.verdict == AccessControlTester.Verdict.VULNERABLE) {
                    detail.append("\n\n▲ 这个结论值得写进测试报告。");
                }
            });
        }, "packetsentry-ac");
        t.setDaemon(true);
        t.start();
    }

    private String renderAcResult(PacketRecord r, AccessControlTester.Result res) {
        StringBuilder sb = new StringBuilder();
        sb.append("══════════ 越权测试结果 ══════════\n\n");
        sb.append("目标    ").append(r.method).append(' ').append(r.host).append(r.path).append('\n');
        sb.append("会话    ").append(r.toolFlag).append("　响应 ").append(r.rawResponse == null
                ? "无" : (r.rawResponse.length + " 字节")).append("\n\n");
        sb.append(res.detail());
        sb.append('\n');
        sb.append("══════════ 判定说明 ══════════\n\n");
        sb.append("为什么用两个相似度指标：\n");
        sb.append("  · 只看「响应像不像」会误判。考虑两种情况：\n");
        sb.append("    甲（越权）  换个身份，仍拿到同一份数据 → 结构像，值也一样\n");
        sb.append("    乙（正常）  A 拿 A 的、B 拿 B 的      → 结构像，值不同\n");
        sb.append("  · 所以：结构相似度高是正常的，值相似度高才可疑。\n\n");
        sb.append("判定规则：\n");
        sb.append(String.format("  · 测试身份被拒（401/403/404）      → √ 有访问控制%n"));
        sb.append(String.format("  · 2xx 且值相似度 ≥ 80%%            → ▲ 疑似越权%n"));
        sb.append(String.format("  · 2xx 且结构相似 ≥ 50%%、值相似 < 35%% → √ 各取各的数据%n"));
        sb.append(String.format("  · 其它                              → ? 需人工判断%n"));
        sb.append('\n');
        sb.append("▲ 这只是一个「信号」，不是结论。\n");
        sb.append("   值相似度高也可能是公开数据（如商品列表），需要人工确认。\n");
        sb.append("   建议在 Repeater 里手工复核一次再写进报告。\n");

        if (res.testRequestText != null && !res.testRequestText.isEmpty()) {
            sb.append('\n').append("══════════ 实际发出的请求 ══════════\n");
            sb.append(renderSide(res.testRequestText.getBytes(
                    java.nio.charset.StandardCharsets.UTF_8), true));
        }
        if (res.testResponseText != null && !res.testResponseText.isEmpty()) {
            sb.append('\n').append("══════════ 测试响应（已脱敏）══════════\n");
            String t = res.testResponseText;
            if (t.length() > 4000) {
                t = t.substring(0, 4000) + "\n…（已截断）";
            }
            sb.append(t).append('\n');
        }
        return sb.toString();
    }

    // ==================================================================

    private void onAutoChanged() {
        if (autoBox.isSelected()) {
            Config cfg = configSupplier.get();
            double per = cost.estimatePerPacketCny(200, 60, 700);
            detail.setText(String.format(
                    "已开启「自动分析新接口」。\n\n"
                            + "当前模型：%s\n"
                            + "单包预估：¥%.4f\n"
                            + "已识别接口结构：%d 种\n"
                            + "预算上限：¥%.2f\n\n"
                            + "▲ 只对「新接口结构」触发 —— 重复接口和静态资源会跳过。\n"
                            + "   这是把成本压到可接受范围的关键机制。\n"
                            + "   超过预算会自动停止（本地扫描继续，它是免费的）。\n",
                    cfg.model, per, pipe.distinctStructures(), cost.budgetCny()));
            detail.setCaretPosition(0);
        }
        refreshStatus();
    }

    private void maybeAutoAnalyze(PacketRecord r) {
        if (!autoBox.isSelected()) {
            return;
        }
        if (!r.worthAnalyzing()) {
            cost.recordSkipped(1);
            return;
        }
        if (cost.budgetExceeded()) {
            cost.recordSkipped(1);
            SwingUtilities.invokeLater(() -> statusLabel.setText(
                    " ■ 已达预算上限 ¥" + String.format("%.2f", cost.budgetCny())
                            + " —— 自动分析已停止（本地扫描仍在继续，它是免费的）"));
            return;
        }
        SwingUtilities.invokeLater(() -> statusLabel.setText(
                " 新接口 #" + r.seq + "：" + r.method + " " + r.path
                        + "  [" + r.purpose + "]"
                        + (visibleIssues(r).isEmpty() ? "" : "  ▲ " + model.summaryOf(r))));
    }

    private void applyBudget() {
        try {
            cost.setBudgetCny(Double.parseDouble(budgetField.getText().trim()));
            refreshStatus();
        } catch (NumberFormatException e) {
            pinDetail("预算格式不对，填个数字（例如 1.0 表示 ¥1）。");
        }
    }

    // ==================================================================

    /**
     * 渲染详情 —— <b>请求 / 响应 分开呈现</b>。
     *
     * <p>为什么分开：定位业务逻辑漏洞时，最常做的是「看请求提交了什么，
     * 再看响应回了什么，比对二者是否一致」。混在一起要来回找。
     * 这里按「请求侧 → 响应侧 → 本地规则 → 将要发送」四段排布。
     */
    private String renderDetail(PacketRecord r) {
        StringBuilder sb = new StringBuilder();
        sb.append("序号    ").append(r.seq).append('\n');
        sb.append("报文    ").append(r.method).append(' ').append(r.host).append(r.path).append('\n');
        if (r.statusCode > 0) {
            sb.append("状态    HTTP ").append(r.statusCode).append('\n');
        }
        sb.append("大小    ").append(r.size).append(" 字节\n");
        sb.append("作用    ").append(r.purpose).append("   （本地规则推断，零成本）\n");
        sb.append("签名    ").append(r.signature).append('\n');
        sb.append("判定    ");
        if (r.lowValue) {
            sb.append("低价值（静态资源等，跳过）");
        } else if (r.duplicate) {
            sb.append("与已有结构重复（跳过）");
        } else {
            sb.append("√ 值得分析的新结构");
        }
        sb.append("\n\n");

        // ══════════ 请求侧 ══════════
        sb.append("══════════ 请求 ══════════\n");
        sb.append(renderSide(r.rawRequest, true));
        sb.append('\n');

        // ══════════ 响应侧 ══════════
        sb.append("══════════ 响应 ══════════\n");
        if (r.rawResponse == null || r.rawResponse.length == 0) {
            sb.append("（没有响应 —— 请求可能失败或被丢弃）\n");
        } else {
            sb.append(renderSide(r.rawResponse, false));
        }
        sb.append('\n');

        // ══════════ 本地规则 ══════════
        sb.append("══════════ 本地规则检测 ══════════\n");
        // ▲ 用过滤后的列表 —— SRC 模式下平台排除的发现不该出现在明细里，
        //    否则会出现「表格里没有、点开却有」的自相矛盾。
        List<LocalRules.Issue> visIssues = visibleIssues(r);
        int hiddenIssues = r.issues.size() - visIssues.size();
        if (visIssues.isEmpty()) {
            sb.append("未发现问题\n");
            if (hiddenIssues > 0) {
                sb.append("（另有 ").append(hiddenIssues)
                        .append(" 条被 SRC 平台规则排除，未显示）\n");
            }
        } else {
            for (LocalRules.Issue i : visIssues) {
                sb.append("  ").append(i.toString()).append('\n');
            }
            if (hiddenIssues > 0) {
                sb.append("  …另有 ").append(hiddenIssues)
                        .append(" 条被 SRC 平台规则排除（关闭 SRC 安全模式可看全部）\n");
            }
        }
        sb.append('\n');

        // ══════════ 本地扫描 ══════════
        sb.append("══════════ 本地敏感数据扫描 ══════════\n");
        if (r.scan != null && !r.scan.isEmpty()) {
            sb.append(r.scan.headline()).append('\n');
            for (com.packetsentry.detect.PiiScanner.Finding f : r.scan.findings) {
                sb.append("  ").append(f.describe()).append('\n');
            }
            for (com.packetsentry.detect.PiiScanner.JwtInfo j : r.scan.jwts) {
                sb.append('\n').append(j.pretty()).append('\n');
            }
        } else {
            sb.append("未发现敏感数据\n");
        }
        sb.append('\n');

        // ══════════ 脱敏 ══════════
        if (r.sanitized != null && r.sanitized.hasSensitiveData()) {
            sb.append("══════════ 脱敏 ══════════\n").append(r.sanitized.summary()).append('\n');
            for (com.packetsentry.sanitize.Sanitizer.Hit h : r.sanitized.hits) {
                sb.append("  ").append(h).append('\n');
            }
            sb.append('\n');
        }

        // ══════════ 将要发送 ══════════
        sb.append("══════════ 将要发送给 AI 的内容 ══════════\n");
        sb.append(r.brief);
        sb.append("\n\n预估 tokens ≈ ").append(CostTracker.estimateTokens(r.brief));
        sb.append("\n\n（双击表格行可直接送到 Repeater 手工测试）\n\n");

        // ══════════ 延伸测试（本地推导，零成本）══════════
        // ▲ 这一段刻意做成<b>本地规则表</b>而不是让 AI 自由发挥。
        //    用户反馈过「无法根据这个包的漏洞延伸其他漏洞」——
        //    而「既然 /page/edit/1 返回了 flag，/page/edit/2 显然值得试」
        //    这类推理根本不需要创造力，只需要把「已知」系统地展开成「待验证」。
        //    做成规则表的好处：零成本、每次都一样、可回归测试、不依赖 AI 可用性。
        sb.append(Pivot.render(Pivot.derive(visibleIssues(r), r.method, r.path,
                r.host, hasBusinessAuth(r.rawRequest))));
        return sb.toString();
    }

    /**
     * 渲染请求或响应一侧 —— 原文<b>已脱敏</b>，并附体量信息。
     *
     * <p>刻意脱敏后才显示：这个面板的截图会被贴进报告，
     * 不该把真实凭据带出去。
     */
    private String renderSide(byte[] raw, boolean isRequest) {
        if (raw == null || raw.length == 0) {
            return "（空）\n";
        }
        String text = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
        Config cfg = configSupplier.get();
        Sanitizer.Result sr = new Sanitizer(maskStrategy(),
                cfg.layerHeaders, cfg.layerFields, cfg.layerValues).sanitize(text);

        StringBuilder sb = new StringBuilder();
        sb.append("原始 ").append(raw.length).append(" 字节");
        if (sr.hasSensitiveData()) {
            sb.append("　（已抹除 ").append(sr.hits.size()).append(" 处敏感数据后显示）");
        }
        sb.append('\n');
        // 体量大的只展示前若干字符，避免详情区被淹没
        String shown = sr.cleanText;
        int cap = 4000;
        if (shown.length() > cap) {
            shown = shown.substring(0, cap) + "\n…（已截断，" + (sr.cleanText.length() - cap) + " 字符未显示）";
        }
        sb.append(shown).append('\n');
        return sb.toString();
    }

    /** 转发到 RealtimePipe 的同名判断（那个是包级可见的，UI 直接调不方便）。 */
    private static boolean hasBusinessAuth(byte[] rawRequest) {
        return com.packetsentry.core.RealtimePipe.hasBusinessAuth(
                rawRequest == null ? null
                        : new String(rawRequest, java.nio.charset.StandardCharsets.UTF_8));
    }
    private Sanitizer.MaskStrategy maskStrategy() {
        try {
            return Sanitizer.MaskStrategy.valueOf(
                    configSupplier.get().maskStrategy.trim().toUpperCase());
        } catch (Exception e) {
            return Sanitizer.MaskStrategy.KEEP_EDGES;
        }
    }

    // ==================================================================
    // 表格模型
    // ==================================================================

    private static final class PacketTableModel extends AbstractTableModel {
        private final String[] cols = {"#", "方法", "域名", "路径", "作用", "漏洞", "标记", "已抹"};
        private final List<PacketRecord> rows = new ArrayList<>();

        /**
         * 发现显示过滤器 —— SRC 模式下只显示平台收录的。
         *
         * <p>null 表示不过滤（显示全部）。刻意放在<b>显示层</b>而不是抓包层：
         * 开关 SRC 模式或改规则时能立刻重算，不需要重新抓包；
         * 抓包时就把发现丢掉的话，就再也找不回来了。
         */
        private volatile java.util.function.Predicate<LocalRules.Issue> issueFilter;

        void setIssueFilter(java.util.function.Predicate<LocalRules.Issue> f) {
            this.issueFilter = f;
        }

        /** 一条记录里通过过滤的发现。 */
        List<LocalRules.Issue> visible(PacketRecord p) {
            java.util.function.Predicate<LocalRules.Issue> f = issueFilter;
            if (f == null) {
                return p.issues;
            }
            List<LocalRules.Issue> out = new ArrayList<>();
            for (LocalRules.Issue i : p.issues) {
                if (f.test(i)) {
                    out.add(i);
                }
            }
            return out;
        }

        /** 过滤后的最严重等级。 */
        LocalRules.Level worstOf(PacketRecord p) {
            LocalRules.Level w = LocalRules.Level.NONE;
            for (LocalRules.Issue i : visible(p)) {
                if (i.level.rank > w.rank) {
                    w = i.level;
                }
            }
            return w;
        }

        /** 过滤后的汇总文本。 */
        String summaryOf(PacketRecord p) {
            List<LocalRules.Issue> vis = visible(p);
            if (vis.isEmpty()) {
                return "无";
            }
            LocalRules.Issue top = vis.get(0);
            for (LocalRules.Issue i : vis) {
                if (i.level.rank > top.level.rank) {
                    top = i;
                }
            }
            String s = top.level.label + "危" + top.name;
            if (vis.size() > 1) {
                s += " +" + (vis.size() - 1);
            }
            return s;
        }

        void addAll(List<PacketRecord> batch) {
            int from = rows.size();
            rows.addAll(batch);
            fireTableRowsInserted(from, rows.size() - 1);
        }

        void clear() {
            int n = rows.size();
            rows.clear();
            if (n > 0) {
                fireTableRowsDeleted(0, n - 1);
            }
        }

        PacketRecord get(int i) {
            return rows.get(i);
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int c) {
            return cols[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            PacketRecord p = rows.get(r);
            switch (c) {
                case 0:
                    return p.seq;
                case 1:
                    return p.method;
                case 2:
                    return p.host;
                case 3:
                    return (p.path == null || p.path.isEmpty()) ? "/" : p.path;
                case 4:
                    return p.purpose;
                case 5:
                    return summaryOf(p);   // ▲ 必须用过滤后的 —— 否则 SRC 模式下排除项照样显示文字
                case 6:
                    if (p.lowValue) {
                        return "低价值";
                    }
                    if (p.duplicate) {
                        return "重复";
                    }
                    return "新";
                case 7:
                    return (p.sanitized == null || !p.sanitized.hasSensitiveData())
                            ? "" : p.sanitized.hits.size();
                default:
                    return "";
            }
        }
    }

    /**
     * 表格渲染 —— <b>整行背景着色</b>，不只改前景色。
     *
     * <p>为什么改成背景着色：早期版本只设 {@code setForeground}，
     * 在 Burp 的 LookAndFeel 下几乎看不出来（用户反馈「全是黑白的」）。
     * 背景色在任何 L&amp;F 下都比前景色显眼，配合斑马纹一眼就能扫出问题行。
     *
     * <p>三层防御：
     * <ol>
     *   <li>整个方法包在 try/catch 里 —— 渲染器抛异常会让 Swing 回退到默认渲染，
     *       表现就是「全部黑白」，正是早期版本的症状</li>
     *   <li>每次先重置背景/前景色 —— {@code DefaultTableCellRenderer} 是共享实例，
     *       不复位会串色</li>
     *   <li>「漏洞」列额外加彩色圆点前缀 —— 即使背景被 L&amp;F 覆盖，
     *       圆点带着自己的颜色（渲染在文本里），仍然能区分</li>
     * </ol>
     */
    private final class RiskRenderer extends DefaultTableCellRenderer {

        private static final Color LOW_BG = new Color(0xF4, 0xF4, 0xF4);
        private static final Color CLEAN_BG = new Color(0xF1, 0xF8, 0xF1);

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel,
                                                       boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, v, sel, focus, row, col);
            try {
                // 先复位 —— 共享实例，不复位会串色
                c.setBackground(Color.WHITE);
                c.setForeground(Color.BLACK);

                if (sel) {
                    return c;       // 选中行交给 L&F
                }

                PacketRecord p = recordAt(t, row);
                if (p == null) {
                    return c;
                }

                // ---- 低价值 / 重复：浅灰整行 ----
                if (p.lowValue || p.duplicate) {
                    c.setBackground(LOW_BG);
                    c.setForeground(new Color(0x9A, 0x9A, 0x9A));
                    return c;
                }

                // ---- 按漏洞等级整行着色（用过滤后的等级 —— SRC 模式下
                //      被平台排除的发现不该影响这行的颜色）----
                LocalRules.Level lv = worstOf(p);
                Color bg = severityBg(lv);
                c.setBackground(bg != null ? bg : CLEAN_BG);
                c.setForeground(severityFg(lv));

                // ---- 「漏洞」列加彩色圆点（文本自带颜色，最不容易失效）----
                if (col == 5 && v != null) {
                    setText("\u25CF " + v);
                    c.setForeground(severityFg(lv));
                }
                // ---- 「作用」列按业务模块着色（仅无漏洞时，避免盖掉风险色）----
                if (col == 4 && lv == LocalRules.Level.NONE) {
                    c.setForeground(purposeColor(p.purpose));
                }
                return c;
            } catch (Throwable ex) {
                // 渲染器绝不能把异常抛出去 —— 那会让整张表退化成默认黑白渲染
                c.setBackground(Color.WHITE);
                c.setForeground(Color.BLACK);
                return c;
            }
        }

        /** 过滤后的最严重等级（渲染器是内部类，能访问外部方法）。 */
        private LocalRules.Level worstOf(PacketRecord p) {
            try {
                return model.worstOf(p);
            } catch (Throwable e) {
                return p.worstLevel;
            }
        }

        private static PacketRecord recordAt(JTable t, int viewRow) {
            try {
                javax.swing.table.TableModel m = t.getModel();
                if (!(m instanceof PacketTableModel)) {
                    return null;
                }
                return ((PacketTableModel) m).get(t.convertRowIndexToModel(viewRow));
            } catch (Throwable e) {
                return null;
            }
        }

        private static Color severityBg(LocalRules.Level lv) {
            if (lv == null) {
                return null;
            }
            switch (lv) {
                case CRITICAL:
                    return new Color(0xF3, 0xE5, 0xF5);   // 浅紫
                case HIGH:
                    return new Color(0xFF, 0xEB, 0xEE);   // 浅红
                case MEDIUM:
                    return new Color(0xFF, 0xF3, 0xE0);   // 浅橙
                case LOW:
                    return new Color(0xFF, 0xFD, 0xE0);   // 浅黄
                default:
                    return null;
            }
        }

        private static Color severityFg(LocalRules.Level lv) {
            if (lv == null) {
                return new Color(0x2E, 0x7D, 0x32);
            }
            switch (lv) {
                case CRITICAL:
                    return new Color(0x6A, 0x1B, 0x9A);
                case HIGH:
                    return new Color(0xB0, 0x1C, 0x2E);
                case MEDIUM:
                    return new Color(0xA0, 0x52, 0x00);
                case LOW:
                    return new Color(0x7A, 0x60, 0x00);
                default:
                    return new Color(0x2E, 0x7D, 0x32);   // 干净：绿
            }
        }

        private static Color purposeColor(String purpose) {
            if (purpose == null) {
                return new Color(0x33, 0x33, 0x33);
            }
            int h = Math.abs(purpose.hashCode());
            return Color.getHSBColor((h % 24) / 24.0f, 0.62f, 0.52f);
        }
    }

    // ==================================================================
    // 提示词
    // ==================================================================

    /**
     * 单包分析提示词 —— <b>面向 SRC / 打点提效</b>。
     *
     * <h3>▲ 这份提示词改过一版，改的原因值得记下来</h3>
     * 旧版让 AI「区分事实和推测」——本意是好的，但实际效果是
     * <b>AI 对什么都写「可能 / 疑似 / 建议确认」</b>。
     * 用户的原话是：<b>「已经确定包有漏洞却还是在分析可能性」</b>。
     *
     * <p>两个问题：
     * <ol>
     *   <li>旧版的 brief 里<b>根本不含本地结论</b>（那是另一个 bug，已修）——
     *       AI 不知道什么已经确认，只能全按推测写</li>
     *   <li>提示词只说了「要区分」，<b>没说「确认了就直接下结论」</b> ——
     *       于是 AI 选择了最安全的写法：全部加上「可能」</li>
     * </ol>
     *
     * <p>现在改成：brief 里有【本地规则已确认的发现】段，提示词要求
     * <b>在那一段的基础上直接下结论</b>，并且必须给出延伸方向。
     */
    private static final String SINGLE_PACKET_PROMPT =
            "你是一名资深渗透测试工程师，正在协助一次<b>已获授权</b>的漏洞挖掘（SRC / 靶场）。\n"
                    + "你的输出会被直接用于决定「下一步测什么」，所以要<b>可执行</b>，不要写套话。\n"
                    + "\n"
                    + "═══ 输入说明 ═══\n"
                    + "报文摘要里可能包含一段【本地规则已确认的发现】。\n"
                    + "那一段里的每一条都<b>有原文证据</b>，是已确认事实。\n"
                    + "另外还会有一段【本地已推导出的延伸测试方向】，那是机械推导的结果。\n"
                    + "\n"
                    + "═══ 硬性要求 ═══\n"
                    + "1. 【本地规则已确认的发现】里的内容，<b>直接当结论用</b>。\n"
                    + "   禁止对它们写「可能」「疑似」「建议确认」「可能存在」——\n"
                    + "   flag 已经出现在响应里了，那就写「已确认拿到 flag」，不要写「疑似信息泄露」。\n"
                    + "2. 只有<b>你自己推断出来的、没有原文证据</b>的东西，才标注「待验证」。\n"
                    + "3. 凭据类字段已被脱敏（如 Bear****c2ln），这是正常的，不要试图还原。\n"
                    + "4. 不要复述报文内容。不要写「值得注意的是」「需要关注」这类没有信息量的话。\n"
                    + "5. 每一条建议都要能直接执行 —— 落到具体的方法、路径、参数、取值。\n"
                    + "\n"
                    + "═══ 输出结构（严格照这个来）═══\n"
                    + "\n"
                    + "【已确认什么】\n"
                    + "把本地已确认的发现用一句话说清「这意味着什么」。\n"
                    + "如果本地没有确认任何东西，就写「本地规则未确认问题」。\n"
                    + "▲ 这一段不许出现「可能」二字。\n"
                    + "\n"
                    + "【这个包是干嘛的】\n"
                    + "一两句通俗说明，并指出<b>哪些输入是可控的</b>（路径段 / 参数 / 头）。\n"
                    + "\n"
                    + "【现在就能做的测试】\n"
                    + "按优先级列出<b>具体动作</b>，每条格式：\n"
                    + "  动作：把 X 改成 Y，重放到哪里，看什么现象算命中\n"
                    + "  理由：为什么这个方向有戏\n"
                    + "重点覆盖：越权 / ID 遍历 / 参数篡改 / 状态机绕过 / 金额数量篡改 /\n"
                    + "方法篡改 / 未授权访问 / 文件包含 / 注入入口。\n"
                    + "\n"
                    + "【延伸：从这个漏洞还能挖到什么】\n"
                    + "从<b>已确认的发现</b>出发，推出还能测什么。例如：\n"
                    + "  · 这个接口能吐数据 → 同前缀的兄弟接口是不是也能？\n"
                    + "  · 这个 ID 可控 → 换 ID 会不会命中另一个对象？\n"
                    + "  · 不需要凭据就能访问 → 同模块其它接口呢？\n"
                    + "不要重复上面【本地已推导出的延伸测试方向】里已经有的条目，\n"
                    + "只补充它<b>漏掉</b>的方向。\n"
                    + "\n"
                    + "【为什么还没确认】\n"
                    + "只写真正缺的信息（比如「响应体没给，不知道有哪些参数」）。\n"
                    + "不要为了显得严谨而堆一堆「无法判断」。";

    /**
     * 宏观业务逻辑分析 —— <b>一次调用覆盖整个域名</b>。
     *
     * <p>这是成本控制的关键：不是每个包问一次，而是把接口清单合成一份问一次。
     */
    private static final String MACRO_PROMPT =
            "你是一名 Web 安全分析助手，正在协助一次已获授权的渗透测试。\n"
                    + "用户会给你一个目标系统的<b>接口清单</b>（方法、路径、业务作用、"
                    + "出现次数、本地规则已发现的问题）。\n"
                    + "\n"
                    + "这份清单是经过脱敏和去重的，只有接口结构，没有具体数据。\n"
                    + "\n"
                    + "请用中文按以下结构回答：\n"
                    + "\n"
                    + "【这是个什么系统】\n"
                    + "从接口构成推断业务类型和大致架构（前后端分离？有管理后台？\n"
                    + "有没有多租户迹象？），说明推断依据。\n"
                    + "\n"
                    + "【业务模块划分】\n"
                    + "把接口按业务域归类，说明每个模块的职责。\n"
                    + "\n"
                    + "【核心业务流程】\n"
                    + "推断出主要业务流程（如登录→浏览→下单→支付），\n"
                    + "标出流程中的关键状态流转点。\n"
                    + "\n"
                    + "【业务逻辑漏洞切入点】\n"
                    + "这是最重要的部分。按优先级列出，每条包含：\n"
                    + "  · 涉及的接口\n"
                    + "  · 漏洞假设（为什么可能有问题）\n"
                    + "  · 具体验证步骤\n"
                    + "重点关注：越权（水平/垂直）、ID 遍历、参数篡改、\n"
                    + "金额与数量篡改、状态机绕过、并发竞争、越权导出。\n"
                    + "\n"
                    + "【优先测试顺序】\n"
                    + "给出一个建议的测试顺序和理由。\n"
                    + "\n"
                    + "【不确定的地方】\n"
                    + "说明哪些判断依据不足。\n"
                    + "\n"
                    + "注意：不要罗列通用漏洞类型清单，要针对这份具体清单给结论。";


    // ==================================================================
    // AI 挖洞（严格说是「假设生成」）
    // ==================================================================

    /**
     * 从抓到的流量里生成<b>可验证的假设</b>。
     *
     * <h3>⚠️ 为什么叫「挖洞」但产出的是「假设」</h3>
     * AI 读一遍 HTTP 流量能做的事只有一件：把散落的接口、参数、响应差异
     * 归纳成一组<b>可验证的假设</b>，并给出精确到"发什么请求、看什么现象"
     * 的验证步骤。
     *
     * <p>真正的确认必须由人在授权目标上做。如果让 AI 直接输出「发现漏洞」，
     * 那就是标准的<b>文字幻觉体</b>（AI 生成、未经人工复现）。
     *
     * <p>所以这里的状态机是硬约束：AI 只能产出 PROPOSED，
     * {@code CONFIRMED} 只能由用户在复核对话框里设置。
     */
    private void runHunting() {
        Config cfg = configSupplier.get();
        if (cfg == null) {
            return;
        }
        if (!cfg.aiAllowed()) {
            pinDetail("══════════ AI 挖洞 ══════════\n\n"
                    + "当前是 SRC 安全模式，不允许把内容发给非本机模型。\n"
                    + "换成 Ollama / LM Studio 后可用。\n");
            return;
        }
        // ⚠️ 这里必须用 selectedHost()，不能直接读下拉框。
        //    下拉框在「不过滤」时显示的是哨兵文本 "(全部)"，
        //    直接拿去和 r.host 比永远不相等 —— 结果就是
        //    "明明抓了 3282 个包，却提示还没有抓到流量"。
        //    selectedHost() 会把哨兵转成 null（null = 不过滤）。
        String host = selectedHost();
        java.util.List<PacketRecord> pool = new java.util.ArrayList<>();
        java.util.List<PacketRecord> all = pipe.snapshot();
        if (all != null) {
            for (PacketRecord r : all) {
                if (r == null) {
                    continue;
                }
                if (host == null || host.equals(r.host)) {
                    pool.add(r);
                }
            }
        }
        if (pool.isEmpty()) {
            pinDetail("══════════ AI 挖洞 ══════════\n\n"
                    + "还没有抓到流量。先去目标站走一遍，再回来。\n");
            return;
        }

        java.util.List<com.packetsentry.ai.HuntingEngine.RouteFact> facts =
                com.packetsentry.ai.HuntingEngine.buildFacts(pool);
        if (facts.isEmpty()) {
            pinDetail("══════════ AI 挖洞 ══════════\n\n"
                    + "抓到了流量，但提取不出可分析的路由。\n"
                    + "（可能是全是静态资源，或者路径信息缺失）\n");
            return;
        }

        pinDetail("══════════ AI 挖洞 ══════════\n\n"
                + "域名：" + (host == null ? "（全部）" : host) + "\n"
                + "路由数：" + facts.size() + "\n"
                + "正在让 " + cfg.model + " 生成假设…\n"
                + "（这一步只产生假设，不会替你发任何请求）\n");

        final String dom = host;
        Thread th = new Thread(() -> {
            String prompt = com.packetsentry.ai.HuntingEngine.buildPrompt(facts, dom);
            LlmClient.Reply reply = llm.chat(cfg,
                    "你是渗透测试专家，只提出可验证的假设，绝不声称已验证任何漏洞。",
                    prompt);
            SwingUtilities.invokeLater(() -> onHuntResult(reply, facts, dom));
        }, "packetsentry-hunt");
        th.setDaemon(true);
        th.start();
    }

    /** 处理 AI 返回的假设。 */
    private void onHuntResult(LlmClient.Reply reply,
                              java.util.List<com.packetsentry.ai.HuntingEngine.RouteFact> facts,
                              String dom) {
        if (reply == null || !reply.ok) {
            pinDetail("══════════ AI 挖洞 ══════════\n\n"
                    + "× 模型调用失败。\n"
                    + "HTTP " + (reply == null ? 0 : reply.httpStatus) + "\n\n"
                    + (reply == null ? "" : reply.error) + "\n\n"
                    + "到「设置 → 测试连接」排查。\n");
            return;
        }

        // 真实路由集合 —— 用来挡「时空错位型」
        java.util.Set<String> known = new java.util.HashSet<>();
        for (com.packetsentry.ai.HuntingEngine.RouteFact f : facts) {
            known.add(com.packetsentry.ai.HuntingEngine.normalize(f.path));
            known.add(f.path);
        }

        com.packetsentry.ai.HuntingEngine.ParseResult pr =
                com.packetsentry.ai.HuntingEngine.parse(reply.content, known);
        lastHypotheses = pr.hypotheses;

        StringBuilder sb = new StringBuilder();
        sb.append("══════════ AI 挖洞结果 ══════════\n\n");
        sb.append("域名：").append(dom.isEmpty() ? "（全部）" : dom).append('\n');
        sb.append("模型：").append("　HTTP ").append(reply.httpStatus)
                .append("　").append(reply.elapsedMs).append(" ms\n");
        sb.append("路由数：").append(facts.size())
                .append("　提出假设：").append(pr.hypotheses.size()).append(" 条\n\n");

        if (!pr.dropped.isEmpty()) {
            sb.append("── 丢弃 ").append(pr.dropped.size()).append(" 条 ──\n");
            for (String d : pr.dropped) {
                sb.append("  × ").append(d).append('\n');
            }
            sb.append('\n');
        }

        if (pr.hypotheses.isEmpty()) {
            sb.append("模型没有提出任何合格假设。\n\n");
            sb.append("▲ 这不一定是坏事 —— 说明它没有在你给的事实上硬凑。\n");
            sb.append("  宁可一条都不提，也不要提一堆站不住的。\n");
            pinDetail(sb.toString());
            return;
        }

        sb.append("── 假设列表（全部为「待验证」）──\n\n");
        for (int i = 0; i < pr.hypotheses.size(); i++) {
            com.packetsentry.ai.Hypothesis h = pr.hypotheses.get(i);
            sb.append(i + 1).append(". ").append(h.render()).append("\n\n");
        }
        sb.append("══════════ 下一步 ══════════\n");
        sb.append("这些是<b>假设</b>，不是发现。请逐条手工验证：\n");
        sb.append("  · 按「验证步骤」在授权目标上实际发请求\n");
        sb.append("  · 对照「判据」判断是否成立\n");
        sb.append("  · 点「复核假设」标记结果并写验证记录\n");
        sb.append("  · 只有标记「已证实」的，才能进报告\n");
        pinDetail(sb.toString());
    }



    /**
     * 复核假设 —— 整个功能的闭环。
     *
     * <h3>⚠️ 为什么必须有这一步</h3>
     * AI 产出的假设状态一律是 {@code PROPOSED}，而
     * {@code Hypothesis.gate()} 会因为「状态不是已证实」直接判成
     * <b>文字幻觉体</b>，永远进不了报告。
     *
     * <p>也就是说：<b>没有人工复核，这个功能一条发现也产不出来</b>。
     * 这是刻意的 —— 用户定的第一条规则就是
     * 「AI 一键生成、未经人工复现的文字幻觉体」不予接受。
     *
     * <p>这里让人亲手标注：
     * <ul>
     *   <li>已证实 —— 必须同时写验证记录，否则闸门仍然拦</li>
     *   <li>已否定 —— 留档，避免重复投入</li>
     *   <li>验证中 —— 暂时搁置</li>
     * </ul>
     */
    private void reviewHypotheses() {
        if (lastHypotheses == null || lastHypotheses.isEmpty()) {
            pinDetail("══════════ 复核假设 ══════════\n\n"
                    + "还没有可复核的假设。先点「AI 挖洞」生成一批。\n");
            return;
        }

        // 反复复核，直到用户点「结束复核」
        while (true) {
            String[] choices = new String[lastHypotheses.size() + 1];
            for (int i = 0; i < lastHypotheses.size(); i++) {
                choices[i] = (i + 1) + ". " + lastHypotheses.get(i).oneLine();
            }
            choices[lastHypotheses.size()] = "结束复核";

            Object picked = javax.swing.JOptionPane.showInputDialog(this,
                    "选择要复核的假设：\n"
                            + "（只有标成「已证实」且写了验证记录的，才能进报告）",
                    "复核假设",
                    javax.swing.JOptionPane.PLAIN_MESSAGE, null, choices, choices[0]);
            if (picked == null || "结束复核".equals(picked)) {
                break;
            }

            int idx = -1;
            for (int i = 0; i < lastHypotheses.size(); i++) {
                if (choices[i].equals(picked)) {
                    idx = i;
                    break;
                }
            }
            if (idx < 0) {
                break;
            }
            reviewOne(lastHypotheses.get(idx));
        }

        showHypothesisList();
    }

    /** 复核单条假设。 */
    private void reviewOne(com.packetsentry.ai.Hypothesis h) {
        // 先给用户看完整卡片，方便一边测一边对照
        Object act = javax.swing.JOptionPane.showInputDialog(this,
                h.render() + "\n\n这条假设现在的状态是："
                        + h.status.label + "\n\n你想标成什么？",
                "复核：" + h.title,
                javax.swing.JOptionPane.PLAIN_MESSAGE, null,
                new String[]{"已证实（我实测确认了）", "已否定（测了不成立）",
                        "验证中（先搁置）", "取消"},
                "已证实（我实测确认了）");
        if (act == null || "取消".equals(act)) {
            return;
        }

        com.packetsentry.ai.Hypothesis.Status target;
        if ("已证实（我实测确认了）".equals(act)) {
            target = com.packetsentry.ai.Hypothesis.Status.CONFIRMED;
        } else if ("已否定（测了不成立）".equals(act)) {
            target = com.packetsentry.ai.Hypothesis.Status.REJECTED;
        } else {
            target = com.packetsentry.ai.Hypothesis.Status.TESTING;
        }

        // 已证实必须留验证记录 —— 闸门会检查这个字段
        String note = "";
        if (target == com.packetsentry.ai.Hypothesis.Status.CONFIRMED) {
            note = javax.swing.JOptionPane.showInputDialog(this,
                    "写下你<b>实际做了什么、看到了什么</b>：\n\n"
                            + "例：用账号 A 的令牌请求 GET /api/order/1002，"
                            + "返回 200 且 body 含账号 B 的收件人，截图 2 张\n\n"
                            + "⚠️ 这一段会跟着进报告。写「测过」等于没写。",
                    h.humanNote == null ? "" : h.humanNote);
            if (note == null) {
                return;
            }
            if (note.trim().isEmpty()) {
                javax.swing.JOptionPane.showMessageDialog(this,
                        "标「已证实」必须写验证记录。\n"
                                + "没有记录的话，报告准入闸门仍然会拦下这条 —— "
                                + "那正是为了防「AI 生成、未经人工复现」的报告。",
                        "缺少验证记录", javax.swing.JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        h.status = target;
        if (!note.trim().isEmpty()) {
            h.humanNote = note.trim();
        }

        com.packetsentry.ai.Hypothesis.Verdict v = h.gate();
        javax.swing.JOptionPane.showMessageDialog(this,
                "已标为「" + target.label + "」。\n\n" + v.render(),
                "复核结果",
                v.pass() ? javax.swing.JOptionPane.INFORMATION_MESSAGE
                        : javax.swing.JOptionPane.WARNING_MESSAGE);
    }

    /** 把当前假设列表和闸门结论刷到详情面板。 */
    private void showHypothesisList() {
        StringBuilder sb = new StringBuilder();
        sb.append("══════════ 假设列表 ══════════\n\n");
        int ok = 0;
        for (int i = 0; i < lastHypotheses.size(); i++) {
            com.packetsentry.ai.Hypothesis h = lastHypotheses.get(i);
            boolean p = h.promotable();
            if (p) {
                ok++;
            }
            sb.append(p ? "√ " : "× ").append(i + 1).append(". ")
                    .append(h.render()).append("\n\n");
        }
        sb.append("──────────────────────────\n");
        sb.append("共 ").append(lastHypotheses.size()).append(" 条，")
                .append("够格进报告 ").append(ok).append(" 条。\n\n");
        if (ok == 0) {
            sb.append("▲ 目前一条都不够格。这是正常的 —— 假设必须先被你实测确认。\n");
            sb.append("  宁可一条都不提交，也不要拿一堆「可能」去换一个误报记录。\n");
        } else {
            sb.append("√ 这 ").append(ok).append(" 条可以写进报告。\n");
        }
        pinDetail(sb.toString());
    }



    /**
     * 本地规则挖洞 —— <b>不需要模型</b>。
     *
     * <h3>为什么这个按钮比 AI 版更重要</h3>
     * 用户挖 SRC，而 SRC 安全模式要求数据不出本机。本地能跑的模型通常只有 7B/8B，
     * 让它在几百条路由里猜"哪个有洞"产出不稳定。
     *
     * <p>但拖慢 SRC 挖洞的不是"看不出有洞"，而是"不知道从哪下手"。而这件事
     * 是<b>确定性</b>的：同一接口不同对象 ID 的响应长度不一样、响应里出现了
     * 别人的邮箱、请求压根没带 Cookie —— 这些信号不需要模型去猜。
     *
     * <p>所以这个功能：<b>零网络、零成本、SRC 模式可用</b>，
     * 而且依据是抓包里的事实，不是概率。
     */
    private void runLocalHunting() {
        // ⚠️ 这里必须用 selectedHost()，不能直接读下拉框。
        //    下拉框在「不过滤」时显示的是哨兵文本 "(全部)"，
        //    直接拿去和 r.host 比永远不相等 —— 结果就是
        //    "明明抓了 3282 个包，却提示还没有抓到流量"。
        //    selectedHost() 会把哨兵转成 null（null = 不过滤）。
        String host = selectedHost();
        java.util.List<PacketRecord> pool = new java.util.ArrayList<>();
        java.util.List<PacketRecord> all = pipe.snapshot();
        if (all != null) {
            for (PacketRecord r : all) {
                if (r == null) {
                    continue;
                }
                if (host == null || host.equals(r.host)) {
                    pool.add(r);
                }
            }
        }
        if (pool.isEmpty()) {
            pinDetail("══════════ 本地挖洞 ══════════\n\n"
                    + "还没有抓到流量。先去目标站走一遍，再回来。\n");
            return;
        }

        com.packetsentry.ai.LocalHunter.Result res =
                com.packetsentry.ai.LocalHunter.hunt(pool);
        lastHypotheses = res.hypotheses;

        StringBuilder sb = new StringBuilder();
        sb.append("══════════ 本地挖洞结果 ══════════\n\n");
        sb.append("域名：").append(host == null ? "（全部）" : host).append('\n');
        sb.append("扫描包数：").append(pool.size())
                .append("　线索：").append(res.hypotheses.size()).append(" 条\n");
        sb.append("⭐ 纯本地规则，0 网络请求，SRC 安全模式下可用\n\n");

        if (!res.ruleHits.isEmpty()) {
            sb.append("── 命中的规则 ──\n");
            for (java.util.Map.Entry<String, Integer> e : res.ruleHits.entrySet()) {
                sb.append("  · ").append(e.getKey())
                        .append(" × ").append(e.getValue()).append('\n');
            }
            sb.append('\n');
        }

        if (res.hypotheses.isEmpty()) {
            sb.append("没有命中任何规则。\n\n");
            sb.append("▲ 常见原因：\n");
            sb.append("  · 抓的流量还不够 —— 先多走几条业务流程（注册/下单/查详情/改资料）\n");
            sb.append("  · 接口路径不带可变 ID 段，规则 1 用不上\n");
            sb.append("  · 请求都带了 Cookie，规则 2 不触发\n");
            pinDetail(sb.toString());
            return;
        }

        sb.append("── 线索列表（全部为「待验证」）──\n\n");
        for (int i = 0; i < res.hypotheses.size(); i++) {
            sb.append(i + 1).append(". ").append(res.hypotheses.get(i).render())
                    .append("\n\n");
        }
        sb.append("══════════ 下一步 ══════════\n");
        sb.append("这些是<b>线索</b>，不是发现。请按「验证步骤」逐条实测：\n");
        sb.append("  · 对照「判据」判断是否成立\n");
        sb.append("  · 点「复核假设」标记结果并写验证记录\n");
        sb.append("  · 只有标记「已证实」的，才能进报告\n");
        pinDetail(sb.toString());
    }

}
