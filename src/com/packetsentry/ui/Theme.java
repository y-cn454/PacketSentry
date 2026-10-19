package com.packetsentry.ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 暗色主题 —— 科技感 / 黑客风。
 *
 * <h3>▲ 这个类里最重要的不是配色，是「怎么让颜色真的显示出来」</h3>
 * Burp 用自己的 Look &amp; Feel 渲染。我们上次踩过一个坑：
 * 只设 {@code setForeground()} 完全看不出效果，最后发现是 L&amp;F
 * 在渲染时把颜色覆盖掉了。
 *
 * <p>所以这里遵守三条规则：
 * <ol>
 *   <li><b>绝不调用 {@code UIManager.put()}</b> ——
 *       那会改掉整个 Burp 的外观，是极不礼貌的行为。
 *       颜色只加在我们自己的组件上。</li>
 *   <li>每个组件都 <b>背景 + 前景一起设</b>，并且 {@code setOpaque(true)} ——
 *       不透明才会用自己的背景色绘制。</li>
 *   <li>表格头、滚动面板、渲染器这些「容易被忽略的地方」也要单独处理 ——
 *       漏一个就会出现「深色表格配白表头」的割裂感。</li>
 * </ol>
 *
 * <p>另外提供 {@link #enabled} 开关：某些 L&amp;F 组合下暗色可能显示异常，
 * 这时用户能一键切回 Burp 原生外观，而不是被一个坏掉的界面卡住。
 */
public final class Theme {

    /** 是否启用暗色主题。关掉则全部交回 Burp 的 L&F。 */
    private static volatile boolean enabled = true;

    public static boolean isEnabled() {
        return enabled;
    }

    public static void setEnabled(boolean b) {
        enabled = b;
    }

    // ==================================================================
    // 配色（科技感 / 黑客风：深蓝黑底 + 青绿主色）
    // ==================================================================

    /** 最底层背景 —— 接近纯黑的深蓝。 */
    public static final Color BG_BASE = new Color(0x0A0E14);
    /** 面板背景。 */
    public static final Color BG_PANEL = new Color(0x11161D);
    /** 输入框 / 文本区背景。 */
    public static final Color BG_INPUT = new Color(0x0D1117);
    /** 表头 / 次级面板。 */
    public static final Color BG_HEADER = new Color(0x1A212B);
    /** 选中行。 */
    public static final Color BG_SELECT = new Color(0x1F3A4D);

    /** 边框 / 分隔线。 */
    public static final Color LINE = new Color(0x2A3441);
    /** 强调色 —— 青绿，终端感。 */
    public static final Color ACCENT = new Color(0x00E5A0);
    /** 次级强调（链接 / 提示）。 */
    public static final Color ACCENT_DIM = new Color(0x58A6FF);

    /** 正文。 */
    public static final Color FG_TEXT = new Color(0xC9D1D9);
    /** 次要文字。 */
    public static final Color FG_DIM = new Color(0x7D8590);
    /** 可编辑内容（亮一点）。 */
    public static final Color FG_INPUT = new Color(0xE6EDF3);

    // 风险等级配色（在深色底上要够亮）
    public static final Color LV_CRITICAL = new Color(0xBC8CFF);
    public static final Color LV_HIGH = new Color(0xFF7B72);
    public static final Color LV_MEDIUM = new Color(0xFFA657);
    public static final Color LV_LOW = new Color(0xE3B341);
    public static final Color LV_CLEAN = new Color(0x3FB950);
    public static final Color LV_MUTED = new Color(0x6E7681);

    /** 行背景（暗色版）—— 用很淡的色调，靠左侧色条 + 前景色区分。 */
    public static final Color ROW_CRITICAL = new Color(0x2A1F3D);
    public static final Color ROW_HIGH = new Color(0x33191B);
    public static final Color ROW_MEDIUM = new Color(0x33260F);
    public static final Color ROW_LOW = new Color(0x2E2A12);
    public static final Color ROW_CLEAN = new Color(0x11241A);
    public static final Color ROW_MUTED = new Color(0x1A1E24);
    public static final Color ROW_BASE = new Color(0x0F141A);

    private Theme() {
    }

    // ==================================================================
    // 统一字体（中文必须能显示 —— 这里曾经是个真 bug）
    // ==================================================================

    /**
     * 用来检测字体是否含中文字形的样本。
     *
     * <p>必须覆盖界面里真实会出现的字，否则检测会假阴性 ——
     * 只测「测试」两个字的话，某个只含部分汉字的字体会通过，
     * 但界面上出现「域名」「越权」时又变成豆腐块。
     */
    private static final String CJK_SAMPLE =
            "目标域名 方法 路径 作用 漏洞 详情 已抹 越权 注入 响应 请求 设置 状态";

    /** 缓存选好的字体族名 —— 枚举字体很贵，而 mono() 会被调用很多次。 */
    private static volatile String fontFamily = null;

    /**
     * 挑一个<b>能显示中文</b>的字体族。
     *
     * <h3>▲ 这里修的是一个把整个界面变成豆腐块的 bug</h3>
     * 旧实现：
     * <pre>
     *   Font f = new Font(Font.MONOSPACED, ...);
     *   return f.getName().equalsIgnoreCase("Monospaced")
     *           ? new Font("Consolas", ...) : f;      // ← 兜底到 Consolas
     * </pre>
     * 那行的本意是「某些环境 MONOSPACED 会退化成正体」，想兜底成等宽字体。
     * <b>但 Consolas 没有中文字形</b> —— 于是所有中文渲染成 □□□□。
     *
     * <p>更讽刺的是：实测本机逻辑字体 {@code Monospaced}
     * <b>反而是能显示中文的</b>（Java 会为它挑一个含 CJK 的物理字体）。
     * 也就是说这个「兜底」把唯一能用的选项换掉了。
     *
     * <p>现在改成：按优先级逐个试，<b>用 {@link Font#canDisplayUpTo} 实测</b>
     * 能不能画出中文样本，第一个通过的胜出。不再靠猜字体名。
     */
    private static String pickFontFamily() {
        String cached = fontFamily;
        if (cached != null) {
            return cached;
        }
        // ▲ 刻意不把 Consolas / Courier New 放进候选：它们没有中文字形
        String[] candidates = {
                "Microsoft YaHei UI",   // Win10/11 最佳中文 UI 字体
                "Microsoft YaHei",      // Win7+
                "微软雅黑",
                "MiSans",               // 部分国产系统自带
                "HarmonyOS Sans SC",
                "Noto Sans SC",
                "PingFang SC",          // macOS
                "Source Han Sans SC",   // Linux
                "SimHei", "黑体",
                "SimSun", "宋体",
                Font.MONOSPACED,        // 逻辑字体：Java 会挑含 CJK 的物理字体
                Font.DIALOG,            // 最后兜底，一定能显示
        };
        for (String name : candidates) {
            try {
                Font f = new Font(name, Font.PLAIN, 12);
                // canDisplayUpTo 返回 -1 表示样本里<b>每个</b>字符都能显示
                if (f.canDisplayUpTo(CJK_SAMPLE) == -1) {
                    fontFamily = name;
                    return name;
                }
            } catch (Throwable ignored) {
                // 这个候选不可用，试下一个
            }
        }
        fontFamily = Font.DIALOG;
        return fontFamily;
    }

    private static Font uiFont(int style, int size) {
        return new Font(pickFontFamily(), style, size);
    }

    /**
     * 正文字体。
     *
     * <p>▲ 名字保留 {@code mono} 是为了不改调用点，但<b>它不再是等宽字体</b> ——
     * 因为能正确显示中文的等宽字体在 Windows 上几乎不存在
     * （Consolas / Courier New 实测都只有 ASCII）。
     *
     * <p><b>可读性优先于「终端感」</b>：宁可字不齐，也不能满屏豆腐块。
     */
    private static Font mono(int size) {
        return uiFont(Font.PLAIN, size);
    }

    /** 正文字体。 */
    public static Font monoText() {
        return mono(12);
    }

    /** 小号加粗（表头）。 */
    public static Font monoSmall() {
        return uiFont(Font.BOLD, 12);
    }

    /** 标题字体。 */
    public static Font title() {
        return uiFont(Font.BOLD, 13);
    }

    /** 当前实际选用的字体族名 —— 排查字体问题时用得上。 */
    public static String currentFontFamily() {
        return pickFontFamily();
    }

    // ==================================================================
    // 组件着色
    // ==================================================================

    /** 面板。 */
    public static void panel(JComponent c) {
        if (!enabled || c == null) {
            return;
        }
        c.setBackground(BG_PANEL);
        c.setForeground(FG_TEXT);
        c.setOpaque(true);
    }

    /** 最底层容器。 */
    public static void base(JComponent c) {
        if (!enabled || c == null) {
            return;
        }
        c.setBackground(BG_BASE);
        c.setForeground(FG_TEXT);
        c.setOpaque(true);
    }

    /** 标签。 */
    public static void label(JLabel l) {
        if (!enabled || l == null) {
            return;
        }
        l.setForeground(FG_TEXT);

        // ▲ 这里原来只写 setBackground(BG_PANEL)，是无效的。
        //
        //    JLabel 默认 isOpaque() == false —— 背景根本不会被绘制。
        //    所以标签的实际底色来自<b>父容器</b>。父容器是暗的就没问题，
        //    但如果父容器是 Burp 的浅色组件（没被我们染上色的那些），
        //    浅灰文字（#C9D1D9）压在白底上 = 基本看不见。
        //
        //    这正好是「文字看不见 + 背景不生效」两个症状同时出现的原因。
        //
        //    修法：只在<b>父容器不是我们的暗色</b>时，才让标签自己带底色。
        //    父容器已经是暗的就不设 opaque —— 保持透明更干净，
        //    也避免 BG_PANEL 在 BG_BASE 上盖出一块略浅的方块。
        Container parent = l.getParent();
        boolean parentIsDark = parent != null && isThemeDark(parent.getBackground());
        if (parentIsDark) {
            l.setOpaque(false);
        } else {
            l.setBackground(BG_PANEL);
            l.setOpaque(true);
        }
    }

    /**
     * 这个颜色是不是「我们的暗色系」。
     *
     * <p>用亮度判断而不是逐一比对常量 —— 因为父容器可能是
     * {@code BG_BASE} / {@code BG_PANEL} / {@code ROW_*} 里的任意一个，
     * 将来还会加新的。亮度阈值对新增颜色自动成立。
     */
    public static boolean isThemeDark(Color c) {
        if (c == null) {
            return false;
        }
        // 感知亮度（ITU-R BT.601），0~255
        int lum = (int) (0.299 * c.getRed() + 0.587 * c.getGreen() + 0.114 * c.getBlue());
        return lum < 110;
    }

    /** 强调标签（青绿）。 */
    public static void accentLabel(JLabel l) {
        label(l);
        if (enabled && l != null) {
            l.setForeground(ACCENT);
        }
    }

    /** 次要说明标签。 */
    public static void dimLabel(JLabel l) {
        label(l);
        if (enabled && l != null) {
            l.setForeground(FG_DIM);
        }
    }

    // ==================================================================
    // 按钮 —— 四级层次
    // ==================================================================

    /**
     * 按钮的视觉级别。
     *
     * <h3>为什么需要分级</h3>
     * 旧界面里 11 个按钮长得<b>一模一样</b>：同样的深灰底、同样的青绿字、
     * 同样的边框。结果是一排按钮里眼睛不知道该先看哪个 ——
     * 「生成报告」和「清空」在视觉上等价，而它们的后果完全不对等。
     *
     * <p>所以按<b>后果的不可逆程度</b>分四级：
     * <ul>
     *   <li>{@link #PRIMARY} 主要动作 —— 实心青底，最醒目</li>
     *   <li>{@link #SECONDARY} 常规动作 —— 默认样式</li>
     *   <li>{@link #DANGER} 破坏性动作 —— 红字红边，清空/批量测试</li>
     *   <li>{@link #GHOST} 轻量开关 —— 无边框，悬停才显底</li>
     * </ul>
     */
    public enum Btn {
        PRIMARY, SECONDARY, DANGER, GHOST
    }

    /** 用于标记「这个按钮已经装过样式」，避免 apply() 反复调用时叠加监听器。 */
    private static final String STYLED_KEY = "packetsentry.styled";

    /** 悬停时的底色。 */
    private static final Color BG_BTN_HOVER = new Color(0x263140);
    /** 主要按钮的悬停色。 */
    private static final Color BG_BTN_PRIMARY_HOVER = new Color(0x33F5BE);
    /** 危险按钮的底色。 */
    private static final Color BG_BTN_DANGER = new Color(0x2A1618);
    private static final Color BG_BTN_DANGER_HOVER = new Color(0x3D1F22);
    /** 危险色。 */
    public static final Color DANGER = new Color(0xFF6B6B);

    /** 常规按钮（保持旧签名，兼容已有调用）。 */
    public static void button(AbstractButton b) {
        styleButton(b, Btn.SECONDARY);
    }

    /** 主要动作按钮 —— 视觉权重最高的那个。 */
    public static void primaryButton(AbstractButton b) {
        styleButton(b, Btn.PRIMARY);
    }

    /** 破坏性动作按钮 —— 清空、批量越权测试这类。 */
    public static void dangerButton(AbstractButton b) {
        styleButton(b, Btn.DANGER);
    }

    /** 轻量开关 —— 暂停这类。 */
    public static void ghostButton(AbstractButton b) {
        styleButton(b, Btn.GHOST);
    }

    /**
     * 给按钮装上某一级的样式。
     *
     * <h3>⚠️ 幂等性是硬要求</h3>
     * {@link #apply(Component)} 会递归调用这里，而 apply() 可能被调用多次
     * （切换主题时、重建界面时）。如果每次都 addMouseListener，
     * 监听器会<b>越叠越多</b> —— 悬停时反复重绘，最终拖慢界面。
     *
     * <p>所以用 client property 标记「已装过」，重复调用只刷新颜色记录。
     */
    public static void styleButton(AbstractButton b, Btn kind) {
        if (!enabled || b == null) {
            return;
        }
        Color bg;
        Color fg;
        Color hover;
        boolean ghost = kind == Btn.GHOST;

        switch (kind) {
            case PRIMARY:
                bg = ACCENT;
                fg = BG_BASE;
                hover = BG_BTN_PRIMARY_HOVER;
                break;
            case DANGER:
                bg = BG_BTN_DANGER;
                fg = DANGER;
                hover = BG_BTN_DANGER_HOVER;
                break;
            case GHOST:
                bg = BG_PANEL;
                fg = FG_DIM;
                hover = BG_BTN_HOVER;
                break;
            case SECONDARY:
            default:
                bg = BG_HEADER;
                fg = ACCENT;
                hover = BG_BTN_HOVER;
                break;
        }

        b.setBackground(bg);
        b.setForeground(fg);
        b.setOpaque(true);
        b.setContentAreaFilled(true);
        b.setFocusPainted(false);
        b.setBorderPainted(!ghost);
        // 主要按钮加粗，进一步拉开层次
        b.setFont(kind == Btn.PRIMARY ? uiFont(Font.BOLD, 12) : mono(12));

        try {
            // 内边距从 3,9 放宽到 6,13 —— 旧值太挤，按钮看起来「憋」
            b.setBorder(BorderFactory.createCompoundBorder(
                    ghost ? BorderFactory.createEmptyBorder(1, 1, 1, 1)
                          : BorderFactory.createLineBorder(LINE, 1),
                    BorderFactory.createEmptyBorder(6, 13, 6, 13)));
        } catch (Throwable ignored) {
            // 某些 L&F 会拒绝自定义边框，忽略即可
        }

        // 悬停反馈 —— 只在第一次装上，之后只刷新记录的颜色
        Object styled = b.getClientProperty(STYLED_KEY);
        if (!Boolean.TRUE.equals(styled)) {
            b.putClientProperty(STYLED_KEY, Boolean.TRUE);
            b.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mouseEntered(java.awt.event.MouseEvent e) {
                    // ⚠️ 这个 !enabled 判断是<b>必须</b>的，少写它就有一个真 bug：
                    //
                    //    关掉暗色主题后，styleButton() 会提前 return，
                    //    但<b>已经挂上的监听器仍然活在按钮上</b>。
                    //    而 client property 里存着的还是旧的深色值 ——
                    //    于是鼠标一悬停，按钮就被刷成深色，在白底界面上看起来「变黑」。
                    //
                    //    用户报告过这个现象：「关闭暗色主题时鼠标放到按钮上会让按钮变黑」。
                    if (!enabled) {
                        return;
                    }
                    Object h = b.getClientProperty(STYLED_KEY + ".hover");
                    if (h instanceof Color && b.isEnabled()) {
                        b.setBackground((Color) h);
                    }
                }

                @Override
                public void mouseExited(java.awt.event.MouseEvent e) {
                    // 同理：主题关了就不要去改背景，否则移出时又刷一次旧色
                    if (!enabled) {
                        return;
                    }
                    Object base = b.getClientProperty(STYLED_KEY + ".base");
                    if (base instanceof Color) {
                        b.setBackground((Color) base);
                    }
                }
            });
        }
        // 无论是否首次，都把当前级别对应的颜色记下来
        b.putClientProperty(STYLED_KEY + ".base", bg);
        b.putClientProperty(STYLED_KEY + ".hover", hover);
        // ⚠️ 记下级别本身 —— apply() 递归时会重新调到这里，
        //    如果不记住级别，它就会把 primary/danger 一律刷回 secondary。
        b.putClientProperty(STYLED_KEY + ".kind", kind);
    }

    /**
     * 读回按钮先前被设过的级别（没设过就返回 SECONDARY）。
     *
     * <p>这是为了让 {@link #apply(Component)} 能<b>保持</b>界面上精心分好的
     * 按钮层次，而不是每次刷主题就把「生成报告」的实心青底刷回普通灰底。
     */
    public static Btn styleOf(AbstractButton b) {
        if (b == null) {
            return Btn.SECONDARY;
        }
        Object k = b.getClientProperty(STYLED_KEY + ".kind");
        return k instanceof Btn ? (Btn) k : Btn.SECONDARY;
    }

    /** 输入框 / 下拉框。 */
    public static void input(JComponent c) {
        if (!enabled || c == null) {
            return;
        }
        c.setBackground(BG_INPUT);
        c.setForeground(FG_INPUT);
        c.setOpaque(true);
        c.setFont(mono(12));
        try {
            c.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(LINE, 1),
                    BorderFactory.createEmptyBorder(2, 6, 2, 6)));
        } catch (Throwable ignored) {
            // 忽略
        }
        if (c instanceof JComboBox) {
            JComboBox<?> cb = (JComboBox<?>) c;
            cb.setRenderer(new DarkComboRenderer());
            styleComboArrow(cb);
        }
    }

    /**
     * 给下拉框的箭头按钮单独上色。
     *
     * <h3>为什么需要单独处理</h3>
     * {@link #apply(Component)} 刻意<b>不递归进 JComboBox</b> ——
     * 因为里面的箭头按钮是 {@code BasicArrowButton extends JButton}，
     * 递归进去会被当成普通按钮刷样式并装上悬停监听器，
     * 表现为「鼠标放到下拉菜单上会冒出不该有的色块」。
     *
     * <p>但完全不处理又会有另一个问题：箭头由 L&F 按<b>它自己的主题</b>画，
     * 在一个深色下拉框上可能是深色箭头 —— 看不见。
     *
     * <p>所以这里只做最小干预：<b>上色 + 不装悬停</b>。
     */
    private static void styleComboArrow(JComboBox<?> cb) {
        try {
            // BasicComboBoxUI 的箭头是第一个子组件
            if (cb.getComponentCount() == 0) {
                return;
            }
            java.awt.Component arrow = cb.getComponent(0);
            if (!(arrow instanceof JComponent)) {
                return;
            }
            JComponent a = (JComponent) arrow;
            a.setBackground(BG_INPUT);
            a.setForeground(FG_DIM);
            a.setOpaque(true);
            // ⚠️ 不调用 styleButton() —— 那样会装上悬停监听器，
            //    正是我们要避免的行为。
        } catch (Throwable ignored) {
            // 某些 L&F 的下拉框没有箭头子组件，忽略即可
        }
    }

    /** 文本区 / 编辑器 —— 是本次改版可读性的重点。 */
    public static void textArea(JTextComponent t) {
        if (!enabled || t == null) {
            return;
        }
        t.setBackground(BG_INPUT);
        t.setForeground(FG_INPUT);
        t.setCaretColor(ACCENT);
        t.setSelectionColor(BG_SELECT);
        t.setSelectedTextColor(FG_INPUT);
        t.setFont(monoText());
        if (t instanceof JTextArea) {
            ((JTextArea) t).setLineWrap(true);
        }
    }

    /** 滚动面板 —— 连滚动条一起处理，否则会出现亮色滚动条。 */
    public static void scroll(JScrollPane sp) {
        if (!enabled || sp == null) {
            return;
        }
        sp.setBackground(BG_BASE);
        sp.setBorder(BorderFactory.createLineBorder(LINE, 1));
        sp.getViewport().setBackground(BG_INPUT);
        sp.getViewport().setOpaque(true);
    }

    /** 表格 —— 含表头、行高、网格线、选择色。 */
    public static void table(JTable t) {
        if (!enabled || t == null) {
            return;
        }
        t.setBackground(ROW_BASE);
        t.setForeground(FG_TEXT);
        t.setSelectionBackground(BG_SELECT);
        t.setSelectionForeground(FG_INPUT);
        t.setGridColor(LINE);
        t.setShowGrid(true);
        t.setOpaque(true);
        t.setFillsViewportHeight(true);
        t.setRowHeight(24);
        t.setFont(monoText());
        t.setIntercellSpacing(new Dimension(1, 1));

        JTableHeader h = t.getTableHeader();
        if (h != null) {
            h.setBackground(BG_HEADER);
            h.setForeground(ACCENT);
            h.setFont(monoSmall());
            h.setOpaque(true);
            h.setReorderingAllowed(false);
            // ▲ 表头也有自己的渲染器，不设的话会出现「深色表格 + 浅色表头」
            final TableCellRenderer def = h.getDefaultRenderer();
            h.setDefaultRenderer(new TableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable table, Object value,
                                                               boolean sel, boolean focus,
                                                               int row, int col) {
                    Component c = def.getTableCellRendererComponent(table, value, sel, focus,
                            row, col);
                    c.setBackground(BG_HEADER);
                    c.setForeground(ACCENT);
                    c.setFont(monoSmall());
                    if (c instanceof JLabel) {
                        ((JLabel) c).setHorizontalAlignment(SwingConstants.LEFT);
                        ((JLabel) c).setBorder(BorderFactory.createCompoundBorder(
                                BorderFactory.createMatteBorder(0, 0, 1, 1, LINE),
                                BorderFactory.createEmptyBorder(2, 6, 2, 6)));
                    }
                    return c;
                }
            });
        }
    }

    /** 复选框。 */
    public static void check(AbstractButton b) {
        if (!enabled || b == null) {
            return;
        }
        b.setBackground(BG_PANEL);
        b.setForeground(FG_TEXT);
        b.setOpaque(true);
        b.setFont(mono(12));
        b.setFocusPainted(false);
    }

    /** 分隔线。 */
    public static Border separatorBorder() {
        return BorderFactory.createMatteBorder(1, 0, 0, 0, LINE);
    }

    // ==================================================================

    /**
     * 递归给一棵组件树着色。
     *
     * <p>适用场景：一个面板构造完之后，一次性刷成暗色，
     * 不用在每个组件上手动调用。已经逐个设过色的组件会被
     * 按类型<b>再设一次</b>（幂等），不会有副作用。
     *
     * <h3>▲ 这里原来有个结构性缺陷，已修</h3>
     * 旧写法把<b>递归也放进 try 里</b>：
     * <pre>
     *   try {
     *       给 root 着色;
     *       for (每个子组件) apply(c);     // ← 递归在 try 里
     *   } catch (Throwable ignored) { }    // ← 吞掉
     * </pre>
     * 后果：<b>第 3 个子组件抛异常，第 4 到第 N 个连同它们的整个子树都不会被着色。</b>
     *
     * <p>表现出来就是「界面有一部分是白的」——
     * 而浅灰文字（#C9D1D9）压在白底上，基本看不见。
     * 一个吞掉的异常，造成的是「文字看不见 + 背景部分不生效」。
     *
     * <p>修法：<b>每个组件各自 try，递归放在 try 外面。</b>
     * 单个组件着色失败只影响它自己，不会波及其兄弟和子树。
     *
     * @param root 根组件
     */
    public static void apply(Component root) {
        if (!enabled || root == null) {
            return;
        }

        // ① 只给这一个组件着色，失败也只影响它自己
        try {
            if (root instanceof JTable) {
                table((JTable) root);
            } else if (root instanceof JTableHeader) {
                // 由 table() 处理
            } else if (root instanceof JScrollPane) {
                scroll((JScrollPane) root);
            } else if (root instanceof JTextComponent) {
                textArea((JTextComponent) root);
            } else if (root instanceof JComboBox) {
                input((JComboBox<?>) root);
            } else if (root instanceof JCheckBox || root instanceof JRadioButton) {
                check((AbstractButton) root);
            } else if (root instanceof JButton) {
                // ⚠️ 用 styleOf 读回级别，而不是一律 button()。
                //    否则每次刷主题都会把 primary/danger 刷回 secondary，
                //    界面的按钮层次就白设计了。
                styleButton((AbstractButton) root, styleOf((AbstractButton) root));
            } else if (root instanceof JLabel) {
                label((JLabel) root);
            } else if (root instanceof JList) {
                // 列表也要有自己的渲染器，否则弹出/列表区是白底黑字
                input((JComponent) root);
                JList<?> list = (JList<?>) root;
                if (!(list.getCellRenderer() instanceof DarkComboRenderer)) {
                    list.setCellRenderer(new DarkComboRenderer());
                }
            } else if (root instanceof JComponent) {
                panel((JComponent) root);
            }
        } catch (Throwable ignored) {
            // 单个组件着色失败绝不阻断整棵树
        }

        // ② 递归放在 try 外面 —— 兄弟节点不会被别人的失败连坐
        if (root instanceof Container) {
            // ⚠️ 下拉框的子组件<b>不能递归</b>，这是一个真实 bug 的来源。
            //
            //    JComboBox 内部有一个箭头按钮（BasicArrowButton extends JButton）
            //    和一个编辑器组件，它们由当前 L&F 自己创建和绘制。
            //    如果递归进去，箭头按钮会被当成<b>普通按钮</b>刷上 BG_HEADER
            //    并装上悬停监听器 —— 结果就是「暗色主题时鼠标放到下拉菜单上
            //    会显示一些不该显示的东西」（用户原话）。
            //
            //    下拉框整体已经在 ① 里被 input() 着色过了，
            //    箭头留着交给 L&F 画，反而更稳。
            if (root instanceof JComboBox) {
                return;
            }
            Component[] kids;
            try {
                kids = ((Container) root).getComponents();
            } catch (Throwable t) {
                return;
            }
            for (Component c : kids) {
                apply(c);
            }
        }
    }

    /** 收集树里所有按钮，方便统一加 hover 效果之类的。 */
    public static List<AbstractButton> buttons(Component root) {
        List<AbstractButton> out = new ArrayList<>();
        collect(root, out);
        return out;
    }

    private static void collect(Component c, List<AbstractButton> out) {
        if (c instanceof AbstractButton) {
            out.add((AbstractButton) c);
        }
        if (c instanceof Container) {
            for (Component k : ((Container) c).getComponents()) {
                collect(k, out);
            }
        }
    }

    // ==================================================================

    /** 下拉框在暗色主题下的渲染器 —— 不设的话弹出列表会是白底黑字。 */
    private static final class DarkComboRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean sel, boolean focus) {
            Component c = super.getListCellRendererComponent(list, value, index, sel, focus);
            if (Theme.enabled) {
                c.setBackground(sel ? BG_SELECT : BG_INPUT);
                c.setForeground(FG_INPUT);
                c.setFont(mono(12));
            }
            return c;
        }
    }

    /** 一个把风险等级映射成前景色的工具（表格渲染器用）。 */
    public static Color levelColor(com.packetsentry.detect.LocalRules.Level lv) {
        if (lv == null) {
            return FG_TEXT;
        }
        switch (lv) {
            case CRITICAL:
                return LV_CRITICAL;
            case HIGH:
                return LV_HIGH;
            case MEDIUM:
                return LV_MEDIUM;
            case LOW:
                return LV_LOW;
            default:
                return LV_CLEAN;
        }
    }

    /** 风险等级 → 行背景色。 */
    public static Color levelRowBg(com.packetsentry.detect.LocalRules.Level lv) {
        if (lv == null) {
            return ROW_BASE;
        }
        switch (lv) {
            case CRITICAL:
                return ROW_CRITICAL;
            case HIGH:
                return ROW_HIGH;
            case MEDIUM:
                return ROW_MEDIUM;
            case LOW:
                return ROW_LOW;
            default:
                return ROW_CLEAN;
        }
    }
}
