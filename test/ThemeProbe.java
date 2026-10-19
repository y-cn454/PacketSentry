import com.packetsentry.ui.Theme;
import javax.swing.*;
import java.awt.*;

/**
 * 验证暗色主题真的会落到组件上。
 *
 * 这个探针是为了一个真实 bug 写的：
 *   复选框「暗色主题」默认勾选，但 applyTheme() 只挂在它的
 *   ActionListener 上 —— 而初始状态不触发事件。
 *   结果主题从未被应用，界面一片白。
 *
 * 所以这里断言的不是「Theme 的配色对不对」，而是
 * 「apply() 真的把颜色写到了组件上」。
 */
public class ThemeProbe {
    static int pass = 0, fail = 0;
    static void check(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  [PASS] " + label); }
        else { fail++; System.out.println("  [FAIL] " + label); }
    }

    public static void main(String[] a) throws Exception {
        System.out.println("============================================================");
        System.out.println(" 暗色主题是否真的应用到组件树");
        System.out.println("============================================================");

        Theme.setEnabled(true);

        // 造一棵跟真实界面结构相近的树
        JPanel base = new JPanel(new BorderLayout());
        JPanel top = new JPanel();
        JLabel lbl = new JLabel("域名");
        JButton btn = new JButton("分析");
        JCheckBox cb = new JCheckBox("暗色主题");
        JComboBox<String> combo = new JComboBox<>(new String[]{"a", "b"});
        JTable table = new JTable(new Object[][]{{"1","2"}}, new Object[]{"A","B"});
        JScrollPane sp = new JScrollPane(table);
        JTextArea ta = new JTextArea("详情");
        JScrollPane sp2 = new JScrollPane(ta);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, sp, sp2);

        top.add(lbl); top.add(btn); top.add(cb); top.add(combo);
        base.add(top, BorderLayout.NORTH);
        base.add(split, BorderLayout.CENTER);

        // ⭐ 关键：调用 apply()，就像 applyTheme() 会做的那样
        Theme.apply(base);

        System.out.println("  base   背景 " + hex(base.getBackground()));
        System.out.println("  top    背景 " + hex(top.getBackground()));
        System.out.println("  label  前景 " + hex(lbl.getForeground()) + "  opaque=" + lbl.isOpaque());
        System.out.println("  button 背景 " + hex(btn.getBackground()) + " 前景 " + hex(btn.getForeground()));
        System.out.println("  表格   背景 " + hex(table.getBackground()));
        System.out.println("  表头   背景 " + hex(table.getTableHeader().getBackground()));
        System.out.println("  viewport 背景 " + hex(sp.getViewport().getBackground()));
        System.out.println("  文本区 背景 " + hex(ta.getBackground()) + " 前景 " + hex(ta.getForeground()));

        check("base 是暗色", Theme.isThemeDark(base.getBackground()));
        check("top 是暗色", Theme.isThemeDark(top.getBackground()));
        check("表格是暗色", Theme.isThemeDark(table.getBackground()));
        check("表头是暗色", Theme.isThemeDark(table.getTableHeader().getBackground()));
        check("滚动面板 viewport 是暗色", Theme.isThemeDark(sp.getViewport().getBackground()));
        check("文本区背景是暗色", Theme.isThemeDark(ta.getBackground()));
        check("文本区前景是亮色（暗底上能看清）", !Theme.isThemeDark(ta.getForeground()));
        check("按钮背景是暗色", Theme.isThemeDark(btn.getBackground()));
        check("按钮前景是亮色", !Theme.isThemeDark(btn.getForeground()));

        // ⭐ 标签：要么自己带暗底，要么父容器是暗的 —— 两者必居其一，否则文字看不见
        boolean labelReadable = Theme.isThemeDark(lbl.getBackground())
                || (lbl.getParent() != null && Theme.isThemeDark(lbl.getParent().getBackground()));
        check("⭐ 标签文字一定看得见（自己带暗底 或 父容器是暗的）", labelReadable);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" ⭐ 异常隔离：一个组件失败不能拖累兄弟");
        System.out.println("============================================================");

        // 造一个「着色时会抛异常」的组件，夹在中间。
        // ⚠️ 必须等构造完成之后才允许抛 ——
        //    JPanel 的构造函数里 LookAndFeel.installColors() 就会调 setBackground()，
        //    如果那时就抛，对象根本造不出来（这个探针的第一版就崩在这）。
        final boolean[] armed = {false};
        JPanel trap = new JPanel() {
            @Override
            public void setBackground(Color c) {
                if (armed[0]) {
                    throw new RuntimeException("故意炸一个，模拟某些 L&F 拒绝改色");
                }
                super.setBackground(c);
            }
        };
        JPanel host = new JPanel();
        JLabel before = new JLabel("before");
        JLabel after = new JLabel("after");
        host.add(before);
        host.add(trap);
        host.add(after);

        // 构造完成，武装陷阱 —— 之后 Theme.apply() 碰到它就会抛
        armed[0] = true;
        Theme.apply(host);

        System.out.println("  before 前景 " + hex(before.getForeground()));
        System.out.println("  after  前景 " + hex(after.getForeground()));
        System.out.println("  after  背景 " + hex(after.getBackground())
                + "（父容器是暗的，所以 label 保持透明 —— 这是<b>正确</b>行为）");
        // ⚠️ 断言前景，不是背景。
        //    label() 总是设前景；背景只在「父容器不是暗色」时才设 ——
        //    这里 host 被 panel() 涂成暗色，所以 after 应当保持透明。
        //    我第一版断言的是背景，于是把一个正确行为判成了失败。
        //
        //    兄弟顺序是 before → trap → after：
        //    旧实现里 trap 抛的异常会冒泡到 apply(host) 的 catch，
        //    导致 apply(after) <b>根本不会执行</b>；现在它在 try 外面，所以会执行。
        check("⭐ 中间组件抛异常后，它后面的兄弟仍然被着色",
                com.packetsentry.ui.Theme.FG_TEXT.equals(after.getForeground()));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    static String hex(Color c) {
        return c == null ? "null" : String.format("#%06X", c.getRGB() & 0xFFFFFF);
    }
}