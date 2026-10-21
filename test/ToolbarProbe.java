import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.packetsentry.core.Config;
import com.packetsentry.core.CostTracker;
import com.packetsentry.core.RealtimePipe;
import com.packetsentry.ui.RealtimeTab;
import com.packetsentry.ui.Theme;

import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * 工具栏排版回归 —— 下拉框被压窄导致编辑区与箭头重叠。
 *
 * <h3>这个套件的来历</h3>
 *
 * 用户截图显示：「目标域名」右边的下拉框变成一个黑块，右侧叠着一个
 * 「1∨」样的东西；「显示」那边的「全部」也被裁掉一半。
 *
 * 根因是<b>只设了 setMaximumSize、没设 setPreferredSize</b>：
 * <pre>
 *   hostBox.setMaximumSize(new Dimension(280, 26));   // 只有上限
 * </pre>
 * BoxLayout 是按【首选尺寸】摆放的，而 JComboBox 的首选宽度由当前内容算出来 ——
 * 「(全部)」「全部」这种两三个字的选项只要 ~66px。于是下拉框被压到 66px，
 * 编辑区和右侧箭头在这个宽度下就重叠了。
 *
 * <p>另外三类控件的默认高度本来就不一样（实测 31 / 32 / 23 / 25），
 * 混在同一个 X_AXIS 里必然参差不齐。
 *
 * <h3>这个套件守什么</h3>
 * <ol>
 *   <li>四个下拉/输入控件都有<b>显式</b>的首选宽度，且不小于可用宽度</li>
 *   <li>所有工具栏控件的<b>高度一致</b>（= RealtimeTab.BAR_H）</li>
 *   <li>两行里都有分组竖线分隔</li>
 * </ol>
 */
public class ToolbarProbe {

    private static int pass = 0;
    private static int fail = 0;
    private static final List<String> log = new ArrayList<>();

    private static void check(String label, boolean ok) {
        if (ok) {
            pass++;
            System.out.println("  [PASS] " + label);
        } else {
            fail++;
            System.out.println("  [FAIL] " + label);
        }
    }

    /** 动态代理造一个不会 NPE 的 Burp 回调桩。 */
    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> iface, String name) {
        return (T) Proxy.newProxyInstance(
                iface.getClassLoader(),
                new Class<?>[]{iface},
                (proxy, m, args) -> {
                    String n = m.getName();
                    log.add(name + "." + n);
                    Class<?> rt = m.getReturnType();
                    if ("getHelpers".equals(n)) {
                        return stub(IExtensionHelpers.class, "helpers");
                    }
                    if (rt == void.class) {
                        return null;
                    }
                    if (rt == boolean.class) {
                        return Boolean.FALSE;
                    }
                    if (rt == int.class) {
                        return 0;
                    }
                    if (rt == long.class) {
                        return 0L;
                    }
                    if (rt == byte[].class) {
                        return new byte[0];
                    }
                    if (rt == String.class) {
                        return "";
                    }
                    if (rt.isArray()) {
                        return java.lang.reflect.Array.newInstance(rt.getComponentType(), 0);
                    }
                    if (rt.isInterface()) {
                        return stub(rt, name + "." + n);
                    }
                    return null;
                });
    }

    private static Object field(Object o, String name) throws Exception {
        Field f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(o);
    }

    private static int barHeight() throws Exception {
        Field f = RealtimeTab.class.getDeclaredField("BAR_H");
        f.setAccessible(true);
        return f.getInt(null);
    }

    /** 递归收集某一类的组件数量。 */
    private static int countOf(Container root, Class<?> type) {
        int n = 0;
        for (Component c : root.getComponents()) {
            if (type.isInstance(c)) {
                n++;
            }
            if (c instanceof Container) {
                n += countOf((Container) c, type);
            }
        }
        return n;
    }

    public static void main(String[] args) {
        // ⚠️ 必须用看门狗包住：构造 RealtimeTab 会创建 Swing 组件，
        //    AWT 的 EDT 是**非守护线程** —— 只要它起来了，main 返回后 JVM
        //    也不会退出，探针看起来就"卡住"了（第一次跑就是这样挂掉的）。
        //    同时这也顺带成了一个超时保护：如果构造函数本身阻塞，
        //    能明确报出来，而不是无限等。
        Thread worker = new Thread(ToolbarProbe::runAll, "toolbar-probe");
        worker.setDaemon(true);
        worker.start();
        try {
            worker.join(90_000L);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        if (worker.isAlive()) {
            System.out.println();
            System.out.println("  [FAIL] 探针超时（90s）—— 构造 RealtimeTab 时阻塞了");
            System.out.println("============================================================");
            System.out.println(" 小计：PASS=" + pass + "  FAIL=" + (fail + 1));
            System.out.println("============================================================");
            System.exit(1);
        }
        System.exit(fail > 0 ? 1 : 0);
    }

    private static void runAll() {
        try {
            runCore();
        } catch (Throwable t) {
            System.out.println("  [FAIL] 探针异常: " + t);
            t.printStackTrace();
            fail++;
        }
    }

    private static void runCore() throws Exception {
        System.out.println("============================================================");
        System.out.println(" 工具栏排版：下拉框不能被压窄，控件高度要一致");
        System.out.println("============================================================");

        final int barH = barHeight();
        System.out.println("  RealtimeTab.BAR_H = " + barH);
        System.out.println();

        final Object[] holder = new Object[1];

        SwingUtilities.invokeAndWait(() -> {
            try {
                Theme.setEnabled(true);
                Config cfg = new Config();
                RealtimePipe pipe = new RealtimePipe(() -> cfg);
                CostTracker cost = new CostTracker();
                IBurpExtenderCallbacks cb = stub(IBurpExtenderCallbacks.class, "callbacks");
                Supplier<Config> sup = () -> cfg;
                holder[0] = new RealtimeTab(pipe, cost, sup, cb);
            } catch (Throwable t) {
                System.out.println("  [FAIL] 构造 RealtimeTab 抛异常: " + t);
                t.printStackTrace();
            }
        });

        Object tab = holder[0];
        if (tab == null) {
            System.out.println("  [FAIL] RealtimeTab 没构造出来，中止");
            System.out.println();
            System.out.println("============================================================");
            System.out.println(" 小计：PASS=" + pass + "  FAIL=" + (fail + 1));
            System.out.println("============================================================");
            System.exit(1);
        }

        Container root = (Container) tab;

        // ------------------------------------------------------------
        // ① 下拉框 / 输入框的尺寸
        // ------------------------------------------------------------
        System.out.println("\n  [①] 下拉框 / 输入框的尺寸");
        String[][] combos = {
                {"hostBox", "目标域名", "200"},
                {"severityBox", "显示过滤", "100"},
                {"identityBox", "身份", "140"},
        };
        for (String[] c : combos) {
            JComponent jc = (JComponent) field(tab, c[0]);
            Dimension p = jc.getPreferredSize();
            int minW = Integer.parseInt(c[2]);
            System.out.println("        " + c[0] + " (" + c[1] + ") preferred = "
                    + p.width + " x " + p.height);
            check(c[0] + " 宽度 ≥ " + minW + "（实际 " + p.width + "）", p.width >= minW);
            check(c[0] + " 高度 == BAR_H（实际 " + p.height + "）", p.height == barH);
        }

        // JTextField 单独处理：它的 getPreferredSize() 按 columns + 字体重算，
        // 会忽略 setPreferredSize —— 所以只能验证 min/max，不能验证 preferred。
        System.out.println("\n        budgetField 是 JTextField：只看 min/max（preferred 由 columns 算）");
        {
            JComponent tf = (JComponent) field(tab, "budgetField");
            Dimension p = tf.getPreferredSize();
            Dimension mn = tf.getMinimumSize();
            Dimension mx = tf.getMaximumSize();
            System.out.println("        budgetField preferred = " + p.width + " x " + p.height
                    + "   min = " + mn.width + " x " + mn.height
                    + "   max = " + mx.width + " x " + mx.height);
            check("budgetField min.h == BAR_H", mn.height == barH);
            check("budgetField max.h == BAR_H", mx.height == barH);
            check("budgetField preferred 宽度 ≥ 40（实际 " + p.width + "）", p.width >= 40);
            check("budgetField preferred 宽度 ≤ max（实际 " + p.width + " ≤ " + mx.width + "）",
                    p.width <= mx.width);
        }

        // ------------------------------------------------------------
        // ② preferred ≤ maximum（否则 BoxLayout 会裁回上限）
        // ------------------------------------------------------------
        System.out.println("\n  [②] preferred ≤ maximum（否则 BoxLayout 会裁回上限）");
        for (String[] c : new String[][]{
                {"hostBox"}, {"severityBox"}, {"identityBox"}, {"budgetField"}}) {
            JComponent jc = (JComponent) field(tab, c[0]);
            Dimension p = jc.getPreferredSize();
            Dimension m = jc.getMaximumSize();
            check(c[0] + " preferred.w(" + p.width + ") ≤ max.w(" + m.width + ")",
                    p.width <= m.width);
        }

        // ------------------------------------------------------------
        // ③ 按钮 / 复选框的高度统一
        //
        //    ⚠️ 必须排除「下拉框 / 滚动条 / 表格的内部子组件」：
        //       JComboBox 的箭头是 MetalComboBoxButton，JScrollBar 的上下钮是
        //       MetalScrollButton —— 它们由各自的 L&F 布局管理，高度本来就不该
        //       等于工具栏行高。第一版探针没排除，误报了 11 个。
        // ------------------------------------------------------------
        System.out.println("\n  [③] 按钮与复选框高度统一为 BAR_H");
        List<String> badH = new ArrayList<>();
        for (Component c : allOf(root, javax.swing.AbstractButton.class)) {
            if (nestedInWidget(c)) {
                continue;
            }
            JComponent jc = (JComponent) c;
            Dimension max = jc.getMaximumSize();
            if (max.height != barH) {
                badH.add(jc.getClass().getSimpleName() + "(" + textOf(c) + ") max.h=" + max.height);
            }
        }
        if (!badH.isEmpty()) {
            System.out.println("        未统一高度的按钮：" + badH);
        }
        check("工具栏按钮的最大高度都是 " + barH, badH.isEmpty());

        // ------------------------------------------------------------
        // ④ 分组竖线
        // ------------------------------------------------------------
        System.out.println("\n  [④] 分组竖线分隔");
        int seps = countOf(root, JSeparator.class);
        System.out.println("        JSeparator 数量 = " + seps);
        check("至少有 6 条分组竖线（实际 " + seps + "）", seps >= 6);

        // ------------------------------------------------------------
        // ⑤ 两行必须用 WrapLayout
        //
        //    BoxLayout(X_AXIS) 在空间不足时不会换行，而是把组件压到 minimumSize。
        //    高 DPI 下字体变大 → 首选宽度变大 → 必然触发，表现就是
        //    按钮文字互相重叠、标签被裁掉半个（用户截图）。
        //    WrapLayout 改成折行，控件始终保持首选尺寸。
        // ------------------------------------------------------------
        System.out.println("\n  [⑤] 工具栏两行用 WrapLayout（不能是 BoxLayout）");
        int wrapRows = 0;
        int boxRows = 0;
        for (Component c : allOf(root, javax.swing.JPanel.class)) {
            java.awt.LayoutManager lm = ((javax.swing.JPanel) c).getLayout();
            if (lm instanceof com.packetsentry.ui.WrapLayout) {
                wrapRows++;
            } else if (lm instanceof javax.swing.BoxLayout
                    && ((javax.swing.BoxLayout) lm).getAxis() == javax.swing.BoxLayout.X_AXIS) {
                // 只统计"像工具栏行"的：子组件多且都在一行
                if (((Container) c).getComponentCount() >= 8) {
                    boxRows++;
                }
            }
        }
        System.out.println("        WrapLayout 面板 = " + wrapRows + "   BoxLayout(X) 面板 = " + boxRows);
        check("工具栏行用了 WrapLayout（实际 " + wrapRows + "）", wrapRows >= 2);
        check("没有还在用 BoxLayout(X_AXIS) 的工具栏行（实际 " + boxRows + "）", boxRows == 0);

        // ------------------------------------------------------------
        // ⑥ 按钮的 minimum 宽度不能是 0
        //
        //    给 0 的话，一旦某层容器判定空间不足（BoxLayout 走 minimum），
        //    按钮会被压成 0 宽。这个断言守住"宁可折行，也不压扁"。
        // ------------------------------------------------------------
        System.out.println("\n  [⑥] 按钮 minimum 宽度 = preferred（不允许压到 0）");
        List<String> collapsed = new ArrayList<>();
        for (Component c : allOf(root, javax.swing.AbstractButton.class)) {
            if (nestedInWidget(c)) {
                continue;
            }
            JComponent jc = (JComponent) c;
            Dimension mn = jc.getMinimumSize();
            Dimension pf = jc.getPreferredSize();
            if (mn.width < pf.width) {
                collapsed.add(textOf(c) + " min.w=" + mn.width + " < pref.w=" + pf.width);
            }
        }
        if (!collapsed.isEmpty()) {
            System.out.println("        宽度可被压缩的按钮：" + collapsed);
        }
        check("没有按钮的 minimum 宽度小于 preferred", collapsed.isEmpty());

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 小计：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        if (fail > 0) {
            System.exit(1);
        }
    }

    private static String textOf(Component c) {
        try {
            Method m = c.getClass().getMethod("getText");
            Object v = m.invoke(c);
            return v == null ? "?" : String.valueOf(v);
        } catch (Exception e) {
            return "?";
        }
    }

    /**
     * 组件是否嵌在「自己的布局管理器」里。
     *
     * <p>JComboBox 的箭头、JScrollBar 的上下钮、JTable 的表头都在这类容器内，
     * 它们的尺寸由各自的 UI 委托管理，不该受工具栏行高约束。
     */
    private static boolean nestedInWidget(Component c) {
        for (Container p = c.getParent(); p != null; p = p.getParent()) {
            if (p instanceof JComboBox
                    || p instanceof javax.swing.JScrollBar
                    || p instanceof javax.swing.JScrollPane
                    || p instanceof javax.swing.JTable
                    || p instanceof javax.swing.table.JTableHeader
                    || p instanceof javax.swing.JSpinner) {
                return true;
            }
        }
        return false;
    }

    private static List<Component> allOf(Container root, Class<?> type) {
        List<Component> out = new ArrayList<>();
        collect(root, type, out);
        return out;
    }

    private static void collect(Container root, Class<?> type, List<Component> out) {
        for (Component c : root.getComponents()) {
            if (type.isInstance(c)) {
                out.add(c);
            }
            if (c instanceof Container) {
                collect((Container) c, type, out);
            }
        }
    }
}
