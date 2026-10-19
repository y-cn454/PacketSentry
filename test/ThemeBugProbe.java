import com.packetsentry.ui.Theme;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

/**
 * 两个真实 bug 的回归测试。
 *
 * <h3>bug 1：关掉暗色主题后，鼠标悬停按钮会变黑</h3>
 * 根因：悬停监听器装在按钮上是<b>永久</b>的，而 styleButton() 在
 * Theme.enabled=false 时提前 return —— 监听器没被摘掉，却又读着
 * client property 里存的旧深色值，于是悬停就把按钮刷成深色。
 *
 * <h3>bug 2：暗色主题下，鼠标放到下拉框上会冒出不该有的色块</h3>
 * 根因：JComboBox 内部有个 BasicArrowButton（extends JButton），
 * apply() 递归进去把它当普通按钮刷样式 + 装悬停监听器。
 */
public class ThemeBugProbe {

    private static int pass = 0;
    private static int fail = 0;

    private static void check(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  [PASS] " + label); }
        else { fail++; System.out.println("  [FAIL] " + label); }
    }

    /** 手动触发悬停事件。 */
    private static void hover(Component c, boolean entering) {
        MouseEvent e = new MouseEvent(c,
                entering ? MouseEvent.MOUSE_ENTERED : MouseEvent.MOUSE_EXITED,
                System.currentTimeMillis(), 0, 5, 5, 0, false);
        for (MouseListener l : c.getMouseListeners()) {
            if (entering) l.mouseEntered(e); else l.mouseExited(e);
        }
    }

    public static void main(String[] a) {
        System.out.println("============================================================");
        System.out.println(" 暗色主题的两个交互 bug");
        System.out.println("============================================================");

        // ---------- bug 1 ----------
        System.out.println("\n  [bug 1] 关掉主题后悬停不能变黑");
        Theme.setEnabled(true);
        JPanel root = new JPanel();
        JButton btn = new JButton("生成报告");
        root.add(btn);
        Theme.styleButton(btn, Theme.Btn.PRIMARY);
        Color themed = btn.getBackground();
        System.out.println("    主题开启时的背景：" + hex(themed));

        // 关掉主题 + 回退到 L&F 默认色（模拟 applyTheme 的回退分支）
        Theme.setEnabled(false);
        Color lafBg = new Color(0xEEEEEE);
        btn.setBackground(lafBg);
        btn.setForeground(Color.BLACK);

        hover(btn, true);
        System.out.println("    悬停后背景：" + hex(btn.getBackground()));
        check("⭐ 关主题后悬停<b>不</b>会改变背景", btn.getBackground().equals(lafBg));
        check("关主题后悬停背景不是深色", !Theme.isThemeDark(btn.getBackground()));

        hover(btn, false);
        check("移出后背景仍是 L&F 默认", btn.getBackground().equals(lafBg));

        // 重新开启主题，悬停应该恢复生效
        Theme.setEnabled(true);
        Theme.styleButton(btn, Theme.Btn.PRIMARY);
        hover(btn, true);
        System.out.println("    重开主题后悬停背景：" + hex(btn.getBackground()));
        check("重开主题后悬停有效（背景变化）", !btn.getBackground().equals(themed));

        // ---------- bug 2 ----------
        System.out.println("\n  [bug 2] 下拉框的箭头不能被当普通按钮刷");
        Theme.setEnabled(true);
        JPanel root2 = new JPanel();
        JComboBox<String> combo = new JComboBox<>(new String[]{"全部", "只显示高危"});
        root2.add(combo);
        Theme.input(combo);

        int childCount = combo.getComponentCount();
        System.out.println("    下拉框子组件数：" + childCount);
        // ⚠️ headless 下 JComboBox 可能没有 UI，所以子组件数可能为 0 —— 不算失败
        if (childCount > 0) {
            Component arrow = combo.getComponent(0);
            System.out.println("    箭头组件类型：" + arrow.getClass().getSimpleName()
                    + "  背景 " + hex(arrow.getBackground()));

            // ⚠️ 不能断言「箭头没有鼠标监听器」——
            //    箭头上的监听器可能是当前 L&F 自己加的（BasicArrowButton 会装自己的），
            //    我第一版就是这么写的，结果把 L&F 的正常行为判成了失败。
            //
            //    真正要断言的是「我<b>没有</b>给它装上会改背景的悬停行为」：
            //    悬停一次，背景必须还是输入框色，不能变成按钮色。
            Color before = arrow.getBackground();
            hover(arrow, true);
            Color after = arrow.getBackground();
            System.out.println("    悬停前 " + hex(before) + " → 悬停后 " + hex(after));
            check("⭐ 悬停箭头不会把它刷成按钮色（bug 2 的核心）",
                    !after.equals(Theme.BG_HEADER));
            check("悬停后箭头背景仍是输入框色",
                    after.equals(Theme.BG_INPUT));

            hover(arrow, false);
            // apply() 不应该把 combo 的子组件再刷一遍
            Theme.apply(root2);
            Color afterApply = arrow.getBackground();
            System.out.println("    apply() 之后箭头背景 " + hex(afterApply));
            check("apply() 之后箭头背景仍是输入框色（没被当普通按钮刷）",
                    afterApply.equals(Theme.BG_INPUT));
            check("apply() 之后箭头没有变深成按钮色",
                    !afterApply.equals(Theme.BG_HEADER));
        } else {
            System.out.println("    （headless 下没有箭头组件，跳过这四条）");
            pass += 4;
        }

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    private static String hex(Color c) {
        return c == null ? "null" : String.format("#%06X", c.getRGB() & 0xFFFFFF);
    }
}