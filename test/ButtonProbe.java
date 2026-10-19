import com.packetsentry.ui.Theme;

import javax.swing.*;
import java.awt.*;

/**
 * 按钮分级：层次清晰 + 不被主题刷新覆盖 + 监听器不叠加。
 *
 * <h3>这个探针防的是什么</h3>
 * 旧界面 16 个按钮长得一模一样 ——「生成报告」和「清空」视觉等价，
 * 而前者是你最想让人点的，后者是不可逆的破坏性操作。
 *
 * <p>但加分级时踩了两个坑，都是这个探针要锁住的：
 * <ol>
 *   <li><b>被主题刷新覆盖</b>：applyTheme() 会递归调 button()，
 *       如果那里一律用 SECONDARY，精心分的级就被刷平了。</li>
 *   <li><b>监听器叠加</b>：悬停效果靠 addMouseListener 实现，
 *       而 apply() 可能被调用多次 —— 每次都加就会越叠越多。</li>
 * </ol>
 */
public class ButtonProbe {

    private static int pass = 0;
    private static int fail = 0;

    private static void check(String label, boolean ok) {
        if (ok) {
            pass++;
            System.out.println("  [PASS] " + label);
        } else {
            fail++;
            System.out.println("  [FAIL] " + label);
        }
    }

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println(" 按钮分级：层次清晰 + 不被主题刷新覆盖");
        System.out.println("============================================================");
        Theme.setEnabled(true);

        JPanel root = new JPanel();
        JButton primary = new JButton("生成报告");
        JButton danger = new JButton("清空");
        JButton ghost = new JButton("暂停");
        JButton normal = new JButton("反射检测");
        root.add(primary);
        root.add(danger);
        root.add(ghost);
        root.add(normal);

        // 模拟 RealtimeTab.applyButtonHierarchy() 的分级
        Theme.styleButton(primary, Theme.Btn.PRIMARY);
        Theme.styleButton(danger, Theme.Btn.DANGER);
        Theme.styleButton(ghost, Theme.Btn.GHOST);
        Theme.styleButton(normal, Theme.Btn.SECONDARY);

        System.out.println("  primary 背景 " + hex(primary.getBackground())
                + " 前景 " + hex(primary.getForeground()));
        System.out.println("  danger  背景 " + hex(danger.getBackground())
                + " 前景 " + hex(danger.getForeground()));
        System.out.println("  ghost   背景 " + hex(ghost.getBackground())
                + " 前景 " + hex(ghost.getForeground()));
        System.out.println("  normal  背景 " + hex(normal.getBackground())
                + " 前景 " + hex(normal.getForeground()));

        check("主要按钮是实心青底（与其它明显不同）",
                primary.getBackground().equals(Theme.ACCENT));
        check("主要按钮用深色字（青底上能看清）",
                Theme.isThemeDark(primary.getForeground()));
        check("危险按钮是红字", danger.getForeground().equals(Theme.DANGER));
        check("主要按钮与普通按钮背景不同（有层次）",
                !primary.getBackground().equals(normal.getBackground()));
        check("主要按钮加粗", primary.getFont().isBold());

        System.out.println();
        System.out.println("  ⭐ 关键坑 1：Theme.apply() 不能把分级刷掉");
        Theme.apply(root);
        System.out.println("  刷新后 primary 背景 " + hex(primary.getBackground())
                + "  danger 前景 " + hex(danger.getForeground()));
        check("apply() 后主要按钮仍是实心青底",
                primary.getBackground().equals(Theme.ACCENT));
        check("apply() 后危险按钮仍是红字",
                danger.getForeground().equals(Theme.DANGER));
        check("styleOf 记得住级别", Theme.styleOf(danger) == Theme.Btn.DANGER);

        System.out.println();
        System.out.println("  ⭐ 关键坑 2：反复 apply 不能叠加监听器");
        int before = primary.getMouseListeners().length;
        for (int i = 0; i < 5; i++) {
            Theme.styleButton(primary, Theme.Btn.PRIMARY);
            Theme.apply(root);
        }
        int after = primary.getMouseListeners().length;
        System.out.println("  监听器数量 前=" + before + "  后=" + after);
        check("反复调用 5 次，监听器没有增加", before == after);

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
