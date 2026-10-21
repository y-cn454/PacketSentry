import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.packetsentry.core.Config;
import com.packetsentry.core.CostTracker;
import com.packetsentry.core.RealtimePipe;
import com.packetsentry.ui.RealtimeTab;
import com.packetsentry.ui.Theme;

import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;
import java.awt.Container;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.lang.reflect.Proxy;

/**
 * 把 RealtimeTab 的工具栏区域离屏渲染成 PNG，用来肉眼确认排版。
 *
 * <p>离屏渲染（{@code printAll}）不需要真实窗口，headless 下也能跑，
 * 所以能在 CI / 命令行里出图对照。
 */
public class RenderBar {

    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> iface, String name) {
        return (T) Proxy.newProxyInstance(
                iface.getClassLoader(),
                new Class<?>[]{iface},
                (proxy, m, args) -> {
                    Class<?> rt = m.getReturnType();
                    if ("getHelpers".equals(m.getName())) {
                        return stub(IExtensionHelpers.class, "helpers");
                    }
                    if (rt == void.class) return null;
                    if (rt == boolean.class) return Boolean.FALSE;
                    if (rt == int.class) return 0;
                    if (rt == long.class) return 0L;
                    if (rt == byte[].class) return new byte[0];
                    if (rt == String.class) return "";
                    if (rt.isArray()) return java.lang.reflect.Array.newInstance(rt.getComponentType(), 0);
                    if (rt.isInterface()) return stub(rt, name + ".x");
                    return null;
                });
    }

    public static void main(String[] args) throws Exception {
        // ⚠️ 构造 RealtimeTab 会创建 Swing 组件，AWT 的 EDT 是**非守护线程** ——
        //    main 返回后 JVM 也不会退出，命令行看起来就"卡住"了。
        //    这里用看门狗 + 显式 exit 保证一定结束。
        final int[] code = {1};
        Thread worker = new Thread(() -> {
            try {
                run(args);
                code[0] = 0;
            } catch (Throwable t) {
                System.out.println("失败: " + t);
                t.printStackTrace();
            }
        }, "render-bar");
        worker.setDaemon(true);
        worker.start();
        worker.join(60_000L);
        if (worker.isAlive()) {
            System.out.println("超时（60s）—— 渲染阻塞");
        }
        System.exit(code[0]);
    }

    private static void run(String[] args) throws Exception {
        int w = 1820;
        int h = 190;
        String outPath = args.length > 0 ? args[0] : "bar.png";
        int themeOn = args.length > 1 ? Integer.parseInt(args[1]) : 1;

        final Object[] holder = new Object[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                Theme.setEnabled(themeOn == 1);
                Config cfg = new Config();
                RealtimePipe pipe = new RealtimePipe(() -> cfg);
                CostTracker cost = new CostTracker();
                IBurpExtenderCallbacks cb = stub(IBurpExtenderCallbacks.class, "cb");
                RealtimeTab tab = new RealtimeTab(pipe, cost, () -> cfg, cb);
                holder[0] = tab;
            } catch (Throwable t) {
                System.out.println("构造失败: " + t);
                t.printStackTrace();
            }
        });

        Container tab = (Container) holder[0];
        if (tab == null) {
            System.out.println("没有 tab，退出");
            throw new IllegalStateException("tab 未构造");
        }

        // 只截顶部两块（row1 + row2 用 BorderLayout.NORTH，是 tab 的第 0 个组件）
        tab.setSize(w, h);
        layoutAll(tab);

        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(Theme.isEnabled() ? new java.awt.Color(0x13, 0x15, 0x18) : new java.awt.Color(240, 240, 240));
        g.fillRect(0, 0, w, h);
        tab.printAll(g);
        g.dispose();

        ImageIO.write(img, "png", new File(outPath));
        System.out.println("已输出: " + new File(outPath).getAbsolutePath());

        // 逐控件打印实际矩形 —— 能看出有没有重叠或溢出
        System.out.println();
        System.out.println("== row1 控件矩形 ==");
        dump(tab.getComponent(0), "");
        System.out.println("== row2 控件矩形 ==");
        // row2 是 BorderLayout.NORTH 之外的那块，从 tab 里按顺序找带 BoxLayout 的面板
        for (java.awt.Component c : tab.getComponents()) {
            if (c != tab.getComponent(0) && c instanceof Container) {
                dump(c, "");
                break;
            }
        }
    }

    private static void dump(java.awt.Component c, String indent) {
        if (c instanceof Container) {
            for (java.awt.Component k : ((Container) c).getComponents()) {
                String label = k.getClass().getSimpleName();
                if (k instanceof javax.swing.AbstractButton) {
                    label += '[' + ((javax.swing.AbstractButton) k).getText() + ']';
                } else if (k instanceof javax.swing.JLabel) {
                    label += '[' + ((javax.swing.JLabel) k).getText() + ']';
                } else if (k instanceof javax.swing.JComboBox) {
                    Object sel = ((javax.swing.JComboBox<?>) k).getSelectedItem();
                    label += "[" + (sel == null ? "—" : String.valueOf(sel)) + "]";
                }
                if (!(k instanceof Container) || k instanceof javax.swing.JComboBox
                        || k instanceof javax.swing.JTextField || k instanceof javax.swing.JLabel
                        || k instanceof javax.swing.AbstractButton) {
                    System.out.println(indent + "  " + label + "  " + k.getBounds());
                }
                if (k instanceof Container && !(k instanceof javax.swing.JComboBox)
                        && !(k instanceof javax.swing.JTextField)) {
                    dump(k, indent + "  ");
                }
            }
        }
    }

    private static void layoutAll(java.awt.Component c) {
        if (c instanceof Container) {
            Container ct = (Container) c;
            ct.doLayout();
            for (java.awt.Component k : ct.getComponents()) {
                layoutAll(k);
            }
        }
    }
}
