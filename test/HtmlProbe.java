import javax.swing.*;
import javax.swing.plaf.basic.BasicHTML;
import java.awt.Font;

public class HtmlProbe {
    static void probe(String name, String text) {
        JLabel l = new JLabel();
        l.setFont(l.getFont().deriveFont(Font.BOLD));
        l.setText(text);
        Object renderer = l.getClientProperty(BasicHTML.propertyKey);
        System.out.printf("  %-26s renderer=%-28s %s%n", name,
                renderer == null ? "null" : renderer.getClass().getSimpleName(),
                renderer != null ? "OK 会渲染 HTML" : "!! 会当纯文本显示");
    }

    public static void main(String[] a) {
        System.out.println("=== JLabel HTML 渲染探测（查 BasicHTML.propertyKey）===");
        probe("纯文本", "云端（数据会离开本机）");
        probe("标准 HTML", "<html><b>粗体</b></html>");
        probe("带 span+style", "<html><span style='color:#B03030'>云端</span></html>");
        probe("实际那串", "<html><span style='color:#B03030'>云端（数据会离开本机）</span> -> https://api.deepseek.com</html>");

        // 关键：GridBag 里先 add 再 setText（我代码里的顺序就是先 new 后 add 再 refresh）
        JPanel p = new JPanel(new java.awt.GridBagLayout());
        JLabel l3 = new JLabel();
        l3.setFont(l3.getFont().deriveFont(Font.BOLD));
        java.awt.GridBagConstraints gc = new java.awt.GridBagConstraints();
        gc.gridx = 0; gc.gridy = 0; gc.weightx = 1; gc.fill = java.awt.GridBagConstraints.HORIZONTAL;
        p.add(l3, gc);
        l3.setText("<html><span style='color:#B03030'>放进面板后再设</span></html>");
        Object r3 = l3.getClientProperty(BasicHTML.propertyKey);
        System.out.printf("  %-26s renderer=%-28s %s%n", "放进GridBag后再设HTML",
                r3 == null ? "null" : r3.getClass().getSimpleName(),
                r3 != null ? "OK 会渲染 HTML" : "!! 会当纯文本显示");

        // 对照：用 HTMLDocument 手工解析，看我的串能不能被解析器接受
        try {
            javax.swing.text.html.HTMLEditorKit kit = new javax.swing.text.html.HTMLEditorKit();
            javax.swing.text.html.HTMLDocument doc = (javax.swing.text.html.HTMLDocument)
                    kit.createDefaultDocument();
            kit.read(new java.io.StringReader(
                    "<html><span style='color:#B03030'>云端（数据会离开本机）</span> -> https://api.deepseek.com</html>"),
                    doc, 0);
            System.out.println("  HTML 解析器：接受该串（长度 " + doc.getLength() + "）");
        } catch (Exception e) {
            System.out.println("  HTML 解析器：拒绝 -> " + e);
        }
    }
}