import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 接线检查 —— 在源码层面找「写了但没接上」的 bug。
 *
 * <h3>这个套件的来历</h3>
 * 用户点了「隐藏入口」按钮没有任何反应。查下来发现：
 * <pre>
 *   JButton routeAuditBtn = new JButton("隐藏入口");
 *   routeAuditBtn.setToolTipText("...");      // 有 tooltip
 *   row1.add(routeAuditBtn);                  // 加进了界面
 *   // 但从来没有 routeAuditBtn.addActionListener(...)
 * </pre>
 * 而 {@code auditRoutes()} 方法写得完全正确 —— 只是永远不被调用。
 *
 * <p>这类 bug 特别隐蔽：界面看起来正常、方法也对，只少了一行接线。
 * 靠人眼 review 很容易漏，所以用静态检查兜住。
 *
 * <h3>同类 bug：域名哨兵</h3>
 * 「AI 挖洞」提示「还没有抓到流量」，但状态栏显示抓了 3282 个包。
 * 根因是直接用 {@code hostBox.getSelectedItem()} 拿 host，
 * 而它在「不过滤」时是哨兵文本 {@code (全部)} —— 和真实 host 永远不相等。
 * 正确做法是用 {@code selectedHost()}（把哨兵转成 null）。
 */
public class WiringProbe {

    private static int pass = 0;
    private static int fail = 0;

    private static void check(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  [PASS] " + label); }
        else { fail++; System.out.println("  [FAIL] " + label); }
    }

    public static void main(String[] args) throws IOException {
        System.out.println("============================================================");
        System.out.println(" 接线检查：写了的功能必须真的接上");
        System.out.println("============================================================");

        Path src = Path.of(args.length > 0 ? args[0] : "src");
        Path rt = src.resolve("com/packetsentry/ui/RealtimeTab.java");
        if (!Files.exists(rt)) {
            System.out.println("  [FAIL] 找不到 " + rt);
            System.exit(1);
        }
        String t = new String(Files.readAllBytes(rt), StandardCharsets.UTF_8);

        // ---------- ① 每个 JButton 都必须有 addActionListener ----------
        System.out.println("\n  [①] 按钮必须接监听器");
        Pattern decl = Pattern.compile(
                "(?:JButton|java\\.swing\\.JButton)\\s+(\\w+)\\s*=\\s*new JButton\\(\"([^\"]+)\"\\)");
        Matcher m = decl.matcher(t);
        List<String> unwired = new ArrayList<>();
        int total = 0;
        while (m.find()) {
            total++;
            String var = m.group(1);
            String text = m.group(2);
            boolean wired = t.matches("(?s).*" + Pattern.quote(var) + "\\.addActionListener.*");
            if (!wired) {
                unwired.add(var + "(" + text + ")");
            }
        }
        System.out.println("    共 " + total + " 个按钮");
        check("⭐ 所有按钮都接了监听器（漏接 = 点了没反应）", unwired.isEmpty());
        for (String u : unwired) {
            System.out.println("      未接线：" + u);
        }

        // ---------- ② 不能直接拿下拉框的值当 host ----------
        System.out.println("\n  [②] host 过滤必须用 selectedHost()，不能直接读下拉框");
        // 找形如 hostBox.getSelectedItem() 被赋给 host 的写法
        Pattern direct = Pattern.compile(
                "String\\s+host\\s*=\\s*[^;]*hostBox\\.getSelectedItem\\(\\)");
        Matcher dm = direct.matcher(t);
        List<Integer> badLines = new ArrayList<>();
        while (dm.find()) {
            badLines.add(countLines(t, dm.start()));
        }
        System.out.println("    直接读下拉框的写法：" + badLines.size() + " 处");
        for (int ln : badLines) {
            System.out.println("      第 " + ln + " 行");
        }
        check("⭐ 没有直接读下拉框当 host（哨兵会产生假空结果）", badLines.isEmpty());
        check("selectedHost() 确实存在",
                t.contains("private String selectedHost()"));
        check("selectedHost 会把 (全部) 转成 null",
                t.contains("\"(全部)\".equals(") || t.contains("\"(全部)\".equalsIgnoreCase("));

        // ---------- ③ 每个 private void 方法至少被调用一次 ----------
        System.out.println("\n  [③] 私有方法不能是死代码");
        Pattern method = Pattern.compile("private\\s+void\\s+(\\w+)\\s*\\(\\s*\\)\\s*\\{");
        Matcher mm = method.matcher(t);
        List<String> dead = new ArrayList<>();
        int mTotal = 0;
        while (mm.find()) {
            String name = mm.group(1);
            mTotal++;
            // 出现次数：定义 1 次 + 调用若干次
            int occurrences = countOccurrences(t, name + "()");
            if (occurrences <= 1) {
                dead.add(name);
            }
        }
        System.out.println("    共 " + mTotal + " 个无参私有方法");
        check("⭐ 没有『写了但从不调用』的私有方法", dead.isEmpty());
        for (String d : dead) {
            System.out.println("      死代码：" + d);
        }

        // ---------- ④ 按钮文字与视觉分级的一致性 ----------
        System.out.println("\n  [④] 危险动作应该有视觉分级");
        check("DANGER 分级里包含「清空」", t.contains("map.put(\"清空\", Theme.Btn.DANGER)"));
        check("DANGER 分级里包含「越权测试」",
                t.contains("map.put(\"越权测试\", Theme.Btn.DANGER)"));
        check("PRIMARY 分级里包含「生成报告」",
                t.contains("map.put(\"生成报告\", Theme.Btn.PRIMARY)"));

        // ---------- ⑤ AI / 本地挖洞都要过闸门 ----------
        System.out.println("\n  [⑤] 挖洞产出必须过报告准入闸门");
        check("AI 挖洞调用了 ReportGate 或 Hypothesis.gate",
                t.contains("ReportGate") || t.contains("promotable()"));
        check("复核时用 promotable() 判断够不够格",
                t.contains("promotable()"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    private static int countLines(String s, int upto) {
        int n = 1;
        for (int i = 0; i < upto && i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                n++;
            }
        }
        return n;
    }

    private static int countOccurrences(String hay, String needle) {
        int n = 0;
        int i = 0;
        while ((i = hay.indexOf(needle, i)) >= 0) {
            n++;
            i += needle.length();
        }
        return n;
    }
}
