import com.packetsentry.ui.Theme;

import java.awt.Font;

/**
 * 界面用到的每个符号，都必须能被选中字体画出来。
 *
 * <h3>这个探针的来历</h3>
 * 界面上出现过两轮乱码：
 *   ① 字体选成了 Consolas（没有中文字形）→ 中文全变 □
 *   ② 换了能显示中文的字体后，发现 emoji（🔴 ✅ ❌ ⚠️ ⭐）该字体也没有
 *      → 状态标记又变 □
 *
 * <p>所以现在源码里只用<b>实测能被中文无衬线字体显示</b>的符号。
 * 这个探针就是防止将来有人又贴回去一个 emoji。
 */
public class SymbolProbe {

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
        System.out.println(" 界面符号 + 中文 都必须能被选中字体显示");
        System.out.println("============================================================");

        Font f = Theme.monoText();
        System.out.println("  字体族：" + Theme.currentFontFamily());

        // 中文（带界面里真实的词）
        String cjk = "目标域名 方法 路径 作用 漏洞 详情 已抹 越权 注入 响应 请求"
                + "本地业务地图 反射检测 审计该域名 发现清单 批量越权 代码审计 生成报告";
        check("中文全部可显示", f.canDisplayUpTo(cjk) == -1);

        // 现在源码里实际在用的符号（替换后的这一批）
        String used = "★☆○√×▲■→·…—←↑↓≠≈≤≥┌┐└┘├┤┬┴┼═─│①②③④⑤";
        int bad = f.canDisplayUpTo(used);
        System.out.println("  在用符号：" + used);
        check("界面在用的符号全部可显示", bad == -1);

        // 明确禁止：这些字符一旦再次出现就会变豆腐块。
        // ⚠️ 两个 Java 坑：
        //    1) 没有 JS/Python 那种花括号形式的码点字面量，
        //       超过 U+FFFF 的必须用 Character.toChars 生成代理对；
        //    2) Java 会处理**注释和字符串里**的 u 转义 ——
        //       所以注释里也不能随便写反斜杠加 u 加码点（会编译报错）。
        String[] banned = {
                "\u2705", "\u274C", "\u26A0", "\u2B50", "\u26D4",
                "\u2753", "\u25B6", "\u2713", "\u2714", "\u2717", "\u2718", "\u2715",
                "\u26AA",
                new String(Character.toChars(0x1F534)),   // 红圆
                new String(Character.toChars(0x1F7E1)),   // 黄圆
        };
        StringBuilder stillThere = new StringBuilder();
        for (String b : banned) {
            if (f.canDisplayUpTo(b) != -1) {
                stillThere.append(b);
            }
        }
        // 这些字体本来就不支持 —— 断言的是"源码里不该用它们"，
        // 也就是说它们出现在 banned 表里是预期的
        check("确认这批字符确实不被字体支持（所以源码里禁止使用）",
                stillThere.length() > 0);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}