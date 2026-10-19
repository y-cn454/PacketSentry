import com.packetsentry.ui.Theme;
import java.awt.Font;

public class FontFixProbe {
    static int pass = 0, fail = 0;
    static void check(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  [PASS] " + label); }
        else { fail++; System.out.println("  [FAIL] " + label); }
    }
    public static void main(String[] a) {
        System.out.println("============================================================");
        System.out.println(" 字体必须能显示中文（否则界面全是豆腐块）");
        System.out.println("============================================================");

        String fam = Theme.currentFontFamily();
        System.out.println("  选中字体族: " + fam);

        // 用界面里真实出现的字检测
        String sample = "目标域名 方法 路径 作用 漏洞 详情 已抹 越权 注入 响应 请求 设置 状态"
                + "本地业务地图 AI 业务逻辑分析 隐藏入口 反射检测 审计该域名 清空"
                + "发现清单 批量越权 CVE 匹配 代码审计 生成报告 深挖选中 暂停 以身份";
        Font f = Theme.monoText();
        int bad = f.canDisplayUpTo(sample);
        System.out.println("  正文样本可显示: " + (bad == -1 ? "全部 ✓" : "第 " + bad + " 个字符起无法显示 ✗"));

        check("正文字体能显示全部中文", bad == -1);
        check("表头字体能显示中文", Theme.monoSmall().canDisplayUpTo(sample) == -1);
        check("标题字体能显示中文", Theme.title().canDisplayUpTo(sample) == -1);
        check("⭐ 选中的不是 Consolas（它没有中文字形）",
                !fam.equalsIgnoreCase("Consolas"));
        check("⭐ 选中的不是 Courier New（它没有中文字形）",
                !fam.equalsIgnoreCase("Courier New"));

        // 常见难字（字符集边界）
        String hard = "□ ■ ▶ ◀ ★ ☆ ⚠ ─ │ ┌ ┐ └ ┘ ← → ↑ ↓ · … —";
        Font ff = Theme.monoText();
        int badHard = ff.canDisplayUpTo(hard);
        System.out.println("  界面符号可显示: " + (badHard == -1 ? "全部 ✓" : "部分缺失（第 " + badHard + " 个）"));
        // 符号缺失不算失败 —— 但要知道
        check("字体选择是稳定的（两次调用一致）",
                Theme.currentFontFamily().equals(Theme.currentFontFamily()));

        System.out.println();
        System.out.println("  ⭐ 旧实现在本机会选到 Consolas，而它 canDisplayUpTo 中文 = "
                + new Font("Consolas", Font.PLAIN, 12).canDisplayUpTo("目标") + "（非 -1 = 显示不了）");

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}