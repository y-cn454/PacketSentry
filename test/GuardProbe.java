import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 单飞守卫检查 —— 「点了没反应就再点几次」导致的重复请求 / 重复扫描。
 *
 * <h3>这个套件的来历</h3>
 *
 * 用户反馈三个问题：
 * <pre>
 *   ① 「AI 挖洞一直在请求模型」
 *   ② 「CVE 匹配和本地挖洞也可能存在类似 bug」
 *   ③ 「OWASP Top10 应该结合到分析中，不要单独一个按钮」
 * </pre>
 *
 * 查下来 ① 的根因是<b>没有防重入</b>：
 * <pre>
 *   huntBtn.addActionListener(e -&gt; runHunting());   // 每次点击都起一个新线程
 *   // runHunting 内部：new Thread(() -&gt; llm.chat(...)).start();
 *   // 没有「正在跑」的标记，也没有禁用按钮
 * </pre>
 * 本地 4B 模型处理一份完整 prompt 要 30–120 秒，期间界面没有任何反馈，
 * 用户以为没反应就会反复点 —— 点 5 次就是 5 个并发请求。
 * 在 Burp 的 HTTP history 里看，就是「一直在请求模型」。
 *
 * <p>② 的根因相同；而且 {@code runLocalHunting} 更糟 —— 它是<b>同步跑在 EDT 上</b>的，
 * 800 条记录要 5 秒以上，界面整个冻住。
 *
 * <p>③ 是设计问题：OWASP 分类只有和具体发现放在一起看才有意义，
 * 单独一个按钮会让人在两份清单之间来回对照。
 *
 * <h3>这个套件守什么</h3>
 * <ol>
 *   <li>四个耗时功能都必须注册守卫，且走 {@code runGuarded} / {@code enterGuard}</li>
 *   <li>{@code runGuarded} 必须在 finally 里释放（漏了按钮就永久禁用）</li>
 *   <li>{@code showCveMatch} 的线程必须在 finally 里释放</li>
 *   <li>OWASP 按钮必须已删除，且三条分析路径都带上了 OWASP 归类</li>
 *   <li>{@code runLocalHunting} 不能再同步跑 {@code LocalHunter.hunt}</li>
 * </ol>
 */
public class GuardProbe {

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

    /** 取一个方法体（按花括号配平），找不到返回 null。 */
    private static String methodBody(String src, String signature) {
        int i = src.indexOf(signature);
        if (i < 0) {
            return null;
        }
        int start = src.indexOf('{', i);
        if (start < 0) {
            return null;
        }
        int depth = 0;
        for (int k = start; k < src.length(); k++) {
            char c = src.charAt(k);
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return src.substring(start, k + 1);
                }
            }
        }
        return null;
    }

    private static int count(String haystack, String needle) {
        int n = 0;
        int i = 0;
        while ((i = haystack.indexOf(needle, i)) >= 0) {
            n++;
            i += needle.length();
        }
        return n;
    }

    public static void main(String[] args) throws IOException {
        System.out.println("============================================================");
        System.out.println(" 单飞守卫检查：重复点击不能再重复发请求 / 重复扫描");
        System.out.println("============================================================");

        Path src = Path.of(args.length > 0 ? args[0] : "src");
        Path rt = src.resolve("com/packetsentry/ui/RealtimeTab.java");
        if (!Files.exists(rt)) {
            System.out.println("  [FAIL] 找不到 " + rt);
            System.exit(1);
        }
        String t = new String(Files.readAllBytes(rt), StandardCharsets.UTF_8);

        // ============================================================
        // ① 守卫基础设施必须存在
        // ============================================================
        System.out.println("\n  [①] 守卫基础设施");
        check("runningKeys 用并发集合（EDT 与后台线程都会读写）",
                t.contains("runningKeys")
                        && t.contains("ConcurrentHashMap.newKeySet()"));
        check("guardedButtons 记录 key → 按钮",
                t.contains("guardedButtons"));
        check("有 enterGuard 方法", t.contains("private boolean enterGuard("));
        check("有 exitGuard 方法", t.contains("private void exitGuard("));
        check("有 runGuarded 统一封装", t.contains("private void runGuarded("));

        // ============================================================
        // ② 四个耗时功能都必须注册守卫
        // ============================================================
        System.out.println("\n  [②] 四个耗时功能都注册了守卫");
        String[][] keys = {
                {"hunt", "AI 挖洞"},
                {"localHunt", "本地挖洞"},
                {"cve", "CVE 匹配"},
                {"businessAi", "AI 业务逻辑分析"},
        };
        for (String[] k : keys) {
            check("guardButton(\"" + k[0] + "\") —— " + k[1],
                    t.contains("guardButton(\"" + k[0] + "\""));
        }

        // ============================================================
        // ③ 三个功能必须真的走守卫
        // ============================================================
        System.out.println("\n  [③] 三个功能走守卫");
        check("AI 挖洞走 runGuarded(\"hunt\")", t.contains("runGuarded(\"hunt\""));
        check("本地挖洞走 runGuarded(\"localHunt\")", t.contains("runGuarded(\"localHunt\""));
        check("CVE 匹配调用 enterGuard(\"cve\")", t.contains("enterGuard(\"cve\""));

        // ============================================================
        // ④ runGuarded 必须在 finally 里释放
        // ============================================================
        System.out.println("\n  [④] 守卫必须在 finally 里释放（漏了就永久禁用按钮）");
        String rg = methodBody(t, "private void runGuarded(");
        if (rg == null) {
            check("能取到 runGuarded 方法体", false);
        } else {
            check("runGuarded 方法体可解析", true);
            check("runGuarded 里有 finally", rg.contains("finally"));
            // finally 之后必须出现 exitGuard
            int fi = rg.indexOf("finally");
            check("finally 里调用了 exitGuard(key)",
                    fi >= 0 && rg.indexOf("exitGuard(key)", fi) > fi);
            check("任务异常也不会漏释放（catch Throwable）",
                    rg.contains("catch (Throwable"));
        }

        // ============================================================
        // ⑤ showCveMatch 的线程必须在 finally 里释放
        // ============================================================
        System.out.println("\n  [⑤] CVE 扫描线程释放守卫");
        String cve = methodBody(t, "private void showCveMatch(");
        if (cve == null) {
            check("能取到 showCveMatch 方法体", false);
        } else {
            check("showCveMatch 方法体可解析", true);
            check("showCveMatch 有 finally", cve.contains("finally"));
            check("showCveMatch 在 finally 里 exitGuard(\"cve\")",
                    cve.contains("exitGuard(\"cve\")"));
        }

        // ============================================================
        // ⑥ 本地挖洞不能再同步跑在 EDT 上
        // ============================================================
        System.out.println("\n  [⑥] 本地挖洞已移到后台线程");
        String lh = methodBody(t, "private void runLocalHunting(");
        if (lh == null) {
            check("能取到 runLocalHunting 方法体", false);
        } else {
            check("runLocalHunting 方法体可解析", true);
            int guardAt = lh.indexOf("runGuarded(");
            // ⚠️ 这里必须匹配带参数的调用（hunt(poolF)），不能只找 "LocalHunter.hunt(" ——
            //    因为方法上方的注释里也写了 "LocalHunter.hunt()" 用来解释旧实现，
            //    那会把 indexOf 引到注释里，测试误报。
            int huntAt = lh.indexOf("LocalHunter.hunt(poolF)");
            check("LocalHunter.hunt 出现在 runGuarded 之后（即已在后台体里）",
                    guardAt >= 0 && huntAt > guardAt);
            check("有独立的渲染方法 showLocalHuntResult",
                    t.contains("private void showLocalHuntResult("));
        }

        // ============================================================
        // ⑦ OWASP 按钮必须已删除
        // ============================================================
        System.out.println("\n  [⑦] OWASP 不再单独生成按钮");
        check("没有 new JButton(\"OWASP",
                !t.contains("new JButton(\"OWASP"));
        check("没有 showOwasp( 调用",
                !t.contains("showOwasp("));
        check("owaspBtn 变量已删除",
                !t.contains("owaspBtn"));

        // ============================================================
        // ⑧ OWASP 必须结合进三条路径
        // ============================================================
        System.out.println("\n  [⑧] OWASP 已结合进分析与报告");
        String hunt = methodBody(t, "private void onHuntResult(");
        check("AI 挖洞结果里带上 OWASP 归类",
                hunt != null && hunt.contains("owaspCompact()"));
        String lhr = methodBody(t, "private void showLocalHuntResult(");
        check("本地挖洞结果里带上 OWASP 归类",
                lhr != null && lhr.contains("owaspCompact()"));
        check("报告骨架里带上 OWASP 覆盖度",
                t.contains("owaspSummary()") && t.contains("skeleton = skeleton + "));

        // ============================================================
        // ⑨ llm.chat 调用点数量（防止新增未受保护的调用）
        // ============================================================
        System.out.println("\n  [⑨] 模型调用点数量");
        int chats = count(t, "llm.chat(");
        System.out.println("        llm.chat( 出现 " + chats + " 处");
        check("llm.chat 调用点仍为 3 处（新增调用请一并加守卫）", chats == 3);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 小计：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        if (fail > 0) {
            System.exit(1);
        }
    }
}
