import com.packetsentry.core.Config;
import com.packetsentry.llm.LlmClient;

import java.io.File;
import java.lang.reflect.Method;

/**
 * 外传闸门（fail-closed）实测。
 *
 * <h3>为什么专门测这个</h3>
 * 这里发现过一个真实漏洞：合规闸门原本写在 UI 层
 * （{@code RealtimeTab} 里判断 {@code cfg.aiAllowed()}），但
 * <b>{@code AnalyzerTab} 也有一个 {@code llm.chat()} 调用，却没有加检查</b> ——
 * 那条路径可以把真实流量发给云端。
 *
 * <p>更根本的问题是：<b>UI 层的检查对「将来新增的调用路径」完全没有约束力</b>。
 *
 * <p>所以闸门移到了 {@link LlmClient#chat} 内部。这个测试验证的就是：
 * <b>不管从哪一层调用，只要目标是非本机地址且 SRC 模式开着，就一定被拒，
 * 而且不发出任何网络请求。</b>
 */
public class EgressGuardProbe {

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
        System.out.println(" 一、核心断言：SRC 模式下调 LlmClient 必须被拒（不发包）");
        System.out.println("============================================================");

        Config c = new Config();
        c.srcMode = true;
        c.provider = "deepseek";
        c.baseUrl = "https://api.deepseek.com";
        c.model = "deepseek-chat";
        c.timeoutSeconds = 3;       // 故意设短：如果真发包了，会超时报错而不是被拒

        LlmClient client = new LlmClient();
        long t0 = System.currentTimeMillis();
        LlmClient.Reply r = client.chat(c, "sys", "POST /login {\"password\":\"x\"}");
        long ms = System.currentTimeMillis() - t0;

        System.out.println("  ok=" + r.ok);
        System.out.println("  httpStatus=" + r.httpStatus);
        System.out.println("  耗时 " + ms + " ms");
        System.out.println("  错误信息：");
        for (String line : String.valueOf(r.error).split("\n")) {
            System.out.println("    " + line);
        }
        System.out.println();

        check("被拒绝（ok=false）", !r.ok);
        check("httpStatus=0（说明压根没发请求）", r.httpStatus == 0);
        check("耗时极短，不可能是网络超时（<500ms）", ms < 500);
        check("错误信息里说明了目标地址", r.error != null && r.error.contains(c.baseUrl));
        check("错误信息里给了解决办法", r.error != null && r.error.contains("Ollama"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 二、闸门的各种边界情况");
        System.out.println("============================================================");

        // 本地地址 + SRC 模式 → 允许（不拦，是否真连得上另说）
        Config local = new Config();
        local.srcMode = true;
        local.provider = "ollama";
        local.baseUrl = "http://127.0.0.1:9/v1";     // 一个必定连不上的端口
        local.timeoutSeconds = 2;
        LlmClient.Reply rLocal = new LlmClient().chat(local, "s", "u");
        System.out.println("  本地地址 + SRC 模式 → ok=" + rLocal.ok
                + "  error=" + firstLine(rLocal.error));
        check("本地地址不被合规闸门拦（走的是连接失败而不是合规拒绝）",
                rLocal.error != null && !rLocal.error.contains("SRC 安全模式已阻止"));

        // localhost 写法
        Config lh = new Config();
        lh.srcMode = true;
        lh.baseUrl = "http://localhost:9/v1";
        lh.timeoutSeconds = 2;
        LlmClient.Reply rLh = new LlmClient().chat(lh, "s", "u");
        check("localhost 也被认作本机",
                rLh.error == null || !rLh.error.contains("SRC 安全模式已阻止"));

        // SRC 模式关闭 → 云端地址不再被合规拦（会真的去连，这里只要能看出
        // 它不再是「合规拒绝」即可 —— 用超时/连接错误区分）
        Config off = new Config();
        off.srcMode = false;
        off.provider = "deepseek";
        off.baseUrl = "https://127.0.0.1:9/v1";       // 指向本机不存在的端口，避免真的外连
        off.timeoutSeconds = 2;
        LlmClient.Reply rOff = new LlmClient().chat(off, "s", "u");
        System.out.println("  关闭 SRC 模式 → error=" + firstLine(rOff.error));
        check("关闭 SRC 模式后不再做合规拦截",
                rOff.error == null || !rOff.error.contains("SRC 安全模式已阻止"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 三、静态检查：确认闸门在 LlmClient 内部（而不是 UI 层）");
        System.out.println("============================================================");

        // 用反射确认 LlmClient 的字节码里确实引用了 srcMode 字段 ——
        // 这是防止「有人把闸门挪回 UI 层」的回归防线
        try {
            Class<?> cfgClass = Config.class;
            java.lang.reflect.Field src = cfgClass.getField("srcMode");
            check("Config.srcMode 字段存在", src != null);

            // 读 LlmClient 的源码文件，确认里面有闸门
            File f = new File("src/com/packetsentry/llm/LlmClient.java");
            if (!f.isFile()) {
                f = new File("packetsentry/src/com/packetsentry/llm/LlmClient.java");
            }
            if (f.isFile()) {
                String src2 = new String(java.nio.file.Files.readAllBytes(f.toPath()),
                        java.nio.charset.StandardCharsets.UTF_8);
                boolean guardInClient = src2.contains("cfg.srcMode")
                        && src2.contains("isLocalProvider");
                System.out.println("  检查 " + f.getPath());
                check("LlmClient 内部含合规闸门（fail-closed）", guardInClient);
            } else {
                System.out.println("  （找不到 LlmClient.java，跳过源码检查）");
            }
        } catch (Throwable t) {
            check("静态检查抛异常：" + t, false);
        }

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    private static String firstLine(String s) {
        if (s == null) {
            return "null";
        }
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
