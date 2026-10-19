import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.lang.reflect.Method;

/**
 * 第十四轮：{@code keep_alive} 的类型必须是 JSON <b>数字</b>。
 *
 * <h3>⚠️ 这个探针是被一个真实故障逼出来的</h3>
 * 线上现象：Burp 插件点「测试连接」直接失败。
 *
 * <p>排查结果（实测）：
 * <pre>
 *   "keep_alive": "-1"   → HTTP 400
 *        {"error":{"message":"time: missing unit in duration \"-1\""}}
 *   "keep_alive": -1     → HTTP 200，ollama ps 显示 <b>Forever</b>
 *   "keep_alive": "24h"  → HTTP 200，显示 24 hours from now
 * </pre>
 *
 * <p><b>根因：</b>Ollama 的 {@code /v1/chat/completions} 对<b>字符串</b>按 Go 的
 * {@code time.ParseDuration} 解析（必须有 {@code s}/{@code m}/{@code h} 单位），
 * 对<b>数字</b>才按秒处理。我传了字符串 {@code "-1"}，于是缺单位报错。
 *
 * <p><b>为什么当时没发现：</b>我是在 {@code /api/generate}（Ollama 原生接口）上
 * 验证这个写法的 —— 那个接口接受数字。而插件走的是 {@code /v1}。
 * <b>我把在 A 接口上验证过的结论用到了 B 接口上。</b>
 *
 * <p>所以这个探针断言的是<b>产出物的类型</b>，而不是「能不能跑通」——
 * 因为后者需要一台真实 Ollama，而类型错误是可以离线抓到的。
 */
public class KeepAliveProbe {

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

    public static void main(String[] args) throws Exception {
        System.out.println("============================================================");
        System.out.println(" keep_alive 的类型必须是 JSON 数字（不是字符串）");
        System.out.println("============================================================");

        Method m = Class.forName("com.packetsentry.llm.LlmClient")
                .getDeclaredMethod("keepAliveValue");
        m.setAccessible(true);
        JsonElement el = (JsonElement) m.invoke(null);

        if (!el.isJsonPrimitive()) {
            System.out.println("  ❌ 返回的不是 JsonPrimitive");
            fail++;
            System.exit(1);
        }
        JsonPrimitive v = el.getAsJsonPrimitive();

        String kind = v.isNumber() ? "number" : (v.isString() ? "string" : "其它");
        System.out.println("  实际产出：" + v + "　类型：" + kind);
        System.out.println("  序列化后：{\"keep_alive\":" + v + "}");

        check("keep_alive 是 JSON number（不是 string）", v.isNumber());
        check("keep_alive 值是 -1（负数 = 常驻不卸载）", v.isNumber() && v.getAsInt() == -1);
        check("不是字符串（字符串会触发 Go duration 解析错误）", !v.isString());

        // 真正序列化一遍，确认产出里没有引号
        JsonObject body = new JsonObject();
        body.add("keep_alive", v);
        String json = body.toString();

        check("序列化后是 \"keep_alive\":-1（无引号）", json.contains("\"keep_alive\":-1"));
        check("序列化后不是 \"keep_alive\":\"-1\"（有引号 = bug）",
                !json.contains("\"keep_alive\":\"-1\""));

        System.out.println();
        System.out.println("  ⭐ 这条断言的价值：");
        System.out.println("     它不需要真实 Ollama 就能跑，但能抓住这一类错误 ——");
        System.out.println("     把「在 A 接口验证过的写法」用到格式要求不同的 B 接口上。");

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
