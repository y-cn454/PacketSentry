package com.packetsentry.llm;

import com.packetsentry.core.Config;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * AI 调用客户端，走 OpenAI 兼容格式。
 *
 * <p>为什么要兼容格式：Ollama、LM Studio、vLLM、DeepSeek、通义、智谱、OpenAI
 * 现在都暴露 {@code /v1/chat/completions}。写一个客户端就能接全部，
 * 而且<b>换服务商不用改代码</b>。
 *
 * <p><b>本类只负责"把已经脱敏好的文本发出去并取回结果"。</b>
 * 它不做脱敏、不做扫描、不做判断 —— 那些在调用之前就该完成。
 * 这样职责单一，也让"到底发出去了什么"这件事容易审计。
 */
public final class LlmClient {

    /** 调用结果。 */
    public static final class Reply {
        public final boolean ok;
        public final String content;
        public final String error;
        public final int httpStatus;
        public final long elapsedMs;

        private Reply(boolean ok, String content, String error, int httpStatus, long elapsedMs) {
            this.ok = ok;
            this.content = content;
            this.error = error;
            this.httpStatus = httpStatus;
            this.elapsedMs = elapsedMs;
        }

        static Reply ok(String content, int status, long ms) {
            return new Reply(true, content, null, status, ms);
        }

        static Reply fail(String error, int status, long ms) {
            return new Reply(false, null, error, status, ms);
        }
    }

    private final HttpClient http;

    public LlmClient() {
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * 本地服务商的 {@code keep_alive} 取值 —— <b>必须是一个 JSON 数字</b>。
     *
     * <h3>▲ 这个方法是踩了一个真 bug 才抽出来的</h3>
     * 我一开始写的是 {@code body.addProperty("keep_alive", "-1")} —— 传的是
     * <b>字符串</b>。结果「测试连接」直接失败：
     * <pre>
     *   HTTP 400  {"error":{"message":"time: missing unit in duration \"-1\""}}
     * </pre>
     * 原因是 Ollama 的 {@code /v1/chat/completions} 对<b>字符串</b>按 Go duration
     * 解析（必须有 {@code s}/{@code m}/{@code h} 单位），对<b>数字</b>才按秒处理。
     *
     * <p>实测对照：
     * <pre>
     *   "keep_alive": "-1"   → HTTP 400        （字符串，缺单位）
     *   "keep_alive": -1     → HTTP 200，ollama ps 显示 <b>Forever</b>
     *   "keep_alive": "24h"  → HTTP 200，显示 24 hours from now
     * </pre>
     *
     * <p><b>为什么当时没测出来：</b>我是拿 {@code /api/generate}（Ollama 原生接口）
     * 试的，那个接口接受数字 —— 而插件走的是 {@code /v1}。两个接口的格式要求不同，
     * 我却把在 A 上验证过的写法用到了 B 上。
     *
     * <p>{@code keep_alive} 为负数 = 常驻不卸载。数字形式是官方文档的写法。
     *
     * @return 一个 JSON number 类型的 {@code -1}
     */
    static com.google.gson.JsonPrimitive keepAliveValue() {
        return new com.google.gson.JsonPrimitive(-1);
    }

    /**
     * 发一次对话请求。
     *
     * @param cfg        配置（提供 baseUrl / model / key / 超时）
     * @param system     系统提示词
     * @param user       用户内容（<b>应当是已经脱敏过的</b>）
     */
    public Reply chat(Config cfg, String system, String user) {
        long t0 = System.currentTimeMillis();

        // ★ 合规闸门放在<b>真正发生外传的地方</b>。
        //
        // ▲ 这个位置是踩过坑才定下来的。早期版本把闸门写在 UI 层
        //    （RealtimeTab 里判断 cfg.aiAllowed()），结果：
        //      · AnalyzerTab（报文编辑器里的标签页）也有一个 llm.chat() 调用，
        //        却没有加检查 —— 那条路径可以把真实流量发给云端；
        //      · 设置页的「保存」不施加 SRC 约束，用户能把地址改回云端再保存；
        //      · 更根本的是：UI 层的检查对「将来新增的调用路径」完全没有约束力。
        //
        //    现在闸门在客户端内部：<b>任何</b>调用者都绕不过去。
        //    这叫 fail-closed —— 限制落在最靠近风险的那一层。
        if (cfg != null && cfg.srcMode && !cfg.isLocalProvider()) {
            return Reply.fail(
                    "SRC 安全模式已阻止本次外传。\n\n"
                            + "目标地址  " + cfg.baseUrl + "\n"
                            + "该地址不是本机（127.0.0.1 / localhost），"
                            + "SRC 安全模式下不允许把业务数据发给它。\n\n"
                            + "多数 SRC 规则禁止向第三方披露业务数据（含用户资料）。\n\n"
                            + "两个选择：\n"
                            + "  1. 到「设置」页把服务商换成 Ollama / LM Studio（本地）\n"
                            + "  2. 关闭 SRC 安全模式（请自行确认合规性）",
                    0, System.currentTimeMillis() - t0);
        }

        int status = 0;
        try {
            String endpoint = buildEndpoint(cfg.baseUrl);

            JsonObject sysMsg = new JsonObject();
            sysMsg.addProperty("role", "system");
            sysMsg.addProperty("content", system);

            JsonObject userMsg = new JsonObject();
            userMsg.addProperty("role", "user");
            userMsg.addProperty("content", user);

            JsonArray messages = new JsonArray();
            messages.add(sysMsg);
            messages.add(userMsg);

            JsonObject body = new JsonObject();
            body.addProperty("model", cfg.model);
            body.add("messages", messages);
            body.addProperty("temperature", cfg.temperature);
            body.addProperty("stream", false);

            // ▲ 本地服务商：让模型常驻，别每次分析都重付加载代价。
            //
            //    这是实测踩出来的。Ollama 默认 5 分钟不用就卸载模型，
            //    而卸载后下一次请求要重新把 4.6 GB 权重读进内存再拷进显存 ——
            //    实测首次调用 31.6 秒（其中 load 占大部分），
            //    而内存紧张时更糟：有一次冷启动单次生成只有 0.04 tokens/秒，
            //    直接撞上插件的 120 秒超时。
            //
            //    常驻之后第二次调用降到 21.8 秒、稳定 45 tokens/s。
            //
            //    为什么放在请求里而不是让用户设 OLLAMA_KEEP_ALIVE 环境变量：
            //    环境变量只在新启动的进程里生效，用户改了环境变量却没重启服务
            //    就会静默失效（我自己就踩了这个坑 —— 设了 -1 但 ollama ps
            //    仍然显示「4 分钟后卸载」）。写在请求里则每次都确定生效。
            //
            //    ▲ 只对本地服务商加这个字段：云端 API 不认它，可能直接报 400。
            if (cfg.isLocalProvider()) {
                body.add("keep_alive", keepAliveValue());
            }

            HttpRequest.Builder rb = HttpRequest.newBuilder()
                    .uri(URI.create(endpoint))
                    .timeout(Duration.ofSeconds(Math.max(5, cfg.timeoutSeconds)))
                    .header("Content-Type", "application/json; charset=UTF-8")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8));

            String key = cfg.resolveApiKey();
            if (key != null && !key.isEmpty()) {
                rb.header("Authorization", "Bearer " + key);
            }

            HttpResponse<String> resp = http.send(rb.build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            status = resp.statusCode();
            long ms = System.currentTimeMillis() - t0;

            if (status < 200 || status >= 300) {
                String snippet = snippet(resp.body(), 400);
                return Reply.fail("HTTP " + status + "：" + snippet, status, ms);
            }
            String content = extractContent(resp.body());
            if (content == null) {
                return Reply.fail("响应里找不到 choices[0].message.content："
                        + snippet(resp.body(), 400), status, ms);
            }
            return Reply.ok(content, status, ms);

        } catch (java.net.http.HttpTimeoutException e) {
            return Reply.fail("请求超时（" + cfg.timeoutSeconds + " 秒）。"
                    + "本地模型首次加载可能较慢，可调大超时。", status,
                    System.currentTimeMillis() - t0);
        } catch (java.net.ConnectException e) {
            return Reply.fail("连不上 " + cfg.baseUrl + "。"
                    + "若用本地模型，请确认 Ollama / LM Studio 已启动。", status,
                    System.currentTimeMillis() - t0);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return Reply.fail("请求失败：" + e, status, System.currentTimeMillis() - t0);
        } catch (Exception e) {
            return Reply.fail("未预期的错误：" + e, status, System.currentTimeMillis() - t0);
        }
    }

    // ------------------------------------------------------------------

    /** 补齐到 /chat/completions；用户填了完整路径就原样用。 */
    /**
     * public 是为了让设置界面能<b>把实际会请求的地址显示给用户</b> ——
     * 地址拼错是排障时最常见的原因之一，让用户看到完整路径比解释规则更有效。
     */
    public static String buildEndpoint(String baseUrl) {
        String b = baseUrl == null ? "" : baseUrl.trim();
        while (b.endsWith("/")) {
            b = b.substring(0, b.length() - 1);
        }
        if (b.endsWith("/chat/completions")) {
            return b;
        }
        return b + "/chat/completions";
    }

    /** 从 OpenAI 兼容响应里取 choices[0].message.content。 */
    static String extractContent(String json) {
        try {
            JsonObject o = JsonParser.parseString(json).getAsJsonObject();
            JsonArray choices = o.getAsJsonArray("choices");
            if (choices == null || choices.size() == 0) {
                return null;
            }
            JsonObject first = choices.get(0).getAsJsonObject();
            JsonObject msg = first.getAsJsonObject("message");
            if (msg == null || !msg.has("content")) {
                return null;
            }
            return msg.get("content").getAsString();
        } catch (Exception e) {
            return null;
        }
    }

    private static String snippet(String s, int max) {
        if (s == null) {
            return "";
        }
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= max ? t : t.substring(0, max) + "…";
    }
}
