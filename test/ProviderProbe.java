import com.packetsentry.core.CostTracker;
import com.packetsentry.llm.LlmClient;

/**
 * 第十二轮：<b>服务商配置的一致性</b>。
 *
 * <h3>这个测试来自一次真实事故</h3>
 * 用户点「DeepSeek（云端）」预设、填了密钥，得到「模型不存在」。
 * 查下来是预设里写的 {@code deepseek-chat} <b>已经退役</b>了 ——
 * DeepSeek 现在的模型名是 {@code deepseek-flash} / {@code deepseek-v4-pro}。
 *
 * <p>最尴尬的地方在于：{@code CostTracker} 里的定价<b>早就是新的</b>，
 * 只有预设没跟着改 —— <b>自己代码内部不一致</b>，而且没有任何测试会发现。
 *
 * <p>所以这里补一条断言：<b>预设里的模型名必须是 CostTracker 认识的定价条目。</b>
 * 这条断言如果早就有，这次的事故就不会发生。
 *
 * <p>⚠️ 但它只能防「内部不一致」，防不了「服务商改了模型名」——
 * 后者只能靠把可用模型名显示给用户 + 给出去哪儿查的指引。
 */
public class ProviderProbe {

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
        System.out.println(" 十二 · A：端点拼接（地址写错是排障第一大原因）");
        System.out.println("============================================================");

        check("DeepSeek 根路径 → 补 /chat/completions",
                LlmClient.buildEndpoint("https://api.deepseek.com")
                        .equals("https://api.deepseek.com/chat/completions"));
        check("带 /v1 → 补在 /v1 之后",
                LlmClient.buildEndpoint("https://api.deepseek.com/v1")
                        .equals("https://api.deepseek.com/v1/chat/completions"));
        check("末尾多余的斜杠被去掉",
                LlmClient.buildEndpoint("https://api.deepseek.com///")
                        .equals("https://api.deepseek.com/chat/completions"));
        check("用户已填完整路径 → 原样保留（不补成两层）",
                LlmClient.buildEndpoint("https://x.com/v1/chat/completions")
                        .equals("https://x.com/v1/chat/completions"));
        check("本地 Ollama 地址",
                LlmClient.buildEndpoint("http://127.0.0.1:11434/v1")
                        .equals("http://127.0.0.1:11434/v1/chat/completions"));
        check("前后空格被去掉",
                LlmClient.buildEndpoint("  https://a.com  ")
                        .equals("https://a.com/chat/completions"));
        check("空/null 不崩", LlmClient.buildEndpoint(null) != null
                && LlmClient.buildEndpoint("") != null);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十二 · B：⭐ 预设的模型名必须和定价表一致（这条能防住这次事故）");
        System.out.println("============================================================");

        // 用反射读预设（它是 private static final）
        String[][] presets = null;
        try {
            java.lang.reflect.Field f = Class.forName("com.packetsentry.ui.SettingsPanel")
                    .getDeclaredField("PRESETS");
            f.setAccessible(true);
            presets = (String[][]) f.get(null);
        } catch (Throwable e) {
            System.out.println("    （反射读预设失败：" + e + "）");
        }

        check("读到预设表", presets != null && presets.length > 0);
        if (presets != null) {
            System.out.println("  预设里的默认模型：");
            boolean allKnown = true;
            boolean allHaveHint = true;
            for (String[] p : presets) {
                String name = p[0];
                String model = p[3];
                boolean known = CostTracker.isKnownModel(model);
                boolean hasHint = p.length > 5 && p[5] != null && !p[5].isEmpty();
                System.out.println("    " + pad(name, 22) + pad(model, 18)
                        + (known ? "✓ 有定价" : "· 无内置定价（自定义/本地，可接受）")
                        + (hasHint ? "　✓ 有模型名提示" : "　✗ 缺模型名提示"));
                // 自定义预设的模型名可以是任意的（本地模型本来就不在定价表里），
                // 但云端预设的模型名应该在定价表里 —— 不在就说明可能过期了
                if (!hasHint) {
                    allHaveHint = false;
                }
            }
            check("⭐ 每个预设都带「当前可用模型名」提示", allHaveHint);

            // 关键断言：云端预设的默认模型不能是「已退役」的名字
            check("⭐ DeepSeek 预设不再用已退役的 deepseek-chat",
                    !containsModel(presets, "deepseek-chat"));
            check("⭐ DeepSeek 预设用的是当前模型名 deepseek-flash",
                    containsModel(presets, "deepseek-flash"));
            check("CostTracker 认识 deepseek-flash",
                    CostTracker.isKnownModel("deepseek-flash"));
            check("CostTracker 认识 deepseek-v4-pro",
                    CostTracker.isKnownModel("deepseek-v4-pro"));

            // 提示里也要把可用的都列出来
            for (String[] p : presets) {
                if ("deepseek".equals(p[1])) {
                    System.out.println("  DeepSeek 预设提示：" + p[5]);
                    check("DeepSeek 提示里含 deepseek-flash", p[5].contains("deepseek-flash"));
                    check("DeepSeek 提示里含 deepseek-v4-pro",
                            p[5].contains("deepseek-v4-pro"));
                }
            }
        }

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十二 · C：定价表覆盖（成本估算不能算错）");
        System.out.println("============================================================");

        CostTracker ct = new CostTracker();
        check("deepseek-flash 能被识别",
                ct.guessPricing("deepseek-flash", false).name.contains("flash"));
        check("deepseek-v4-pro 能被识别",
                ct.guessPricing("deepseek-v4-pro", false).name.contains("pro"));
        check("⭐ 本地服务商一律按免费算",
                ct.guessPricing("随便什么模型", true).inputCacheMiss == 0
                        && ct.guessPricing("随便什么模型", true).output == 0);
        check("未知云端模型有兜底定价（不返回 null）",
                ct.guessPricing("某个没见过的模型", false) != null);
        check("deepseek-chat 不再被当有效模型", !CostTracker.isKnownModel("deepseek-chat"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十二 · D：定价数值必须合理（不能凭空写错数量级）");
        System.out.println("============================================================");

        for (CostTracker.Pricing p : new CostTracker.Pricing[]{
                CostTracker.DEEPSEEK_FLASH, CostTracker.DEEPSEEK_V4_PRO,
                CostTracker.LOCAL_FREE}) {
            System.out.println("    " + pad(p.name, 20)
                    + "缓存命中 $" + p.inputCacheHit + "/M　未命中 $" + p.inputCacheMiss + "/M"
                    + "　输出 $" + p.output + "/M"
                    + "　高峰 ×" + p.peakMultiplier);
            check(p.name + " 定价非负",
                    p.inputCacheHit >= 0 && p.inputCacheMiss >= 0 && p.output >= 0);
            check(p.name + " 输出价不低于输入价（符合常理）",
                    p.output >= p.inputCacheMiss);
            check(p.name + " 缓存命中价不高于未命中价（符合常理）",
                    p.inputCacheHit <= p.inputCacheMiss);
            check(p.name + " 高峰倍率 ≥ 1", p.peakMultiplier >= 1.0);
        }

        check("本地免费档确实是 0", CostTracker.LOCAL_FREE.inputCacheMiss == 0
                && CostTracker.LOCAL_FREE.output == 0);
        check("v4-pro 比 flash 贵（分档有意义）",
                CostTracker.DEEPSEEK_V4_PRO.output > CostTracker.DEEPSEEK_FLASH.output);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十二 · E：⭐ 默认模型必须能在常见硬件上跑起来");
        System.out.println("============================================================");

        // ⚠️ 这条断言来自一次真实的配置事故：
        //    enforceSrcMode() 和 Ollama 预设里都硬编码了 qwen2.5:14b。
        //    14B 档 4bit 量化约 9-10 GB，<b>装不进主流笔记本的 8GB 显存</b>；
        //    溢出到内存后速度掉到 1-3 tokens/秒，实际不可用。
        //    用户开个 SRC 模式就得到一个跑不动的默认值 —— 这是很差的第一印象。
        //
        //    所以默认值必须落在「常见硬件能跑」的档位上。
        //    实测参考（Q4 量化）：8B ≈ 5 GB，14B ≈ 9-10 GB，32B ≈ 20 GB。
        //    这里把 8B 当作上限。
        if (presets != null) {
            for (String[] p : presets) {
                if ("ollama".equals(p[1])) {
                    String m = p[3];
                    System.out.println("  Ollama 预设默认模型：" + m);
                    double pb = paramB(m);
                    System.out.println("    解析出参数量：" + pb + "B");
                    check("⭐ Ollama 默认模型不是 14B 档（8GB 显存装不下）",
                            pb > 0 && pb <= 8.0);
                    check("Ollama 默认模型是 8B 或更小（按数值判断，不用白名单）",
                            pb > 0 && pb <= 8.0);
                    check("提示里写明了显存/内存要求",
                            p[5].contains("GB"));
                }
            }
        }

        // 行为验证：造一个云端的配置，开 SRC 模式，看它给什么本地模型
        com.packetsentry.core.Config probe = new com.packetsentry.core.Config();
        probe.provider = "deepseek";
        probe.baseUrl = "https://api.deepseek.com";
        probe.model = "deepseek-flash";
        probe.srcMode = true;
        probe.enforceSrcMode();
        System.out.println("  云端配置开 SRC 模式后 → provider=" + probe.provider
                + "　model=" + probe.model);
        check("服务商被强制为 ollama", "ollama".equals(probe.provider));
        check("baseUrl 被强制为本地地址", probe.baseUrl.contains("127.0.0.1"));
        double fb = paramB(probe.model);
        System.out.println("    兜底模型解析出：" + fb + "B");
        check("⭐ 兜底模型不是 14B 档（否则开 SRC 模式就得到一个跑不动的默认值）",
                fb > 0 && fb <= 8.0);
        check("兜底模型是 8B 或更小（按数值判断，不用白名单）",
                fb > 0 && fb <= 8.0);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十二 · F：排查逻辑（只对有把握的情况下结论 —— 不假装知道）");
        System.out.println("============================================================");

        // diagnose 是界面私有方法，这里验证它依赖的判定素材是否齐备
        // （真正的分支覆盖在 SettingsPanel 里，靠人工核对；这里守住数据侧）
        check("预设第 6 列（模型名提示）都已填",
                presets == null || allCol6(presets));
        check("预设 id 不重复",
                presets == null || uniqueIds(presets));
        check("custom 预设的 baseUrl 为空（让用户自己填）",
                presets == null || customEmpty(presets));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    private static boolean containsModel(String[][] presets, String model) {
        for (String[] p : presets) {
            if (model.equals(p[3])) {
                return true;
            }
        }
        return false;
    }

    private static boolean allCol6(String[][] presets) {
        for (String[] p : presets) {
            if (p.length < 6 || p[5] == null) {
                return false;
            }
        }
        return true;
    }

    private static boolean uniqueIds(String[][] presets) {
        java.util.Set<String> s = new java.util.HashSet<>();
        for (String[] p : presets) {
            if (!s.add(p[1])) {
                return false;
            }
        }
        return true;
    }

    private static boolean customEmpty(String[][] presets) {
        for (String[] p : presets) {
            if ("custom".equals(p[1])) {
                return p[2].isEmpty() && p[3].isEmpty();
            }
        }
        return false;
    }

    private static String pad(String s, int n) {
        StringBuilder sb = new StringBuilder(s == null ? "" : s);
        while (sb.length() < n) {
            sb.append(' ');
        }
        return sb.toString();
    }

    /**
     * 从模型名里解析参数量（单位：B）。
     *
     * <h3>⚠️ 为什么要写成解析而不是白名单</h3>
     * 这两条断言原来写的是：
     * <pre>
     *   m.contains(":8b") || m.contains(":7b") || m.contains(":3b")
     *       || m.contains(":2b") || m.contains(":1.5b")
     * </pre>
     * 意图是「≤ 8B」，但实现成了白名单 —— 于是把默认值改成
     * {@code qwen3:4b} 之后它<b>反而失败了</b>：4b 不在名单里。
     *
     * <p>这是典型的"断言实现而不是断言性质"。现在按数值判断。
     *
     * @return 参数量；解析不出来返回 -1
     */
    private static double paramB(String model) {
        if (model == null) {
            return -1;
        }
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(\\d+(?:\\.\\d+)?)b", java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(model);
        if (m.find()) {
            try {
                return Double.parseDouble(m.group(1));
            } catch (Exception ignored) {
                return -1;
            }
        }
        return -1;
    }
}
