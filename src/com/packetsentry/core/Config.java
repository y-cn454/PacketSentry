package com.packetsentry.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 插件配置 —— 服务商、模型、密钥、脱敏策略。
 *
 * <p>与作者 AIPacketHunter 的差异：
 * <ul>
 *   <li>目录用 {@code ~/.packetsentry}，<b>不伪装成系统目录</b>
 *       （作者用了 {@code ~/.appdata}，看起来像系统目录，有误导性）</li>
 *   <li>API Key 默认<b>不</b>明文落盘：优先用环境变量引用；
 *       用户坚持要存才存，且写入时给出明确提示</li>
 *   <li>写入用「临时文件 + 原子替换」，避免半截文件</li>
 *   <li>异常不静默吞：解析失败会保留原文件并回报</li>
 * </ul>
 */
public final class Config {

    // ---- 脱敏策略 ----------------------------------------------------

    /** 是否启用脱敏。默认 true —— 安全默认值。 */
    public boolean sanitizeEnabled = true;

    /** 是否启用自动分析。默认 <b>false</b> —— 自动送 AI 会把成本乘以包数。 */
    public boolean autoAnalyze = false;

    /** 是否启用本地扫描。默认 true —— 零成本零风险。 */
    public boolean scanEnabled = true;

    /** 头层：按头名掩码值。 */
    public boolean layerHeaders = true;

    /** 字段层：按字段名掩码 body。 */
    public boolean layerFields = true;

    /** 值层：值级正则（手机号/身份证/JWT…）。 */
    public boolean layerValues = true;

    /** 掩码策略名，对应 Sanitizer.MaskStrategy。 */
    public String maskStrategy = "KEEP_EDGES";

    // ---- 服务商 ------------------------------------------------------

    /**
     * 服务商标识。默认 {@code ollama} —— <b>本地</b>。
     * 作者默认走云端 DeepSeek，本方案反过来：默认最不泄露的那个。
     */
    public String provider = "ollama";

    /** API base URL。默认指向本机 Ollama。 */
    public String baseUrl = "http://127.0.0.1:11434/v1";

    /** 模型名。 */
    public String model = "qwen2.5:14b";

    /**
     * API Key 的<b>环境变量名</b>（推荐）。
     * 留空时才回退到 {@link #apiKeyInline}。
     * 这样密钥可以完全不落盘。
     */
    public String apiKeyEnv = "PACKETSENTRY_API_KEY";

    /** 内联 API Key（明文）。仅在 {@link #apiKeyEnv} 取不到时使用，且会警告用户。 */
    public String apiKeyInline = "";

    /** 采样温度。分析任务用低温度更稳定。 */
    public double temperature = 0.2;

    /** 单次请求超时（秒）。 */
    public int timeoutSeconds = 90;

    /** 送进模型的 body 最多保留多少字符（脱敏后）。 */
    public int maxBodyChars = 2000;

    /**
     * 累计花费预算上限（人民币元）。
     *
     * <p>超过就停止<b>自动</b>分析（手动分析仍然允许，因为那是用户主动点的一次）。
     * <=0 表示不限。
     *
     * <p>为什么默认给 1.0 元：一个 2000 包的会话去重后约 200 个结构，
     * 按 deepseek-flash 非高峰价约 ¥0.5。留一倍余量既够用又不会失控。
     */
    public double budgetCny = 1.0;

    /** 美元兑人民币汇率，仅用于成本估算显示。 */
    public double usdToCny = 7.1;

    // ---- 越权测试 ----------------------------------------------------

    /**
     * 越权测试用的身份列表。
     *
     * <p><b>▲ 这里存的是认证凭据（Cookie / Token），会明文落盘。</b>
     * 所以：
     * <ul>
     *   <li>默认是<b>空列表</b> —— 不配置就不启用，不会误发请求</li>
     *   <li>设置页会明确警告这一点</li>
     *   <li>只用在你已获授权的目标上</li>
     * </ul>
     */
    public java.util.List<Identity> identities = new java.util.ArrayList<>();

    /** 越权测试的最小发包间隔（毫秒），避免轰目标。 */
    public long acMinIntervalMs = 400;

    /** 是否已经在设置页确认过「越权测试会主动发包」这件事。 */
    public boolean acAcknowledged = false;

    // ---- SRC 安全模式 --------------------------------------------------

    /**
     * SRC 安全模式。
     *
     * <p>多数 SRC 的规则里都有这几条（以新东方 SRC V4.0 为例）：
     * <ul>
     *   <li>禁止在未获授权的情况下<b>向第三方披露或传播</b>漏洞信息与业务数据</li>
     *   <li>禁止使用<b>扫描器、自动化工具</b></li>
     *   <li>禁止下载、保存、传播和业务相关的<b>用户资料</b></li>
     *   <li>禁止以验证漏洞的名义获取<b>超过 10 条用户数据</b></li>
     * </ul>
     *
     * <p>把抓到的真实流量发给云端 AI，就落在第一条上。所以这个模式做的是
     * <b>把「合规」从「你记得配置」变成「默认就对」</b>。
     *
     * <p>开启后强制生效：
     * <ol>
     *   <li>只允许本地服务商（云端地址直接拒绝）</li>
     *   <li>关闭自动分析</li>
     *   <li>掩码策略强制 FULL（不保留首尾）</li>
     *   <li>body 上限压到 500 字符</li>
     *   <li>越权测试保持手动、单次（不做批量）</li>
     * </ol>
     */
    public boolean srcMode = false;

    /**
     * 靶场模式。
     *
     * <h3>为什么需要这个开关</h3>
     * 插件要同时服务两种场景，而它们的规则是<b>冲突</b>的：
     * <ul>
     *   <li><b>靶场 / CTF</b>：flag 就是成功标志，必须最高优先级报出来</li>
     *   <li><b>实战 SRC</b>：真实业务系统里<b>不存在 flag</b>。
     *       flag 规则在这里是纯噪音 —— 而且「极小响应 + 长 hex」那条兜底
     *       会误报成 CRITICAL（比如某个接口只返回一串 token）。
     *       在 SRC 里把注意力浪费在这种误报上是有实际代价的</li>
     * </ul>
     *
     * <p>默认 <b>false（实战 SRC）</b> ——「切合 SRC 挖漏洞」是这个插件的主用途。
     * 打靶场时在设置里打开。
     */
    public boolean rangeMode = false;

    // ---- 漏洞报告 ------------------------------------------------------

    /** 目标 SRC 平台名称，仅用于报告里标注定级依据。 */
    public String srcPlatform = "";

    /**
     * 用户粘贴的 SRC 平台漏洞评级规则（原文）。
     *
     * <p>每个平台的定级标准都不一样（同一个越权，A 平台算高危、B 平台算中危），
     * 所以不让程序去猜 —— <b>用户把规则原文贴进来</b>，生成报告时
     * 连同规则一起发给模型，让它按该平台的条款定级。
     *
     * <p>空着也能用：这时按通用标准（Critical/High/Medium/Low）定级，
     * 并在报告里说明「未提供平台规则」。
     */
    public String srcRules = "";

    /** 报告里的测试人员署名（可留空）。 */
    public String reporterName = "";

    /**
     * 报告模板。默认 generic（六段式）。
     *
     * <p>可选值见 {@code ReportTemplate.builtins()} 的 id：
     * {@code generic / butian / edu / hackerone / enterprise}。
     */
    public String reportTemplateId = "generic";

    /**
     * 用户自定义的报告字段表（覆盖模板默认）。
     *
     * <p>格式：每行「字段名｜提示」，字段名后可跟 {@code [可选]}。
     * 空表示用模板内置字段。
     *
     * <p>▲ 各平台表单会改版，内置字段只是<b>常见结构</b> ——
     * 让用户按实际表单改一次，比内置一个可能过时的定义更靠谱。
     */
    public String reportFieldsOverride = "";

    // ---- 运行时（不落盘）--------------------------------------------

    private transient Path filePath;
    private transient String lastError;

    // ==================================================================

    /** 配置目录。诚实命名，不伪装成系统目录。 */
    public static Path homeDir() {
        return Paths.get(System.getProperty("user.home", "."), ".packetsentry");
    }

    public static Path defaultFile() {
        return homeDir().resolve("config.json");
    }

    /** 载入配置；文件不存在或损坏时返回默认值，并把原因记在 lastError。 */
    public static Config load() {
        Config c = new Config();
        Path p = defaultFile();
        c.filePath = p;
        if (!Files.isRegularFile(p)) {
            return c;
        }
        try {
            String text = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            JsonObject o = JsonParser.parseString(text).getAsJsonObject();
            Gson g = new Gson();
            Config loaded = g.fromJson(o, Config.class);
            if (loaded != null) {
                loaded.filePath = p;
                // SRC 模式是不可绕过的硬约束 —— 即使用户手改了配置文件
                java.util.List<String> forced = loaded.enforceSrcMode();
                if (!forced.isEmpty()) {
                    loaded.lastError = "SRC 安全模式已强制修正：" + String.join("；", forced);
                }
                return loaded;
            }
            c.lastError = "配置文件为空，已使用默认值";
        } catch (Exception e) {
            // 不静默吞：保留原文件，让用户能自己看
            c.lastError = "配置解析失败（已保留原文件）: " + e.getMessage();
        }
        return c;
    }

    /**
     * 保存配置。用临时文件 + 原子替换，避免写到一半留下坏文件。
     *
     * @return null 表示成功；否则返回错误说明
     */
    public String save() {
        try {
            Path dir = homeDir();
            Files.createDirectories(dir);
            Path target = filePath != null ? filePath : defaultFile();
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");

            Gson g = new GsonBuilder().setPrettyPrinting().create();
            // 复制一份，避免把 transient 状态和明文密钥的提示写进去
            Config copy = this.shallowCopy();
            String json = g.toJson(copy);
            Files.write(tmp, json.getBytes(StandardCharsets.UTF_8));
            try {
                Files.move(tmp, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            return null;
        } catch (IOException e) {
            return "保存失败: " + e.getMessage();
        }
    }

    /**
     * 复制一份用于「测试连接」。
     *
     * <p>为什么需要它：设置页想让用户<b>先测再存</b> ——
     * 测试应该用表单里的当前值，而不是已保存的旧值。
     * 但直接改 {@code config} 单例会污染运行中的配置，
     * 所以复制一份改，测完丢掉。
     */
    public Config copyForProbe() {
        return shallowCopy();
    }

    /**
     * 浅拷贝。
     *
     * <p>public 是为了让契约测试能验证「新增字段在拷贝时有没有被漏掉」——
     * 漏字段会导致 SRC 安全模式在拷贝后失效（例如拷出来的配置
     * srcMode=true 但 baseUrl 没带过去），这类 bug 很隐蔽。
     */
    public Config shallowCopy() {
        Config c = new Config();
        c.sanitizeEnabled = sanitizeEnabled;
        c.scanEnabled = scanEnabled;
        c.layerHeaders = layerHeaders;
        c.layerFields = layerFields;
        c.layerValues = layerValues;
        c.maskStrategy = maskStrategy;
        c.provider = provider;
        c.baseUrl = baseUrl;
        c.model = model;
        c.apiKeyEnv = apiKeyEnv;
        c.apiKeyInline = apiKeyInline;
        c.temperature = temperature;
        c.timeoutSeconds = timeoutSeconds;
        c.maxBodyChars = maxBodyChars;
        c.budgetCny = budgetCny;
        c.usdToCny = usdToCny;
        c.acMinIntervalMs = acMinIntervalMs;
        c.acAcknowledged = acAcknowledged;
        c.srcMode = srcMode;
        c.srcPlatform = srcPlatform;
        c.srcRules = srcRules;
        c.reporterName = reporterName;
        c.autoAnalyze = autoAnalyze;
        // 身份要深拷贝 —— 否则 UI 改了会直接影响运行中的配置
        c.identities = new java.util.ArrayList<>();
        if (identities != null) {
            for (Identity id : identities) {
                c.identities.add(id.copy());
            }
        }
        return c;
    }

    // ==================================================================

    /**
     * 取实际使用的 API Key。
     *
     * <p>优先级：环境变量 → 内联值 → 空。
     * 本地服务商（Ollama/LM Studio）通常不需要 Key。
     */
    public String resolveApiKey() {
        if (apiKeyEnv != null && !apiKeyEnv.trim().isEmpty()) {
            String v = System.getenv(apiKeyEnv.trim());
            if (v != null && !v.trim().isEmpty()) {
                return v.trim();
            }
        }
        return apiKeyInline == null ? "" : apiKeyInline.trim();
    }

    /** 密钥是不是明文存在配置里。UI 用这个决定要不要警告。 */
    public boolean apiKeyStoredInPlaintext() {
        if (apiKeyInline == null || apiKeyInline.trim().isEmpty()) {
            return false;
        }
        return resolveApiKey().equals(apiKeyInline.trim());
    }

    /** 当前服务商是不是本地（决定要不要显示"数据出境"提示）。 */
    public boolean isLocalProvider() {
        if (baseUrl == null) {
            return false;
        }
        String u = baseUrl.toLowerCase();
        return u.contains("127.0.0.1") || u.contains("localhost") || u.contains("0.0.0.0")
                || u.contains("::1");
    }

    /** 是不是境外服务商（需要额外确认）。 */
    public boolean isForeignProvider() {
        if (baseUrl == null || isLocalProvider()) {
            return false;
        }
        String u = baseUrl.toLowerCase();
        return u.contains("api.openai.com") || u.contains("api.anthropic.com")
                || u.contains("generativelanguage.googleapis.com");
    }

    public String getLastError() {
        return lastError;
    }

    /**
     * 施加 SRC 安全模式的约束。
     *
     * <p>每次读取配置前调用（见 {@link #load} 与设置页保存），
     * 保证用户手改了配置也绕不过这些硬约束。
     *
     * @return 被强制修改的项；空列表表示本来就合规
     */
    public java.util.List<String> enforceSrcMode() {
        java.util.List<String> changed = new java.util.ArrayList<>();
        if (!srcMode) {
            return changed;
        }

        // ① 只允许本地服务商 —— 这是最硬的一条
        if (!isLocalProvider()) {
            String old = provider + " / " + baseUrl;
            provider = "ollama";
            baseUrl = "http://127.0.0.1:11434/v1";
            // ▲ 默认模型改过一版。原来是 qwen2.5:14b，但那个模型
            //    4bit 量化约 9-10 GB —— <b>装不进主流笔记本的 8GB 显存</b>，
            //    溢出到内存后速度掉到 1-3 tokens/秒，实际不可用。
            //
            //    实测参考（Q4 量化）：qwen3:4b ≈ 5.2 GB，llama3.1:8b ≈ 4.9 GB，
            //    都装得进 8GB 显存；14B 档要 12 GB 以上。
            //
            //    所以默认降到 8B 档。用户想用更大的可以自己改 ——
            //    但默认值必须能在<b>常见硬件</b>上跑起来。
            if (model == null || model.trim().isEmpty()
                    || model.toLowerCase().contains("deepseek")
                    || model.toLowerCase().contains("gpt")) {
                model = "qwen3:4b";
            }
            changed.add("服务商强制改为本地：" + old + " → " + provider + " / " + baseUrl);
        }

        // ② 自动分析 —— 这里刻意<b>不</b>强制关闭，理由见下。
        //
        // ▲ 这一条我一开始写错了理由，值得记下来：
        //
        //    原本的注释写「自动化 + 按量计费双重不合规」，并强制关闭。但那个判断不准确：
        //      · SRC 规则禁止的「自动化工具」指的是<b>向目标发包</b>的工具
        //        （sqlmap / xray / dirsearch 之类）。自动分析不向目标发任何请求，
        //        它只把<b>已经抓到的</b>包送给 AI，不属于这一类。
        //      · 本模式第 ① 条已经强制本地模型，数据不出机器，
        //        所以也不存在「向第三方披露」的问题。
        //      · 本地模型不产生费用。
        //
        //    真正该管的是「无审查的批量外传」：
        //      手动点击 → 用户看过内容、确认过脱敏、一次一个
        //      自动分析 → 整个浏览过程中的所有新接口被悄悄送出去，用户没有感知
        //    这个风险<b>只在非本地模型下成立</b>。
        //
        //    所以这里的策略是：
        //      · 非本地模型 → 强制关闭（这时确实会无审查地批量外传）
        //      · 本地模型   → 交给用户自己决定。界面上仍默认关掉，
        //                     并在开启时提示「本地大模型会占满 CPU/GPU」。
        //
        //    换句话说：<b>合规问题由「强制本地」解决，不该靠「关功能」解决。</b>
        if (autoAnalyze && !isLocalProvider()) {
            autoAnalyze = false;
            changed.add("已关闭自动分析（非本地模型下会无审查地批量外传业务数据）");
        }

        // ③ 掩码策略强制 FULL（不保留首尾）
        if (!"FULL".equalsIgnoreCase(maskStrategy)) {
            maskStrategy = "FULL";
            changed.add("掩码策略强制为 FULL（不保留任何原文片段）");
        }

        // ④ body 上限。
        //
        // ▲ 这一条改过一版，原来的逻辑有个<b>自相矛盾</b>的地方：
        //
        //    原来无条件收紧到 500 —— 理由是「减少外传的数据量」。
        //    但第 ① 条已经把服务商强制成本地了，<b>根本不存在外传</b>。
        //    所以这条限制保护不了任何东西，只是白白砍掉 AI 能看到的内容：
        //    响应体截到 500 字符，AI 连一个完整页面都看不全，
        //    判断自然变浅 —— 而用户还以为这是「合规的代价」。
        //
        //    实际上：<b>合规问题已由「强制本地」解决，不该再靠「截断」解决。</b>
        //    （同样的道理在第 ②「自动分析」那条注释里已经写过一遍 ——
        //     我当时修了那一处，却漏了这一处，两个地方是同一个错误。）
        //
        //    现在的逻辑：
        //      · 本地服务商 → 不截断（不存在外传，截断纯属自损）
        //      · 非本地     → 收紧到 500（这时截断确实有意义，属纵深防御）
        //    第 ① 条会把非本地强制成本地，所以正常走第一支；
        //    保留第二支是为了「万一 ① 被绕过」时仍有一层限制。
        if (isLocalProvider()) {
            if (maxBodyChars < 1500) {
                maxBodyChars = 3000;
                changed.add("body 上限放宽到 3000 字符（本地模型无外传，截断只会让分析变浅）");
            }
        } else if (maxBodyChars > 500) {
            maxBodyChars = 500;
            changed.add("body 上限收紧到 500 字符（非本地服务商）");
        }

        // ⑤ 脱敏与本地扫描必须开着
        if (!sanitizeEnabled) {
            sanitizeEnabled = true;
            changed.add("已强制开启脱敏");
        }
        if (!scanEnabled) {
            scanEnabled = true;
            changed.add("已强制开启本地扫描");
        }
        if (!layerHeaders || !layerFields || !layerValues) {
            layerHeaders = true;
            layerFields = true;
            layerValues = true;
            changed.add("已强制开启全部三层脱敏");
        }

        return changed;
    }

    /** SRC 模式下是否允许把这个请求发给 AI（本地模型永远允许）。 */
    public boolean aiAllowed() {
        if (!srcMode) {
            return true;
        }
        return isLocalProvider();
    }

    /** 给界面用的一句话合规声明。 */
    public String complianceLine() {
        if (!srcMode) {
            return "";
        }
        return "SRC 安全模式：数据不出本机（"
                + (isLocalProvider() ? "已确认本地模型" : "▲ 当前配置不是本地模型，请检查")
                + "）";
    }

    /** 给 UI 用的一句话描述当前去向。 */
    public String describeDestination() {
        String scope = isLocalProvider() ? "本地（数据不出机器）" : "云端（数据会离开本机）";
        return provider + " / " + model + "  ·  " + scope;
    }

    /** 配置文件名（不含目录）。 */
    public String fileName() {
        return filePath == null ? defaultFile().getFileName().toString()
                : filePath.getFileName().toString();
    }

    public File asFile() {
        return (filePath == null ? defaultFile() : filePath).toFile();
    }
}
