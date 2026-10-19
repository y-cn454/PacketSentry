package com.packetsentry.burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.ITab;

import com.packetsentry.core.Config;
import com.packetsentry.core.CostTracker;
import com.packetsentry.core.RealtimePipe;
import com.packetsentry.ui.AnalyzerTab;
import com.packetsentry.ui.RealtimeTab;
import com.packetsentry.ui.SettingsPanel;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * PacketSentry 的 Burp 入口。
 *
 * <h3>职责（刻意保持极薄）</h3>
 * <ol>
 *   <li>注册 HTTP 监听器 —— <b>只把报文丢进队列，立刻返回</b></li>
 *   <li>注册报文编辑器标签页工厂 —— 返回 {@link AnalyzerTab}</li>
 *   <li>组装主标签页：总览 / 实时 / 设置 / 状态</li>
 * </ol>
 *
 * <h3>为什么 {@code processHttpMessage} 必须极快</h3>
 * 它会在 Burp 处理的<b>每一个</b>报文上被调用。作者 AIPacketHunter
 * 在这一点上判断正确（只做 {@code incrementAndGet()}），本方案保留这个原则：
 * <b>这里只入队，不做解析、不做网络、不做 UI</b>。
 * 真正的扫描 / 脱敏 / 去重由 {@link RealtimePipe} 的后台线程消费。
 *
 * <h3>本类的硬约束</h3>
 * <ul>
 *   <li>{@code processHttpMessage} 不做任何耗时操作，队列满就丢弃</li>
 *   <li>联网只发生在用户点击「分析」之后</li>
 *   <li>启动时只读配置，不探测网络</li>
 * </ul>
 */
public final class BurpExtender implements IBurpExtender, ITab, IMessageEditorTabFactory, IHttpListener,
        burp.api.montoya.BurpExtension {

    /**
     * 两条注册通道，谁先用谁负责建界面。
     *
     * <h3>为什么要同时实现 legacy 和 Montoya</h3>
     * 实测发现：在 Burp Pro v2025.2 上，legacy 的 {@code addSuiteTab(ITab)} 路径
     * <b>回调正常但标签页不上屏</b> —— 诊断日志显示 Burp 主动调用了
     * {@code getTabCaption()} 和 {@code getUiComponent()}，拿到了一个合法的
     * JTabbedPane，然后没有渲染它。插件侧每一步都正确，问题在 legacy 路径本身。
     *
     * <p>Montoya 是 Burp 2022.1+ 的现代 API，2025.x 上持续维护，
     * {@code api.userInterface().registerSuiteTab(...)} 是官方推荐的注册方式。
     *
     * <p>这里两者都实现：标签页<b>优先走 Montoya</b>，其余能力（HTTP 监听、
     * 发到 Repeater、主动发包）保持 legacy —— 那部分实测可用，不必改动。
     * 用 {@link #bootstrapped} 保证界面只建一次，避免出现两个标签页。
     */
    private final java.util.concurrent.atomic.AtomicBoolean bootstrapped =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private volatile burp.api.montoya.MontoyaApi montoya;

    // ==================================================================
    // 通道一：Montoya（现代 API，标签页优先走这条）
    // ==================================================================

    @Override
    public void initialize(burp.api.montoya.MontoyaApi api) {
        this.montoya = api;

        boolean first = bootstrapped.compareAndSet(false, true);
        logMontoya("Montoya initialize 进入　（legacy 是否已先到=" + !first + "）");

        try {
            api.extension().setName("PacketSentry");
        } catch (Throwable t) {
            logMontoya("设置扩展名失败：" + t);
        }

        bootstrapShared();

        // ★ 标签页一律走 Montoya。
        //
        // ▲ 这里踩过一个坑：早期版本用「谁先到谁注册」的守卫，但实测发现
        //    Burp v2025.2 会<b>先</b>调 registerExtenderCallbacks（legacy），
        //    <b>后</b>调 initialize（Montoya）。结果 legacy 抢到了注册权，
        //    Montoya 被跳过 —— 而 legacy 路径正是标签页不上屏的那条。
        //
        //    现在改成：legacy 通道<b>不立刻注册标签页</b>，只排一个延迟兜底；
        //    Montoya 一到就立刻注册。这样新 Burp 走 Montoya（能显示），
        //    老 Burp（不调 initialize）由兜底接管。
        try {
            Component panel = ensureRoot();
            api.userInterface().registerSuiteTab("PacketSentry", panel);
            uiReady = true;
            logMontoya("★ registerSuiteTab 已调用（Montoya 通道）");
        } catch (Throwable t) {
            logMontoya("× registerSuiteTab 失败：" + t);
            uiReady = false;
        }

        try {
            fillUi();
            logMontoya("界面内容已填充：" + (root == null ? 0 : root.getTabCount()) + " 个页签");
        } catch (Throwable t) {
            logMontoya("× 内容填充失败：" + t);
            if (root != null) {
                root.removeAll();
                root.addTab("错误", placeholder("界面内容构建失败：\n\n" + stackOf(t)));
            }
        }
    }

    /** 确保 root 存在并带一个占位页签。 */
    private JTabbedPane ensureRoot() {
        if (root == null) {
            root = new JTabbedPane();
            root.addTab("总览", placeholder("正在初始化…"));
        }
        return root;
    }

    private void logMontoya(String msg) {
        String line = "[Montoya] " + msg;
        if (montoya != null) {
            try {
                montoya.logging().logToOutput(line);
            } catch (Throwable ignored) {
                // 日志失败不影响功能
            }
        }
        System.out.println("[PacketSentry] " + line);
    }

    // ==================================================================
    // 通道二：legacy
    // ==================================================================

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
        this.callbacks = cb;
        this.helpers = cb.getHelpers();

        boolean first = bootstrapped.compareAndSet(false, true);

        cb.setExtensionName("PacketSentry");
        step("1", "registerExtenderCallbacks 进入　EDT="
                + javax.swing.SwingUtilities.isEventDispatchThread()
                + "　是否首个通道=" + first);

        bootstrapShared();

        // ▲ legacy 通道<b>不立刻注册标签页</b>。
        //
        // 实测：Burp v2025.2 先调 registerExtenderCallbacks，后调 initialize(MontoyaApi)。
        // 如果这里抢先注册，就会走 legacy 那条「回调正常但不上屏」的路径，
        // 而 Montoya 通道反而被跳过。
        //
        // 所以这里只排一个延迟兜底：1.5 秒后如果还没有任何通道成功注册，
        // 说明这是不支持 Montoya 的老 Burp，再用 legacy 注册。
        // 新 Burp 上 initialize 会先跑完并把 uiReady 置 true，兜底自然跳过。
        scheduleLegacyTabFallback();

        step("10", "registerExtenderCallbacks 返回　uiReady=" + uiReady
                + "（等待 Montoya 通道或兜底）");
        printLoadBanner();
    }

    /**
     * 兜底：老 Burp 不支持 Montoya 时，用 legacy 注册标签页。
     *
     * <p>延迟 1.5 秒是为了给 {@code initialize(MontoyaApi)} 让路 ——
     * Burp 会在 registerExtenderCallbacks 之后紧接着调它。
     */
    private void scheduleLegacyTabFallback() {
        try {
            javax.swing.Timer t = new javax.swing.Timer(1500, e -> {
                ((javax.swing.Timer) e.getSource()).stop();
                if (uiReady) {
                    step("-", "兜底检查：标签页已由 Montoya 通道注册，跳过 legacy");
                    scheduleTabDiagnosis();
                    return;
                }
                step("-", "兜底检查：Montoya 通道未生效，改用 legacy 注册标签页");
                try {
                    ensureRoot();
                    callbacks.addSuiteTab(this);
                    uiReady = true;
                    step("-", "★ legacy 兜底注册成功");
                    fillUi();
                } catch (Throwable ex) {
                    step("-", "× legacy 兜底注册失败：" + ex);
                    reportUiFailure(ex);
                }
                scheduleTabDiagnosis();
            });
            t.setRepeats(false);
            t.start();
        } catch (Throwable ignored) {
            // 兜底本身失败不该影响插件其余功能
        }
    }

    /** 两条通道共用的初始化：配置、计价、管道、HTTP 监听。 */
    private void bootstrapShared() {
        // ⚠️⚠️ 单实例保护必须在<b>一切副作用之前</b>。
        //
        //    用户实测过这个场景：Extender 列表里同时打勾两条 PacketSentry
        //    （旧那条指向已删除的 jar，为了修复又添加了一次）。
        //    Burp 会给每次加载创建独立的 classloader，于是：
        //      · 静态字段不共享，两个实例互不知道对方存在
        //      · 两个都注册 HTTP 监听器 → 同一个包被抓两遍
        //      · 两个都写 config.json / findings.json → 互相覆盖
        //      · 界面上出现两个同名标签页
        //
        //    所以这里先拿一把文件锁；拿不到就说明已有实例，本实例
        //    <b>不注册 HTTP 监听器</b>（避免双份抓包）。界面仍然会建出来，
        //    这样用户能在标签页里看到警告、知道该怎么修。
        if (!singleInstanceChecked) {
            singleInstanceChecked = true;
            if (SingleInstance.duplicate()) {
                duplicateInstance = true;
                try {
                    if (callbacks != null) {
                        callbacks.printOutput(SingleInstance.warning());
                    }
                    if (montoya != null) {
                        montoya.logging().logToOutput(SingleInstance.warning());
                    }
                } catch (Throwable ignored) {
                    // 日志打不出来也不能阻止后面把界面建起来
                }
            }
        }

        if (config == null) {
            try {
                config = Config.load();
                step("3", "配置已载入：" + config.describeDestination());
            } catch (Throwable t) {
                step("3", "配置载入失败：" + t);
                config = new Config();
            }
            syncCostPricing();
            step("4", "计价方案：" + cost.pricing().name);
        }

        if (pipe == null) {
            try {
                pipe = new RealtimePipe(() -> config);
                pipe.start();
                step("5", "实时管道已启动");
            } catch (Throwable t) {
                step("5", "实时管道启动失败：" + t);
            }
        }

        // 重复实例不注册 HTTP 监听器 —— 这是本类里最关键的"不做什么"
        if (duplicateInstance) {
            step("6", "⚠️ 重复实例：跳过 HTTP 监听器注册（避免同一个包被抓两遍）");
        } else if (callbacks != null && !httpListenerRegistered) {
            try {
                callbacks.registerHttpListener(this);
                httpListenerRegistered = true;
                step("6", "HTTP 监听器已注册");
            } catch (Throwable t) {
                step("6", "HTTP 监听器注册失败：" + t);
            }
        }
    }

    private volatile boolean httpListenerRegistered = false;

    /** 单实例检测是否已做过（只做一次）。 */
    private boolean singleInstanceChecked = false;

    /**
     * 本次是否被判定为「重复加载」。
     *
     * <p>为 true 时<b>不注册 HTTP 监听器</b> —— 否则会把同一个包抓两遍，
     * 而且两个实例会互相覆盖 config.json / findings.json。
     *
     * <p>用户实测过：Extender 列表里同时打勾两条 PacketSentry，
     * 于是界面出现两个同名标签页、同一个包被记两次。
     */
    private boolean duplicateInstance = false;

    /** 加载横幅。 */
    private void printLoadBanner() {
        out("");
        out("[+] PacketSentry 已加载");
        out("    脱敏引擎    三层规则就绪（头 / 字段 / 值级正则）");
        out("    本地扫描    已启用（零网络调用，零成本）");
        out("    实时管道    已启动（有界队列 2048，满则丢弃不阻塞 Burp）");
        out("    本地规则    作用推断 + 11 条漏洞检测（零成本）");
        if (config != null) {
            out("    服务商      " + config.describeDestination());
            CostTracker.Pricing p = cost.pricing();
            if (p.inputCacheMiss == 0) {
                out("    成本        本地模型，无 API 费用");
            } else {
                out(String.format("    成本        按 %s 估：输入(未命中) $%.3f/M，输出 $%.3f/M%s",
                        p.name, p.inputCacheMiss, p.output,
                        CostTracker.isPeakNow() ? "，当前高峰时段单价翻倍" : "，当前非高峰"));
            }
            if (!config.isLocalProvider()) {
                out("    ▲ 当前不是本地服务商，分析时数据会离开本机");
            }
            if (config.getLastError() != null && callbacks != null) {
                callbacks.printError("[-] 配置提示：" + config.getLastError());
            }
        }
        out("    标签页通道  " + (montoya != null ? "Montoya（现代 API）" : "legacy")
                + "　uiReady=" + uiReady);
        out("");
    }

    private void out(String s) {
        if (callbacks != null) {
            callbacks.printOutput(s);
        }
        if (montoya != null) {
            try {
                montoya.logging().logToOutput(s);
            } catch (Throwable ignored) {
                // 忽略
            }
        }
        System.out.println("[PacketSentry] " + s);
    }

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    /** Burp 处理的报文总数（含请求和响应）。仅用于状态显示。 */
    private final AtomicInteger seen = new AtomicInteger();

    private JTabbedPane root;
    private JLabel statusLabel;
    private RealtimeTab realtimeTab;
    /** UI 是否已经成功构建并注册。用于在输出里如实汇报，而不是假定成功。 */
    private volatile boolean uiReady = false;

    /**
     * Burp 是否真的来问过标签页信息（{@code getTabCaption()} / {@code getUiComponent()}）。
     *
     * <p>这个标记把两种完全不同的故障分开：
     * <ul>
     *   <li>从没被调用 → 注册没生效，问题在注册环节</li>
     *   <li>被调用过   → 注册生效了，问题在渲染环节</li>
     * </ul>
     */
    private volatile boolean tabCallbacksInvoked = false;

    private volatile Config config;
    private RealtimePipe pipe;
    private final CostTracker cost = new CostTracker();

    // ==================================================================
    // 诊断辅助
    // ==================================================================

    private void step(String n, String msg) {
        String line = "[启动 " + n + "/10] " + msg;
        if (callbacks != null) {
            callbacks.printOutput(line);
        }
        System.out.println("[PacketSentry] " + line);
    }

    /**
     * 启动后延迟自检：Burp 到底有没有来问过标签页信息？
     *
     * <p>这一步把两种可能彻底分开：
     * <ul>
     *   <li><b>Burp 从没调用</b> {@code getTabCaption()}/{@code getUiComponent()}
     *       → 注册没生效，问题在注册环节</li>
     *   <li><b>Burp 调用过</b> → 注册生效了，问题在渲染环节</li>
     * </ul>
     *
     * <p>如果确认「从没调用」，就<b>自动重试一次注册</b> —— 这在部分 Burp 版本上
     * 是有效的规避手段（注册时机早于 Burp 的标签页收集窗口时会丢失）。
     * 只在「从没调用」时才重试，所以不会造成重复标签页。
     */
    private void scheduleTabDiagnosis() {
        try {
            javax.swing.Timer t = new javax.swing.Timer(2500, e -> {
                ((javax.swing.Timer) e.getSource()).stop();
                if (callbacks == null) {
                    return;
                }
                if (tabCallbacksInvoked) {
                    callbacks.printOutput("[标签页] √ Burp 已经询问过标签页信息"
                            + "（getTabCaption/getUiComponent 都被调用）");
                    callbacks.printOutput("[标签页]    如果标签栏里仍然看不到，"
                            + "说明是 Burp 的渲染问题，与注册无关。");
                } else {
                    callbacks.printOutput("[标签页] ▲ Burp 在 2.5 秒内<b>从未</b>调用 "
                            + "getTabCaption()/getUiComponent()");
                    callbacks.printOutput("[标签页]    说明 addSuiteTab 注册了但没被采纳，"
                            + "现在重新注册一次…");
                    try {
                        callbacks.addSuiteTab(this);
                        callbacks.printOutput("[标签页]    重新注册已调用，"
                                + "请等 2 秒后看下面一行结果");
                    } catch (Throwable ex) {
                        callbacks.printError("[标签页]    重新注册失败：" + ex);
                    }
                    javax.swing.Timer t2 = new javax.swing.Timer(2000, e2 -> {
                        ((javax.swing.Timer) e2.getSource()).stop();
                        callbacks.printOutput("[标签页] 重试后是否被询问：" + tabCallbacksInvoked
                                + (tabCallbacksInvoked
                                ? "　→ 修复成功，标签页应该出现了"
                                : "　→ 仍然没被询问，这是 Burp 侧的兼容性问题"));
                    });
                    t2.setRepeats(false);
                    t2.start();
                }
            });
            t.setRepeats(false);
            t.start();
        } catch (Throwable ignored) {
            // 诊断本身不该影响插件功能
        }
    }

    private static java.awt.Component placeholder(String text) {
        JTextArea t = new JTextArea(text);
        t.setEditable(false);
        t.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
        return new JScrollPane(t);
    }

    private static String stackOf(Throwable t) {
        java.io.StringWriter sw = new java.io.StringWriter();
        t.printStackTrace(new java.io.PrintWriter(sw));
        return sw.toString();
    }

    /**
     * 在 EDT 上构建 UI，并<b>等它建完</b>。
     *
     * <p>为什么不能用 {@code invokeLater}：见 {@link #registerExtenderCallbacks} 的注释。
     * 标签页注册必须发生在 {@code registerExtenderCallbacks} 返回之前。
     *
     * <p>这里刻意<b>不静默吞异常</b> —— UI 构建失败会让整个插件不可见，
     * 是最需要暴露出来的错误。失败时打到 Burp 的错误输出。
     */
    private void buildUiSynchronously() {
        if (javax.swing.SwingUtilities.isEventDispatchThread()) {
            safeBuildUi();
            return;
        }
        try {
            javax.swing.SwingUtilities.invokeAndWait(this::safeBuildUi);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            safeBuildUi();
        } catch (java.lang.reflect.InvocationTargetException e) {
            reportUiFailure(e.getCause() == null ? e : e.getCause());
        } catch (Throwable t) {
            // 极端情况下（EDT 不可用）退化为直接构建。
            // Swing 组件在未 realize 前于非 EDT 上构造通常也能工作。
            safeBuildUi();
        }
    }

    private void safeBuildUi() {
        try {
            fillUi();
        } catch (Throwable t) {
            reportUiFailure(t);
        }
    }

    private void reportUiFailure(Throwable t) {
        if (callbacks != null) {
            callbacks.printError("[-] PacketSentry 界面构建失败，标签页不会出现：");
            callbacks.printError("    " + t);
            for (StackTraceElement e : t.getStackTrace()) {
                callbacks.printError("      at " + e);
            }
        }
        System.err.println("[PacketSentry] 界面构建失败：" + t);
    }

    private void syncCostPricing() {
        cost.setPricing(CostTracker.guessPricing(config.model, config.isLocalProvider()));
        cost.setBudgetCny(config.budgetCny);
    }

    /**
     * 往已经注册好的 {@code root} 里填真正的内容。
     *
     * <p>与早期 {@code buildUi()} 的区别：那时候是「先建好整个 UI，最后才注册标签页」——
     * 只要任何一步出问题，标签页就完全不存在。现在标签页在 {@link #registerExtenderCallbacks}
     * 第 7-8 步就已经注册好了，这里即使失败，标签页也还在，只是显示错误页。
     */
    private void fillUi() {
        if (root == null) {
            root = new JTabbedPane();
        }
        root.removeAll();

        // ---- 总览 / 帮助 ----
        JPanel overview = new JPanel(new BorderLayout());
        JTextArea info = new JTextArea();
        info.setEditable(false);
        info.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        info.setText(String.join("\n",
                "PacketSentry —— 把 Burp 报文安全地交给 AI 分析",
                "",
                "════════ 两种用法 ════════",
                "",
                "【A】实时看（零成本）",
                "    去「实时」页。每个经过 Burp 的报文都会被本地扫描并列表化：",
                "    · 有什么敏感数据、什么风险等级、将被抹掉几处",
                "    · 这一步不联网、不花钱、不限量",
                "",
                "【B】问 AI（按量计费）",
                "    在 Proxy / Repeater 里选中一个报文 → 报文编辑器上方的",
                "    PacketSentry 标签页 → 确认脱敏内容 → 点「分析」",
                "",
                "════════ 关于成本（重要）════════",
                "",
                "「实时」和「送 AI」是两件事，刻意拆开了：",
                "",
                "  本地扫描      实时，每个包都跑，¥0",
                "  送 AI         按量，只有你点了才发",
                "",
                "因为一个真实会话有几百到几千个包，全自动送 AI 就是几块到几十块。",
                "",
                "把成本压到可接受范围靠三道闸：",
                "",
                "  ① 去重        一个接口调用 300 次只算 1 个结构 —— 省 90%",
                "  ② 低价值过滤  静态资源 / 埋点 / 心跳直接跳过",
                "  ③ 预算上限    累计花费超过设定值就停",
                "",
                "典型成本（deepseek-flash，非高峰）：",
                "",
                "  单个包        ≈ ¥0.0026   （约 0.26 分）",
                "  2000 包会话   去重后约 200 个结构 ≈ ¥0.5",
                "",
                "勾上「自动分析新接口」会按上面三道闸自动跑，但仍受预算约束。",
                "",
                "════════ 安全设计 ════════",
                "",
                "· 报文到达时不分析、不外发，只入队",
                "· 脱敏是默认行为，三层规则（头 / 字段 / 值级正则）",
                "· 脱敏同时省 token —— 150 字符的 JWT 会变成 11 字符",
                "· 发送前你看到的就是将要发送的，可以再改",
                "· 默认服务商是本地，数据不出机器",
                "· 发现私钥 / 云密钥这类 CRITICAL 数据时默认拦截",
                "· 密钥优先从环境变量读，不必明文落盘",
                "",
                "════════ ▲ 边界 ════════",
                "",
                "本插件降低泄露风险，但不能消除风险：",
                "· 新形态的凭据可能不在规则里，脱敏不保证 100%",
                "· 它不能阻止你自己把敏感数据贴进对话",
                "· 它不替代客户的数据处理协议",
                "",
                "测客户系统前，先确认你的合同允许把数据发给 AI 服务商",
                "—— 无论是否脱敏。",
                "",
                "════════ 配置文件 ════════",
                "",
                "  " + Config.defaultFile(),
                ""));
        overview.add(new JScrollPane(info), BorderLayout.CENTER);
        root.addTab("总览", overview);

        // ---- 实时 ----
        realtimeTab = new RealtimeTab(pipe, cost, () -> config, callbacks);
        // Burp 卸载扩展（或关闭）时把发现清单落盘 ——
        // 这是 SRC 场景下最要紧的一件事：清单是跨天累积的产物，
        // 不能因为「还没到攒批窗口」就丢了最后几条。
        try {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    if (realtimeTab != null) {
                        realtimeTab.flushLedger();
                    }
                } catch (Throwable ignored) {
                    // 关闭路径不抛异常
                }
            }, "packetsentry-ledger-flush"));
        } catch (Throwable ignored) {
            // 某些受限环境不允许加 shutdown hook —— 不影响主流程
        }
        root.addTab("实时", realtimeTab);

        // ---- 设置 ----
        SettingsPanel settings = new SettingsPanel(
                () -> config,
                () -> {
                    syncCostPricing();
                    // 设置页可能改了身份列表 —— 让实时页的下拉框同步
                    if (realtimeTab != null) {
                        realtimeTab.refreshIdentities();
                    }
                    callbacks.printOutput("[+] 配置已更新：" + config.describeDestination()
                            + "　身份 " + (config.identities == null ? 0 : config.identities.size())
                            + " 个");
                });
        root.addTab("设置", settings);

        // ---- 状态 ----
        statusLabel = new JLabel(" 已处理报文: 0");
        root.addTab("状态", statusLabel);

        // ▲ 这里<b>不再</b>调用 addSuiteTab —— 标签页在第 7-8 步就注册好了。
        //    早期版本是「先建 UI 再注册」，一旦建 UI 出问题标签页就整个消失。
        //
        // customizeUiComponent 也挪到这里：它只影响外观，不该挡在注册前面。
        try {
            callbacks.customizeUiComponent(root);
        } catch (Throwable t) {
            reportUiFailure(t);
        }
    }

    // ==================================================================
    // ITab
    // ==================================================================

    @Override
    public String getTabCaption() {
        // 诊断：如果这行不出现，说明 Burp <b>从没问过</b>我们要标签页标题 ——
        // 那问题在注册环节，而不是渲染环节。两种情况的修法完全不同。
        tabCallbacksInvoked = true;
        if (callbacks != null) {
            callbacks.printOutput("[标签页] Burp 调用了 getTabCaption() → 返回 PacketSentry");
        }
        return "PacketSentry";
    }

    /**
     * Burp 取标签页组件。
     *
     * <p><b>绝不返回 null</b> —— 返回 null 时 Burp 会静默地不显示这个标签页，
     * 而且不报任何错，极难排查。
     */
    @Override
    public Component getUiComponent() {
        tabCallbacksInvoked = true;
        if (callbacks != null) {
            callbacks.printOutput("[标签页] Burp 调用了 getUiComponent() → 返回 "
                    + (root == null ? "占位面板（root 为 null）" : "JTabbedPane（"
                    + root.getTabCount() + " 个页签）"));
        }
        if (root != null) {
            return root;
        }
        return buildFallbackPanel();
    }

    private JPanel buildFallbackPanel() {
        JPanel fallback = new JPanel(new BorderLayout());
        JTextArea t = new JTextArea();
        t.setEditable(false);
        t.setText(String.join("\n",
                "PacketSentry 界面未能初始化。",
                "",
                "请到 Burp 的「扩展 → 错误」标签页查看具体异常。",
                "",
                "常见原因：",
                "  · 与其它扩展的类冲突（尤其是打包了同一个库的情况）",
                "  · Burp 版本过旧，缺少某个 API",
                "  · 配置文件损坏（可删除 ~/.packetsentry/config.json 后重启）",
                ""));
        fallback.add(new JScrollPane(t), BorderLayout.CENTER);
        return fallback;
    }

    // ==================================================================
    // IHttpListener —— 全插件调用最频繁的方法，必须极薄
    // ==================================================================

    /**
     * 把报文丢进队列，立刻返回。
     *
     * <p><b>这里绝不做的事</b>：解析、字符串处理、正则、网络、文件、Swing。
     * 任何一项都会乘以 Burp 处理的报文总数。
     *
     * <p>队列是有界的（512）。满就丢弃并计数 ——
     * 抓包场景下「漏几个包」远比「Burp 卡住」可接受。
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse message) {
        if (message == null || pipe == null) {
            return;
        }
        // 只取引用，不做任何转换 —— bytesToString 是 O(n)，留到后台线程做
        byte[] req = message.getRequest();
        byte[] resp = message.getResponse();

        // ▲ transactionKey 用对象身份：Burp 对同一事务的请求阶段和响应阶段
        //    传的是同一个 IHttpRequestResponse 对象，据此把两次回调合并成一条记录。
        //    没有这个键，每个事务会产生两条记录、漏洞被报两遍。
        pipe.submit(req, resp, toolFlag, messageIsRequest,
                message, message.getHttpService());

        int n = seen.incrementAndGet();
        if (n % 50 == 0 && statusLabel != null) {
            SwingUtilities.invokeLater(() ->
                    statusLabel.setText(" 已处理报文: " + n
                            + "　队列 " + pipe.queuedCount()
                            + "　不同结构 " + pipe.distinctStructures()));
        }
    }

    // ==================================================================
    // IMessageEditorTabFactory
    // ==================================================================

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // 只构造对象，不做 IO。真正的处理在 Burp 调用 setMessage 时发生。
        return new AnalyzerTab(controller, editable, () -> config);
    }

    // ==================================================================

    /** 卸载时停掉后台线程，避免线程泄漏。 */
    public void shutdown() {
        if (pipe != null) {
            pipe.stop();
        }
    }
}
