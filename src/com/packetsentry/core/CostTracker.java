package com.packetsentry.core;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Token 与费用追踪 —— 让「实时自动分析」不至于变成烧钱机器。
 *
 * <p>为什么需要它：用户想要「实时分析」，但一个真实会话有几百到几千个包。
 * 每个包都送 AI 就是几块到几十块。所以要能<b>看见花了多少</b>，
 * 并在超过预算时<b>自动停</b>。
 *
 * <p><b>估算口径说明</b>：这里算的是<b>预估值</b>，不是账单。
 * 真实计费由服务商按自己的分词器统计，跟这里的估算会有出入
 * （中文尤其明显：估算按字符数折半，实际分词器可能更多或更少）。
 * 所以 UI 上要标明「预估」，不要让人以为这是精确账单。
 */
public final class CostTracker {

    /**
     * 计价方案。
     *
     * <p>价格单位：美元 / 百万 tokens。数据取自服务商公开定价页
     * （2026 年口径），会变，所以做成常量便于更新。
     */
    public static final class Pricing {
        public final String name;
        public final double inputCacheHit;    // 输入·缓存命中
        public final double inputCacheMiss;   // 输入·未命中
        public final double output;           // 输出
        public final double peakMultiplier;   // 高峰倍数

        public Pricing(String name, double hit, double miss, double out, double peakMul) {
            this.name = name;
            this.inputCacheHit = hit;
            this.inputCacheMiss = miss;
            this.output = out;
            this.peakMultiplier = peakMul;
        }
    }

    /** deepseek-flash：性价比最高的档位。 */
    public static final Pricing DEEPSEEK_FLASH =
            new Pricing("deepseek-flash", 0.003, 0.15, 0.60, 2.0);

    /** deepseek-v4-pro：更强也更贵。 */
    public static final Pricing DEEPSEEK_V4_PRO =
            new Pricing("deepseek-v4-pro", 0.022, 0.66, 1.98, 2.0);

    /** 本地模型：免费。 */
    public static final Pricing LOCAL_FREE =
            new Pricing("local", 0, 0, 0, 1.0);

    // ------------------------------------------------------------------

    private final AtomicLong inputTokens = new AtomicLong();
    private final AtomicLong outputTokens = new AtomicLong();
    private final AtomicLong analyzedPackets = new AtomicLong();
    private final AtomicLong skippedPackets = new AtomicLong();
    private final AtomicLong cacheHits = new AtomicLong();

    private volatile Pricing pricing = DEEPSEEK_FLASH;
    /** 预算上限（人民币元）。<=0 表示不限。 */
    private volatile double budgetCny = 1.0;
    private volatile double usdToCny = 7.1;

    // ------------------------------------------------------------------

    public void setPricing(Pricing p) {
        if (p != null) {
            this.pricing = p;
        }
    }

    public Pricing pricing() {
        return pricing;
    }

    public void setBudgetCny(double v) {
        this.budgetCny = v;
    }

    public double budgetCny() {
        return budgetCny;
    }

    public void setUsdToCny(double v) {
        if (v > 0) {
            this.usdToCny = v;
        }
    }

    // ------------------------------------------------------------------
    // 估算
    // ------------------------------------------------------------------

    /**
     * 粗略估算文本的 token 数。
     *
     * <p>经验算法，<b>不是精确分词</b>：
     * <ul>
     *   <li>ASCII 约 4 字符 / token（英文、代码、base64）</li>
     *   <li>CJK 约 1.5 字符 / token（中文比英文密）</li>
     * </ul>
     *
     * <p>为什么不用精确分词器：那要打包一个词表（几 MB），
     * 而这里只需要「量级对得上」，好让用户判断「这个按钮会不会让我破产」。
     * 精确账单在服务商控制台看。
     */
    public static int estimateTokens(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        int ascii = 0;
        int cjk = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 0x2E80) {
                ascii++;
            } else {
                cjk++;
            }
        }
        return (int) Math.ceil(ascii / 4.0) + (int) Math.ceil(cjk / 1.5);
    }

    /** 判断当前是不是服务商的高峰时段（会翻倍计费）。 */
    public static boolean isPeakNow() {
        // DeepSeek 高峰：UTC 01:00-04:00 与 06:00-10:00，周一至周五
        java.time.ZonedDateTime utc = java.time.ZonedDateTime.now(java.time.ZoneOffset.UTC);
        int dow = utc.getDayOfWeek().getValue();     // 1=周一 … 7=周日
        if (dow >= 6) {
            return false;                            // 周末全时段非高峰
        }
        int h = utc.getHour();
        return (h >= 1 && h < 4) || (h >= 6 && h < 10);
    }

    // ------------------------------------------------------------------
    // 记账
    // ------------------------------------------------------------------

    /** 记一次真实调用。 */
    public void recordCall(String systemPrompt, String brief, String replyText) {
        int sys = estimateTokens(systemPrompt);
        int in = estimateTokens(brief);
        int out = estimateTokens(replyText);
        // 系统提示词固定不变 → 假设它走缓存命中（DeepSeek 的缓存以相同前缀为准）
        inputTokens.addAndGet(sys + in);
        outputTokens.addAndGet(out);
        analyzedPackets.incrementAndGet();
        cacheHits.incrementAndGet();      // 这里只用于统计"命中缓存的输入量"，见 costCny()
    }

    /** 记一次被跳过（去重 / 低价值 / 预算超限）。 */
    public void recordSkipped(int n) {
        skippedPackets.addAndGet(n);
    }

    // ------------------------------------------------------------------

    /** 预估已花费（人民币元）。 */
    public double costCny() {
        Pricing p = pricing;
        boolean peak = isPeakNow();
        double mul = peak ? p.peakMultiplier : 1.0;

        // 系统提示词那部分按缓存命中价，其余输入按未命中价。
        // 我们不知道每次到底多少命中，保守起见按 20% 命中估。
        long in = inputTokens.get();
        long out = outputTokens.get();
        double hitTokens = in * 0.2;
        double missTokens = in - hitTokens;

        double usd = (hitTokens / 1_000_000.0) * p.inputCacheHit
                + (missTokens / 1_000_000.0) * p.inputCacheMiss
                + (out / 1_000_000.0) * p.output;
        usd *= mul;
        return usd * usdToCny;
    }

    /** 预估单个包的花费（人民币元）—— 用于「开始前」显示。 */
    public double estimatePerPacketCny(int systemTokens, int briefTokens, int replyTokens) {
        Pricing p = pricing;
        if (p.inputCacheMiss == 0 && p.output == 0) {
            return 0;                      // 本地模型
        }
        double mul = isPeakNow() ? p.peakMultiplier : 1.0;
        double usd = (systemTokens / 1_000_000.0) * p.inputCacheHit
                + (briefTokens / 1_000_000.0) * p.inputCacheMiss
                + (replyTokens / 1_000_000.0) * p.output;
        return usd * mul * usdToCny;
    }

    /** 预算是否已用尽。 */
    public boolean budgetExceeded() {
        if (budgetCny <= 0) {
            return false;
        }
        return costCny() >= budgetCny;
    }

    public long analyzedPackets() {
        return analyzedPackets.get();
    }

    public long skippedPackets() {
        return skippedPackets.get();
    }

    public long inputTokens() {
        return inputTokens.get();
    }

    public long outputTokens() {
        return outputTokens.get();
    }

    public void reset() {
        inputTokens.set(0);
        outputTokens.set(0);
        analyzedPackets.set(0);
        skippedPackets.set(0);
        cacheHits.set(0);
    }

    /** 给 UI 状态栏用的一行。 */
    public String oneLine() {
        StringBuilder sb = new StringBuilder();
        sb.append("已分析 ").append(analyzedPackets.get()).append(" 个");
        sb.append("　跳过 ").append(skippedPackets.get()).append(" 个");
        sb.append("　tokens ").append(inputTokens.get() + outputTokens.get());
        sb.append("　预估 ¥").append(String.format("%.3f", costCny()));
        if (budgetCny > 0) {
            sb.append(" / ¥").append(String.format("%.2f", budgetCny));
        }
        if (isPeakNow()) {
            sb.append("　[高峰时段，单价翻倍]");
        }
        if (budgetExceeded()) {
            sb.append("　■ 已达预算上限");
        }
        return sb.toString();
    }

    /**
     * 这个模型名有没有内置定价。
     *
     * <p>加这个方法是<b>被一次真实事故逼出来的</b>：
     * 预设里写的是 {@code deepseek-chat}，但那个模型已经退役、
     * 定价表里也早就换成了 {@code deepseek-flash} —— 两处不一致，
     * 而且<b>没有任何测试会发现</b>。用户点预设、填密钥，得到的是
     * 「模型不存在」，一头雾水。
     *
     * <p>有了这个方法就可以断言「预设里的模型名必须是定价表认识的」，
     * 从而在<b>发布前</b>抓住这类内部不一致。
     *
     * <p>▲ 它只能防「自己代码内部不一致」，防不了「服务商改了模型名」——
     * 后者只能靠把可用模型名显示给用户 + 给出去哪儿查的指引。
     */
    public static boolean isKnownModel(String model) {
        if (model == null || model.isEmpty()) {
            return false;
        }
        String m = model.toLowerCase().trim();
        return m.equals(DEEPSEEK_FLASH.name)
                || m.equals(DEEPSEEK_V4_PRO.name)
                || m.equals(LOCAL_FREE.name);
    }

    /**
     * 根据模型名猜一个计价方案。
     * 认不出来就按 flash 算 —— 宁可高估，不要让用户被账单吓到。
     */
    public static Pricing guessPricing(String model, boolean localProvider) {
        if (localProvider) {
            return LOCAL_FREE;
        }
        if (model == null) {
            return DEEPSEEK_FLASH;
        }
        String m = model.toLowerCase();
        if (m.contains("v4-pro") || m.contains("pro") || m.contains("reasoner") || m.contains("r1")) {
            return DEEPSEEK_V4_PRO;
        }
        return DEEPSEEK_FLASH;
    }
}
