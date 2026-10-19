import com.packetsentry.core.Config;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.core.RealtimePipe;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 第七轮排查：<b>内存与资源上界</b>。
 *
 * <h3>为什么这一轮单独做</h3>
 * 抓包插件是<b>长时间运行</b>的 —— 用户挂着代理跑几个小时甚至一整天。
 * 一个「每来一个包就涨一点」的容器，短测完全看不出来，
 * 长会话会把 Burp 拖到卡死或 OOM。
 *
 * <p>所以这一轮专门找<b>没有上限的容器</b>，以及
 * 「上限写了但没生效」的情况。
 *
 * <p>关键手法：喂<b>看似无限的不同输入</b>。
 * 随机字母数字 ID 是个好诱饵 —— 它既不是纯数字（会被归一化），
 * 也不是十六进制（会被归一化），所以会真正撑爆去重表。
 */
public class ResourceProbe {

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

    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] resp() {
        return b("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}");
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** 用反射读私有容器的 size —— 这是唯一能看到「内部有没有涨」的办法。 */
    @SuppressWarnings("unchecked")
    private static int sizeOf(Object target, String field) {
        try {
            Field f = target.getClass().getDeclaredField(field);
            f.setAccessible(true);
            Object v = f.get(target);
            if (v instanceof Map) {
                return ((Map<?, ?>) v).size();
            }
            if (v instanceof Set) {
                return ((Set<?>) v).size();
            }
            if (v instanceof List) {
                return ((List<?>) v).size();
            }
        } catch (Throwable ignored) {
            return -1;
        }
        return -1;
    }

    /**
     * 生成随机字母数字串（长度 10，base62）—— 这类 ID 不会被签名归一化。
     *
     * <p>⚠️ 但这个生成器<b>不保证唯一</b>：它是个确定性 LCG，调用足够多次会重复。
     * 早期用它灌 22000 次只产出约 4200 个不同值，于是「灌到上界」的断言
     * 根本没被真正触发（报了假 FAIL）。需要唯一值时用 {@link #uniqueToken}。
     */
    private static String randId(long seed) {
        final String cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder();
        long x = seed * 6364136223846793005L + 1442695040888963407L;
        for (int i = 0; i < 10; i++) {
            x = x * 6364136223846793005L + 1442695040888963407L;
            sb.append(cs.charAt((int) Math.abs(x % 62)));
        }
        return sb.toString();
    }

    /**
     * 生成<b>真正唯一</b>且不会被签名归一化的 token。
     *
     * <p>做法：把序号转成 base-26 的纯字母串，补足到 10 位。
     * 纯字母不含数字，所以 {@code DIGIT_RUN} 不会碰它；
     * 26^10 的空间足够大到不会重复。
     */
    private static String uniqueToken(long n) {
        StringBuilder sb = new StringBuilder();
        long x = n;
        for (int i = 0; i < 10; i++) {
            sb.append((char) ('a' + (int) (x % 26)));
            x /= 26;
        }
        return sb.reverse().toString();
    }

    public static void main(String[] args) {
        Config cfg = new Config();
        cfg.sanitizeEnabled = true;
        cfg.scanEnabled = true;

        System.out.println("============================================================");
        System.out.println(" 第七轮 · A：随机字母数字 ID 会不会撑爆去重表");
        System.out.println("============================================================");

        RealtimePipe p1 = new RealtimePipe(() -> cfg);
        p1.start();

        // 先来 200 条正常的（结构有限）
        for (int i = 0; i < 200; i++) {
            p1.submit(b("GET /api/user/" + i + " HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                    resp(), 1, true, new Object(), null);
        }
        sleep(1500);
        int afterNormal = sizeOf(p1, "seenSignatures");
        System.out.println("  200 条数字 ID（应归一化）→ 去重表 " + afterNormal + " 条");

        // 再来 3000 条随机字母数字 ID —— 每条都是新签名
        for (int i = 0; i < 3000; i++) {
            p1.submit(b("GET /download/" + uniqueToken(i) + " HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                    resp(), 1, true, new Object(), null);
        }
        sleep(6000);
        int afterRandom = sizeOf(p1, "seenSignatures");
        System.out.println("  再加 3000 条随机字母数字 ID → 去重表 " + afterRandom + " 条");
        System.out.println("  全量计数 " + p1.processedCount() + "，worth " + p1.worthCount());

        check("数字 ID 被正确归一化（200 条只占很少签名）", afterNormal > 0 && afterNormal <= 5);
        // ⚠️ 这条断言我一开始写弱了：写成 <=5000 的话，喂 3000 个输入当然通过 ——
        //    那等于什么都没测。真正要测的是「上界真的生效」，
        //    所以必须<b>灌到超过上界</b>，然后看它停在哪。
        System.out.println("  去重表实际停在 " + afterRandom + " 条");
        check("去重表停在上界（20000），不会随随机 ID 无界增长",
                afterRandom <= 20000);
        check("到界后优雅降级而不是清空（表不会被清零导致成本突增）",
                afterRandom >= 20000 || !p1.dedupSaturated());

        // 灌到超过上界，验证饱和行为。
        //
        // ⚠️ 必须<b>控制提交节奏</b>。裸灌 22000 条进容量 2048 的队列，
        //    绝大部分会当场被 dropped，根本走不到签名表 ——
        //    于是「有没有饱和」这件事压根没被测到（这是第二个假 FAIL 的原因）。
        //    所以分批提交、每批等消费者追上再继续。
        int batches = 22;
        int perBatch = 1000;
        for (int bat = 0; bat < batches; bat++) {
            for (int i = 0; i < perBatch; i++) {
                p1.submit(b("GET /x/" + uniqueToken(bat * perBatch + i)
                                + "/y HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                        resp(), 1, true, new Object(), null);
            }
            long target = (long) (bat + 1) * perBatch;
            long deadline = System.currentTimeMillis() + 20000;
            while (p1.processedCount() < target && System.currentTimeMillis() < deadline) {
                sleep(50);
            }
        }
        int saturated = sizeOf(p1, "seenSignatures");
        System.out.println("  灌 " + (batches * perBatch) + " 个唯一签名后 → 去重表 " + saturated
                + " 条，饱和=" + p1.dedupSaturated()
                + "，溢出计数=" + p1.dedupOverflowCount()
                + "，dropped=" + p1.droppedCount());
        check("灌爆之后去重表仍停在上界内（内存有界）", saturated <= 20000);
        check("饱和状态被如实上报（dedupSaturated）", p1.dedupSaturated());
        check("溢出的签名被计数（不是静默吞掉）", p1.dedupOverflowCount() > 0);
        System.out.println("  结构比（签名/已处理）="
                + String.format("%.2f", p1.structureRatio()) + "　（接近 1 说明去重失效）");
        p1.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第七轮 · B：其它容器都必须有上界");
        System.out.println("============================================================");

        RealtimePipe p2 = new RealtimePipe(() -> cfg);
        p2.start();
        for (int i = 0; i < 3000; i++) {
            p2.submit(b("POST /api/thing/" + randId(i) + " HTTP/1.1\r\nHost: s.com\r\n"
                            + "Content-Type: application/json\r\n\r\n"
                            + "{\"k" + i + "\":" + i + "}"),
                    resp(), 1, true, new Object(), null);
        }
        sleep(6000);

        int recentSize = p2.snapshot().size();
        int pendingSize = sizeOf(p2, "pending");
        int queueSize = p2.queuedCount();
        int logicSigs = p2.logicTrackedSignatures();

        System.out.println("  recent      " + recentSize + "（上限 500）");
        System.out.println("  pending     " + pendingSize + "（上限 512）");
        System.out.println("  queue       " + queueSize + "（容量 2048）");
        System.out.println("  logicSigs   " + logicSigs + "（上限 4000）");

        check("recent 有上界（<=500）", recentSize <= 500);
        check("pending 有上界（<=512）", pendingSize <= 512);
        check("queue 有上界（<=2048）", queueSize <= 2048);
        check("逻辑线索引擎的签名表有上界（<=4000）", logicSigs <= 4000);
        p2.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第七轮 · C：计数器不能溢出 / 失真");
        System.out.println("============================================================");

        RealtimePipe p3 = new RealtimePipe(() -> cfg);
        p3.start();
        int n = 2000;
        for (int i = 0; i < n; i++) {
            p3.submit(b("GET /api/c/" + randId(i) + " HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                    resp(), 1, true, new Object(), null);
        }
        sleep(5000);

        long processed = p3.processedCount();
        long low = p3.lowValueCount();
        long dup = p3.duplicateCount();
        long worth = p3.worthCount();
        long dropped = p3.droppedCount();
        long issues = p3.issueCount();

        System.out.println("  processed=" + processed + "  low=" + low
                + "  dup=" + dup + "  worth=" + worth + "  dropped=" + dropped);
        check("processed == low + dup + worth（三类互斥且完备）",
                processed == low + dup + worth);
        check("processed == 提交数（队列未溢出时）", processed == n);
        check("dropped == 0（队列装得下 2000，容量 2048）", dropped == 0);
        check("issueCount <= processed（不能比处理的包还多）", issues <= processed);

        double ratio = p3.savedRatio();
        System.out.println("  省下的比例 " + String.format("%.1f%%", ratio * 100));
        check("节省比例在 0~1 之间（不能是负数或超过 100%）", ratio >= 0 && ratio <= 1);
        p3.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第七轮 · D：reset 必须把资源真的放掉");
        System.out.println("============================================================");

        RealtimePipe p4 = new RealtimePipe(() -> cfg);
        p4.start();
        for (int i = 0; i < 1500; i++) {
            p4.submit(b("GET /api/r/" + randId(i) + " HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                    resp(), 1, true, new Object(), null);
        }
        sleep(4000);
        int beforeSigs = sizeOf(p4, "seenSignatures");
        int beforeRecent = p4.snapshot().size();
        long beforeProcessed = p4.processedCount();

        p4.reset();
        sleep(300);
        int afterSigs = sizeOf(p4, "seenSignatures");
        int afterRecent = p4.snapshot().size();
        int afterLogic = p4.logicTrackedSignatures();
        long afterDropped = p4.droppedCount();

        System.out.println("  重置前：签名 " + beforeSigs + "　recent " + beforeRecent
                + "　processed " + beforeProcessed);
        System.out.println("  重置后：签名 " + afterSigs + "　recent " + afterRecent
                + "　逻辑签名 " + afterLogic + "　dropped " + afterDropped);

        check("reset 清空去重表", afterSigs == 0);
        check("reset 清空 recent", afterRecent == 0);
        check("reset 清空逻辑签名表", afterLogic == 0);
        check("reset 归零 dropped", afterDropped == 0);
        // ⚠️ 刻意保留 processed 吗？不 —— 现有实现把 processed 也保留了。
        //    这是设计选择：processed 是「全量统计」，用于算省钱比例，
        //    清空会话后是否该归零有争议。这里只断言「不崩、不倒退」。
        check("reset 后 processed 不倒退（单调不减）", p4.processedCount() >= beforeProcessed);
        p4.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第七轮 · E：listen 注册不会重复累积");
        System.out.println("============================================================");

        RealtimePipe p5 = new RealtimePipe(() -> cfg);
        int[] callbacks = {0};
        for (int i = 0; i < 50; i++) {
            p5.addListener(new RealtimePipe.Listener() {
                @Override
                public void onRecord(PacketRecord r) {
                    callbacks[0]++;
                }

                @Override
                public void onOverflow(long n) {
                    // 不需要
                }
            });
        }
        p5.start();
        p5.submit(b("GET /api/l HTTP/1.1\r\nHost: s.com\r\n\r\n"), resp(), 1, true, new Object(), null);
        sleep(1000);
        long l5Processed = p5.processedCount();
        System.out.println("  注册 50 个 listener，处理 " + l5Processed + " 条，回调触发 "
                + callbacks[0] + " 次");
        // 注册 50 个 listener 就该被调用 50 次 —— 没有去重是合理的，
        // 但如果将来加了去重，这里会失败，提醒作者确认语义。
        check("每个 listener 都被调用（语义一致，无静默去重）",
                callbacks[0] == 50 * (int) l5Processed);
        p5.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第七轮 · F：长时间空转不涨内存");
        System.out.println("============================================================");

        RealtimePipe p6 = new RealtimePipe(() -> cfg);
        p6.start();
        Runtime rt = Runtime.getRuntime();
        for (int warm = 0; warm < 3; warm++) {
            for (int i = 0; i < 500; i++) {
                p6.submit(b("GET /api/w/" + randId(i) + " HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                        resp(), 1, true, new Object(), null);
            }
            sleep(1500);
            p6.reset();
            System.gc();
            sleep(300);
        }
        long used1 = rt.totalMemory() - rt.freeMemory();

        // 再来三轮同样的量
        for (int warm = 0; warm < 3; warm++) {
            for (int i = 0; i < 500; i++) {
                p6.submit(b("GET /api/w/" + randId(i) + " HTTP/1.1\r\nHost: s.com\r\n\r\n"),
                        resp(), 1, true, new Object(), null);
            }
            sleep(1500);
            p6.reset();
            System.gc();
            sleep(300);
        }
        long used2 = rt.totalMemory() - rt.freeMemory();

        System.out.println("  第一批后 " + (used1 / 1024 / 1024) + " MB，第二批后 "
                + (used2 / 1024 / 1024) + " MB");
        // 完全相等不现实（JIT / 类加载 / GC 时机），给一个宽松但能抓住泄漏的界
        check("反复灌量并 reset 后内存没有显著增长（< 32MB 增量）",
                used2 - used1 < 32L * 1024 * 1024);
        p6.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
