import com.packetsentry.core.Config;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.core.RealtimePipe;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 第四轮（并发与线程安全）+ 第五轮（生命周期与状态机）实测。
 *
 * <h3>为什么这两轮要放在一起</h3>
 * 它们查的是同一类东西：<b>「多线程 + 状态切换时，代码还对不对」</b>。
 * 前三轮都在「静止」状态下测（干净输入、单线程），
 * 抓不到并发窗口和状态切换的边界。
 *
 * <p>这两轮刻意<b>真的起线程去撞</b>，而不是静态读代码猜。
 */
public class ConcurrencyProbe {

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

    private static byte[] resp(String body) {
        return b("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body);
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public static void main(String[] args) throws Exception {
        Config cfg = new Config();
        cfg.sanitizeEnabled = true;
        cfg.scanEnabled = true;

        // ==============================================================
        System.out.println("============================================================");
        System.out.println(" 第四轮 · A：多线程并发提交（不许丢、不许重复、不许崩）");
        System.out.println("============================================================");

        RealtimePipe p1 = new RealtimePipe(() -> cfg);
        p1.start();

        final int threads = 8;
        final int perThread = 150;
        final CountDownLatch ready = new CountDownLatch(threads);
        final CountDownLatch go = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(threads);
        final AtomicInteger threw = new AtomicInteger();

        for (int t = 0; t < threads; t++) {
            final int tid = t;
            Thread th = new Thread(() -> {
                ready.countDown();
                try {
                    go.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                for (int i = 0; i < perThread; i++) {
                    try {
                        p1.submit(b("GET /api/t" + tid + "/n" + i + " HTTP/1.1\r\nHost: c.com\r\n"
                                        + "Cookie: a=1\r\n\r\n"),
                                resp("{\"i\":" + i + "}"), 1, true, new Object(), null);
                    } catch (Throwable ex) {
                        threw.incrementAndGet();
                    }
                }
                done.countDown();
            }, "probe-" + t);
            th.setDaemon(true);
            th.start();
        }

        ready.await();
        go.countDown();
        done.await();
        sleep(3000);

        int submitted = threads * perThread;
        long inRecent = p1.snapshot().size();
        long processedTotal = p1.processedCount();
        System.out.println("  提交 " + submitted + " 条；recent 里 " + inRecent
                + " 条（上限 500）；全量计数 " + processedTotal + " 条");
        System.out.println("  提交时抛异常：" + threw.get() + " 次");

        check("并发提交不抛异常", threw.get() == 0);
        // ⚠️ 注意断言对象：recent 是「界面展示窗口」，有 500 的上界，本来就装不下 1200。
        //    真正要保证的不变量是「全量计数一条不漏」—— 早期这里断言错了对象，
        //    报了个假 FAIL。全量计数与 recent 分离正是为了避免这种统计失真。
        check("全量计数一条不漏（processedCount == 提交数）", processedTotal == submitted);
        check("recent 被限制在上界内（<=500）", inRecent <= 500);
        // 序号必须唯一 —— 重复序号说明有重复记录
        Set<Integer> seqs = new HashSet<>();
        boolean dupSeq = false;
        for (PacketRecord r : p1.snapshot()) {
            if (!seqs.add(r.seq)) {
                dupSeq = true;
                break;
            }
        }
        check("序号唯一（没有重复记录）", !dupSeq);
        p1.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第四轮 · B：并发读 snapshot（UI 线程在不间断刷新）");
        System.out.println("============================================================");

        RealtimePipe p2 = new RealtimePipe(() -> cfg);
        p2.start();

        final AtomicInteger readErrors = new AtomicInteger();
        final AtomicInteger stopFlag = new AtomicInteger();
        Thread reader = new Thread(() -> {
            while (stopFlag.get() == 0) {
                try {
                    List<PacketRecord> snap = p2.snapshot();
                    // 真的遍历一遍 —— 只取 size 测不出 ConcurrentModification
                    long n = 0;
                    for (PacketRecord r : snap) {
                        if (r != null) {
                            n++;
                        }
                    }
                    if (n < 0) {
                        throw new IllegalStateException("impossible");
                    }
                } catch (Throwable ex) {
                    readErrors.incrementAndGet();
                }
            }
        }, "probe-reader");
        reader.setDaemon(true);
        reader.start();

        for (int i = 0; i < 400; i++) {
            p2.submit(b("GET /api/x" + i + " HTTP/1.1\r\nHost: c.com\r\n\r\n"),
                    resp("{}"), 1, true, new Object(), null);
            if (i % 50 == 0) {
                sleep(20);
            }
        }
        sleep(1500);
        stopFlag.set(1);
        reader.join(2000);

        System.out.println("  读线程遍历 snapshot " + readErrors.get() + " 次失败");
        check("UI 边提交边遍历 snapshot 不抛异常（无 ConcurrentModification）",
                readErrors.get() == 0);
        p2.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第五轮 · C：暂停 —— 任务不该丢、dropped 不该虚增");
        System.out.println("============================================================");

        RealtimePipe p3 = new RealtimePipe(() -> cfg);
        p3.start();
        p3.setPaused(true);
        sleep(200);

        // ⚠️ 刻意提交<b>超过队列容量</b>的量（QUEUE_CAPACITY = 2048）。
        //    只提交 300 条测不出问题 —— 队列装得下，怎么都不会丢。
        //    填满之后才能暴露「暂停时取出再放回」的丢包风险。
        final int pausedCount = 2600;
        for (int i = 0; i < pausedCount; i++) {
            p3.submit(b("GET /api/p" + i + " HTTP/1.1\r\nHost: c.com\r\n\r\n"),
                    resp("{}"), 1, true, new Object(), null);
        }
        sleep(1500);
        long droppedWhilePaused = p3.droppedCount();
        long processedWhilePaused = p3.processedCount();
        System.out.println("  暂停期间提交 " + pausedCount + " 条：dropped=" + droppedWhilePaused
                + "　processed=" + processedWhilePaused + "　排队中=" + p3.queuedCount());

        // ⚠️ 暂停期间队列本来就装不下 2600 条（容量 2048），
        //    所以「溢出部分被丢弃」是<b>正常且有界</b>的行为 ——
        //    真正要保证的不变量是<b>守恒</b>：
        //    每条提交要么被处理、要么被明确计入 dropped，不能凭空消失。
        //    早期那个 bug 违反的正是这条：它在暂停时把队列里的任务也丢了。
        check("暂停期间消费者完全不消费（processed 不增长）", processedWhilePaused == 0);

        p3.setPaused(false);
        sleep(8000);
        long afterProcessed = p3.processedCount();
        long afterDropped = p3.droppedCount();
        System.out.println("  恢复后：processed=" + afterProcessed + "　dropped=" + afterDropped);

        check("守恒律：processed + dropped == 提交数（没有凭空消失的）",
                afterProcessed + afterDropped == pausedCount);
        check("恢复后把队列里能装的都处理了（>=2048）", afterProcessed >= 2048);
        p3.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第五轮 · D：reset 之后不该冒出旧会话的记录");
        System.out.println("============================================================");

        RealtimePipe p4 = new RealtimePipe(() -> cfg);
        p4.start();
        // 只发请求不发响应 → 进入 pending 挂起表
        for (int i = 0; i < 20; i++) {
            p4.submit(b("GET /api/hang" + i + " HTTP/1.1\r\nHost: c.com\r\n\r\n"),
                    null, 1, true, "key-hang-" + i, null);
        }
        sleep(300);
        // 清空会话
        p4.reset();
        int rightAfterReset = p4.snapshot().size();
        System.out.println("  reset 后立刻：" + rightAfterReset + " 条");

        // 等超过 pending 超时（5s），看旧挂起项会不会被冲进新会话
        sleep(6500);
        int afterTimeout = p4.snapshot().size();
        System.out.println("  等 6.5 秒（超过 pending 超时）后：" + afterTimeout + " 条");
        check("reset 后旧会话的挂起请求不会被冲进新会话", afterTimeout == 0);
        p4.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第五轮 · E：stop 后立刻 start —— 不能有两个消费线程");
        System.out.println("============================================================");

        RealtimePipe p5 = new RealtimePipe(() -> cfg);
        p5.start();
        p5.submit(b("GET /a HTTP/1.1\r\nHost: c.com\r\n\r\n"), resp("{}"), 1, true, new Object(), null);
        sleep(200);
        p5.stop();
        p5.start();          // 立刻重启
        p5.submit(b("GET /b HTTP/1.1\r\nHost: c.com\r\n\r\n"), resp("{}"), 1, true, new Object(), null);
        sleep(1200);
        int afterRestart = p5.snapshot().size();
        int liveThreads = 0;
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            if ("packetsentry-pipe".equals(t.getName()) && t.isAlive()) {
                liveThreads++;
            }
        }
        System.out.println("  重启后记录 " + afterRestart + " 条，存活的 packetsentry-pipe 线程 " + liveThreads + " 个");
        check("stop+start 后只应有一个消费线程", liveThreads <= 1);
        check("重启后还能正常处理", afterRestart >= 2);
        p5.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第五轮 · F：stop 之后 submit 必须是空操作");
        System.out.println("============================================================");

        RealtimePipe p6 = new RealtimePipe(() -> cfg);
        p6.start();
        p6.stop();
        sleep(300);
        int before = p6.snapshot().size();
        for (int i = 0; i < 50; i++) {
            p6.submit(b("GET /z" + i + " HTTP/1.1\r\nHost: c.com\r\n\r\n"),
                    resp("{}"), 1, true, new Object(), null);
        }
        sleep(500);
        int after = p6.snapshot().size();
        System.out.println("  stop 前 " + before + " 条，提交 50 次后 " + after + " 条");
        check("stop 后 submit 不产生记录", after == before);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第五轮 · G：反复 start/stop —— 不许线程泄漏");
        System.out.println("============================================================");

        RealtimePipe p7 = new RealtimePipe(() -> cfg);
        for (int i = 0; i < 15; i++) {
            p7.start();
            p7.submit(b("GET /r" + i + " HTTP/1.1\r\nHost: c.com\r\n\r\n"),
                    resp("{}"), 1, true, new Object(), null);
            p7.stop();
        }
        sleep(800);
        int leaked = 0;
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            if ("packetsentry-pipe".equals(t.getName()) && t.isAlive()) {
                leaked++;
            }
        }
        System.out.println("  15 轮 start/stop 后存活线程：" + leaked + " 个");
        check("反复 start/stop 后没有线程泄漏", leaked <= 1);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
