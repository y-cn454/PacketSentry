package com.packetsentry.burp;

import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 单实例保护 —— 防止同一个插件被加载两次。
 *
 * <h2>为什么需要</h2>
 * Burp 的 Extender 允许同一个 jar 被添加多次。每次添加都会创建一个
 * <b>独立的 classloader</b>，所以：
 * <ul>
 *   <li>静态字段<b>不共享</b> —— 两个实例互不知道对方存在</li>
 *   <li>两个实例都会 {@code registerHttpListener} → <b>同一个包被抓两遍</b></li>
 *   <li>两个实例都会写 {@code ~/.packetsentry/config.json} 和
 *       {@code findings.json} → <b>互相覆盖</b></li>
 *   <li>界面出现两个同名标签页，用户分不清哪个是真的</li>
 * </ul>
 *
 * <p>实测触发方式很普通：旧的那条 entry 指向一个已被删除的 jar，
 * 用户为了修复又添加了一次 —— 于是列表里两条都打勾。
 *
 * <h2>怎么检测</h2>
 * 用 {@link FileLock} 锁住 {@code ~/.packetsentry/instance.lock}。
 * 文件锁是<b>进程级</b>的，同一 JVM 内第二次尝试 {@code tryLock} 会抛
 * {@link OverlappingFileLockException} —— 正好用来识别「同进程内重复加载」。
 *
 * <p>⚠️ 注意这只能识别<b>同一个 Burp 进程内</b>的重复加载。
 * 两个 Burp 同时跑会是两个进程，文件锁能正确互斥（第二个拿不到锁），
 * 那是另一层保护，也是对的 —— 两个 Burp 同时写 findings.json 一样会坏。
 */
public final class SingleInstance {

    private SingleInstance() {
    }

    /** 拿到的锁与文件句柄 —— 必须一直持有，否则锁会释放。 */
    private static FileLock lock;
    private static FileChannel channel;

    /** 检测结果。 */
    public enum Verdict {
        /** 本次是唯一的实例。 */
        PRIMARY,
        /** 已经有另一个实例在跑了。 */
        ALREADY_RUNNING,
        /** 锁文件不可用（只读目录等）—— 当作 PRIMARY，但不能保证互斥。 */
        UNKNOWN
    }

    private static Verdict verdict = null;

    /**
     * 尝试成为主实例。可重复调用，结果缓存。
     *
     * @return 判定结果
     */
    public static synchronized Verdict acquire() {
        if (verdict != null) {
            return verdict;
        }
        Path dir = Paths.get(System.getProperty("user.home"), ".packetsentry");
        Path lockFile = dir.resolve("instance.lock");
        try {
            Files.createDirectories(dir);
            channel = new RandomAccessFile(lockFile.toFile(), "rw").getChannel();
            try {
                lock = channel.tryLock();
            } catch (OverlappingFileLockException dup) {
                // ⭐ 同一 JVM 内已经有实例锁住了这个文件 —— 就是重复加载
                lock = null;
            }
            if (lock == null) {
                verdict = Verdict.ALREADY_RUNNING;
                return verdict;
            }
            // 把 pid 写进去，方便人工排查是谁占着
            try {
                channel.truncate(0);
                channel.write(java.nio.ByteBuffer.wrap(
                        ("pid=" + ProcessHandle.current().pid() + "\n")
                                .getBytes(StandardCharsets.UTF_8)));
            } catch (Throwable ignored) {
                // 写 pid 只是便于排查，失败不影响互斥
            }
            verdict = Verdict.PRIMARY;
        } catch (Throwable t) {
            // 拿不到锁文件（权限/只读）—— 不能保证互斥，但也不该阻止插件工作
            verdict = Verdict.UNKNOWN;
        }
        return verdict;
    }

    /** 是否已经有另一个实例在跑。 */
    public static boolean duplicate() {
        return acquire() == Verdict.ALREADY_RUNNING;
    }

    /** 给人看的提示（重复加载时打印到 Burp 的 Extender → Output）。 */
    public static String warning() {
        return "\n"
                + "══════════════════════════════════════════════════\n"
                + "  ⚠️ 检测到 PacketSentry 被加载了两次\n"
                + "══════════════════════════════════════════════════\n"
                + "  本次实例不会注册 HTTP 监听器，也不会写配置文件 ——\n"
                + "  否则会把同一个包抓两遍，并且两个实例会互相覆盖\n"
                + "  config.json 与 findings.json。\n"
                + "\n"
                + "  怎么修：\n"
                + "    Extender → Extensions 里会有两条 PacketSentry，\n"
                + "    选中多出来的那条 → 点「删除」。\n"
                + "\n"
                + "  ⚠️ 删之前先确认保留的是哪条：点每条看一下\n"
                + "    「详细信息」里的「文件名称」，保留 dist\\PacketSentry.jar。\n"
                + "══════════════════════════════════════════════════\n";
    }
}
