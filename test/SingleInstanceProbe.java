import com.packetsentry.burp.SingleInstance;

/**
 * 单实例保护测试。
 *
 * 要证明：第一次 acquire 拿到 PRIMARY，第二次拿到 ALREADY_RUNNING。
 * 这对应真实场景 —— Extender 里同一条 jar 被添加两次（两个 classloader），
 * 第二次必须被挡住，否则会双份抓包、双份写文件。
 */
public class SingleInstanceProbe {
    static int pass = 0, fail = 0;
    static void check(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  [PASS] " + label); }
        else { fail++; System.out.println("  [FAIL] " + label); }
    }

    public static void main(String[] a) throws Exception {
        System.out.println("============================================================");
        System.out.println(" 单实例保护");
        System.out.println("============================================================");

        SingleInstance.Verdict v1 = SingleInstance.acquire();
        System.out.println("  第一次 acquire: " + v1);
        check("第一次拿到 PRIMARY", v1 == SingleInstance.Verdict.PRIMARY);
        check("duplicate() 为 false", !SingleInstance.duplicate());
        check("幂等（重复 acquire 结果一致）",
                SingleInstance.acquire() == SingleInstance.Verdict.PRIMARY);

        // ⚠️ 同一个 JVM 内无法真正模拟"第二个 classloader"，
        //    但可以用另一把锁去撞同一个文件，验证 tryLock 确实会失败。
        java.nio.file.Path lf = java.nio.file.Paths.get(
                System.getProperty("user.home"), ".packetsentry", "instance.lock");
        boolean blocked;
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(lf.toFile(), "rw");
             java.nio.channels.FileChannel ch = raf.getChannel()) {
            java.nio.channels.FileLock l2 = null;
            try {
                l2 = ch.tryLock();
            } catch (java.nio.channels.OverlappingFileLockException expected) {
                // 正是我们要的：同 JVM 内重复加锁会被拒
            }
            blocked = (l2 == null);
            if (l2 != null) { l2.release(); }
        }
        check("⭐ 同一 JVM 内第二次加锁被拒（重复加载能被识别）", blocked);

        String w = SingleInstance.warning();
        check("警告文案包含修复指引", w.contains("Extender"));
        check("警告文案说明了后果", w.contains("抓两遍") || w.contains("覆盖"));
        check("警告文案点名了要保留哪个文件", w.contains("PacketSentry.jar"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}