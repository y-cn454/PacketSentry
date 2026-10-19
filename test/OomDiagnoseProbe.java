import java.util.List;

/**
 * 验证 diagnoseOom() 能认出「显存/内存不足」这一类错误。
 *
 * 这是被一次真实事故驱动的测试：用户点「测试连接」得到
 * cudaMalloc failed: out of memory，而当时的 diagnose() 认不出来，
 * 只回了一句「没能自动判断出原因」+ 四行通用排查项。
 *
 * 断言的就是那时候缺的那条分支。
 */
public class OomDiagnoseProbe {
    static int pass = 0, fail = 0;
    static void check(String label, boolean ok) {
        if (ok) { pass++; System.out.println("  [PASS] " + label); }
        else { fail++; System.out.println("  [FAIL] " + label); }
    }

    public static void main(String[] a) throws Exception {
        System.out.println("============================================================");
        System.out.println(" diagnoseOom() 认得出 OOM 类错误吗");
        System.out.println("============================================================");

        // 用户实际遇到的 CUDA OOM 文案
        String cudaErr = ("llama-server process has terminated: exit status 1: "
                + "cudaMalloc failed: out of memory\n"
                + "ggml_backend_buft_alloc_buffer_n_default: failed to allocate CUDA0 buffer of size 4869357568\n"
                + "error loading model: unable to allocate CUDA0 buffer").toLowerCase();

        // 纯 CPU 的 OOM 文案（同一台机器上复现出来的）
        String cpuErr = ("llama-server process has terminated: exit status 1: "
                + "ggml_backend_cpu_buffer_type_alloc_buffer: failed to allocate buffer of size 3312451584\n"
                + "failed to allocate CPU_REPACK buffer of size 3312451584\n"
                + "error loading model: unable to allocate CPU_REPACK").toLowerCase();

        java.lang.reflect.Method m = Class.forName("com.packetsentry.ui.SettingsPanel")
                .getDeclaredMethod("diagnoseOom", String.class);
        m.setAccessible(true);

        for (String[] k : new String[][]{{"CUDA OOM", cudaErr}, {"CPU OOM", cpuErr}}) {
            @SuppressWarnings("unchecked")
            List<String> lines = (List<String>) m.invoke(null, k[1]);
            String joined = lines == null ? "" : String.join("\n", lines);
            System.out.println("\n  [" + k[0] + "] 命中 " + (lines == null ? 0 : lines.size()) + " 行建议");
            if (lines != null) for (String s : lines) System.out.println("    " + s);
            check(k[0] + "：被识别（返回非 null）", lines != null);
            check(k[0] + "：指向显存/内存", joined.contains("显存") || joined.contains("内存"));
            check(k[0] + "：提醒不要连按测试连接", joined.contains("测试连接"));
            check(k[0] + "：提到提交限制这个坑", joined.contains("提交限制"));
        }

        // 反面：正常错误不该被 OOM 分支吞掉
        @SuppressWarnings("unchecked")
        List<String> normal = (List<String>) m.invoke(null, "invalid api key");
        check("无关错误不会被 OOM 分支误判（返回 null）", normal == null);

        @SuppressWarnings("unchecked")
        List<String> nul = (List<String>) m.invoke(null, (Object) null);
        check("null 输入安全返回 null", nul == null);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}