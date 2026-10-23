import com.packetsentry.core.PacketRecord;
import com.packetsentry.core.RealtimePipe;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 二进制响应误判 —— 回归测试。
 *
 * <p>背景（真实用户报障）：
 * <pre>
 *   GET mts.xxx.mobi/video5/xxx.ts   →   Content-Type: binary/octet-stream
 * </pre>
 * 这段 HLS 视频分片一路混进了分析流程：
 * <ol>
 *   <li>被转成 UTF-8 字符串扫了一遍，二进制里恰好出现 {@code <%=} →
 *       误报「高危：源码泄露」</li>
 *   <li>又被整段拼进 AI prompt → 模型吃进乱码，请求直接失败</li>
 * </ol>
 *
 * <p>本探针锁死三件事：
 * <ol>
 *   <li>{@code looksBinary} 能识别真正的二进制（NUL / 高比例控制字符）</li>
 *   <li>二进制响应进管道后：{@code lowValue == true} 且 {@code issues} 为空</li>
 *   <li>⭐ <b>真正的文本源码泄露仍然会被抓到</b>（不能为了去误报把真漏洞也干掉）</li>
 * </ol>
 */
public final class BinaryGuardProbe {

    private static int pass = 0;
    private static int fail = 0;

    public static void main(String[] args) throws Exception {
        // ---------- ① looksBinary 单元判据 ----------
        Method looksBinary = RealtimePipe.class.getDeclaredMethod("looksBinary", byte[].class);
        looksBinary.setAccessible(true);

        check("空数组 → 不是二进制", false, looksBinary(looksBinary, new byte[0]));
        check("null → 不是二进制", false, looksBinary(looksBinary, (byte[]) null));

        check("普通 HTML → 不是二进制", false, looksBinary(looksBinary,
                "<html><body>hello</body></html>".getBytes(StandardCharsets.UTF_8)));

        check("JSON → 不是二进制", false, looksBinary(looksBinary,
                "{\"code\":200,\"data\":[1,2,3]}".getBytes(StandardCharsets.UTF_8)));

        // ⭐ 中文 UTF-8 必须判成"文本" —— 不能因为高位字节多就误判
        check("UTF-8 中文 → 不是二进制", false, looksBinary(looksBinary,
                "<p>用户登录失败，请重试</p>".getBytes(StandardCharsets.UTF_8)));

        check("含制表/换行 → 不是二进制", false, looksBinary(looksBinary,
                "a\tb\r\nc\nd".getBytes(StandardCharsets.UTF_8)));

        // ⭐ NUL 字节：最可靠的二进制信号
        byte[] withNul = "abc\0def".getBytes(StandardCharsets.ISO_8859_1);
        check("含 NUL → 是二进制", true, looksBinary(looksBinary, withNul));

        // ⭐ 模拟 MPEG-TS 分片：同步字节 0x47 + 大量控制字符
        byte[] mpegTs = new byte[512];
        for (int i = 0; i < mpegTs.length; i++) {
            mpegTs[i] = (byte) ((i % 188 == 0) ? 0x47 : (0x00 + (i * 37) % 256));
        }
        check("MPEG-TS 分片 → 是二进制", true, looksBinary(looksBinary, mpegTs));

        // ⭐ PNG 头
        byte[] png = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13};
        check("PNG 头 → 是二进制", true, looksBinary(looksBinary, png));

        // 少量控制字符不足以判定
        byte[] mostlyText = ("hello world, this is a long text body with one "
                + "\u0001" + " control char at the end").getBytes(StandardCharsets.ISO_8859_1);
        check("仅 1 个控制字符 → 不是二进制", false, looksBinary(looksBinary, mostlyText));

        // ---------- ② 端到端：二进制响应不该被扫 ----------
        RealtimePipe pipe = new RealtimePipe(() -> new com.packetsentry.core.Config());
        pipe.start();

        String req =
                "GET /video5/7cc28/7cc28.ts HTTP/1.1\r\n"
                        + "Host: mts.xxx.mobi\r\n"
                        + "User-Agent: test\r\n\r\n";

        // 构造响应头 + 二进制体（体里刻意塞入 <%%= 让"源码泄露"规则有机会误报）
        String head =
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: binary/octet-stream\r\n"
                        + "Content-Length: 256\r\n\r\n";
        byte[] body = new byte[256];
        byte[] trigger = "<%=".getBytes(StandardCharsets.ISO_8859_1);
        for (int i = 0; i < body.length; i++) {
            body[i] = (byte) (i % 7 == 0 ? 0x00 : (byte) (0x80 + (i % 64)));
        }
        System.arraycopy(trigger, 0, body, 40, trigger.length);
        byte[] respHead = head.getBytes(StandardCharsets.UTF_8);
        byte[] resp = new byte[respHead.length + body.length];
        System.arraycopy(respHead, 0, resp, 0, respHead.length);
        System.arraycopy(body, 0, resp, respHead.length, body.length);

        pipe.submit(req.getBytes(StandardCharsets.UTF_8), resp, 1, true, new Object(), null);
        sleep(400);

        List<PacketRecord> snap = pipe.snapshot();
        PacketRecord bin = last(snap);
        check("二进制报文已进入管道", true, bin != null);
        if (bin != null) {
            check("二进制报文 lowValue == true", true, bin.lowValue);
            check("二进制报文没有误报 issue", 0, bin.issues == null ? 0 : bin.issues.size());
            check("二进制报文的 brief 不含乱码正文",
                    false, bin.brief != null && bin.brief.contains("\uFFFD\uFFFD"));
        }

        // ---------- ③ 真阳性不能丢：文本响应里的源码泄露仍要报 ----------
        String leakReq =
                "GET /index.php?page=home HTTP/1.1\r\n"
                        + "Host: victim.local\r\n"
                        + "User-Agent: test\r\n\r\n";
        String leakResp =
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html; charset=utf-8\r\n\r\n"
                        + "<html><body>\n"
                        + "<?php echo $db_password; ?>\n"
                        + "<%= session.getAttribute(\"user\") %>\n"
                        + "</body></html>";

        pipe.submit(leakReq.getBytes(StandardCharsets.UTF_8),
                leakResp.getBytes(StandardCharsets.UTF_8), 1, true, new Object(), null);
        sleep(400);

        PacketRecord txt = last(pipe.snapshot());
        check("文本报文已进入管道", true, txt != null);
        if (txt != null) {
            check("文本报文 lowValue == false", false, txt.lowValue);
            check("⭐ 文本源码泄露仍被抓到", true,
                    txt.issues != null && !txt.issues.isEmpty());
        }

        pipe.stop();

        System.out.println();
        System.out.println("==========================================");
        System.out.println("PASS=" + pass + "  FAIL=" + fail);
        System.out.println("==========================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    // ------------------------------------------------------------------

    private static boolean looksBinary(Method m, byte[] b) throws Exception {
        return (Boolean) m.invoke(null, (Object) b);
    }

    private static PacketRecord last(List<PacketRecord> snap) {
        return snap == null || snap.isEmpty() ? null : snap.get(snap.size() - 1);
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void check(String what, Object expect, Object actual) {
        boolean ok = (expect == null) ? actual == null : expect.equals(actual);
        if (ok) {
            pass++;
            System.out.println("  PASS  " + what + "  (" + actual + ")");
        } else {
            fail++;
            System.out.println("  FAIL  " + what + "  期望=" + expect + "  实际=" + actual);
        }
    }
}
