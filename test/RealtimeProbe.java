import com.packetsentry.core.Config;
import com.packetsentry.core.CostTracker;
import com.packetsentry.core.PacketRecord;
import com.packetsentry.core.RealtimePipe;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 实时管道 + 成本追踪实测。
 *
 * <p>重点验证<b>省钱机制真的有效</b>：
 * <ol>
 *   <li>去重能不能把「同一接口调 300 次」收敛成 1 个结构</li>
 *   <li>低价值过滤能不能跳过静态资源</li>
 *   <li>成本估算量级是否合理（用户要求「几分钱到几毛钱」）</li>
 * </ol>
 */
public class RealtimeProbe {

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

    private static byte[] req(String firstLine, String host, String body) {
        return (firstLine + "\r\n"
                + "Host: " + host + "\r\n"
                + "Content-Type: application/json\r\n"
                + "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                + ".eyJzdWIiOiIxMDA4NiIsInJvbGUiOiJhZG1pbiIsImV4cCI6NDA3MDkwODgwMH0"
                + ".c2ln\r\n"
                + "\r\n"
                + body).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] resp(int status) {
        return ("HTTP/1.1 " + status + " OK\r\n"
                + "Content-Type: application/json\r\n"
                + "\r\n"
                + "{\"ok\":true}").getBytes(StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        Config cfg = new Config();
        cfg.sanitizeEnabled = true;
        cfg.scanEnabled = true;

        RealtimePipe pipe = new RealtimePipe(() -> cfg);
        pipe.start();

        System.out.println("============================================================");
        System.out.println(" 模拟一个真实会话：2000 个包，其中 90% 是重复接口调用");
        System.out.println("============================================================");
        System.out.println();

        int total = 0;
        // ① 同一个接口，不同 ID —— 300 次
        for (int i = 1000; i < 1300; i++) {
            pipe.submit(req("GET /api/product/" + i + "?lang=zh HTTP/1.1", "shop.example.com", ""),
                    resp(200), 1, true, new Object(), null);
            total++;
        }
        // ② 同一个搜索接口，不同关键词 —— 400 次
        for (int i = 0; i < 400; i++) {
            pipe.submit(req("GET /api/search?q=item" + i + "&page=1 HTTP/1.1", "shop.example.com", ""),
                    resp(200), 1, true, new Object(), null);
            total++;
        }
        // ③ 登录接口 —— 500 次（真实场景里是重复提交）
        for (int i = 0; i < 500; i++) {
            pipe.submit(req("POST /backstage/auth/login HTTP/1.1", "ywt.example.edu.cn",
                    "{\"username\":\"admin\",\"password\":\"P@ssw0rd!2026\",\"phone\":\"13812345678\"}"),
                    resp(200), 1, true, new Object(), null);
            total++;
        }
        // ④ 静态资源 —— 600 次，应当全部判为低价值
        for (int i = 0; i < 600; i++) {
            pipe.submit(req("GET /static/chunk" + i + ".js HTTP/1.1", "cdn.example.com", ""),
                    resp(200), 1, true, new Object(), null);
            total++;
        }
        // ⑤ 几个真正不同的接口 —— 20 个，应当全部标记为「新」
        for (int i = 0; i < 20; i++) {
            pipe.submit(req("POST /api/v1/resource" + i + "/create HTTP/1.1", "api.example.com",
                    "{\"name\":\"x\",\"amount\":100}"), resp(201), 1, true, new Object(), null);
            total++;
        }

        System.out.println("  已提交 " + total + " 个包，等待后台处理…");
        for (int i = 0; i < 100 && pipe.queuedCount() > 0; i++) {
            Thread.sleep(200);
        }
        Thread.sleep(800);

        List<PacketRecord> all = pipe.snapshot();

        // ⚠️ 统计必须用全量计数器，不能用 snapshot()
        // —— recent 列表只保留最近 RECENT_MAX(500) 条，
        //    早期版本用它统计，把 1820 个包算成了 500 个。
        long processed = pipe.processedCount();
        long low = pipe.lowValueCount();
        long dup = pipe.duplicateCount();
        long worth = pipe.worthCount();
        long dropped = pipe.droppedCount();

        System.out.println("  管道已处理 " + processed + " 个（队列中剩 " + pipe.queuedCount()
                + "，丢弃 " + dropped + "）");
        System.out.println("  快照窗口内 " + all.size() + " 条（recent 上限 500，仅用于界面展示）");
        System.out.println();

        System.out.println("============================================================");
        System.out.println(" 分类结果（全量统计）");
        System.out.println("============================================================");
        System.out.printf("  提交总数        %d%n", total);
        System.out.printf("  已处理          %d%n", processed);
        System.out.printf("  队列丢弃        %d%n", dropped);
        System.out.printf("  低价值（跳过）  %d%n", low);
        System.out.printf("  重复结构（跳过）%d%n", dup);
        System.out.printf("  ✅ 值得送 AI    %d%n", worth);
        System.out.printf("  不同结构数      %d%n", pipe.distinctStructures());
        System.out.printf("  去重节省        %.1f%%%n", pipe.savedRatio() * 100);
        System.out.println();

        // 成本推算用「值得送 AI 的真实数量」，不是总包数
        int worthInt = (int) worth;
        CostTracker cost = new CostTracker();
        cost.setPricing(CostTracker.DEEPSEEK_FLASH);
        cost.setBudgetCny(1.0);

        // 取一个真实记录估算单包 tokens
        int briefTokens = 0;
        for (PacketRecord r : all) {
            if (r.worthAnalyzing()) {
                briefTokens = CostTracker.estimateTokens(r.brief);
                break;
            }
        }
        int sysTokens = CostTracker.estimateTokens(
                "你是一名 Web 安全分析助手，正在协助一次已获授权的渗透测试。"
                        + "用户会给你一段 HTTP 报文的摘要。只根据给出的内容判断，不要臆测。"
                        + "请按结构回答：这个报文在做什么 / 关键参数 / 值得测试的方向 / 已观测到的问题 / 不确定的地方。");

        double perPacket = cost.estimatePerPacketCny(sysTokens, briefTokens, 600);

        System.out.println("============================================================");
        System.out.println(" 成本推算（deepseek-flash，非高峰）");
        System.out.println("============================================================");
        System.out.printf("  估算口径       system %d + brief %d + 输出 600 tokens%n",
                sysTokens, briefTokens);
        System.out.printf("  单包预估       ¥%.5f  （约 %.2f 分）%n", perPacket, perPacket * 100);
        System.out.printf("  不做去重 %d 包 ¥%.2f   ← 假如每个包都送 AI%n", total, perPacket * total);
        System.out.printf("  去重后 %d 包   ¥%.2f   ← 实际花费%n", worthInt, perPacket * worthInt);
        System.out.printf("  省下           %.1f%%%n", pipe.savedRatio() * 100);
        System.out.println();

        // ---------- 断言 ----------
        System.out.println("============================================================");
        System.out.println(" 断言");
        System.out.println("============================================================");

        check("管道处理了全部 " + total + " 个包（丢弃 " + dropped + "）",
                processed == total && dropped == 0);
        check("静态资源被识别为低价值（=600）", low == 600);
        // 重复 = product 的 299 + search 的 399 + login 的 499 + resource 的 19
        // 注意 resource0..19 归一化后是「1 个新 + 19 个重复」，不是 20 个新
        check("重复结构被识别（=1216）", dup == 1216);
        // 归一化后的真实接口数：product / search / login / resource{n} = 4 个
        // （resource0..19 现在会被归一化成同一个结构）
        check("值得送 AI 的是 4 个真实接口（除去重后）", worth == 4);
        check("不同结构数 = 值得送的数量（低价值不进表）",
                pipe.distinctStructures() == (int) worth);

        double savedPct = pipe.savedRatio() * 100;
        check(String.format("去重省下超过 99%%（实际 %.1f%%）", savedPct), savedPct > 99);

        check("单包成本在 1 分以内", perPacket < 0.01);
        check(String.format("去重后总成本在 ¥1 以内（实际 ¥%.2f）", perPacket * worthInt),
                perPacket * worthInt < 1.0);
        check(String.format("不做去重会超预算（¥%.2f > ¥1.00）", perPacket * total),
                perPacket * total > 1.0);

        // 脱敏确实生效（JWT 被抹）
        boolean sanitized = all.stream().anyMatch(r ->
                r.sanitized != null && r.sanitized.hasSensitiveData());
        check("脱敏确实生效（记录里有命中）", sanitized);

        boolean noRawJwt = all.stream().noneMatch(r ->
                r.brief != null && r.brief.contains("eyJzdWIiOiIxMDA4NiIsInJvbGUiOiJhZG1pbiIsImV4cCI6NDA3MDkwODgwMH0"));
        check("摘要里没有未脱敏的 JWT", noRawJwt);

        // 展示一个样例
        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 样例：一个「值得分析」的包的摘要（这就是要发给 AI 的全部内容）");
        System.out.println("============================================================");
        for (PacketRecord r : all) {
            if (r.worthAnalyzing()) {
                System.out.println(r.brief);
                System.out.println();
                System.out.println("  字符数 " + r.brief.length()
                        + "　估算 tokens " + CostTracker.estimateTokens(r.brief));
                break;
            }
        }

        pipe.stop();

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
