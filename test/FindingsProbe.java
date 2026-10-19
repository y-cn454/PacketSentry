import com.packetsentry.core.Finding;
import com.packetsentry.core.FindingsLedger;
import com.packetsentry.detect.LocalRules;
import com.packetsentry.detect.PlatformRules;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 第十轮：<b>发现清单</b> —— 面向前者 SRC 平台挖漏洞的回归。
 *
 * <h3>这个测试针对的是一类「换个思路才看得见」的问题</h3>
 * 靶场是「拿到 flag 就结束」，一个包一个包看就行。
 * SRC 是「盯一个目标挖几天」，靠的是清单。
 *
 * <p>所以这里测的不是「某个函数算得对不对」，而是<b>清单作为工作载体能不能立住</b>：
 * <ul>
 *   <li>去重 —— 5 个 ID 验证同一个越权，必须只算 1 条</li>
 *   <li>持久化 —— 关掉再开，清单还在</li>
 *   <li>状态机 —— 待验证 → 已验证 → 已提交，能跟踪</li>
 *   <li>版本段不被并掉 —— /api/v1 和 /api/v2 是不同接口（这个坑踩过）</li>
 *   <li>靶场模式 —— flag 规则只在靶场生效，实战里是噪音</li>
 * </ul>
 */
public class FindingsProbe {

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

    private static Finding mk(String method, String host, String path,
                              String type, LocalRules.Level lv) {
        return Finding.from(method, host, path, "id", type, lv, "证据片段",
                PlatformRules.Decision.ACCEPTED, lv.label);
    }

    public static void main(String[] args) throws Exception {
        Path tmp = Files.createTempDirectory("ps-findings");
        Path file = tmp.resolve("findings.json");

        System.out.println("============================================================");
        System.out.println(" 十 · A：路径规范化（去重的基础）");
        System.out.println("============================================================");

        check("/api/user/1 → {n}",
                Finding.normalizePath("/api/user/1").equals("/api/user/{n}"));
        check("/api/user/12345 → {n}",
                Finding.normalizePath("/api/user/12345").equals("/api/user/{n}"));
        check("UUID 段 → {n}",
                Finding.normalizePath("/o/550e8400-e29b-41d4-a716-446655440000/x")
                        .equals("/o/{n}/x"));
        check("长 hex 段 → {n}",
                Finding.normalizePath("/f/62e19f2d7aff8c130f5c15721f7d71fa9b13b6389b04")
                        .equals("/f/{n}"));
        check("数字混在段里也归一化",
                Finding.normalizePath("/order-12345/detail").equals("/order-{n}/detail"));
        // ⭐ 版本段必须保留 —— 并掉会漏掉 v2 上的漏洞（第 6 轮踩过的坑）
        check("⭐ 版本段不被替换成 {n}（v1/v2 是不同接口）",
                Finding.normalizePath("/api/v1/user/9").equals("/api/v1/user/{n}")
                        && Finding.normalizePath("/api/v2/user/9").equals("/api/v2/user/{n}"));
        check("v1 与 v2 规范化后仍然不同",
                !Finding.normalizePath("/api/v1/x").equals(Finding.normalizePath("/api/v2/x")));
        check("query 保留", Finding.normalizePath("/api/u/1?a=2").equals("/api/u/{n}?a=2"));
        check("空/null 不崩",
                Finding.normalizePath(null).isEmpty() && Finding.normalizePath("").isEmpty());

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十 · B：去重 —— 5 个 ID 验证同一个越权必须只算 1 条");
        System.out.println("============================================================");

        FindingsLedger led = new FindingsLedger(file);
        int added = 0;
        for (int id = 1; id <= 5; id++) {
            if (led.upsert(mk("GET", "shop.com", "/api/user/" + id,
                    "ID可预测", LocalRules.Level.MEDIUM))) {
                added++;
            }
        }
        System.out.println("  5 次不同 ID 的观测 → 清单里 " + led.size()
                + " 条，其中新增 " + added + " 条");
        check("5 个不同 ID 归并成 1 条发现", led.size() == 1);
        check("只有第 1 次算「新增」", added == 1);
        check("观测次数累加到 5", led.all().get(0).seenCount == 5);
        check("路径保留第一次观测的真实 ID（可复现）",
                led.all().get(0).path.equals("/api/user/1"));

        // 不同类型 → 不同发现
        led.upsert(mk("GET", "shop.com", "/api/user/9", "信息泄露",
                LocalRules.Level.HIGH));
        check("同一接口的另一个漏洞类型算新发现", led.size() == 2);

        // 不同方法 → 不同发现
        led.upsert(mk("POST", "shop.com", "/api/user/9", "ID可预测",
                LocalRules.Level.MEDIUM));
        check("同一路径的不同方法算新发现", led.size() == 3);

        // 不同域名 → 不同发现
        led.upsert(mk("GET", "other.com", "/api/user/9", "ID可预测",
                LocalRules.Level.MEDIUM));
        check("不同域名的同路径算新发现", led.size() == 4);

        // 规则名的措辞后缀不该影响指纹
        led.upsert(mk("GET", "shop.com", "/api/user/77", "Flag（已确认）",
                LocalRules.Level.CRITICAL));
        int before = led.size();
        led.upsert(mk("GET", "shop.com", "/api/user/88", "Flag", LocalRules.Level.CRITICAL));
        check("「Flag（已确认）」与「Flag」视为同一类型（措辞后缀不影响指纹）",
                led.size() == before);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十 · C：持久化 —— 关掉再开清单还在");
        System.out.println("============================================================");

        String err = led.save();
        check("保存无错误", err.isEmpty());
        check("文件已生成", Files.isRegularFile(file));

        FindingsLedger led2 = new FindingsLedger(file);
        System.out.println("  重新载入 → " + led2.size() + " 条");
        check("重新载入后条数一致", led2.size() == led.size());
        check("重新载入后次数没丢", led2.get(led.all().get(0).id) != null
                && led2.get(led.all().get(0).id).seenCount
                == led.get(led.all().get(0).id).seenCount);
        check("重新载入后状态没丢", led2.all().get(0).status.equals("待验证"));

        // 坏文件不该让插件起不来
        Path bad = tmp.resolve("bad.json");
        Files.write(bad, "{ this is not json".getBytes("UTF-8"));
        FindingsLedger ledBad = new FindingsLedger(bad);
        check("损坏的清单文件不抛异常（插件仍能启动）", ledBad.size() == 0);
        check("损坏时给出错误信息而不是静默",
                !ledBad.getLastError().isEmpty());
        check("损坏的原文件被保留（用户可手工抢救）", Files.isRegularFile(bad));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十 · D：状态机 —— 这就是 SRC 的工作流");
        System.out.println("============================================================");

        String id1 = led.all().get(0).id;
        check("新发现默认是「待验证」",
                led.get(id1).statusEnum() == Finding.Status.TODO);

        led.setStatus(id1, Finding.Status.VERIFIED, "在 Repeater 里换了账号复现成功");
        check("能标为「已验证」",
                led.get(id1).statusEnum() == Finding.Status.VERIFIED);
        check("备注被保存", led.get(id1).note.contains("Repeater"));

        check("「已验证」进入「可以提交」列表",
                led.readyToSubmit().stream().anyMatch(f -> f.id.equals(id1)));

        led.setStatus(id1, Finding.Status.SUBMITTED, null);
        check("能标为「已提交」",
                led.get(id1).statusEnum() == Finding.Status.SUBMITTED);
        check("已提交后不再算「待提交」",
                led.readyToSubmit().stream().noneMatch(f -> f.id.equals(id1)));
        check("已提交算「已交付」", led.get(id1).statusEnum().isDelivered());

        // 状态持久化
        led.save();
        FindingsLedger led3 = new FindingsLedger(file);
        check("状态变更也持久化",
                led3.get(id1).statusEnum() == Finding.Status.SUBMITTED);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十 · E：统计与「现在该做什么」");
        System.out.println("============================================================");

        java.util.Map<String, Integer> st = led.statusCounts();
        System.out.println("  状态分布：" + st);
        check("状态统计含全部状态", st.size() == Finding.Status.values().length);
        check("「已提交」计数正确", st.get("已提交") == 1);

        String steps = led.nextSteps("shop.com");
        System.out.println("  下一步提示：");
        for (String line : steps.split("\n")) {
            System.out.println("    " + line);
        }
        check("nextSteps 给出按模块分布", steps.contains("按模块分布"));
        check("nextSteps 指出还没验证的", steps.contains("还没验证") || steps.contains("可以提交"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十 · F：导出 Markdown（能直接贴进平台报告框）");
        System.out.println("============================================================");

        String id2 = null;
        for (Finding f : led.all()) {
            if (!f.id.equals(id1)) {
                id2 = f.id;
                break;
            }
        }
        led.setStatus(id2, Finding.Status.VERIFIED, "复现成功");
        String md = led.exportMarkdown("shop.com", true);

        check("导出含标题", md.startsWith("# 漏洞报告"));
        check("导出含「漏洞 URL」", md.contains("漏洞 URL"));
        check("导出含「风险评级」", md.contains("风险评级"));
        check("导出含「复现请求」", md.contains("复现请求"));
        check("导出含「证据」", md.contains("证据"));
        check("导出含提交前核对提醒", md.contains("提交前请人工核对"));
        check("导出提醒不要附带业务数据", md.contains("不要附带业务数据"));
        check("⭐ 只导出已验证及以上（待验证的不进报告）",
                !md.contains("待验证"));
        check("已弃用/不收的不导出", !md.contains("弃用"));

        // 一条都没验证时，导出要明确拒绝而不是给空报告
        FindingsLedger empty = new FindingsLedger(tmp.resolve("empty.json"));
        empty.upsert(mk("GET", "h.com", "/a/1", "测试", LocalRules.Level.LOW));
        String md2 = empty.exportMarkdown("h.com", true);
        check("没有已验证的发现时明确说「没有可导出的」",
                md2.contains("没有可导出"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十 · G：靶场模式 —— flag 规则只在靶场生效");
        System.out.println("============================================================");

        String flagResp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                + "^FLAG^62e19f2d7aff8c130f5c15721f7d71fa9b13b6389b04d40042c16bc015ffc0f9$FLAG$";
        String req = "GET /x HTTP/1.1\r\nHost: a.com\r\n\r\n";

        List<LocalRules.Issue> asRange = LocalRules.detect(req, flagResp, null, true);
        List<LocalRules.Issue> asSrc = LocalRules.detect(req, flagResp, null, false);

        check("靶场模式：flag 规则生效",
                asRange.stream().anyMatch(i -> i.name.contains("Flag")));
        check("⭐ 实战 SRC：flag 规则<b>不</b>生效（真实业务没有 flag，那是噪音）",
                asSrc.stream().noneMatch(i -> i.name.contains("Flag")));
        check("实战 SRC 下其它规则仍然生效（不是整个检测被关掉）",
                asSrc.stream().anyMatch(i -> i.name.contains("安全响应头")));

        // 「极小响应 + 长 hex」的兜底在实战里最容易误报，必须也关掉
        String tokenResp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                + "62e19f2d7aff8c130f5c15721f7d71fa9b13b6389b04d40042c16bc015ffc0f9";
        check("⭐ 实战 SRC 下「极小响应+长 hex」兜底也不误报",
                LocalRules.detect(req, tokenResp, null, false).stream()
                        .noneMatch(i -> i.name.contains("Flag")));
        check("靶场模式下这条兜底仍然生效",
                LocalRules.detect(req, tokenResp, null, true).stream()
                        .anyMatch(i -> i.name.contains("Flag")));

        // 3 参重载 = 靶场模式（保持测试与靶场用法的兼容）
        check("3 参重载等价于靶场模式",
                LocalRules.detect(req, flagResp, null).stream()
                        .anyMatch(i -> i.name.contains("Flag")));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 十 · H：边界（不许崩）");
        System.out.println("============================================================");

        boolean ok = true;
        try {
            FindingsLedger x = new FindingsLedger(tmp.resolve("edge.json"));
            x.upsert(null);
            x.upsert(new Finding());                       // 空 id
            x.setStatus(null, Finding.Status.VERIFIED, null);
            x.setStatus("nope", null, null);
            x.remove("nope");
            x.get(null);
            x.byHost(null);
            x.byHost("");
            x.nextSteps(null);
            x.nextSteps("");
            x.exportMarkdown(null, false);
            x.exportMarkdown("", true);
            x.toPromptText(null);
            x.oneLine();
            x.levelCounts();
            x.hostCount();
            x.hosts();
            Finding f = new Finding();
            f.mergeFrom(null);
            f.mergeFrom(new Finding());
            f.statusEnum();
            f.displayLevel();
            f.url();
            f.where();
            f.toString();
            Finding.normalizePath("///");
            Finding.normalizePath("?a=b");
            Finding.fingerprint(null, null, null, null);
            Finding.Status.of(null);
            Finding.Status.of("不存在的状态");
        } catch (Throwable e) {
            ok = false;
            System.out.println("    ✗ 抛异常：" + e);
        }
        check("null / 空 / 非法状态 / 畸形路径 都不抛异常", ok);

        // 清理
        try {
            Files.walk(tmp).sorted(java.util.Comparator.reverseOrder())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (Exception ignored) {
                            // 临时目录清理失败无所谓
                        }
                    });
        } catch (Exception ignored) {
            // 同上
        }

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
