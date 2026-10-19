import com.packetsentry.core.Config;
import com.packetsentry.core.Identity;
import com.packetsentry.detect.LocalRules;
import com.packetsentry.detect.PlatformRules;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 第三轮排查：<b>集成与一致性</b>（契约测试）。
 *
 * <h3>这一轮找的是「跨模块对不上」</h3>
 * 前两轮看单个模块内部（代码写错没、喂怪输入崩不崩）。
 * 这一轮看<b>模块之间的约定有没有被破坏</b> —— 这类 bug
 * 靠人读代码最容易漏，因为它需要同时记住两个文件的内容。
 *
 * <p>具体检查三类契约：
 * <ol>
 *   <li><b>配置往返</b>：新增字段存盘再读回来还在不在</li>
 *   <li><b>规则名 ↔ 平台映射</b>：新加的检测规则如果在平台映射表里没有条目，
 *       SRC 模式下会被判「未提及」而被隐藏 —— 用户永远看不到，还以为是没检测到</li>
 *   <li><b>枚举覆盖</b>：每个 Level / Verdict 都被 UI 处理到了没有</li>
 * </ol>
 */
public class ContractProbe {

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

    public static void main(String[] args) throws Exception {
        System.out.println("============================================================");
        System.out.println(" 第三轮 · A：配置往返（新增字段存盘再读还在不在）");
        System.out.println("============================================================");

        Config c = new Config();
        c.srcMode = true;
        c.srcPlatform = "某SRC平台";
        c.srcRules = "【高危】越权提权操作";
        c.reporterName = "测试员";
        c.maskStrategy = "FULL";
        c.maxBodyChars = 500;
        c.autoAnalyze = true;
        c.budgetCny = 2.5;
        c.provider = "ollama";
        c.baseUrl = "http://127.0.0.1:11434/v1";
        c.model = "qwen2.5:14b";
        c.sanitizeEnabled = true;
        c.scanEnabled = true;
        c.layerHeaders = true;
        c.layerFields = true;
        c.layerValues = true;

        File tmp = File.createTempFile("pktcfg", ".json");
        tmp.delete();
        Config copy = c.shallowCopy();
        check("shallowCopy 保住 srcMode", copy.srcMode == c.srcMode);
        check("shallowCopy 保住 srcPlatform", "某SRC平台".equals(copy.srcPlatform));
        check("shallowCopy 保住 srcRules", "【高危】越权提权操作".equals(copy.srcRules));
        check("shallowCopy 保住 reporterName", "测试员".equals(copy.reporterName));
        check("shallowCopy 保住 maskStrategy", "FULL".equals(copy.maskStrategy));
        check("shallowCopy 保住 maxBodyChars", copy.maxBodyChars == 500);
        check("shallowCopy 保住 budgetCny", copy.budgetCny == 2.5);
        check("shallowCopy 保住 baseUrl", c.baseUrl.equals(copy.baseUrl));
        check("shallowCopy 保住 model", c.model.equals(copy.model));

        // Gson 往返（模拟存盘 / 读盘）
        com.google.gson.Gson gson = new com.google.gson.GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(c);
        Config back = gson.fromJson(json, Config.class);
        check("Gson 往返：srcMode", back.srcMode == c.srcMode);
        check("Gson 往返：srcPlatform", "某SRC平台".equals(back.srcPlatform));
        check("Gson 往返：srcRules", "【高危】越权提权操作".equals(back.srcRules));
        check("Gson 往返：reporterName", "测试员".equals(back.reporterName));
        check("Gson 往返：maxBodyChars", back.maxBodyChars == 500);
        check("Gson 往返：budgetCny", back.budgetCny == 2.5);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第三轮 · B：检测规则名 ↔ 平台映射 的覆盖（最关键）");
        System.out.println("============================================================");

        // 收集 LocalRules 里所有会产出的规则名
        Set<String> ruleNames = allRuleNames();
        System.out.println("  LocalRules 共产生 " + ruleNames.size() + " 种规则名：");
        List<String> sorted = new ArrayList<>(ruleNames);
        java.util.Collections.sort(sorted);
        for (String n : sorted) {
            Set<String> aliases = PlatformRules.aliasesOf(n);
            String marker = aliases.isEmpty() ? "  ❌ 无平台映射" : "  ✓ " + aliases.size() + " 个说法";
            System.out.println("    " + pad(n, 22) + marker);
        }
        System.out.println();

        // 用一份「什么都收」的规则，看有多少规则名会被判 UNKNOWN
        String acceptAll = String.join("\n",
                "【严重】远程命令执行、任意代码执行、SQL注入、越权",
                "【高危】敏感信息泄露、源码泄露、代码仓库、硬编码、越权提权、逻辑设计缺陷",
                "【中危】未授权访问、信息泄露、路径遍历、文件未授权访问、XSS、CSRF、CORS、"
                        + "JSONP、参数污染、报错、错误信息、调试、配置",
                "【低危】路径信息泄露、版本、指纹、Cookie、会话、明文传输、组件、供应链、"
                        + "异常、fail-open、频控、限流、注释、隐藏、接口泄露、API泄露");
        PlatformRules.Parsed p = PlatformRules.parse(acceptAll);

        List<String> unmapped = new ArrayList<>();
        for (String n : sorted) {
            if (PlatformRules.aliasesOf(n).isEmpty()) {
                unmapped.add(n);
            }
        }

        // 诊断报告写到 UTF-8 文件 —— 中文控制台会乱码，只有看文件才准
        try {
            StringBuilder rep = new StringBuilder();
            rep.append("规则名 -> 平台映射 覆盖报告\n");
            rep.append("总数: ").append(sorted.size()).append("\n\n");
            for (String n : sorted) {
                java.util.Set<String> al = PlatformRules.aliasesOf(n);
                rep.append(al.isEmpty() ? "MISS " : "OK   ")
                        .append("len=").append(n.length()).append("  ").append(n);
                if (!al.isEmpty()) {
                    rep.append("   -> ").append(al);
                }
                rep.append("\n");
            }
            java.nio.file.Files.write(java.nio.file.Paths.get("unmapped-report.txt"),
                    rep.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception ignore) {
            // 纯诊断，失败不影响断言
        }

        if (unmapped.isEmpty()) {
            System.out.println("  ✓ 所有规则名都有平台映射");
        } else {
            System.out.println("  ❌ 以下 " + unmapped.size() + " 个规则名没有平台映射 ——");
            System.out.println("     在 SRC 模式下会被判「未提及」而隐藏，用户永远看不到：");
            for (String n : unmapped) {
                System.out.println("       · " + n);
            }
            System.out.println("     （完整对照见 unmapped-report.txt）");
        }
        check("每条检测规则都能映射到平台说法（否则 SRC 模式会静默隐藏）",
                unmapped.isEmpty());

        // 有映射的规则，在「什么都收」的规则下至少不该全是 UNKNOWN
        int accepted = 0;
        for (String n : sorted) {
            if (PlatformRules.decide(n, p) == PlatformRules.Decision.ACCEPTED) {
                accepted++;
            }
        }
        System.out.println();
        System.out.println("  在「什么都收」的规则下：" + accepted + "/" + sorted.size()
                + " 条判为「收」");
        check("映射生效：至少一半规则在宽规则下判「收」",
                accepted >= sorted.size() / 2);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第三轮 · C：枚举覆盖（UI 有没有漏处理某个值）");
        System.out.println("============================================================");

        // Level 的每个值都要有 label（UI 直接显示 label）
        boolean levelOk = true;
        for (LocalRules.Level lv : LocalRules.Level.values()) {
            if (lv.label == null || lv.label.isEmpty()) {
                levelOk = false;
                System.out.println("    ✗ Level." + lv + " 没有 label");
            }
        }
        check("LocalRules.Level 每个值都有 label", levelOk);

        // rank 必须严格递增（过滤/取最严依赖它）
        boolean rankOk = true;
        LocalRules.Level[] lvs = LocalRules.Level.values();
        for (int i = 1; i < lvs.length; i++) {
            if (lvs[i].rank <= lvs[i - 1].rank) {
                rankOk = false;
                System.out.println("    ✗ rank 不递增：" + lvs[i - 1] + "(" + lvs[i - 1].rank
                        + ") → " + lvs[i] + "(" + lvs[i].rank + ")");
            }
        }
        check("Level.rank 严格递增（取最严重等级依赖它）", rankOk);

        // PlatformRules.Decision 每个值都有 label
        boolean decOk = true;
        for (PlatformRules.Decision d : PlatformRules.Decision.values()) {
            if (d.label == null || d.label.isEmpty()) {
                decOk = false;
                System.out.println("    ✗ Decision." + d + " 没有 label");
            }
        }
        check("PlatformRules.Decision 每个值都有 label", decOk);

        // CodeAudit.Verdict 每个值都有 label
        boolean vOk = true;
        for (com.packetsentry.audit.CodeAudit.Verdict v
                : com.packetsentry.audit.CodeAudit.Verdict.values()) {
            if (v.label == null || v.label.isEmpty()) {
                vOk = false;
                System.out.println("    ✗ Verdict." + v + " 没有 label");
            }
        }
        check("CodeAudit.Verdict 每个值都有 label", vOk);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第三轮 · D：OWASP 2025 清单完整性");
        System.out.println("============================================================");

        List<com.packetsentry.audit.OwaspTop10.Category> cats =
                com.packetsentry.audit.OwaspTop10.evaluate(new ArrayList<>());
        check("OWASP 清单正好 10 类", cats.size() == 10);

        boolean idsOk = true;
        String[] expectIds = {"A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025",
                "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"};
        for (int i = 0; i < Math.min(expectIds.length, cats.size()); i++) {
            if (!expectIds[i].equals(cats.get(i).id)) {
                idsOk = false;
                System.out.println("    ✗ 第 " + (i + 1) + " 项是 " + cats.get(i).id
                        + "，期望 " + expectIds[i]);
            }
        }
        check("10 个类别 ID 与 2025 版官方清单一致", idsOk);

        // 两个新增类别必须在
        boolean hasNew = cats.stream().anyMatch(x -> x.id.equals("A03:2025")
                && x.name.contains("供应链"))
                && cats.stream().anyMatch(x -> x.id.equals("A10:2025")
                && x.name.contains("异常"));
        check("含 2025 两个新增类别（A03 供应链 / A10 异常处理）", hasNew);

        // A02 必须是第 2 位（2025 版升幅最大）
        check("A02 是第 2 项（2025 版从 #5 升到 #2）",
                cats.get(1).id.equals("A02:2025"));

        // 每一项都要有「怎么做」和「对应规则」
        boolean complete = true;
        for (com.packetsentry.audit.OwaspTop10.Category x : cats) {
            if (x.howToTest == null || x.howToTest.trim().isEmpty()
                    || x.ourRules == null || x.ourRules.trim().isEmpty()) {
                complete = false;
                System.out.println("    ✗ " + x.id + " 缺 howToTest 或 ourRules");
            }
        }
        check("每类都有「怎么做」与「对应规则」说明", complete);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第三轮 · E：Identity 契约");
        System.out.println("============================================================");

        Identity id = new Identity();
        id.name = "A";
        id.headers.put("Cookie", "sid=A");
        Identity id2 = id.copy();
        check("copy() 是深拷贝（改副本不影响原件）", deepCopyWorks(id, id2));
        check("usable() 对有头的身份返回 true", id.usable());
        Identity empty = new Identity();
        check("usable() 对空身份返回 false", !empty.usable());
        check("describe() 不泄露头值原文",
                id.describe() == null || !id.describe().contains("sid=A"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }

    private static boolean deepCopyWorks(Identity a, Identity b) {
        b.headers.put("Cookie", "sid=B");
        return "sid=A".equals(a.headers.get("Cookie"));
    }

    private static String pad(String s, int n) {
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < n) {
            sb.append(' ');
        }
        return sb.toString();
    }

    /**
     * 用反射 + 源码扫描收集 LocalRules 会产出的规则名。
     *
     * <p>不能用反射读 —— 规则名是字面量，不是枚举。所以扫源码里
     * {@code new Issue(...)} 的第二个参数。
     */
    private static Set<String> allRuleNames() throws Exception {
        Set<String> names = new LinkedHashSet<>();
        File f = new File("src/com/packetsentry/detect/LocalRules.java");
        if (!f.isFile()) {
            f = new File("packetsentry/src/com/packetsentry/detect/LocalRules.java");
        }
        if (!f.isFile()) {
            // 退路：用已知列表（从 Issue 构造调用里手工提取的）
            for (String n : new String[]{
                    "密码明文回显", "Authorization回显", "敏感字段回显", "JWT凭证", "CORS反射",
                    "明文HTTP", "Cookie属性缺失", "敏感文件泄露", "SQL报错泄露", "堆栈泄露",
                    "敏感路径可访问", "内网地址泄露", "Flag", "源码泄露", "调试信息泄露",
                    "服务器路径泄露", "服务端版本泄露", "备份/配置文件可访问", "JSONP接口",
                    "注释信息泄露", "隐藏表单字段", "硬编码凭据", "安全响应头缺失",
                    "第三方脚本无完整性校验", "组件版本指纹", "错误细节泄露",
                    "疑似fail-open", "扫描已截断"}) {
                names.add(n);
            }
            return names;
        }
        String src = new String(java.nio.file.Files.readAllBytes(f.toPath()),
                java.nio.charset.StandardCharsets.UTF_8);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "new Issue\\(\\s*Level\\.\\w+\\s*,\\s*\"([^\"]+)\"", java.util.regex.Pattern.DOTALL)
                .matcher(src);
        while (m.find()) {
            names.add(m.group(1));
        }
        // 动态构造的名字（三元表达式等）手工补
        if (src.contains("postMessage")) {
            names.add("postMessage 监听");
        }
        return names;
    }
}
