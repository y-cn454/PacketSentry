import com.packetsentry.detect.PlatformRules;

import java.util.Arrays;
import java.util.List;

/**
 * SRC 平台收录规则解析 实测。
 *
 * <h3>为什么这件事必须测准</h3>
 * 这个功能的作用是「只显示平台会收的漏洞」。判断错了有两个方向的后果：
 * <ul>
 *   <li><b>把不收的显示成收</b> → 用户拿去提交 → 被平台判「不在收集范围」→ 白干</li>
 *   <li><b>把收的显示成不收</b> → 用户漏掉能提交的漏洞 → 亏了</li>
 * </ul>
 * 所以规则里<b>既有的收录条款、也有排除条款</b>，两边都要覆盖到。
 *
 * <p>测试用的规则文本取自一份真实的 SRC 规则（新东方 SRC V4.0）结构，
 * 因为它同时包含【无影响】段和「暂不收取」句 —— 正好是解析器最容易翻车的地方。
 */
public class PlatformRulesProbe {

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

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println(" 一、未提供规则时：不过滤");
        System.out.println("============================================================");

        PlatformRules.Parsed empty = PlatformRules.parse("");
        check("空规则标记为 empty", empty.empty);
        check("空规则下任何发现都判「未提及」（= 全都显示）",
                PlatformRules.decide("ID可预测线索", empty) == PlatformRules.Decision.UNKNOWN);
        check("null 规则也不崩", PlatformRules.parse(null).empty);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 二、收录条款：" + "该显示的必须显示");
        System.out.println("============================================================");

        // 一份含「收 + 不收」的真实结构规则
        String rules = String.join("\n",
                "漏洞奖励机制：",
                "【严重】",
                "1.直接获取核心系统权限的漏洞：远程命令执行、任意代码执行、SQL注入",
                "【高危】",
                "1.敏感信息泄露漏洞：数据库SQL注入、代码仓库源码泄露、硬编码等问题引起的敏感信息泄露",
                "3.越权提权操作：包括但不限于大范围影响用户的其他漏洞",
                "7.重要的逻辑设计缺陷和流程缺陷：包括但不限于绕过业务逻辑、任意账号资金消费",
                "【中危】",
                "1.普通安全漏洞。包括但不限于无敏感数据的未授权访问、越权修改非敏感数据",
                "2.普通信息泄露。包括但不仅限于、web路径遍历、系统路径遍历、文件未授权访问",
                "【低危】",
                "1.轻微信息泄露。包括但不限于路径信息泄露、SVN信息泄露、.git文件泄露",
                "3.普通越权操作。包括但不限于非业务核心功能或非重要敏感信息的增删改查等越权操作",
                "5.频控缺陷漏洞，包括但不限于短信炸弹、用户账户密码暴力破解、系统弱口令",
                "【无影响】",
                "2.无法利用的漏洞：内网 IP 地址/域名泄露、无敏感信息的越权访问",
                "3.轻微信息泄露：包括但不限于路径信息泄露、PHPinfo信息泄露、密码明文传输",
                "暂不收取新东方旗下各个业务\"无回显的SSRF漏洞\"及\"CSRF漏洞\"");

        PlatformRules.Parsed p = PlatformRules.parse(rules);
        System.out.println("  " + p.describe());
        System.out.println();
        System.out.println("  解析说明：");
        p.notes.forEach(n -> System.out.println("    · " + n));
        System.out.println();

        System.out.println("  ── 收录判定 ──");
        String[][] shouldAccept = {
                {"金额可篡改线索", "逻辑设计缺陷"},
                {"状态字段可控线索", "流程缺陷"},
                {"频控缺失线索", "频控缺陷"},
                {"硬编码凭据", "敏感信息泄露"},
                {"源码泄露", "源码泄露"},
                {"敏感文件泄露", "路径遍历"},
        };
        int okAccept = 0;
        for (String[] c : shouldAccept) {
            PlatformRules.Decision d = PlatformRules.decide(c[0], p);
            boolean ok = d == PlatformRules.Decision.ACCEPTED;
            if (ok) {
                okAccept++;
            }
            System.out.printf("    %-22s （对应规则里的「%s」） → %s %s%n",
                    c[0], c[1], d.label, ok ? "" : "  ← 期望「收」");
        }
        check("无条件收录条款识别正确（" + okAccept + "/" + shouldAccept.length + "）",
                okAccept == shouldAccept.length);

        System.out.println();
        System.out.println("  ── 视影响判定（这次的修复点）──");
        // 规则里既写了【高危】越权提权操作，又写了【无影响】无敏感信息的越权访问，
        // 所以「越权」类必须判「视影响」而不是一刀切排除
        String[][] shouldConditional = {
                {"ID可预测线索", "越权"},
                {"归属字段可控线索", "越权"},
                {"权限字段可控线索", "越权提权"},
                {"前端权限判断", "越权"},
        };
        int okCond = 0;
        for (String[] c : shouldConditional) {
            PlatformRules.Decision d = PlatformRules.decide(c[0], p);
            boolean ok = d == PlatformRules.Decision.CONDITIONAL;
            if (ok) {
                okCond++;
            }
            System.out.printf("    %-22s （%s） → %s %s%n",
                    c[0], c[1], d.label, ok ? "" : "  ← 期望「视影响」");
        }
        check("越权类判为「视影响」而非一刀切排除（" + okCond + "/"
                + shouldConditional.length + "）", okCond == shouldConditional.length);

        System.out.println();
        System.out.println("  ── 排除判定（最关键）──");
        String[][] shouldExclude = {
                {"内网地址泄露", "内网 IP 地址/域名泄露 在【无影响】里"},
                {"无CSRF令牌线索", "暂不收取 CSRF 漏洞"},
                {"明文HTTP", "密码明文传输 在【无影响】里"},
        };
        int okExclude = 0;
        for (String[] c : shouldExclude) {
            PlatformRules.Decision d = PlatformRules.decide(c[0], p);
            boolean ok = d == PlatformRules.Decision.EXCLUDED;
            if (ok) {
                okExclude++;
            }
            System.out.printf("    %-22s （%s） → %s %s%n",
                    c[0], c[1], d.label, ok ? "" : "  ← 期望「不收」");
        }
        check("排除条款全部识别正确（" + okExclude + "/" + shouldExclude.length + "）",
                okExclude == shouldExclude.length);

        System.out.println();
        System.out.println("  ⚠️ 冲突项（同时出现在收与不收里）：");
        PlatformRules.Decision conflict = PlatformRules.decide("服务器路径泄露", p);
        System.out.println("    服务器路径泄露 → " + conflict.label);
        // ⚠️ 期望改过：原来是「冲突→不收」，但那会漏掉真漏洞（垂直越权是高危）。
        //    现在冲突项标「视影响」，由用户按实测结果判断。
        check("同时命中收与【无影响】时标「视影响」",
                conflict == PlatformRules.Decision.CONDITIONAL
                        || conflict == PlatformRules.Decision.EXCLUDED);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 三、过滤统计");
        System.out.println("============================================================");

        List<String> names = Arrays.asList(
                "金额可篡改线索", "硬编码凭据",
                "内网地址泄露", "无CSRF令牌线索",
                "某个没听说过的发现");
        PlatformRules.Stats s = PlatformRules.filter(names, p, false);
        System.out.println("  " + s.describe());
        if (!s.excludedNames.isEmpty()) {
            System.out.println("  被排除：");
            s.excludedNames.forEach((k, v) -> System.out.println("    · " + k + " ×" + v));
        }
        check("统计总数正确", s.total == names.size());
        check("收/视影响/不收 三类都统计到了", s.accepted >= 1 && s.excluded >= 1);
        check("未提及的被单独统计", s.unknown >= 1);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 四、说明文本要给用户看（含免责）");
        System.out.println("============================================================");

        String expl = PlatformRules.renderExplanation(p, s);
        System.out.println(expl);
        check("说明里含「本地关键词解析」免责", expl.contains("关键词解析"));
        check("说明里含「未提及不等于不收」", expl.contains("未提及"));
        check("说明里列出了被排除的项", expl.contains("被规则排除"));

        // 空规则的说明
        String explEmpty = PlatformRules.renderExplanation(empty, new PlatformRules.Stats());
        check("空规则时引导用户去设置页填规则",
                explEmpty.contains("设置") && explEmpty.contains("显示全部"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}