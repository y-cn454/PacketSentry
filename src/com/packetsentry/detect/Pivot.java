package com.packetsentry.detect;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 延伸测试推导 —— 从一个<b>已确认</b>的发现，机械地推出下一步该测什么。
 *
 * <h3>为什么这个要做成规则表，而不是交给 AI 自由发挥</h3>
 * 用户反馈过一个很具体的问题：<b>「已经确定包有漏洞，却还在分析可能性，
 * 而且无法根据这个包的漏洞延伸其他漏洞」</b>。
 *
 * <p>延伸这件事，一部分是<b>机械可推导</b>的：
 * 既然 {@code /page/edit/1} 返回了 flag，那 {@code /page/edit/2} 值不值得试？
 * 既然这个请求没带任何认证头就返回了 200，那去掉 Cookie 重放会怎样？
 * —— 这类推理不需要创造力，需要的是<b>把「已知」系统地展开成「待验证」</b>。
 *
 * <p>交给 AI 做这件事的问题是：它有时候想得到，有时候想不到，
 * 而且每次都要花钱。做成规则表则是<b>零成本、每次都一样、可回归测试</b>。
 *
 * <p>AI 仍然有用 —— 它负责解释「为什么这个方向有戏」；
 * 但「有哪些方向」这件事，由这里保证不漏。
 *
 * <h3>▲ 输出的是「待验证」，不是「已确认」</h3>
 * 这里的每一条都是<b>下一步动作</b>，不是结论。
 * 界面上会明确标注「待验证」，避免用户直接把推测写进报告。
 */
public final class Pivot {

    /** 一条延伸建议。 */
    public static final class Suggestion {
        /** 来源：哪条已确认发现引出的。 */
        public final String from;
        /** 要做什么（一句话，可执行）。 */
        public final String action;
        /** 为什么这么做（推理依据）。 */
        public final String why;
        /** 优先级权重，越大越先做。 */
        public final int weight;

        Suggestion(String from, String action, String why, int weight) {
            this.from = from;
            this.action = action;
            this.why = why;
            this.weight = weight;
        }

        @Override
        public String toString() {
            return action;
        }
    }

    // ==================================================================

    /**
     * 从一组已确认发现推导出延伸测试清单。
     *
     * @param issues 本地规则 / 逻辑线索产出的发现
     * @param method 当前请求方法（可为 null）
     * @param path   当前请求路径（可为 null）
     * @param host   目标主机（可为 null）
     * @param authed 这个请求有没有带业务认证凭据（只有 _ga 这类统计 Cookie 不算）
     */
    public static List<Suggestion> derive(List<LocalRules.Issue> issues,
                                          String method, String path, String host,
                                          boolean authed) {
        List<Suggestion> out = new ArrayList<>();
        if (issues == null || issues.isEmpty()) {
            return out;
        }
        Set<String> names = new LinkedHashSet<>();
        for (LocalRules.Issue i : issues) {
            names.add(i.name);
        }
        String where = (method == null ? "" : method + " ") + (path == null ? "" : path);

        // ==============================================================
        // 一、Flag 已确认 —— 靶场里最直接的信号，延伸方向也最明确
        // ==============================================================
        if (containsAny(names, "Flag")) {
            out.add(new Suggestion("Flag（已确认）",
                    "把路径里的 ID 换成相邻值（0、2、3、-1、9999、非数字）逐个试",
                    "这个接口已经证明能吐 flag，而路径里带着 " + idHint(path)
                            + "。"
                            + "同一套代码换个 ID 往往就是另一道题 —— 这是靶场里投入产出比最高的一步。",
                    100));
            out.add(new Suggestion("Flag（已确认）",
                    "换 HTTP 方法重放：GET / POST / PUT / DELETE / PATCH",
                    "不同方法走的可能是不同的处理分支，鉴权与参数校验常常不一致。",
                    85));
            out.add(new Suggestion("Flag（已确认）",
                    "去掉 Cookie（以及任何认证头）重放同一个请求",
                    authed
                            ? "确认这个接口在有/无凭据下行为是否一致。"
                            : "这个请求本来就没带业务凭据 —— 去掉剩下的统计 Cookie 再确认一次，"
                            + "如果仍返回同样内容，就是明确的未授权访问。",
                    80));
            out.add(new Suggestion("Flag（已确认）",
                    "找同前缀下的兄弟路径：把 " + lastSeg(path)
                            + " 换成 list / index / view / detail / admin / new / all",
                    "同一个控制器里的兄弟动作常常共用（或共用缺失）同一套鉴权。",
                    75));
            out.add(new Suggestion("Flag（已确认）",
                    "在路径末尾加斜杠、加 ..、加 .json / .xml / .txt 后缀再试",
                    "不同后缀可能绕过路由匹配，落到没做鉴权的那条规则上。",
                    60));
        }

        // ==============================================================
        // 二、无认证却返回数据 —— 未授权访问
        // ==============================================================
        if (!authed && containsAny(names, "敏感字段回显", "Flag", "敏感文件泄露")) {
            out.add(new Suggestion("响应含业务数据但请求无凭据",
                    "确认这个请求真的没带业务认证头（只带统计 Cookie 不算），"
                            + "然后到同域名下找 <b>同前缀</b> 的其它接口，逐个不带凭据访问",
                    "一个接口没有访问控制，同一个控制器里的兄弟接口往往也没有 —— "
                            + "这是「一个点扩成一个面」最快的方式。",
                    95));
        }

        // ==============================================================
        // 三、ID 可预测 —— 越权/遍历
        // ==============================================================
        if (containsAny(names, "ID可预测", "归属字段")) {
            out.add(new Suggestion("ID 可预测（已观测）",
                    "用<b>另一个账号</b>的凭据重放，看能否拿到同一个 ID 的数据",
                    "ID 连续只说明可以猜；能拿到别人的数据才是越权。"
                            + "这一步是把它从「线索」变成「漏洞」的唯一办法。",
                    98));
            out.add(new Suggestion("ID 可预测（已观测）",
                    "试边界值：0、负数、超大数（2147483647）、非数字（abc）、空",
                    "边界值常触发未处理分支 —— 报错、返回全量、或者跳过权限检查。",
                    70));
            out.add(new Suggestion("ID 可预测（已观测）",
                    "试数组/重复参数：id=1&id=2、id[]=1、id=1,2",
                    "不同框架对重复参数取值规则不同，可能取到非预期的那一个。",
                    65));
        }

        // ==============================================================
        // 四、金额 / 数量 / 状态 / 权限字段可控
        // ==============================================================
        if (containsAny(names, "金额可篡改")) {
            out.add(new Suggestion("金额字段在客户端",
                    "改小（0.01）、改成 0、改成负数、改成超大值，看服务端是否重新计价",
                    "服务端若信任客户端传来的金额，就是直接的资损漏洞。"
                            + "改负数还能测「退款/提现」方向。",
                    97));
        }
        if (containsAny(names, "数量可篡改")) {
            out.add(new Suggestion("数量字段在客户端",
                    "试 0、负数、小数、超大值；配合金额字段一起改",
                    "负数量 + 正金额、或超大数量配折扣，是套利与超卖的常见组合。",
                    90));
        }
        if (containsAny(names, "状态字段")) {
            out.add(new Suggestion("状态字段在客户端",
                    "直接提交终态值（status=paid / done / approved / verified=1），跳过中间步骤",
                    "状态机若只在前端串联，后端就可能接受任意跳转 —— 典型流程绕过。",
                    92));
        }
        if (containsAny(names, "权限字段")) {
            out.add(new Suggestion("权限字段在客户端",
                    "改成管理员值（role=admin / isAdmin=true / level=9）提交，再重新拉取自己的资料看是否生效",
                    "这是垂直越权最直接的测法。注意：改完要<b>回读</b>确认生效，"
                            + "只看提交响应可能会被骗。",
                    96));
        }

        // ==============================================================
        // 五、无 CSRF / 可重复提交 / 频控
        // ==============================================================
        if (containsAny(names, "无CSRF")) {
            out.add(new Suggestion("改状态请求无 CSRF 令牌",
                    "构造一个只含该请求的第三方页面，用受害者浏览器打开，看请求是否被接受",
                    "注意先确认 Cookie 的 SameSite —— 如果是 Lax/Strict，"
                            + "跨站请求根本不会带上 Cookie，那 CSRF 就不成立。",
                    72));
        }
        if (containsAny(names, "可重复提交")) {
            out.add(new Suggestion("同一请求可重复提交",
                    "连点两次 / 并发发两个相同请求，看是否重复生效（重复领券、重复下单、重复扣款）",
                    "这是幂等性缺失。并发测试比顺序点击更容易命中竞态窗口。",
                    88));
        }
        if (containsAny(names, "频控缺失")) {
            out.add(new Suggestion("接口无频率限制",
                    "如果是短信 / 邮件 / 验证码 / 登录接口，测是否可被高频调用",
                    "▲ 只做<b>最小验证</b>（比如多来 2-3 次确认没有拦截），"
                            + "不要真的打满 —— 那是「影响业务正常运行」，SRC 明令禁止。",
                    55));
        }

        // ==============================================================
        // 六、信息泄露 / 配置类
        // ==============================================================
        if (containsAny(names, "源码泄露", "备份/配置文件", "敏感路径可访问")) {
            out.add(new Suggestion("敏感文件可访问（已确认）",
                    "对同一目录试常见备份后缀与编辑器残留："
                            + "index.php~ / .index.php.swp / index.php.bak / .index.php.old / index.php.save",
                    "开发改完代码留残留文件是通病。既然这个文件能访问，"
                            + "同目录下的残留大概率也能。",
                    80));
            out.add(new Suggestion("敏感文件可访问（已确认）",
                    "如果是 .git 泄露：只取 .git/HEAD 与 .git/config 作为证据，<b>不要 clone 整个仓库</b>",
                    "多数 SRC 规则明确禁止「下载、保存、传播业务数据」。"
                            + "取最小证据即可证明问题存在。",
                    70));
        }
        if (containsAny(names, "错误细节泄露", "调试信息", "堆栈泄露", "SQL报错")) {
            out.add(new Suggestion("错误细节泄露（已确认）",
                    "从报错里读出框架与版本，再往该版本的已知漏洞（CVE）方向测",
                    "报错已经把技术栈交代清楚了 —— 这是从「信息泄露」走向"
                            + "「可利用漏洞」的标准路径。",
                    78));
            out.add(new Suggestion("错误细节泄露（已确认）",
                    "构造畸形输入触发<b>不同</b>的报错，看能否暴露更多内部结构（绝对路径、内网地址、SQL 片段）",
                    "不同报错类型暴露的信息不一样，集成一份能拼出更完整的地图。",
                    62));
        }
        if (containsAny(names, "CORS")) {
            out.add(new Suggestion("CORS 反射 Origin（已确认反射）",
                    "▲ 先用浏览器实测：从外部页面 fetch 该接口并带 credentials，"
                            + "看能否读到数据",
                    "反射 ACAO 本身不等于可利用 —— 如果会话 Cookie 是 SameSite=Lax/Strict，"
                            + "跨站请求根本不会带上 Cookie，那就不可利用。"
                            + "<b>不验证这条就提交，平台复核一跑就会发现用不了。</b>",
                    94));
        }
        if (containsAny(names, "JWT")) {
            out.add(new Suggestion("流量里携带 JWT",
                    "本地解码看 alg / exp / role；试 alg=none、把 HS256 改成 RS256、改 role 后重签（若能拿到公钥）",
                    "JWT 的常见缺陷集中在这几处。解码是零成本的。",
                    76));
        }
        if (containsAny(names, "第三方脚本", "组件版本")) {
            out.add(new Suggestion("组件版本已知",
                    "拿版本号去 NVD / 组件官方公告查有没有已知漏洞",
                    "报出的是版本指纹，不是漏洞 —— 必须自己查过才知道有没有戏。",
                    50));
        }

        // ==============================================================
        // 七、通用：任何已确认发现都值得做的一次横向扩面
        // ==============================================================
        if (!out.isEmpty()) {
            out.add(new Suggestion("（通用）同一个漏洞点横向扩面",
                    "把能复现的那个请求，在同域名下换前缀 / 换模块再试一轮"
                            + "（比如 /user/edit/1 → /order/edit/1、/admin/edit/1）",
                    "同一套开发习惯会重复出现在多个模块里。"
                            + "找到一个点之后横向扫一遍，是 SRC 提效最快的方式。",
                    68));
        }

        // 排序 + 去重（同一 action 只留权重最高的）
        out.sort((a, b) -> b.weight - a.weight);
        List<Suggestion> unique = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Suggestion s : out) {
            if (seen.add(s.action)) {
                unique.add(s);
            }
        }
        return unique;
    }

    // ==================================================================

    static boolean containsAny(Set<String> names, String... keys) {
        for (String n : names) {
            for (String k : keys) {
                if (n.contains(k)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 从路径里取出「看起来是 ID」的那一段，用于生成提示文案。 */
    static String idHint(String path) {
        if (path == null) {
            return "一个数字段";
        }
        for (String seg : path.split("/")) {
            if (seg.matches("\\d{1,15}")) {
                return "ID " + seg;
            }
        }
        return "一个数字段";
    }

    /** 路径最后一段。 */
    static String lastSeg(String path) {
        if (path == null || path.isEmpty()) {
            return "动作名";
        }
        String[] parts = path.split("/");
        for (int i = parts.length - 1; i >= 0; i--) {
            if (parts[i].matches("\\d+") && i > 0) {
                return parts[i - 1];
            }
            if (!parts[i].isEmpty()) {
                return parts[i];
            }
        }
        return "动作名";
    }

    // ==================================================================

    /** 渲染成给用户看的「延伸测试清单」。 */
    public static String render(List<Suggestion> list) {
        if (list == null || list.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("────── 延伸测试（从已确认发现推导，待验证）──────\n");
        sb.append("（这些是<b>下一步动作</b>，不是结论 —— 验证过才能写进报告）\n\n");
        int n = 0;
        for (Suggestion s : list) {
            if (n++ >= 12) {
                sb.append("  …（另有 ").append(list.size() - 12).append(" 条）\n");
                break;
            }
            sb.append("  ").append(n).append(". ").append(s.action).append('\n');
            sb.append("     为什么：").append(s.why).append('\n');
            sb.append("     来源：").append(s.from).append('\n');
        }
        return sb.toString();
    }

    /** 汇总成给 AI 的文本。 */
    public static String toPromptText(List<Suggestion> list) {
        if (list == null || list.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("【本地已推导出的延伸测试方向】\n");
        sb.append("（这些是机械推导的结果，覆盖度有保证；请在此基础上补充，不要重复）\n");
        for (Suggestion s : list) {
            sb.append("  · ").append(s.action).append('\n');
        }
        return sb.toString();
    }
}
