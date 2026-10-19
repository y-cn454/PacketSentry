import com.packetsentry.audit.RouteAudit;

/**
 * 隐藏入口审计 实测。
 *
 * <h3>为什么这个功能必须测准</h3>
 * 它找的是「页面没入口、代码里还在」的路由 —— 用户会拿这些路径
 * <b>去敲目标系统的 URL</b>。所以有两个方向的错误都很有代价：
 * <ul>
 *   <li><b>误报</b>：把静态资源、变量拼接残渣当成路由 → 用户敲一堆 404，
 *       浪费时间还可能触发告警</li>
 *   <li><b>漏报</b>：把真有价值的管理/注册入口过滤掉 → 白做</li>
 * </ul>
 *
 * <p>所以测试用<b>一个真实场景</b>：模拟一个 Vue 后台，
 * 登录页把注册按钮注释掉了，但路由表还在。
 */
public class RouteAuditProbe {

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

    private static boolean hasCandidate(RouteAudit.Result r, String path) {
        return r.hiddenCandidates.stream().anyMatch(c -> c.path.equals(path));
    }

    private static boolean hasSensitive(RouteAudit.Result r, String path) {
        return r.sensitiveRoutes.stream().anyMatch(c -> c.path.equals(path));
    }

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println(" 场景：Vue 后台，登录页把注册按钮注释掉了，路由表还在");
        System.out.println("============================================================");

        RouteAudit audit = new RouteAudit();
        RouteAudit.Result r = new RouteAudit.Result();

        // ---- 1. 路由表（JS）—— 包含注册、管理、调试等敏感路由 ----
        String routerJs = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"
                + "const routes=["
                + "{path:'/login',component:Login},"
                + "{path:'/register',component:Register},"                       // 敏感
                + "{path:'/admin/users',component:AdminUsers},"                  // 敏感
                + "{path:'/admin/export',component:Export},"                     // 敏感
                + "{path:'/debug/env',component:DebugEnv},"                      // 敏感
                + "{path:'/user/profile',component:Profile},"                    // 普通
                + "{path:'/help',component:Help}"                                // 普通
                + "];\n"
                // 被注释掉的跳转 —— 正是用户描述的场景
                + "// router.push('/register')\n"
                + "// <el-button @click=\"goRegister\">注册新账号</el-button>\n"
                // 静态资源不该被当路由
                + "fetch('/static/logo.png');fetch('/assets/app.js');"
                + "fetch('/api/v1/user/list');";

        audit.feed("/static/router.js", routerJs, r);

        // ---- 2. 登录页 HTML —— 注册按钮被注释掉了 ----
        String loginHtml = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                + "<html><body>"
                + "<form action=\"/api/login\">"
                + "<input name=\"u\"><input name=\"p\" type=\"password\">"
                + "<button>登录</button></form>"
                // ⭐ 关键：注册按钮被注释掉，但代码还在
                + "<!-- <a href=\"/register\">注册新账号</a> -->"
                + "<!-- <a href=\"/admin/users\">用户管理</a> -->"
                + "<a href=\"/help\">帮助</a>"
                + "<a href=\"/user/profile\">个人中心</a>"
                + "</body></html>";

        audit.feed("/login", loginHtml, r);

        audit.finish(r);

        System.out.println("  提取路由 " + r.allRoutes.size() + " 条：");
        for (String s : r.allRoutes) {
            System.out.println("    " + s);
        }
        System.out.println();
        System.out.println("  隐藏入口候选 " + r.hiddenCandidates.size() + " 条：");
        for (RouteAudit.Candidate c : r.hiddenCandidates) {
            System.out.println("    [" + c.tag + "] " + c.path);
        }
        System.out.println();

        System.out.println("── 核心断言：该报的必须报 ──");
        check("检出隐藏的 /register（用户描述的场景）", hasCandidate(r, "/register"));
        check("检出隐藏的 /admin/users", hasCandidate(r, "/admin/users"));
        check("检出隐藏的 /admin/export", hasCandidate(r, "/admin/export"));
        check("检出隐藏的 /debug/env", hasCandidate(r, "/debug/env"));

        System.out.println();
        System.out.println("── 不该报的必须不报 ──");
        check("静态资源不被当路由（/static/logo.png）", !hasCandidate(r, "/static/logo.png"));
        check("静态资源不被当路由（/assets/app.js）", !hasCandidate(r, "/assets/app.js"));
        check("页面里有链接的 /help 不算隐藏入口", !hasCandidate(r, "/help"));
        check("页面里有链接的 /user/profile 不算隐藏入口",
                !hasCandidate(r, "/user/profile"));

        System.out.println();
        System.out.println("── 注释代码提取 ──");
        System.out.println("  提取到 " + r.commentedCode.size() + " 条被注释的代码：");
        for (String c : r.commentedCode) {
            System.out.println("    · " + c);
        }
        check("检出 HTML 里被注释掉的注册链接",
                r.commentedCode.stream().anyMatch(c -> c.contains("register")));
        check("检出 JS 里被注释掉的 router.push",
                r.commentedCode.stream().anyMatch(c -> c.contains("router.push")));
        check("不把版权头当成被注释的代码",
                r.commentedCode.stream().noneMatch(c -> c.contains("Copyright")));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第二部分：后端源码泄露识别 + 合规提醒");
        System.out.println("============================================================");

        RouteAudit a2 = new RouteAudit();
        RouteAudit.Result r2 = new RouteAudit.Result();
        a2.feed("/.git/HEAD",
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nref: refs/heads/master\n", r2);
        a2.feed("/backup/index.php.bak",
                "HTTP/1.1 200 OK\r\n\r\n<?php $db='x'; ?>", r2);
        a2.feed("/app.js",
                "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"
                        + "var a=1;\n//# sourceMappingURL=app.js.map", r2);
        a2.finish(r2);

        System.out.println("  源码泄露迹象：");
        r2.backendLeakSigns.forEach(s -> System.out.println("    · " + s));
        System.out.println("  Source Map：");
        r2.sourceMaps.forEach(s -> System.out.println("    · " + s));
        System.out.println();

        check("识别出 .git/HEAD 泄露", r2.backendLeakSigns.stream()
                .anyMatch(s -> s.contains(".git/HEAD")));
        check("识别出 PHP 源码泄露", r2.backendLeakSigns.stream()
                .anyMatch(s -> s.contains("PHP")));
        check("识别出 Source Map", r2.sourceMaps.stream()
                .anyMatch(s -> s.contains("app.js.map")));

        String rendered = RouteAudit.render(r2);
        check("报告含合规红线提醒（不要 clone 仓库）",
                rendered.contains("不要 git clone") || rendered.contains("git clone"));
        check("报告含「只取最小证据」的指引", rendered.contains("最小证据"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第三部分：诚实性声明");
        System.out.println("============================================================");

        String full = RouteAudit.render(r);
        check("报告声明「0 个网络请求」", full.contains("网络请求") && full.contains("0"));
        check("报告明确说来源是前端代码、不是逆向的后端源码",
                full.contains("前端") && full.contains("后端源码从流量里拿不到"));
        check("报告警告「路由存在 ≠ 漏洞」", full.contains("路由存在 ≠ 漏洞"));
        check("报告提醒不要写脚本批量扫", full.contains("自动化工具"));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 第四部分：边界（不许崩）");
        System.out.println("============================================================");

        boolean ok = true;
        try {
            RouteAudit a3 = new RouteAudit();
            RouteAudit.Result r3 = new RouteAudit.Result();
            a3.feed(null, null, r3);
            a3.feed("/x", "", r3);
            a3.feed("/y", "\u0000\uFEFF", r3);
            // 超长
            StringBuilder huge = new StringBuilder("<html>");
            for (int i = 0; i < 5000; i++) {
                huge.append("<a href=\"/p").append(i).append("\">x</a>");
            }
            a3.feed("/huge", huge.toString(), r3);
            a3.finish(r3);
            RouteAudit.render(r3);
        } catch (Throwable e) {
            ok = false;
            System.out.println("    ✗ 抛异常：" + e);
        }
        check("null / 空 / 控制字符 / 超大页面都不抛异常", ok);

        // 大量路由不能把结果撑爆
        RouteAudit a4 = new RouteAudit();
        RouteAudit.Result r4 = new RouteAudit.Result();
        StringBuilder many = new StringBuilder("<html>");
        for (int i = 0; i < 3000; i++) {
            many.append("{path:'/admin/p").append(i).append("'},");
        }
        a4.feed("/many.js", many.toString(), r4);
        a4.finish(r4);
        check("路由表被限制在上限内（不会无限增长）", r4.allRoutes.size() <= 600);

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");
        System.exit(fail == 0 ? 0 : 1);
    }
}
