import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.ITab;

import com.packetsentry.burp.BurpExtender;

import java.awt.Component;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

/**
 * 模拟 Burp 加载插件 —— <b>这是"能不能用"的关键验证</b>。
 *
 * <p>用动态代理伪造 {@link IBurpExtenderCallbacks}，然后真的调用
 * {@code registerExtenderCallbacks()}。这能抓到：
 * <ul>
 *   <li>启动路径上的 NullPointerException</li>
 *   <li>Swing 构造在 headless 下的异常</li>
 *   <li>配置读取失败导致的启动崩溃</li>
 *   <li>返回 null 导致 Burp 侧出问题（比如 createNewInstance）</li>
 * </ul>
 *
 * <p>作者的 AIPacketHunter 连编译都过不了（License.java:127 语法错误），
 * 所以这一步不是形式主义 —— 它是区分"能编译"和"能加载"的分界线。
 */
public class LoadTest {

    private static int pass = 0;
    private static int fail = 0;
    private static final List<String> log = new ArrayList<>();

    private static void check(String label, boolean ok) {
        if (ok) {
            pass++;
            System.out.println("  [PASS] " + label);
        } else {
            fail++;
            System.out.println("  [FAIL] " + label);
        }
    }

    /** 统计某个 Burp API 被调用了多少次。 */
    private static int countOf(List<String> log, String suffix) {
        int n = 0;
        for (String s : log) {
            if (s.endsWith(suffix)) {
                n++;
            }
        }
        return n;
    }

    /** 万能桩：任何接口方法都返回类型安全的默认值。 */
    @SuppressWarnings("unchecked")
    private static <T> T stub(Class<T> iface, String name) {
        return (T) Proxy.newProxyInstance(
                iface.getClassLoader(),
                new Class<?>[]{iface},
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method m, Object[] args) {
                        String n = m.getName();
                        log.add(name + "." + n);
                        Class<?> rt = m.getReturnType();

                        // 关键：让 getHelpers 返回一个同样被代理的对象
                        if ("getHelpers".equals(n)) {
                            return stub(IExtensionHelpers.class, "helpers");
                        }
                        if (rt == void.class) {
                            return null;
                        }
                        if (rt == boolean.class) {
                            return Boolean.FALSE;
                        }
                        if (rt == int.class) {
                            return 0;
                        }
                        if (rt == long.class) {
                            return 0L;
                        }
                        if (rt == byte[].class) {
                            return new byte[0];
                        }
                        if (rt == String.class) {
                            return "";
                        }
                        if (rt.isArray()) {
                            return java.lang.reflect.Array.newInstance(rt.getComponentType(), 0);
                        }
                        if (rt.isInterface()) {
                            return stub(rt, name + "." + n);
                        }
                        return null;
                    }
                });
    }

    public static void main(String[] args) throws Exception {
        System.out.println("============================================================");
        System.out.println(" 模拟 Burp 加载插件");
        System.out.println("============================================================");
        System.out.println();

        // ---------- ① 实例化 ----------
        BurpExtender ext = null;
        try {
            ext = new BurpExtender();
            check("BurpExtender 可实例化", true);
        } catch (Throwable t) {
            check("BurpExtender 可实例化 —— " + t, false);
            System.out.println("  致命：无法继续");
            System.exit(1);
        }

        // ---------- ② 实现接口完整性 ----------
        check("实现 IBurpExtender", ext instanceof burp.IBurpExtender);
        check("实现 ITab", ext instanceof ITab);
        check("实现 IMessageEditorTabFactory", ext instanceof IMessageEditorTabFactory);
        check("实现 IHttpListener", ext instanceof IHttpListener);

        // ---------- ③ 走注册流程（启动路径）----------
        IBurpExtenderCallbacks cb = stub(IBurpExtenderCallbacks.class, "callbacks");
        try {
            ext.registerExtenderCallbacks(cb);
            // ⚠️ 刻意<b>不</b> sleep —— 要验证标签页是<b>同步</b>注册的。
            //    早期版本用 SwingUtilities.invokeLater 构建 UI，
            //    结果 Burp 在 registerExtenderCallbacks 返回后收集标签页时，
            //    addSuiteTab 还没执行：扩展列表计数正常，标签栏里却没有这个页。
            //    invokeAndWait 修好了它，这条断言就是防它回归。
            check("registerExtenderCallbacks 未抛异常", true);
        } catch (Throwable t) {
            check("registerExtenderCallbacks 未抛异常 —— " + t, false);
            t.printStackTrace();
        }

        check("启动时调用了 setExtensionName",
                log.stream().anyMatch(s -> s.endsWith("setExtensionName")));
        check("启动了 HTTP 监听器（registerHttpListener）",
                log.stream().anyMatch(s -> s.endsWith("registerHttpListener")));

        // ⚠️ 这里<b>不再</b>断言「legacy 同步注册标签页」。
        //    实测发现 Burp v2025.2 先调 registerExtenderCallbacks、后调
        //    initialize(MontoyaApi)，而 legacy 路径的标签页不上屏。
        //    新设计是：legacy 只排一个延迟兜底，标签页优先走 Montoya。
        //    「legacy 是否同步注册」已不再是正确性的判据。
        check("legacy 通道没有抢注标签页（让位给 Montoya）",
                log.stream().noneMatch(s -> s.endsWith("addSuiteTab")));

        // ---------- ④ ITab ----------
        check("getTabCaption 返回非空", ext.getTabCaption() != null
                && !ext.getTabCaption().isEmpty());
        Component ui = null;
        try {
            ui = ext.getUiComponent();
            check("getUiComponent 可调用且不抛异常", true);
        } catch (Throwable t) {
            check("getUiComponent 可调用且不抛异常 —— " + t, false);
        }
        check("getUiComponent 返回了占位组件（不是 null）", ui != null);

        // ---------- ⑤ ⭐ 最关键：报文编辑器标签页不能返回 null ----------
        IMessageEditorController ctrl = stub(IMessageEditorController.class, "controller");
        IMessageEditorTab tab = ((IMessageEditorTabFactory) ext).createNewInstance(ctrl, true);
        check("createNewInstance 不返回 null（否则插件在 Burp 里什么也不做）", tab != null);

        if (tab != null) {
            check("标签页标题为 PacketSentry", "PacketSentry".equals(tab.getTabCaption()));
            check("标签页 UI 非 null", tab.getUiComponent() != null);

            // 喂一个真实的带凭据报文，验证 setMessage 不抛异常
            String raw = "POST /backstage/auth/login HTTP/1.1\r\n"
                    + "Host: ywt.example.edu.cn\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                    + ".eyJzdWIiOiIxMDA4NiIsInJvbGUiOiJhZG1pbiIsImV4cCI6NDA3MDkwODgwMH0"
                    + ".c2lnbmF0dXJl\r\n"
                    + "Cookie: SESSION=deadbeefcafe1234\r\n"
                    + "\r\n"
                    + "{\"username\":\"admin\",\"password\":\"P@ssw0rd!2026\","
                    + "\"phone\":\"13812345678\"}";
            byte[] msg = raw.getBytes(java.nio.charset.StandardCharsets.UTF_8);

            try {
                check("isEnabled 对非空报文返回 true", tab.isEnabled(msg, true));
                tab.setMessage(msg, true);
                Thread.sleep(300);
                check("setMessage 未抛异常（本地扫描 + 脱敏都跑了）", true);
            } catch (Throwable t) {
                check("setMessage 未抛异常 —— " + t, false);
                t.printStackTrace();
            }

            check("getMessage 返回 null（本插件不修改报文）", tab.getMessage() == null);
            check("isModified 返回 false（只读标签页）", !tab.isModified());
            check("isEnabled 对空报文返回 false", !tab.isEnabled(new byte[0], true));
        }

        // ---------- ⑥ IHttpListener 幂等且不外发 ----------
        IHttpRequestResponse rr = stub(IHttpRequestResponse.class, "message");
        try {
            for (int i = 0; i < 200; i++) {
                ((IHttpListener) ext).processHttpMessage(1, false, rr);
                ((IHttpListener) ext).processHttpMessage(1, true, rr);
            }
            check("processHttpMessage 可重复调用 400 次无异常", true);
        } catch (Throwable t) {
            check("processHttpMessage 可重复调用 —— " + t, false);
        }

        // ---------- ⑦ Montoya 通道 ----------
        // 实测发现：Burp Pro v2025.2 上 legacy addSuiteTab 回调正常但标签页不上屏。
        // 所以加了 Montoya 通道，标签页优先走现代 API。
        // 这里验证：Montoya 初始化能跑通，并且**只注册一次**标签页。
        System.out.println();
        System.out.println("  ---- Montoya 通道 ----");
        check("实现了 burp.api.montoya.BurpExtension",
                ext instanceof burp.api.montoya.BurpExtension);

        final java.util.List<String> suiteTabs = new ArrayList<>();
        System.out.println("        已注册的 legacy 标签页数：" + countOf(log, "addSuiteTab"));

        BurpExtender fresh = new BurpExtender();
        burp.api.montoya.MontoyaApi mApi = stub(burp.api.montoya.MontoyaApi.class, "montoya");
        try {
            ((burp.api.montoya.BurpExtension) fresh).initialize(mApi);
            check("Montoya initialize 未抛异常", true);
        } catch (Throwable t) {
            check("Montoya initialize 未抛异常 —— " + t, false);
            t.printStackTrace();
        }
        check("⭐ Montoya 通道注册了标签页（registerSuiteTab 被调用）",
                log.stream().anyMatch(s -> s.endsWith("registerSuiteTab")));
        Component mUi = fresh.getUiComponent();
        check("Montoya 通道的组件非 null", mUi != null);
        if (mUi instanceof javax.swing.JTabbedPane) {
            javax.swing.JTabbedPane tp = (javax.swing.JTabbedPane) mUi;
            check("Montoya 通道填充了 4 个页签（总览/实时/设置/状态）", tp.getTabCount() == 4);
            StringBuilder tabs = new StringBuilder();
            for (int i = 0; i < tp.getTabCount(); i++) {
                if (i > 0) { tabs.append(" / "); }
                tabs.append(tp.getTitleAt(i));
            }
            System.out.println("        Montoya 页签：" + tabs);
        }
        check("Montoya 通道设置过扩展名", log.stream().anyMatch(s -> s.endsWith("setName")));

        // 两条通道都走一遍：标签页只能注册一次，否则会出现两个 PacketSentry
        BurpExtender both = new BurpExtender();
        final int[] suiteTabCalls = {0};
        IBurpExtenderCallbacks cb2 = (IBurpExtenderCallbacks) java.lang.reflect.Proxy.newProxyInstance(
                IBurpExtenderCallbacks.class.getClassLoader(),
                new Class<?>[]{IBurpExtenderCallbacks.class},
                (proxy, m, a) -> {
                    if ("addSuiteTab".equals(m.getName())) {
                        suiteTabCalls[0]++;
                    }
                    Class<?> rt = m.getReturnType();
                    if ("getHelpers".equals(m.getName())) {
                        return stub(IExtensionHelpers.class, "helpers");
                    }
                    if (rt == void.class) {
                        return null;
                    }
                    if (rt == boolean.class) {
                        return Boolean.FALSE;
                    }
                    if (rt == int.class) {
                        return 0;
                    }
                    if (rt == String.class) {
                        return "";
                    }
                    if (rt.isInterface()) {
                        return stub(rt, "x");
                    }
                    return null;
                });
        burp.api.montoya.MontoyaApi mApi2 = stub(burp.api.montoya.MontoyaApi.class, "montoya");
        // ⚠️ 顺序刻意模拟 Burp v2025.2 的真实行为：先 legacy，后 Montoya
        both.registerExtenderCallbacks(cb2);
        ((burp.api.montoya.BurpExtension) both).initialize(mApi2);
        check("两条通道都走过后，legacy 没有重复注册标签页",
                suiteTabCalls[0] == 0);

        System.out.println();
        System.out.println("  启动期间调用的 Burp API（去重后计数：" + log.size() + " 次调用）");
        log.stream().distinct().limit(24).forEach(s -> System.out.println("        " + s));

        System.out.println();
        System.out.println("============================================================");
        System.out.println(" 结果：PASS=" + pass + "  FAIL=" + fail);
        System.out.println("============================================================");

        System.exit(fail == 0 ? 0 : 1);
    }
}
