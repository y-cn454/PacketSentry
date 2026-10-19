package com.packetsentry.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.packetsentry.detect.LocalRules;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 发现清单 —— <b>跨会话持久化</b>的 SRC 工作台账。
 *
 * <h3>为什么这个类是「切合 SRC」的核心</h3>
 * 靶场是「拿到 flag 就结束」，一个包一个包地看就行。
 * 但 SRC 的实际形态是：<b>盯着一个目标挖几天</b>。
 *
 * <p>在这之前，插件的问题很实在：
 * <ul>
 *   <li>关掉 Burp，半天的工作全没了（「最近 500 条包」只在内存里）</li>
 *   <li>同一个接口用 5 个 ID 验证越权，清单里会出现 5 次</li>
 *   <li>挖到第三天，记不清哪条验证过、哪条提交了</li>
 * </ul>
 *
 * <p>所以需要这个东西：<b>把包里的问题归并成发现，存到磁盘，并跟踪状态。</b>
 *
 * <h3>存哪儿、怎么保证不坏</h3>
 * {@code ~/.packetsentry/findings.json}。写入用「临时文件 + 原子改名」——
 * 中途崩溃不会留下半个坏文件（这是 {@link Config} 验证过的做法）。
 *
 * <h3>▲ 证据里不许存业务数据</h3>
 * {@link Finding#evidence} 只存<b>能证明问题存在的最小片段</b>，而且截断到 300 字符。
 * SRC 规则普遍禁止保存、传播业务数据 —— 清单本身也不该成为泄露渠道。
 */
public final class FindingsLedger {

    private static final int MAX_FINDINGS = 20000;

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();

    private final Path file;
    /** id → Finding。用 LinkedHashMap 保持插入顺序，展示时更符合「发现顺序」。 */
    private final Map<String, Finding> byId = new LinkedHashMap<>();
    private final Object lock = new Object();

    private String lastError = "";

    public FindingsLedger() {
        this(defaultFile());
    }

    public FindingsLedger(Path file) {
        this.file = file;
        load();
    }

    public static Path defaultFile() {
        return Config.homeDir().resolve("findings.json");
    }

    public Path file() {
        return file;
    }

    public String getLastError() {
        return lastError;
    }

    // ==================================================================
    // 读写
    // ==================================================================

    /** 从磁盘载入。文件不存在或损坏都<b>不抛异常</b> —— 清单坏了不该让插件起不来。 */
    public void load() {
        synchronized (lock) {
            byId.clear();
            if (file == null || !Files.isRegularFile(file)) {
                return;
            }
            try {
                String json = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
                if (json.trim().isEmpty()) {
                    return;
                }
                List<Finding> list = GSON.fromJson(json,
                        new TypeToken<List<Finding>>() { }.getType());
                if (list == null) {
                    return;
                }
                for (Finding f : list) {
                    if (f == null) {
                        continue;
                    }
                    // 修正字段：老版本存下来的可能缺 id
                    if (f.id == null || f.id.isEmpty()) {
                        f.id = Finding.fingerprint(f.method, f.host, f.normPath, f.type);
                    }
                    if (f.normPath == null || f.normPath.isEmpty()) {
                        f.normPath = Finding.normalizePath(f.path);
                    }
                    if (f.status == null || f.status.isEmpty()) {
                        f.status = Finding.Status.TODO.label;
                    }
                    byId.put(f.id, f);
                }
                lastError = "";
            } catch (Exception e) {
                // 坏文件不删 —— 也许用户想手工抢救
                lastError = "发现清单解析失败（已忽略，原文件保留）: " + e.getMessage();
            }
        }
    }

    /** 原子写盘。返回错误信息，成功返回空串。 */
    public String save() {
        List<Finding> snapshot;
        synchronized (lock) {
            snapshot = new ArrayList<>(byId.values());
        }
        try {
            Path parent = file.getParent();
            if (parent != null && !Files.isDirectory(parent)) {
                Files.createDirectories(parent);
            }
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.write(tmp, GSON.toJson(snapshot).getBytes(StandardCharsets.UTF_8));
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (Exception atomicFailed) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
            lastError = "";
            return "";
        } catch (Exception e) {
            lastError = "发现清单保存失败: " + e.getMessage();
            return lastError;
        }
    }

    // ==================================================================
    // 增 / 改 / 查
    // ==================================================================

    /**
     * 记一条观测。
     *
     * <p>同样的发现（按指纹）会<b>合并</b>而不是新增 —— 这是清单能用的前提。
     *
     * @return true 表示这是一条<b>新发现</b>（不是合并）
     */
    public boolean upsert(Finding f) {
        if (f == null || f.id == null || f.id.isEmpty()) {
            return false;
        }
        synchronized (lock) {
            Finding existing = byId.get(f.id);
            if (existing == null) {
                if (byId.size() >= MAX_FINDINGS) {
                    return false;
                }
                byId.put(f.id, f);
                return true;
            }
            existing.mergeFrom(f);
            return false;
        }
    }

    /** 按 id 设置状态与备注。 */
    public boolean setStatus(String id, Finding.Status status, String note) {
        synchronized (lock) {
            Finding f = byId.get(id);
            if (f == null) {
                return false;
            }
            if (status != null) {
                f.status = status.label;
            }
            if (note != null) {
                f.note = note;
            }
            return true;
        }
    }

    /** 删除一条（用户判断没价值时）。 */
    public boolean remove(String id) {
        synchronized (lock) {
            return byId.remove(id) != null;
        }
    }

    /** 清空清单。 */
    public void clear() {
        synchronized (lock) {
            byId.clear();
        }
    }

    public Finding get(String id) {
        synchronized (lock) {
            return byId.get(id);
        }
    }

    public int size() {
        synchronized (lock) {
            return byId.size();
        }
    }

    /** 全部发现，按「等级降序 → 次数降序 → 最近出现降序」排。 */
    public List<Finding> all() {
        List<Finding> out;
        synchronized (lock) {
            out = new ArrayList<>(byId.values());
        }
        out.sort(Comparator
                .comparingInt((Finding f) -> -f.levelRank)
                .thenComparingInt(f -> -f.seenCount)
                .thenComparingLong(f -> -f.lastSeen));
        return out;
    }

    public List<Finding> byHost(String host) {
        List<Finding> out = new ArrayList<>();
        for (Finding f : all()) {
            if (host == null || host.isEmpty() || host.equalsIgnoreCase(f.host)) {
                out.add(f);
            }
        }
        return out;
    }

    public List<Finding> byStatus(Finding.Status st) {
        List<Finding> out = new ArrayList<>();
        for (Finding f : all()) {
            if (f.statusEnum() == st) {
                out.add(f);
            }
        }
        return out;
    }

    /**
     * 该提交的 —— 已经验证过、还没交出去的。
     *
     * <p>这是 SRC 里最该被回答的问题：「我现在手上有哪些能交？」
     */
    public List<Finding> readyToSubmit() {
        List<Finding> out = new ArrayList<>();
        for (Finding f : all()) {
            if (f.statusEnum() == Finding.Status.VERIFIED) {
                out.add(f);
            }
        }
        return out;
    }

    /** 还在待验证的。 */
    public List<Finding> toVerify() {
        return byStatus(Finding.Status.TODO);
    }

    // ==================================================================
    // 统计 / 展示
    // ==================================================================

    /** 按状态统计。 */
    public Map<String, Integer> statusCounts() {
        Map<String, Integer> m = new LinkedHashMap<>();
        for (Finding.Status st : Finding.Status.values()) {
            m.put(st.label, 0);
        }
        synchronized (lock) {
            for (Finding f : byId.values()) {
                String k = f.statusEnum().label;
                m.put(k, m.getOrDefault(k, 0) + 1);
            }
        }
        return m;
    }

    /** 按等级统计。 */
    public Map<String, Integer> levelCounts() {
        Map<String, Integer> m = new LinkedHashMap<>();
        for (LocalRules.Level lv : LocalRules.Level.values()) {
            if (lv == LocalRules.Level.NONE) {
                continue;
            }
            m.put(lv.label, 0);
        }
        synchronized (lock) {
            for (Finding f : byId.values()) {
                String k = f.displayLevel();
                m.put(k, m.getOrDefault(k, 0) + 1);
            }
        }
        return m;
    }

    /** 涉及的域名数。 */
    public int hostCount() {
        java.util.Set<String> set = new java.util.LinkedHashSet<>();
        synchronized (lock) {
            for (Finding f : byId.values()) {
                set.add(f.host);
            }
        }
        return set.size();
    }

    public java.util.Set<String> hosts() {
        java.util.Set<String> set = new java.util.LinkedHashSet<>();
        synchronized (lock) {
            for (Finding f : byId.values()) {
                if (f.host != null && !f.host.isEmpty()) {
                    set.add(f.host);
                }
            }
        }
        return set;
    }

    // ==================================================================
    // 导出
    // ==================================================================

    /**
     * 导出 Markdown —— <b>可以直接贴进 SRC 平台报告框</b>的那种。
     *
     * <p>只导出「已验证及以上」的发现。待验证的还没确认，写进报告是给自己找麻烦。
     */
    public String exportMarkdown(String host, boolean onlyReady) {
        StringBuilder sb = new StringBuilder();
        sb.append("# 漏洞报告\n\n");
        List<Finding> list = new ArrayList<>();
        for (Finding f : byHost(host)) {
            if (onlyReady && f.statusEnum() == Finding.Status.TODO) {
                continue;
            }
            if (f.statusEnum() == Finding.Status.IGNORED
                    || f.statusEnum() == Finding.Status.OUT_OF_SCOPE) {
                continue;
            }
            list.add(f);
        }
        if (list.isEmpty()) {
            return "（没有可导出的发现。先把发现标成「已验证」，或关掉「只导出已验证」。）";
        }
        for (int i = 0; i < list.size(); i++) {
            Finding f = list.get(i);
            sb.append("## ").append(i + 1).append(". ").append(f.type).append("\n\n");
            sb.append("- **漏洞 URL**：").append(f.url()).append('\n');
            sb.append("- **风险评级**：").append(f.displayLevel()).append('\n');
            if (f.decision != null && !f.decision.isEmpty()) {
                sb.append("- **平台规则**：").append(f.decision).append('\n');
            }
            sb.append("- **命中参数**：")
                    .append(f.param == null || f.param.isEmpty() ? "（无）" : f.param)
                    .append('\n');
            sb.append("- **复现请求**：`").append(f.where()).append("`\n");
            if (f.evidence != null && !f.evidence.isEmpty()) {
                sb.append("- **证据（截断）**：`").append(f.evidence).append("`\n");
            }
            sb.append("- **观测次数**：").append(f.seenCount).append('\n');
            sb.append("- **状态**：").append(f.status).append('\n');
            if (f.note != null && !f.note.isEmpty()) {
                sb.append("- **备注**：").append(f.note).append('\n');
            }
            sb.append('\n');
        }
        sb.append("---\n\n");
        sb.append("> ▲ 提交前请人工核对：\n");
        sb.append("> 1. 每条是否真的能复现（清单里是「候选」，不是已确认）\n");
        sb.append("> 2. 危害说明要写清业务影响，逻辑漏洞尤其要说透\n");
        sb.append("> 3. 资产证明（域名归属、关键截图）需要自己补\n");
        sb.append("> 4. 证据只放最小证明，不要附带业务数据\n");
        return sb.toString();
    }

    /** 一行摘要，给状态栏用。 */
    public String oneLine() {
        Map<String, Integer> st = statusCounts();
        int open = st.getOrDefault(Finding.Status.TODO.label, 0)
                + st.getOrDefault(Finding.Status.VERIFIED.label, 0);
        return "发现 " + size() + " 条（待处理 " + open + "　已验证 "
                + st.getOrDefault(Finding.Status.VERIFIED.label, 0) + "　已提交 "
                + (st.getOrDefault(Finding.Status.SUBMITTED.label, 0)
                + st.getOrDefault(Finding.Status.ACCEPTED.label, 0)) + "）";
    }

    /**
     * 从发现清单反推「还该测什么」。
     *
     * <p>这是 SRC 的复利：一条发现验证完，往往能推出同模块的其它测试点。
     */
    public String nextSteps(String host) {
        List<Finding> all = byHost(host);
        if (all.isEmpty()) {
            return "清单还是空的。先在目标站里正常走一遍，让流量经过代理。";
        }
        StringBuilder sb = new StringBuilder();
        Map<String, Integer> byHostPrefix = new LinkedHashMap<>();
        for (Finding f : all) {
            String p = f.normPath == null ? "" : f.normPath;
            int slash = p.indexOf('/', 1);
            String prefix = slash > 0 ? p.substring(0, slash) : p;
            byHostPrefix.merge(prefix, 1, Integer::sum);
        }
        sb.append("按模块分布（挖得多的模块往往还有料）：\n");
        byHostPrefix.entrySet().stream()
                .sorted((a, b) -> b.getValue() - a.getValue())
                .limit(10)
                .forEach(e -> sb.append("  ").append(e.getKey())
                        .append("　").append(e.getValue()).append(" 条\n"));

        List<Finding> todo = toVerify();
        if (!todo.isEmpty()) {
            sb.append("\n还没验证的 ").append(todo.size()).append(" 条：\n");
            for (int i = 0; i < Math.min(8, todo.size()); i++) {
                sb.append("  · ").append(todo.get(i).type).append(" @ ")
                        .append(todo.get(i).path).append('\n');
            }
        }
        List<Finding> ready = readyToSubmit();
        if (!ready.isEmpty()) {
            sb.append("\n★ 已验证、可以提交的 ").append(ready.size()).append(" 条：\n");
            for (int i = 0; i < Math.min(8, ready.size()); i++) {
                sb.append("  · [").append(ready.get(i).displayLevel()).append("] ")
                        .append(ready.get(i).type).append(" @ ")
                        .append(ready.get(i).path).append('\n');
            }
        }
        return sb.toString();
    }

    /** 给 AI 看的文本（生成报告时带上）。 */
    public String toPromptText(String host) {
        StringBuilder sb = new StringBuilder();
        sb.append("【已确认的发现清单】（来自本地规则，有原文证据）\n");
        int n = 0;
        for (Finding f : byHost(host)) {
            if (n++ >= 20) {
                break;
            }
            sb.append("  · [").append(f.displayLevel()).append("] ").append(f.type)
                    .append(" @ ").append(f.where());
            if (f.decision != null && !f.decision.isEmpty()
                    && !"未提及".equals(f.decision)) {
                sb.append("　平台规则：").append(f.decision);
            }
            sb.append('\n');
        }
        return sb.toString();
    }
}
