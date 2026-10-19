# lib/ —— 依赖说明

## ⚠️ 这个目录里的两个 jar **不随仓库分发**

| 文件 | 来源 | 许可 | 是否可分发 |
|---|---|---|---|
| `montoya-api.jar` | PortSwigger（Burp 官方） | **专有** | ❌ **不可** |
| `burp-extender-api-2.3.jar` | PortSwigger（Burp 官方） | **专有** | ❌ **不可** |
| `gson-2.11.0.jar` | Google | Apache-2.0 | ✅ 可（已打包进 dist 的 jar） |

**原因：** 前两个是 PortSwigger 的闭源产物（`burp-extender-api-2.3.jar` 的 manifest 里构建者写着 `PORTSWIGGER\rik.tyer`）。把它们提交到公开仓库属于再分发他人专有代码。

**但构建必须用到它们** —— 所以请按下面的方式自行获取。

---

## 怎么获取这两个 jar

### 方式 1：从 Burp Suite 安装目录提取（推荐）

Burp Suite 自带这两个 API：

```
Burp Suite → Extender → APIs
    ↓
点 "Save jar file"（Montoya API）
点 "Save jar file"（Legacy API / burp-extender-api）
    ↓
保存为 lib/montoya-api.jar 和 lib/burp-extender-api-2.3.jar
```

### 方式 2：从 PortSwigger 官方 Maven 仓库下载

```
# Montoya API
https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/

# Legacy Extender API
https://repo1.maven.org/maven2/net/portswigger/burp/extensions/burp-extender-api/
```

### 方式 3：Maven / Gradle 依赖

```xml
<!-- pom.xml -->
<dependency>
  <groupId>net.portswigger.burp.extensions</groupId>
  <artifactId>montoya-api</artifactId>
  <version>2025.5</version>
  <scope>provided</scope>   <!-- ⚠️ provided：Burp 运行时自己提供 -->
</dependency>
```

---

## Gson

`gson-2.11.0.jar` 是 Apache-2.0，**可以随仓库分发**。

它是唯一需要打包进产物 jar 的依赖 —— 因为 Burp 只加载单个 jar 文件，不会替你解析传递依赖。

从 Maven Central 获取：
```
https://repo1.maven.org/maven2/com/google/code/gson/gson/2.11.0/
```

---

## ⚠️ 打包铁律

```
产物 jar 里必须只有：
  ✅ com/packetsentry/**      ← 插件自己的类
  ✅ com/google/gson/**       ← Gson
  ✅ META-INF/MANIFEST.MF

绝对不能有：
  ❌ burp/**                  ← PortSwigger 的 API
```

**打包进 Burp API 会导致类加载冲突** —— Burp 自己已经提供了这些类。

**发布前必查：**
```bash
jar --list --file dist/PacketSentry-*.jar | grep '^burp/'
# 输出必须为空
```

构建脚本里已经包含这一步校验。
