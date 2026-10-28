---
name: skill-quality
description: >-
  Use when the user asks to check, review, audit or score an Agent Skill (SKILL.md) or a code directory:
  skill structure and broken links, dependency problems (missing, undeclared, vulnerable packages), bug detection,
  code quality ratings, or SonarQube / SonarCloud issues and quality gates. Works for Python, JavaScript, TypeScript,
  React, Vue, Java / Spring, Kotlin, Go, C# and PHP projects. 触发词：检查 skill、技能质量、代码质量、找 bug、
  依赖分析、漏洞、SonarQube、质量门禁、代码审查。
---

# Skill Quality

本插件自带 `skill-quality` MCP 服务。检查技能或代码质量时调用它的工具，不要自己手写一遍检查逻辑。

## 选哪个工具

| 用户想要 | 调用 |
| --- | --- |
| 一句话结论、完整报告 | `full_quality_report`（target 传技能名、技能目录或代码目录） |
| 本机有哪些技能、有没有重名 | `list_skills` |
| 只看某个技能的结构（frontmatter、失效链接、锚点、引用文件） | `inspect_skill` |
| 依赖装没装、声明没声明、有没有已知漏洞 | `analyze_dependencies`（要查漏洞传 `check_vulnerabilities=true`，会联网查 OSV） |
| Bug、安全问题、代码异味、复杂度、重复代码 | `code_quality_scan` |
| SonarQube 能不能连上 | `sonar_check_connection` |
| SonarQube 里的问题、指标、质量门禁 | `sonar_issues`、`sonar_project_metrics` |
| 扫描并上传到 SonarQube | `sonar_run_scan`（会在用户机器上跑扫描器，先征得同意） |

## 流程

1. 先调用 `full_quality_report`。目标是技能时传技能名或技能目录的绝对路径；不确定名字先 `list_skills`。
2. 先向用户报结论（通过 / 有警告 / 未通过）和原因，再按 BLOCKER → CRITICAL → MAJOR 列要修的问题，每条带文件和行号。
3. 用户同意后再改代码；改完重跑同一个工具对比。
4. 安全热点（SECURITY_HOTSPOT）只提示人工确认，不擅自改业务逻辑。
5. 升级依赖、重写复杂函数这类有副作用的改动，先问用户。

## 读结果时注意

- 默认返回简版：各类计数完整；问题只逐条列前 15 条（漏洞 → Bug → 安全热点 → 代码异味），其余按规则给出条数；末尾的“完整报告”是全部明细的文件路径。
- 要逐条修复时，用读文件工具按需读那个完整报告（可只读相关段落），不要反复传 `detail=true` 把全文拉进对话。
- `list_skills` 默认只列名称；找某个技能传 `query`，同名冲突（内容不同）才需要关注，镜像（同名同内容）无害。
- 报告里写“达到文件上限，后面的未扫描”时，结论只覆盖已扫描部分，要告诉用户。
- 本地扫描覆盖 Python、JavaScript / TypeScript（含 JSX / TSX、React）、Vue / Svelte 单文件组件、Java、Kotlin、Go、C#、PHP，以及 Spring `application.yml` / `.properties`、`appsettings.json`、MyBatis Mapper XML。
- 规则 ID 形如 `java:S2629`、`typescript:S6479`：前缀是语言，Sxxxx 近似对应 SonarQube 同名规则；`local:xxx` 是 SonarQube 没有或做法不同的补充规则（如 `local:mybatis-dollar`、`local:vue-v-html`）。这些都不是 SonarQube 官方结果，用户配置了 SonarQube 时以 SonarQube 为准。
- 项目里装了 ESLint（且有配置）、ruff、go 时会自动合并 ESLint / ruff / go vet 的结果，报告“外部检查器”一行写明用了哪些。
- 测试文件（`__tests__/`、`*.test.ts`、`*_test.go`、`src/test/`…）不报安全类问题、重复字符串和超长函数，也不计入重复率；带 sourcemap 的编译产物直接跳过。
- 评级口径同 SonarQube：可靠性、安全性看最严重的 Bug、漏洞；可维护性看技术债比例（A ≤5%、B ≤10%、C ≤20%、D ≤50%）。
- 依赖分析覆盖 Python、npm（含 monorepo / 路径别名）、Maven、Gradle、Go modules、Composer、NuGet；有锁文件或已安装时才能查 OSV 漏洞。
- 依赖表里“是（代码自加路径）”表示包装在代码自己往 `sys.path` 加的目录里，换机器会失效。

## SonarQube 配置

在系统环境变量里设置后重启 Cursor / Codex：

- `SONAR_HOST_URL`：如 `http://localhost:9000`；SonarCloud 用 `https://sonarcloud.io`
- `SONAR_TOKEN`：SonarQube → My Account → Security 生成的令牌
- `SONAR_PROJECT_KEY`：默认项目 key（工具参数可覆盖）
- `SONAR_ORGANIZATION`：只有 SonarCloud 需要

没配置时报告自动只用本地规则，不算错误。
