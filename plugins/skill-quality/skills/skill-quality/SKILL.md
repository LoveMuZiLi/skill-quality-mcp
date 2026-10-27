---
name: skill-quality
description: >-
  Use when the user asks to check, review, audit or score an Agent Skill (SKILL.md) or a code directory:
  skill structure and broken links, dependency problems (missing, undeclared, vulnerable packages), bug detection,
  code quality ratings, or SonarQube / SonarCloud issues and quality gates. 触发词：检查 skill、技能质量、代码质量、
  找 bug、依赖分析、漏洞、SonarQube、质量门禁。
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

- 本地规则带 `python:Sxxxx` 的是"近似对应 SonarQube 同名规则"，不是 SonarQube 官方结果；用户配置了 SonarQube 时以 SonarQube 为准。
- 评级口径同 SonarQube：可靠性、安全性看最严重的 Bug、漏洞；可维护性看技术债比例（A ≤5%、B ≤10%、C ≤20%、D ≤50%）。
- 依赖表里“是（代码自加路径）”表示包装在代码自己往 `sys.path` 加的目录里，换机器会失效。
- 本地扫描只覆盖 Python；其他语言需要 SonarQube。

## SonarQube 配置

在系统环境变量里设置后重启 Cursor / Codex：

- `SONAR_HOST_URL`：如 `http://localhost:9000`；SonarCloud 用 `https://sonarcloud.io`
- `SONAR_TOKEN`：SonarQube → My Account → Security 生成的令牌
- `SONAR_PROJECT_KEY`：默认项目 key（工具参数可覆盖）
- `SONAR_ORGANIZATION`：只有 SonarCloud 需要

没配置时报告自动只用本地规则，不算错误。
