# Skill Quality MCP

一个 MCP 服务 + 一个 Agent Skill，打包成 **Cursor 插件** 和 **Codex 插件**：

- **Agent Skills 检查**：SKILL.md 的 frontmatter（name / description）、正文长度、失效链接和锚点、文中引用的文件是否存在、技能重名
- **依赖分析**：第三方包是否安装、是否写进依赖清单、未使用的声明、模块循环依赖、外部命令（ffmpeg、git…）是否在 PATH、OSV 已知漏洞及建议升级版本
- **Bug 检测与代码质量**：本地规则覆盖 Bug、漏洞、安全热点、代码异味、认知复杂度、重复代码、技术债，按 SonarQube 口径给 A–E 评级；装了 ruff 会自动合并
- **SonarQube / SonarCloud**：拉取未解决问题、指标、质量门禁，或用 sonar-scanner 扫描上传

不需要 SonarQube 也能用；配置后报告会合并 SonarQube 的结果。

## 安装

前提：Python 3.10+ 在 PATH 上（Windows 安装时勾选 “Add to PATH”）。`mcp` 依赖会自动安装。

### 一行命令装进 Cursor 和 Codex

Windows（PowerShell）：

```powershell
irm https://raw.githubusercontent.com/LoveMuZiLi/skill-quality-mcp/main/install.ps1 | iex
```

macOS / Linux：

```bash
curl -fsSL https://raw.githubusercontent.com/LoveMuZiLi/skill-quality-mcp/main/install.sh | bash
```

直连不了 github.com 时：Windows 脚本会自动沿用系统代理；macOS / Linux 先 `export HTTPS_PROXY=http://127.0.0.1:7890`（换成你的代理端口）。

装完：Cursor 里运行 **Developer: Reload Window**；Codex 新开一个对话。只装一边时，PowerShell 加 `-CursorOnly` / `-CodexOnly`，bash 加 `--cursor-only` / `--codex-only`（远程运行时先下载脚本再带参数执行）。

### Codex（手动）

```bash
codex plugin marketplace add LoveMuZiLi/skill-quality-mcp
codex plugin add skill-quality@skill-quality-mcp
```

### Cursor（手动）

把仓库里的 `plugins/skill-quality` 整个复制到 `~/.cursor/plugins/local/skill-quality`（Windows：`%USERPROFILE%\.cursor\plugins\local\skill-quality`），然后 Reload Window。必须是真实复制，指向别处的符号链接会被 Cursor 忽略。

只要 MCP、不要插件里的 Skill，也可以用一键链接（需要先装 [uv](https://docs.astral.sh/uv/)）：

[在 Cursor 中安装 MCP](https://cursor.com/en/install-mcp?name=skill-quality&config=eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyItLWZyb20iLCJnaXQraHR0cHM6Ly9naXRodWIuY29tL0xvdmVNdVppTGkvc2tpbGwtcXVhbGl0eS1tY3AiLCJza2lsbC1xdWFsaXR5LW1jcCJdfQ%3D%3D)

### 其他 MCP 客户端（Claude Desktop、Windsurf、VS Code…）

```bash
pip install git+https://github.com/LoveMuZiLi/skill-quality-mcp
```

```json
{
  "mcpServers": {
    "skill-quality": { "command": "skill-quality-mcp" }
  }
}
```

或者不安装、用 uv 直接运行：`"command": "uvx", "args": ["--from", "git+https://github.com/LoveMuZiLi/skill-quality-mcp", "skill-quality-mcp"]`。

## 工具

| 工具 | 作用 |
| --- | --- |
| `full_quality_report` | 一站式报告：技能结构 + 依赖 + 本地扫描 + SonarQube，给出 通过 / 有警告 / 未通过 |
| `list_skills` | 列出 Cursor、Codex、Claude 用户目录和插件里的所有技能，提示重名 |
| `inspect_skill` | 检查单个技能的结构 |
| `analyze_dependencies` | 依赖分析，`check_vulnerabilities=true` 时联网查 OSV |
| `code_quality_scan` | 本地 Bug 检测和代码质量评级 |
| `sonar_check_connection` | 检查 SonarQube 配置和连通性 |
| `sonar_issues` / `sonar_project_metrics` | 拉取 SonarQube 问题、指标、质量门禁 |
| `sonar_run_scan` | 用 sonar-scanner 扫描并上传（没装时可 `use_npx=true`） |

还附带提示词 `review_skill`：先出报告，再按严重度给修复方案。

用法示例（在 Cursor / Codex 对话里直接说）：“检查一下 drama-commentary 这个 skill 的质量”“扫描 D:\project 的 bug 和依赖漏洞”。

## SonarQube 配置（可选）

设置系统环境变量后重启 Cursor / Codex：

| 变量 | 说明 |
| --- | --- |
| `SONAR_HOST_URL` | 如 `http://localhost:9000`；SonarCloud 用 `https://sonarcloud.io` |
| `SONAR_TOKEN` | SonarQube → My Account → Security 生成 |
| `SONAR_PROJECT_KEY` | 默认项目 key，工具参数可覆盖 |
| `SONAR_ORGANIZATION` | 只有 SonarCloud 需要 |
| `SONAR_SCANNER` | sonar-scanner 不在 PATH 时填完整路径 |
| `SKILL_DIRS` | 额外的技能搜索目录，多个用系统路径分隔符隔开 |

## 说明

- 本地规则只覆盖 Python；规则 ID 带 `python:Sxxxx` 的表示近似对应 SonarQube 同名规则，不等于 SonarQube 官方结果。
- 插件用 `python` 命令启动。macOS / Linux 只有 `python3` 时，安装脚本会自动改写 Cursor 插件里的命令；Codex 插件需要 `python` 可用（如 `ln -s "$(command -v python3)" ~/.local/bin/python`）。

## 仓库结构

```text
.cursor-plugin/marketplace.json     Cursor 插件市场清单
.agents/plugins/marketplace.json    Codex 插件市场清单
plugins/skill-quality/
  .cursor-plugin/plugin.json        Cursor 插件清单
  .codex-plugin/plugin.json         Codex 插件清单
  mcp.json / .mcp.json              Cursor / Codex 的 MCP 启动配置
  server.py                         启动入口（缺 mcp 时自动安装）
  skill_quality_mcp/                MCP 服务源码
  skills/skill-quality/SKILL.md     教 Agent 何时、如何调用这些工具
pyproject.toml                      pip / uvx 安装用
install.ps1 / install.sh            一行命令安装
```

## License

MIT
