"""skill-quality MCP：Agent Skills 检查 + 依赖分析 + SonarQube Bug 检测 + 代码质量，合成一个 MCP。

作为 Cursor / Codex 插件时由插件根目录的 server.py 启动；pip 安装后也可直接运行 skill-quality-mcp。
"""
import functools
import json
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__
from . import deps as sq_deps
from . import local_rules as sq_local
from . import report as sq_report
from . import skills as sq_skills
from . import sonar as sq_sonar

mcp = MCPServer(
    name='skill-quality',
    version=__version__,
    instructions=(
        '检查 Cursor/Codex Agent Skills 和任意代码目录的质量。想要一站式结论时调用 full_quality_report；'
        '只看技能结构用 inspect_skill，只看依赖用 analyze_dependencies，只看 Bug/代码异味用 code_quality_scan；'
        'SonarQube 相关工具需要环境变量 SONAR_HOST_URL、SONAR_TOKEN（SonarCloud 另需 SONAR_ORGANIZATION）。'
        '目标参数可以是技能名（list_skills 里的名称）、技能目录或任意代码目录/文件；相对路径按 MCP 进程的工作目录解析，优先传绝对路径。'),
)


def resolve_target(target):
    skill_dir = sq_skills.resolve_skill(target)
    if skill_dir: return skill_dir, skill_dir
    path = Path(target).expanduser()
    if not path.exists(): raise ValueError(f'找不到“{target}”：既不是已安装的技能名，也不是存在的路径。可先调用 list_skills 查看技能名。')
    return path.resolve(), None


def dump(obj): return json.dumps(obj, ensure_ascii=False, indent=2, default=str)


def tool(fn):
    """注册工具；配置缺失、路径不存在这类预期错误转成 ToolError，Agent 能看到原因而不是"工具崩溃"。"""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try: return fn(*args, **kwargs)
        except (RuntimeError, ValueError, OSError) as e: raise ToolError(str(e)) from None
    return mcp.tool()(wrapper)


@tool
def list_skills(extra_dirs: str = '') -> str:
    """列出本机所有 Agent Skills（~/.cursor/skills-cursor、~/.agents/skills、~/.codex/skills、插件缓存、SKILL_DIRS）。
    extra_dirs：额外要搜索的目录，逗号分隔。"""
    skills = sq_skills.list_skills(extra_dirs)
    names = [s['name'] for s in skills]
    rows = [f"| {s['name']} | {sq_report.cell(s['description'], 70)} | {s['path']} |" for s in skills]
    dup = sorted({n for n in names if names.count(n) > 1})
    return (f'共 {len(skills)} 个技能' + (f'；重名：{"、".join(dup)}（Agent 可能选错）' if dup else '') +
            '\n\n| 名称 | 描述 | 路径 |\n|---|---|---|\n' + '\n'.join(rows))


@tool
def inspect_skill(skill: str) -> str:
    """检查单个 Agent Skill 的结构：frontmatter（name/description）、正文长度、Markdown 链接和锚点、文中引用的文件是否存在。
    skill：技能名、技能目录或 SKILL.md 路径。"""
    skill_dir = sq_skills.resolve_skill(skill)
    if not skill_dir: return f'找不到技能“{skill}”，先调用 list_skills 看看名字。'
    result = sq_skills.validate_skill(skill_dir)
    return sq_report.skill_section(result) + '\n文件：\n' + '\n'.join(f'- {f}' for f in result['files'][:80])


@tool
def analyze_dependencies(path: str, check_vulnerabilities: bool = False) -> str:
    """分析代码依赖：第三方 Python 包是否安装/声明、未使用的声明、模块循环依赖、调用的外部命令（ffmpeg、git 等）是否在 PATH、
    package.json。check_vulnerabilities=true 时联网查询 OSV 漏洞库。path：技能名、目录或 .py 文件。"""
    target, _ = resolve_target(path)
    return sq_report.deps_section(sq_deps.analyze(target, check_vulnerabilities))


@tool
def code_quality_scan(path: str, use_ruff: bool = True, max_issues: int = 100) -> str:
    """本地 Bug 检测和代码质量扫描（不需要 SonarQube 服务）：Bug、漏洞、安全热点、代码异味，
    认知复杂度、重复代码、技术债，并按 SonarQube 口径给出 A–E 评级。装了 ruff 会合并 ruff 结果。"""
    target, _ = resolve_target(path)
    return sq_report.local_section(sq_local.scan(target, use_ruff), max_issues)


@tool
def sonar_check_connection() -> str:
    """检查 SonarQube/SonarCloud 配置和连通性（服务状态、令牌是否有效、sonar-scanner 是否可用）。"""
    return dump(sq_sonar.check_connection())


@tool
def sonar_issues(project_key: str = '', types: str = 'BUG,VULNERABILITY', severities: str = '', limit: int = 50) -> str:
    """从 SonarQube 拉取项目未解决的问题。types：BUG,VULNERABILITY,CODE_SMELL 任选；
    severities：BLOCKER,CRITICAL,MAJOR,MINOR,INFO，留空为全部。project_key 留空用 SONAR_PROJECT_KEY。"""
    data = sq_sonar.issues(project_key, types, severities, limit)
    return f"项目 {data['project']} 共 {data['total']} 条未解决问题：\n\n" + sq_report.issues_table(data['issues'], limit)


@tool
def sonar_project_metrics(project_key: str = '') -> str:
    """查询 SonarQube 项目指标：质量门禁、可靠性/安全性/可维护性评级、Bug、漏洞、代码异味、覆盖率、重复率。"""
    return dump(sq_sonar.metrics(project_key))


@tool
def sonar_run_scan(path: str, project_key: str = '', use_npx: bool = False) -> str:
    """用 sonar-scanner 扫描目录并上传到 SonarQube，等待服务端分析完成。没装 sonar-scanner 时可传 use_npx=true
    改用 npx @sonar/scan（首次会下载扫描器）。path：技能名或目录。"""
    target, _ = resolve_target(path)
    return dump(sq_sonar.run_scan(target if target.is_dir() else target.parent, project_key, True, use_npx))


@tool
def full_quality_report(target: str, sonar: str = 'auto', check_vulnerabilities: bool = False, save_to: str = '') -> str:
    """一站式质量报告：Agent Skill 结构检查（目标是技能时）+ 依赖分析 + 本地 Bug/代码质量扫描 + SonarQube 结果，给出通过/警告/未通过结论。
    target：技能名、技能目录或代码目录。
    sonar：auto=配置了就拉取已有分析结果；scan=先扫描上传再拉结果；off=不用 SonarQube。
    check_vulnerabilities：联网查 OSV 依赖漏洞。save_to：报告保存路径（.md），留空只返回不保存。"""
    path, skill_dir = resolve_target(target)
    skill = sq_skills.validate_skill(skill_dir) if skill_dir else None
    deps = sq_deps.analyze(path, check_vulnerabilities)
    local = sq_local.scan(path)
    sonar_part = None
    if sonar == 'off': sonar_part = {'skipped': '按参数关闭'}
    elif not sq_sonar.configured(): sonar_part = {'skipped': '未配置 SONAR_HOST_URL / SONAR_TOKEN，只用本地规则。配置方法见 sonar_check_connection。'}
    elif not sq_sonar.config()['project']: sonar_part = {'skipped': '未配置 SONAR_PROJECT_KEY，无法定位 SonarQube 项目'}
    else:
        try:
            sonar_part = {}
            if sonar == 'scan': sonar_part['scan'] = sq_sonar.run_scan(path if path.is_dir() else path.parent)
            sonar_part['metrics'] = sq_sonar.metrics()
            sonar_part['issues'] = sq_sonar.issues()
            sonar_part['hotspots'] = sq_sonar.hotspots()
        except RuntimeError as e:
            sonar_part = {'error': str(e)}
    report = sq_report.render(skill['name'] if skill and skill.get('name') else str(path), skill, deps, local, sonar_part)
    if save_to:
        out = Path(save_to).expanduser(); out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding='utf-8'); report += f'\n\n（报告已保存到 {out}）'
    return report


@mcp.prompt()
def review_skill(skill: str) -> str:
    """让 Agent 生成质量报告并按严重度修复问题。"""
    return (f'调用 full_quality_report，target="{skill}"，check_vulnerabilities=true。'
            '先列出结论和未通过原因，再按 BLOCKER → CRITICAL → MAJOR 的顺序给出修复方案；'
            '每处修复引用文件和行号，改完再跑一次 full_quality_report 对比。安全热点只提示人工确认，不擅自改业务逻辑。')


def main():
    mcp.run('stdio')


if __name__ == '__main__':
    main()
