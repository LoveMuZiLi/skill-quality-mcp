"""skill-quality MCP：Agent Skills 检查 + 依赖分析 + SonarQube Bug 检测 + 代码质量，合成一个 MCP。

作为 Cursor / Codex 插件时由插件根目录的 server.py 启动；pip 安装后也可直接运行 skill-quality-mcp。
默认返回简版（计数完整、问题取前若干条），完整内容写进文件并返回路径；detail=true 时直接返回全部。
"""
import functools
import inspect
import json
import re
import tempfile
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__
from . import deps as sq_deps
from . import local_rules as sq_local
from . import report as sq_report
from . import skills as sq_skills
from . import sonar as sq_sonar

REPORT_DIR = Path(tempfile.gettempdir())/'skill-quality-reports'

mcp = MCPServer(
    name='skill-quality',
    version=__version__,
    instructions=(
        '检查 Agent Skill 或代码目录的质量。要结论用 full_quality_report；只看某一项用 inspect_skill / analyze_dependencies / '
        'code_quality_scan / sonar_*。默认返回简版：计数完整，问题按严重度只列前几条，完整报告写入文件并给出路径，'
        '需要全部明细时再读该文件或传 detail=true。target/path 可传技能名、技能目录或代码路径，优先绝对路径。'),
)


def resolve_target(target):
    """返回 (路径, 技能目录或 None, 提示)；技能名对应多个内容不同的技能时在提示里说明用了哪个。"""
    p = Path(target).expanduser()
    if p.exists():
        p = p.resolve()
        if p.is_file() and p.name == 'SKILL.md': p = p.parent
        skill_dir = p if p.is_dir() and (p/'SKILL.md').is_file() else None
        return p, skill_dir, ''
    matches = sq_skills.skill_matches(target)
    if not matches:
        raise ValueError(f'找不到“{target}”：不是已安装的技能名，也不是存在的路径。可调用 list_skills(query=...) 查找。')
    note = ''
    if len({m['digest'] for m in matches}) > 1:
        others = '；'.join(sq_report.short_path(m['path']) for m in matches[1:])
        note = f"注意：同名技能 {len(matches)} 个且内容不同，本次检查 {sq_report.short_path(matches[0]['path'])}；其他：{others}\n\n"
    skill_dir = Path(matches[0]['path'])
    return skill_dir, skill_dir, note


def dump(obj): return json.dumps(obj, ensure_ascii=False, separators=(',', ':'), default=str)


def save_full(name, text, save_to=''):
    out = Path(save_to).expanduser() if save_to else REPORT_DIR/(re.sub(r'[^\w.-]+', '_', name).strip('_')[:80] + '.md')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding='utf-8')
    return out


def brief_or_full(name, brief, full, detail, save_to=''):
    """detail=True 直接返回完整版；否则返回简版，完整版只在内容确实更多时才落盘。"""
    if detail:
        if save_to: full += f'\n（已保存到 {save_full(name, full, save_to)}）'
        return full
    if full == brief and not save_to: return brief
    return brief + f'\n完整报告：{save_full(name, full, save_to)}\n'


def strip_titles(schema):
    """pydantic 给每个参数生成的 title 只是参数名换个写法，每次会话都要占上下文，去掉。"""
    if isinstance(schema, dict):
        schema.pop('title', None)
        for v in schema.values(): strip_titles(v)
    elif isinstance(schema, list):
        for v in schema: strip_titles(v)


def tool(fn):
    """注册工具；配置缺失、路径不存在这类预期错误转成 ToolError，Agent 能看到原因而不是"工具崩溃"。
    返回值都是文本，关掉 structured_output，省掉多余的 output_schema。"""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try: return fn(*args, **kwargs)
        except (RuntimeError, ValueError, OSError) as e: raise ToolError(str(e)) from None
    mcp.tool(description=inspect.cleandoc(fn.__doc__ or ''), structured_output=False)(wrapper)
    strip_titles(mcp._tool_manager.get_tool(fn.__name__).parameters)
    return wrapper


@tool
def list_skills(query: str = '', extra_dirs: str = '', detail: bool = False) -> str:
    """列出本机 Agent Skills（Cursor、Codex、Claude 用户目录、插件、SKILL_DIRS），区分同名冲突与镜像。
    query：按名称/描述过滤，结果带描述和路径。extra_dirs：额外目录，逗号分隔。detail：全部带描述。"""
    skills = sq_skills.list_skills(extra_dirs)
    mirrors, conflicts = sq_skills.name_conflicts(skills)
    lines = [f'共 {len(skills)} 个技能，{len({s["name"] for s in skills})} 个不同名称。']
    if conflicts:
        lines.append(f'\n**同名冲突 {len(conflicts)} 个**（内容不同，Agent 可能选错；列的是所在目录，完整路径传 query=名称）：')
        lines += [f"- {n}：" + '；'.join(sq_report.compact_dir(str(Path(s['path']).parent)) for s in g) for n, g in sorted(conflicts.items())]
    if mirrors:
        lines.append(f'\n镜像 {len(mirrors)} 个（同名同内容，多处安装，无害）：' + '、'.join(sorted(mirrors)))
    q = query.strip().lower()
    if q or detail:
        hits = [s for s in skills if not q or q in s['name'].lower() or q in s['description'].lower()]
        lines.append(f'\n匹配 {len(hits)} 个：' if q else '\n全部：')
        lines += [f"- {s['name']}：{sq_report.cell(s['description'], 110)}｜{sq_report.short_path(s['path'])}" for s in hits]
    else:
        groups = {}
        for s in skills: groups.setdefault(sq_report.compact_dir(str(Path(s['path']).parent)), []).append(s['name'])
        lines.append('\n按目录（传 query 可看描述和路径）：')
        lines += [f'- {d}（{len(ns)}）：' + ', '.join(sorted(ns)) for d, ns in groups.items()]
    return '\n'.join(lines)


@tool
def inspect_skill(skill: str, detail: bool = False) -> str:
    """检查一个 Agent Skill 的结构：frontmatter、正文长度、失效链接/锚点、文中引用的文件。skill：技能名或路径。"""
    path, skill_dir, note = resolve_target(skill)
    if not skill_dir: raise ValueError(f'“{skill}”不是技能目录（缺 SKILL.md）。')
    result = sq_skills.validate_skill(skill_dir)
    brief, full = sq_report.skill_section(result), sq_report.skill_section(result, None)
    if detail: full += '\n文件：\n' + '\n'.join(f'- {f}' for f in result['files'])
    return note + brief_or_full(f"skill-{result.get('name') or path.name}", brief, full, detail)


@tool
def analyze_dependencies(path: str, check_vulnerabilities: bool = False, detail: bool = False) -> str:
    """依赖分析：第三方包是否安装/声明、未用的声明、循环依赖、外部命令是否在 PATH、package.json。
    check_vulnerabilities：联网查 OSV 漏洞。detail：列出每个包的使用文件和全部漏洞编号。"""
    target, _, note = resolve_target(path)
    d = sq_deps.analyze(target, check_vulnerabilities)
    return note + brief_or_full(f'deps-{target.name}', sq_report.deps_section(d), sq_report.deps_section(d, None), detail)


@tool
def code_quality_scan(path: str, use_ruff: bool = True, max_issues: int = 30, detail: bool = False) -> str:
    """本地 Bug 与代码质量扫描（无需 SonarQube）：Bug、漏洞、安全热点、异味、复杂度、重复、技术债，A–E 评级。
    max_issues：简版列出的重要问题条数。detail：列出全部问题。"""
    target, _, note = resolve_target(path)
    q = sq_local.scan(target, use_ruff)
    brief = sq_report.local_section(q, max(1, max_issues))
    return note + brief_or_full(f'quality-{target.name}', brief, sq_report.local_section(q, None), detail)


@tool
def sonar_check_connection() -> str:
    """检查 SonarQube/SonarCloud 配置、连通性、令牌和 sonar-scanner 是否可用。"""
    return dump(sq_sonar.check_connection())


@tool
def sonar_issues(project_key: str = '', types: str = 'BUG,VULNERABILITY', severities: str = '', limit: int = 50, detail: bool = False) -> str:
    """拉取 SonarQube 未解决问题。types：BUG,VULNERABILITY,CODE_SMELL；severities：BLOCKER..INFO，空为全部；
    project_key 空则用 SONAR_PROJECT_KEY。"""
    data = sq_sonar.issues(project_key, types, severities, limit)
    issues = sq_report.by_type_then_severity(data['issues'])
    head = (f"项目 {data['project']} 未解决问题共 {data['total']} 条" + (f"（已拉取 {len(issues)} 条）" if len(issues) < data['total'] else '')
            + f"：{sq_report.severity_counts(issues)}\n\n")
    return brief_or_full(f"sonar-{data['project']}", head + sq_report.issues_block(issues), head + sq_report.issues_block(issues, None), detail)


@tool
def sonar_project_metrics(project_key: str = '') -> str:
    """SonarQube 项目指标：质量门禁、三项评级、Bug/漏洞/异味数、覆盖率、重复率。"""
    return dump(sq_sonar.metrics(project_key))


@tool
def sonar_run_scan(path: str, project_key: str = '', use_npx: bool = False) -> str:
    """用 sonar-scanner 扫描并上传到 SonarQube，等待分析完成。没装扫描器可 use_npx=true（首次会下载）。"""
    target, _, _ = resolve_target(path)
    return dump(sq_sonar.run_scan(target if target.is_dir() else target.parent, project_key, True, use_npx))


@tool
def full_quality_report(target: str, sonar: str = 'auto', check_vulnerabilities: bool = False, detail: bool = False, save_to: str = '') -> str:
    """一站式报告：Skill 结构（目标是技能时）+ 依赖 + 本地扫描 + SonarQube，给出 通过/有警告/未通过。
    sonar：auto=已配置就拉结果，scan=先扫描再拉，off=不用。check_vulnerabilities：联网查 OSV。
    detail：返回完整报告。save_to：完整报告另存路径（.md）。"""
    path, skill_dir, note = resolve_target(target)
    skill = sq_skills.validate_skill(skill_dir) if skill_dir else None
    deps = sq_deps.analyze(path, check_vulnerabilities)
    local = sq_local.scan(path)
    if sonar == 'off': sonar_part = {'skipped': '按参数关闭'}
    elif not sq_sonar.configured(): sonar_part = {'skipped': '未配置 SONAR_HOST_URL / SONAR_TOKEN，只用本地规则'}
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
    name = skill['name'] if skill and skill.get('name') else path.name
    title = name if skill else sq_report.short_path(str(path))
    brief = sq_report.render(title, skill, deps, local, sonar_part)
    full = sq_report.render(title, skill, deps, local, sonar_part, None)
    return note + brief_or_full(f'report-{name}', brief, full, detail, save_to)


@mcp.prompt()
def review_skill(skill: str) -> str:
    """让 Agent 生成质量报告并按严重度修复问题。"""
    return (f'调用 full_quality_report，target="{skill}"，check_vulnerabilities=true。'
            '先给结论和原因，再按 BLOCKER → CRITICAL → MAJOR 给修复方案，每处引用文件和行号；简版没列全时读返回的完整报告文件。'
            '改完再跑一次对比。安全热点只提示人工确认，不擅自改业务逻辑。')


def main():
    mcp.run('stdio')


if __name__ == '__main__':
    main()
