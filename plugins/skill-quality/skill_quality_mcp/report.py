"""把技能校验、依赖分析、本地扫描、SonarQube 结果合成 Markdown 报告。

返回给 Agent 的简版：计数永远完整，问题按严重度取前 N 条、按文件分组，其余按规则汇总；
完整版（limit=None）列出全部问题，保存成文件供需要时再读。
"""
import os
import re
from collections import Counter
from pathlib import Path

TYPE_CN = {'BUG': 'Bug', 'VULNERABILITY': '漏洞', 'SECURITY_HOTSPOT': '热点', 'CODE_SMELL': '异味'}
SEVERITIES = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO']
BRIEF_LIMIT = 15


def cell(text, width=90):
    text = str(text if text is not None else '').replace('|', '\\|').replace('\n', ' ')
    return text if len(text) <= width else text[:width - 1] + '…'


def short_path(p):
    home = str(Path.home())
    return '~' + p[len(home):] if p.lower().startswith(home.lower()) else p


def compact_dir(p):
    """展示用：家目录换成 ~，插件缓存里 40 位提交哈希只留前 7 位。不能当真实路径用。"""
    return re.sub(r'([\\/])([0-9a-f]{7})[0-9a-f]{25,}(?=[\\/]|$)', r'\1\2…', short_path(p))


def short_rule(rule): return (rule or '').removeprefix('python:')


# 安全热点用 HIGH / MEDIUM / LOW 表示风险，排序时并入同一刻度
RANK = {'BLOCKER': 0, 'CRITICAL': 1, 'HIGH': 1, 'MAJOR': 2, 'MEDIUM': 2, 'MINOR': 3, 'LOW': 3, 'INFO': 4}


TYPE_RANK = {'VULNERABILITY': 0, 'BUG': 1, 'SECURITY_HOTSPOT': 2, 'CODE_SMELL': 3}


def by_severity(issues):
    return sorted(issues, key=lambda i: RANK.get(i.get('severity'), 5))


def by_type_then_severity(issues):
    """简版只列前几条时，漏洞、Bug、安全热点必须排在代码异味前面，不能被一堆高复杂度函数挤掉。"""
    return sorted(issues, key=lambda i: (TYPE_RANK.get(i.get('type'), 4), RANK.get(i.get('severity'), 5)))


def severity_counts(issues):
    c = Counter(i.get('severity') or '?' for i in issues)
    return '、'.join(f'{s} {n}' for s, n in sorted(c.items(), key=lambda x: RANK.get(x[0], 5))) or '0'


def issues_block(issues, limit=BRIEF_LIMIT, with_type=True):
    """issues 已按严重度排好序。取前 limit 条按文件分组列出；其余按规则汇总，条数不丢。"""
    if not issues: return '无\n'
    shown = issues if limit is None else issues[:limit]
    groups = {}
    for i in shown: groups.setdefault(i.get('file') or '（项目级）', []).append(i)
    lines = []
    for file, items in groups.items():
        lines.append(f'- `{file}`')
        for i in items:
            kind = f"{TYPE_CN.get(i.get('type'), i.get('type') or '')} " if with_type else ''
            lines.append(f"  - L{i.get('line') or '-'} {i.get('severity')} {kind}{short_rule(i.get('rule'))}：{cell(i.get('message'), 140)}")
    rest = issues[len(shown):]
    if rest:
        by_rule = Counter(short_rule(i.get('rule')) for i in rest)
        lines.append(f'- 其余 {len(rest)} 条（{severity_counts(rest)}），按规则：' + '、'.join(f'{k}×{v}' for k, v in by_rule.most_common()))
    return '\n'.join(lines) + '\n'


def skill_section(s, limit=BRIEF_LIMIT):
    files = s.get('files', [])
    dirs = Counter(Path(f).parts[0] if len(Path(f).parts) > 1 else '根目录' for f in files)
    layout = '、'.join(f'{d} {n}' for d, n in dirs.most_common())
    issues = by_severity(s['issues'])
    head = (f"## Skill 结构\n\n`{s.get('name') or '?'}`（{short_path(s['skill'])}）：SKILL.md 正文 {s.get('body_lines', '?')} 行，"
            f"{len(files)} 个文件（{layout}）；问题 {len(issues)} 个" + (f'（{severity_counts(issues)}）' if issues else '') + '\n')
    return head + ('\n' + issues_block(issues, limit, with_type=False) if issues else '')


def _package_line(e, has_manifest, full):
    state = ['代码自加路径' if e.get('location') else ('已装' if e['installed'] else '**未装**')]
    if has_manifest: state.append('已声明' if e['declared'] else '**未声明**')
    if e['optional']: state.append('可选导入')
    line = f"{e['distribution'] or e['import']} {e['version'] or '?'}（{'，'.join(state)}）"
    if e['distribution'] and norm_name(e['distribution']) != norm_name(e['import']): line = f"{e['import']}→" + line
    return line + (f"：{', '.join(e['files'][:8])}" if full else '')


def norm_name(n): return n.lower().replace('_', '-')


def deps_section(d, limit=BRIEF_LIMIT):
    full = limit is None
    out = ['## 依赖']
    scope = f"{d['python_files']} 个 .py" + ('（**达到文件上限，后面的未扫描**）' if d.get('truncated') else '')
    out.append(f"{scope}；依赖清单：{'、'.join(d['manifests']) or '**无**（建议加 requirements.txt）'}")
    has_manifest = bool(d['manifests'])
    if d['third_party']:
        out.append(f"第三方包 {len(d['third_party'])} 个：" + '；'.join(_package_line(e, has_manifest, full) for e in d['third_party']))
    else:
        out.append('第三方包：无')
    if d.get('extra_sys_paths'):
        out.append('代码往 sys.path 加了：' + '；'.join(f'`{p}`' + ('' if os.path.isdir(p) else '（**目录不存在**）') for p in d['extra_sys_paths'])
                   + '，写死的路径换机器失效')
    if d['missing']: out.append('**缺失（运行会 ImportError）**：' + '、'.join(e['import'] for e in d['missing']))
    if d['undeclared']: out.append('**用了没声明**：' + '、'.join(e['distribution'] or e['import'] for e in d['undeclared']))
    if d['unused_declared']: out.append('**声明了没用到**：' + '、'.join(d['unused_declared']))
    if d['cycles']: out.append('**循环依赖**：' + '；'.join(' → '.join(c) for c in d['cycles']))
    if d.get('syntax_errors'): out.append(f"**{len(d['syntax_errors'])} 个文件有语法错误，未分析导入**")
    if d['external_tools']:
        ok = [t['command'] for t in d['external_tools'] if t['found_on_path']]
        bad = [t['command'] for t in d['external_tools'] if not t['found_on_path']]
        out.append('外部命令：' + '；'.join(([f"{'、'.join(ok)} 在 PATH"] if ok else []) + ([f"**{'、'.join(bad)} 不在 PATH**"] if bad else [])))
    if d['node']:
        n = d['node']
        out.append(f"Node 依赖 {len(n['declared'])} 个，node_modules {'存在' if n['node_modules_present'] else '**不存在**'}"
                   + (f"，缺失：{'、'.join(n['missing'])}" if n['missing'] else ''))
    out.append(_vuln_lines(d, full))
    return '\n\n'.join(out) + '\n'


def _vuln_lines(d, full):
    check, vulns = d['vulnerability_check'], d['vulnerabilities']
    if check != '已查询 OSV': return f'已知漏洞（OSV）：{check}'
    if not vulns: return '已知漏洞（OSV）：未发现'
    from .deps import _version_key
    groups = {}
    for v in vulns: groups.setdefault((v['package'], v['version']), []).append(v)
    lines = [f'**已知漏洞（OSV）{len(vulns)} 个**：']
    for (pkg, ver), vs in groups.items():
        fixes = [v['fixed'] for v in vs if v.get('fixed')]
        target = f'≥ {max(fixes, key=_version_key)}' if fixes else '最新版'
        ids = [v['id'] for v in vs]
        shown = ids if full else ids[:3]
        lines.append(f"- {pkg} {ver}：{len(vs)} 个，升级到 {target}（{', '.join(shown)}{' 等' if len(shown) < len(ids) else ''}）")
    return '\n'.join(lines)


def local_section(q, limit=BRIEF_LIMIT):
    c, r = q['counts'], q['ratings']
    scope = f"{q['files']} 个文件" + ('（**达到文件上限，后面的未扫描**）' if q.get('truncated') else '')
    out = ['## 代码质量（本地规则）\n',
           f"评级：可靠性 {r['reliability']}｜安全性 {r['security']}｜可维护性 {r['maintainability']}；"
           f"Bug {c['BUG']}、漏洞 {c['VULNERABILITY']}、热点 {c['SECURITY_HOTSPOT']}、异味 {c['CODE_SMELL']}",
           f"{scope}、{q['ncloc']} 行、{q['functions']} 个函数；重复 {q['duplicated_lines_density']}%；"
           f"技术债 {q['technical_debt_minutes']} 分钟（{q['debt_ratio_percent']}%）；{q['ruff']}\n"]
    blocks = q['duplicated_blocks']
    if blocks:
        shown = blocks if limit is None else blocks[:3]
        out.append(f'重复代码块 {len(blocks)} 处：' + '；'.join(' ↔ '.join(b[:3]) + (f' 等 {len(b)} 处' if len(b) > 3 else '') for b in shown)
                   + ('；…' if len(shown) < len(blocks) else '') + '\n')
    if limit is None: return '\n'.join(out) + '\n' + issues_block(by_type_then_severity(q['issues']), None)
    important = by_type_then_severity([i for i in q['issues'] if i['type'] != 'CODE_SMELL' or i['severity'] in ('BLOCKER', 'CRITICAL', 'MAJOR')])
    minor = [i for i in q['issues'] if i['type'] == 'CODE_SMELL' and i['severity'] not in ('BLOCKER', 'CRITICAL', 'MAJOR')]
    out.append(issues_block(important, limit) if important else '重要问题：无\n')
    if minor:
        by_rule = Counter(short_rule(i['rule']) for i in minor)
        out.append(f'次要异味 {len(minor)} 条，按规则：' + '、'.join(f'{k}×{v}' for k, v in by_rule.most_common()) + '\n')
    return '\n'.join(out)


def sonar_section(s, limit=BRIEF_LIMIT):
    if s.get('skipped'): return f"## SonarQube\n\n{s['skipped']}\n"
    if s.get('error'): return f"## SonarQube\n\n调用失败：{s['error']}\n"
    m = s['metrics']['metrics']
    gate = f"质量门禁 **{m.get('quality_gate') or '?'}**" + (f"（未通过：{'；'.join(m['failed_conditions'])}）" if m.get('failed_conditions') else '')
    out = [f"## SonarQube（`{s['metrics']['project']}`）\n", gate,
           f"评级：可靠性 {m.get('reliability_rating', '?')}｜安全性 {m.get('security_rating', '?')}｜可维护性 {m.get('sqale_rating', '?')}；"
           f"Bug {m.get('bugs', '?')}、漏洞 {m.get('vulnerabilities', '?')}、热点 {m.get('security_hotspots', '?')}、异味 {m.get('code_smells', '?')}；"
           f"覆盖率 {m.get('coverage', '—')}%、重复 {m.get('duplicated_lines_density', '?')}%、{m.get('ncloc', '?')} 行\n"]
    if s.get('scan'): out.append(f"本次扫描：{s['scan'].get('analysis', '已提交')}\n")
    issues = s['issues']
    fetched = len(issues['issues'])
    out.append(f"未解决的 Bug/漏洞共 {issues['total']} 条" + (f'（已拉取 {fetched} 条）' if fetched < issues['total'] else '') + '：\n')
    out.append(issues_block(by_type_then_severity(issues['issues']), limit))
    hs = s.get('hotspots')
    if hs and hs['hotspots']:
        fetched = len(hs['hotspots'])
        out.append(f"待审查安全热点共 {hs['total']} 个" + (f'（已拉取 {fetched} 个）' if fetched < hs['total'] else '') + '：\n\n'
                   + issues_block(by_severity(hs['hotspots']), limit))
    return '\n'.join(out)


def verdict(skill, deps, local, sonar):
    blockers, warnings = [], []
    if skill:
        bad = [i for i in skill['issues'] if i['severity'] in ('BLOCKER', 'CRITICAL')]
        if bad: blockers.append(f'Skill 结构有 {len(bad)} 个严重问题')
        if any(i['severity'] == 'MAJOR' for i in skill['issues']): warnings.append('Skill 有失效链接或超长等问题')
    if deps['missing']: blockers.append(f"缺失依赖 {len(deps['missing'])} 个")
    if deps['vulnerabilities']: blockers.append(f"依赖有 {len(deps['vulnerabilities'])} 个已知漏洞")
    if deps['undeclared'] or not deps['manifests'] and deps['third_party']: warnings.append('依赖未完整声明')
    if deps['cycles']: warnings.append('存在模块循环依赖')
    serious = [i for i in local['issues'] if i['type'] in ('BUG', 'VULNERABILITY') and i['severity'] in ('BLOCKER', 'CRITICAL', 'MAJOR')]
    if serious: blockers.append(f'本地扫描发现 {len(serious)} 个严重 Bug/漏洞')
    if local['ratings']['maintainability'] in ('C', 'D', 'E'): warnings.append(f"可维护性评级 {local['ratings']['maintainability']}")
    if local['counts']['SECURITY_HOTSPOT']: warnings.append(f"{local['counts']['SECURITY_HOTSPOT']} 个安全热点待人工确认")
    if local.get('truncated') or deps.get('truncated'): warnings.append('文件数超过上限，只扫描了一部分')
    if sonar and sonar.get('metrics') and sonar['metrics']['metrics'].get('quality_gate') == 'ERROR': blockers.append('SonarQube 质量门禁未通过')
    status = '未通过' if blockers else ('有警告' if warnings else '通过')
    return status, blockers, warnings


def render(target, skill, deps, local, sonar, limit=BRIEF_LIMIT):
    status, blockers, warnings = verdict(skill, deps, local, sonar)
    reasons = '；'.join(blockers + warnings)
    lines = [f'# 质量报告：{target}\n', f'**结论：{status}**' + (f'。{reasons}' if reasons else '') + '\n']
    if skill: lines.append(skill_section(skill, limit))
    lines += [deps_section(deps, limit), local_section(local, limit), sonar_section(sonar or {'skipped': '未启用'}, limit)]
    return '\n'.join(lines)
