"""把技能校验、依赖分析、本地扫描、SonarQube 结果合成一份 Markdown 报告。"""
import datetime
import os

TYPE_CN = {'BUG': 'Bug', 'VULNERABILITY': '漏洞', 'SECURITY_HOTSPOT': '安全热点', 'CODE_SMELL': '代码异味'}


def cell(text, width=90):
    text = str(text if text is not None else '').replace('|', '\\|').replace('\n', ' ')
    return text if len(text) <= width else text[:width - 1] + '…'


def issues_table(issues, limit=60, with_type=True):
    if not issues: return '无\n'
    head = '| 严重度 | ' + ('类型 | ' if with_type else '') + '规则 | 位置 | 说明 |\n|---|' + ('---|' if with_type else '') + '---|---|---|\n'
    rows = []
    for i in issues[:limit]:
        loc = f"{i.get('file') or ''}:{i.get('line') or ''}".strip(':')
        rows.append(f"| {i.get('severity') or ''} | " + (f"{TYPE_CN.get(i.get('type'), i.get('type') or '')} | " if with_type else '')
                    + f"{cell(i.get('rule'), 40)} | {cell(loc, 60)} | {cell(i.get('message'))} |")
    more = f'\n…另有 {len(issues) - limit} 条未列出\n' if len(issues) > limit else '\n'
    return head + '\n'.join(rows) + more


def skill_section(s):
    out = [f"## Agent Skill 结构检查\n\n技能：`{s.get('name') or '?'}`（{s['skill']}），SKILL.md 正文 {s.get('body_lines', '?')} 行，共 {len(s.get('files', []))} 个文件。\n"]
    out.append(issues_table([{**i, 'file': i['file'].replace(s['skill'], '.') if i.get('file') else None} for i in s['issues']], with_type=False))
    return '\n'.join(out)


def deps_section(d):
    out = ['## 依赖分析\n', f"扫描 {d['python_files']} 个 Python 文件；依赖清单：{'、'.join(d['manifests']) or '无（未声明依赖，建议加 requirements.txt）'}。\n"]
    if d['third_party']:
        out.append('| 导入名 | 发行包 | 版本 | 已安装 | 已声明 | 可选 | 用到的文件 |\n|---|---|---|---|---|---|---|')
        for e in d['third_party']:
            yes = lambda v: '—' if v is None else ('是' if v else '**否**')
            inst = '是（代码自加路径）' if e.get('location') else yes(e['installed'])
            out.append(f"| {e['import']} | {e['distribution'] or '?'} | {e['version'] or '?'} | {inst} | {yes(e['declared'])} | "
                       f"{'是' if e['optional'] else '否'} | {cell(', '.join(e['files']), 60)} |")
        out.append('')
    else: out.append('没有第三方 Python 依赖。\n')
    if d.get('extra_sys_paths'):
        out.append('代码自己往 sys.path 加了：' + '；'.join(f'`{p}`' + ('' if os.path.isdir(p) else '（**目录不存在**）') for p in d['extra_sys_paths'])
                   + '。写死的绝对路径换台机器就失效，建议改成 requirements.txt + 虚拟环境。\n')
    if d['missing']: out.append('**缺失依赖（运行会 ImportError）：** ' + '、'.join(f"`{e['import']}`" for e in d['missing']) + '\n')
    if d['undeclared']: out.append('**用了但没写进依赖清单：** ' + '、'.join(f"`{e['distribution'] or e['import']}`" for e in d['undeclared']) + '\n')
    if d['unused_declared']: out.append('**声明了但代码没用到：** ' + '、'.join(f'`{n}`' for n in d['unused_declared']) + '\n')
    if d['cycles']: out.append('**模块循环依赖：** ' + '；'.join(' → '.join(c) for c in d['cycles']) + '\n')
    if d['external_tools']:
        out.append('外部命令：' + '；'.join(f"`{t['command']}` {'在 PATH' if t['found_on_path'] else '**不在 PATH**'}" for t in d['external_tools']) + '\n')
    if d['node']:
        n = d['node']; out.append(f"Node 依赖 {len(n['declared'])} 个，node_modules {'存在' if n['node_modules_present'] else '**不存在**'}"
                                  + (f"，缺失：{'、'.join(n['missing'])}" if n['missing'] else '') + '\n')
    out.append(f"已知漏洞（OSV）：{d['vulnerability_check']}" + (f"，发现 {len(d['vulnerabilities'])} 个" if d['vulnerabilities'] else '，未发现' if d['vulnerability_check'] == '已查询 OSV' else '') + '\n')
    groups = {}
    for v in d['vulnerabilities']: groups.setdefault((v['package'], v['version']), []).append(v)
    if groups:
        out.append('| 包 | 当前版本 | 漏洞数 | 建议升级到 | 漏洞编号（前5个） |\n|---|---|---|---|---|')
        from .deps import _version_key
        for (pkg, ver), vs in groups.items():
            fixes = [v['fixed'] for v in vs if v.get('fixed')]
            target = f'≥ {max(fixes, key=_version_key)}' if fixes else '最新版'
            out.append(f"| {pkg} | {ver} | {len(vs)} | {target} | {cell(', '.join(v['id'] for v in vs[:5]), 80)} |")
        out.append('')
    return '\n'.join(out)


def local_section(q, limit=60):
    c, r = q['counts'], q['ratings']
    out = ['## 代码质量（本地规则）\n',
           f"{q['files']} 个文件、{q['ncloc']} 行代码、{q['functions']} 个函数；重复行 {q['duplicated_lines_density']}%；"
           f"技术债约 {q['technical_debt_minutes']} 分钟（{q['debt_ratio_percent']}%）；{q['ruff']}。\n",
           '| 可靠性 | 安全性 | 可维护性 | Bug | 漏洞 | 安全热点 | 代码异味 |\n|---|---|---|---|---|---|---|',
           f"| {r['reliability']} | {r['security']} | {r['maintainability']} | {c['BUG']} | {c['VULNERABILITY']} | {c['SECURITY_HOTSPOT']} | {c['CODE_SMELL']} |\n"]
    if q['duplicated_blocks']: out.append('重复代码块示例：' + '；'.join(' ↔ '.join(b[:3]) for b in q['duplicated_blocks'][:5]) + '\n')
    important = [i for i in q['issues'] if i['type'] != 'CODE_SMELL' or i['severity'] in ('BLOCKER', 'CRITICAL', 'MAJOR')]
    minor = len(q['issues']) - len(important)
    out.append(issues_table(important, limit))
    if minor:
        rules = {}
        for i in q['issues']:
            if i not in important: rules[i['rule']] = rules.get(i['rule'], 0) + 1
        out.append(f'次要代码异味 {minor} 条（按规则汇总）：' + '、'.join(f'{k}×{v}' for k, v in sorted(rules.items(), key=lambda x: -x[1])) + '\n')
    return '\n'.join(out)


def sonar_section(s):
    if s.get('skipped'): return f"## SonarQube\n\n{s['skipped']}\n"
    if s.get('error'): return f"## SonarQube\n\n调用失败：{s['error']}\n"
    m = s['metrics']['metrics']
    out = [f"## SonarQube（项目 `{s['metrics']['project']}`）\n",
           f"质量门禁：**{m.get('quality_gate') or '?'}**" + (f"，未通过条件：{'；'.join(m['failed_conditions'])}" if m.get('failed_conditions') else '') + '\n',
           '| 可靠性 | 安全性 | 可维护性 | Bug | 漏洞 | 安全热点 | 代码异味 | 覆盖率 | 重复率 | 代码行 |\n|---|---|---|---|---|---|---|---|---|---|',
           f"| {m.get('reliability_rating', '?')} | {m.get('security_rating', '?')} | {m.get('sqale_rating', '?')} | {m.get('bugs', '?')} | "
           f"{m.get('vulnerabilities', '?')} | {m.get('security_hotspots', '?')} | {m.get('code_smells', '?')} | {m.get('coverage', '—')}% | "
           f"{m.get('duplicated_lines_density', '?')}% | {m.get('ncloc', '?')} |\n"]
    if s.get('scan'): out.append(f"本次扫描：{s['scan'].get('analysis', '已提交')}\n")
    out.append(f"未解决的 Bug 和漏洞（共 {s['issues']['total']} 条）：\n")
    out.append(issues_table(s['issues']['issues']))
    if s.get('hotspots'): out.append('待审查安全热点：\n\n' + issues_table(s['hotspots']))
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
    if sonar and sonar.get('metrics') and sonar['metrics']['metrics'].get('quality_gate') == 'ERROR': blockers.append('SonarQube 质量门禁未通过')
    status = '未通过' if blockers else ('有警告' if warnings else '通过')
    return status, blockers, warnings


def render(target, skill, deps, local, sonar):
    status, blockers, warnings = verdict(skill, deps, local, sonar)
    lines = [f'# 质量报告：{target}\n', f"生成时间：{datetime.datetime.now():%Y-%m-%d %H:%M}\n",
             f'**结论：{status}**' + ('' if status == '通过' else '。') + '；'.join(blockers + warnings) + '\n']
    if skill: lines.append(skill_section(skill))
    lines += [deps_section(deps), local_section(local), sonar_section(sonar or {'skipped': '未启用'})]
    return '\n'.join(lines)
