"""本地代码质量扫描（无 SonarQube 服务时的兜底）。

规则仿照 SonarQube 的 Python 规则编写，rule 字段带 python:Sxxxx 的表示"近似对应该 Sonar 规则"，
local: 开头的是本 MCP 自己的规则。评级口径按 SonarQube：可靠性/安全性看最严重的 Bug/漏洞，
可维护性看技术债比例（债务分钟 ÷ 代码行数×30分钟）。
"""
import ast
import hashlib
import json
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

from .deps import python_files

SEVERITIES = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO']
DEBT_MINUTES = {'BLOCKER': 60, 'CRITICAL': 30, 'MAJOR': 15, 'MINOR': 5, 'INFO': 0}
COGNITIVE_MAX, FUNCTION_LINES_MAX, PARAMS_MAX, LINE_MAX, DUP_WINDOW = 15, 100, 7, 160, 6
SECRET_NAME = re.compile(r'(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)$', re.I)
SAFE_HTTP = ('http://localhost', 'http://127.0.0.1', 'http://www.w3.org', 'http://schemas.', 'http://0.0.0.0')


def cognitive_complexity(fn):
    total = 0
    def visit(nodes, nesting):
        nonlocal total
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                visit(node.body if isinstance(node.body, list) else [node.body], nesting + 1); continue
            if isinstance(node, ast.If):
                total += 1 + nesting; visit([node.test], nesting); visit(node.body, nesting + 1)
                orelse = node.orelse
                while len(orelse) == 1 and isinstance(orelse[0], ast.If):
                    total += 1; visit([orelse[0].test], nesting); visit(orelse[0].body, nesting + 1); orelse = orelse[0].orelse
                if orelse: total += 1; visit(orelse, nesting + 1)
                continue
            if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                total += 1 + nesting; visit(node.body, nesting + 1)
                if node.orelse: total += 1; visit(node.orelse, nesting + 1)
                continue
            if isinstance(node, (ast.Try, getattr(ast, 'TryStar', ast.Try))):
                visit(node.body, nesting)
                for h in node.handlers: total += 1 + nesting; visit(h.body, nesting + 1)
                visit(node.orelse, nesting); visit(node.finalbody, nesting); continue
            if isinstance(node, ast.IfExp): total += 1 + nesting
            elif isinstance(node, ast.BoolOp): total += 1
            elif isinstance(node, ast.comprehension): total += len(node.ifs)
            elif isinstance(node, ast.match_case): total += 1 + nesting; visit(node.body, nesting + 1); continue
            visit(list(ast.iter_child_nodes(node)), nesting)
    visit(fn.body, 0)
    return total


class FileChecker(ast.NodeVisitor):
    def __init__(self, path, text, rel):
        self.path, self.rel, self.text, self.issues = path, rel, text, []

    def add(self, type_, severity, rule, message, line):
        self.issues.append({'type': type_, 'severity': severity, 'rule': rule, 'message': message, 'file': self.rel, 'line': line})

    def check_block(self, body):
        for i, stmt in enumerate(body[:-1]):
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                self.add('BUG', 'MAJOR', 'python:S1763', '这句后面的代码永远执行不到', body[i + 1].lineno); break
        names = Counter()
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names[stmt.name] += 1
                if names[stmt.name] == 2 and not stmt.decorator_list:
                    self.add('BUG', 'MAJOR', 'local:duplicate-def', f'函数 {stmt.name} 在同一作用域重复定义，前一个被覆盖', stmt.lineno)

    def generic_visit(self, node):
        for field in ('body', 'orelse', 'finalbody'):
            block = getattr(node, field, None)
            if isinstance(block, list) and block and isinstance(block[0], ast.stmt): self.check_block(block)
        super().generic_visit(node)

    def visit_Module(self, node):
        self.check_unused_imports(node); self.generic_visit(node)

    def visit_FunctionDef(self, node):
        cc = cognitive_complexity(node)
        if cc > COGNITIVE_MAX: self.add('CODE_SMELL', 'CRITICAL', 'python:S3776', f'函数 {node.name} 认知复杂度 {cc}，超过 {COGNITIVE_MAX}', node.lineno)
        length = (node.end_lineno or node.lineno) - node.lineno + 1
        if length > FUNCTION_LINES_MAX: self.add('CODE_SMELL', 'MAJOR', 'python:S138', f'函数 {node.name} 有 {length} 行，超过 {FUNCTION_LINES_MAX}', node.lineno)
        params = [a for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs if a.arg not in ('self', 'cls')]
        if len(params) > PARAMS_MAX: self.add('CODE_SMELL', 'MAJOR', 'python:S107', f'函数 {node.name} 有 {len(params)} 个参数，超过 {PARAMS_MAX}', node.lineno)
        for d in node.args.defaults + [d for d in node.args.kw_defaults if d]:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)) or (isinstance(d, ast.Call) and getattr(d.func, 'id', '') in ('list', 'dict', 'set')):
                self.add('BUG', 'MINOR', 'local:mutable-default', f'函数 {node.name} 用可变对象做默认参数，多次调用会共享同一个对象', d.lineno)
        self.check_unused_locals(node)
        self.generic_visit(node)
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Try(self, node):
        for h in node.handlers:
            if h.type is None: self.add('CODE_SMELL', 'MAJOR', 'python:S5754', '裸 except: 会连 KeyboardInterrupt/SystemExit 一起吞掉，写明异常类型', h.lineno)
            if len(h.body) == 1 and isinstance(h.body[0], ast.Pass): self.add('CODE_SMELL', 'MAJOR', 'local:swallowed-exception', '异常被 pass 静默吞掉，出错时无从排查', h.lineno)
        for stmt in ast.walk(ast.Module(body=node.finalbody, type_ignores=[])):
            if isinstance(stmt, (ast.Return, ast.Break, ast.Continue)):
                self.add('BUG', 'MAJOR', 'python:S1143', 'finally 里的 return/break/continue 会吞掉正在抛出的异常', stmt.lineno)
        self.generic_visit(node)

    def visit_Compare(self, node):
        for op, right in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(right, ast.Constant) and right.value is not None and not isinstance(right.value, bool):
                self.add('BUG', 'MAJOR', 'python:S5795', 'is 比较字面量结果不可靠，改用 ==', node.lineno)
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(right, ast.Constant) and right.value is None:
                self.add('CODE_SMELL', 'MINOR', 'local:none-equality', '和 None 比较用 is / is not', node.lineno)
        if len(node.ops) == 1 and ast.dump(node.left) == ast.dump(node.comparators[0]) and not isinstance(node.left, ast.Constant):
            self.add('BUG', 'MAJOR', 'python:S1764', '比较运算两边是同一个表达式', node.lineno)
        self.generic_visit(node)

    def visit_Assert(self, node):
        if isinstance(node.test, ast.Tuple) and node.test.elts:
            self.add('BUG', 'MAJOR', 'python:S5905', 'assert 一个元组永远为真，括号写错了', node.lineno)
        self.generic_visit(node)

    def visit_Assign(self, node):
        for t in node.targets:
            if isinstance(t, ast.Name) and isinstance(node.value, ast.Name) and t.id == node.value.id:
                self.add('BUG', 'MAJOR', 'python:S1656', f'{t.id} = {t.id} 自赋值，没有效果', node.lineno)
            if isinstance(t, ast.Name) and SECRET_NAME.search(t.id) and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, str) and len(node.value.value) >= 6 and ' ' not in node.value.value:
                self.add('VULNERABILITY', 'CRITICAL', 'python:S2068', f'{t.id} 疑似硬编码密钥/密码，改为环境变量读取', node.lineno)
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        if not any(isinstance(v, ast.FormattedValue) for v in node.values):
            self.add('CODE_SMELL', 'MINOR', 'python:S3457', 'f-string 里没有占位符，去掉 f 前缀', node.lineno)
        # 只进占位符表达式，f-string 的字面片段不算明文 HTTP 等字符串规则
        for v in node.values:
            if isinstance(v, ast.FormattedValue): self.visit(v.value)

    def visit_Call(self, node):
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ''
        owner = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else ''
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        if isinstance(fn, ast.Name) and name in ('eval', 'exec'):
            self.add('SECURITY_HOTSPOT', 'CRITICAL', 'python:S1523', f'{name}() 动态执行代码，确认输入可信', node.lineno)
        if owner == 'os' and name in ('system', 'popen'):
            self.add('SECURITY_HOTSPOT', 'MAJOR', 'python:S4721', f'os.{name}() 走系统 shell，确认命令不拼接外部输入', node.lineno)
        if 'shell' in kw and isinstance(kw['shell'], ast.Constant) and kw['shell'].value is True:
            self.add('SECURITY_HOTSPOT', 'MAJOR', 'python:S4721', 'subprocess 使用 shell=True，有命令注入风险', node.lineno)
        if 'verify' in kw and isinstance(kw['verify'], ast.Constant) and kw['verify'].value is False:
            self.add('VULNERABILITY', 'CRITICAL', 'python:S4830', 'verify=False 关闭了 TLS 证书校验', node.lineno)
        if owner == 'pickle' and name in ('load', 'loads'):
            self.add('SECURITY_HOTSPOT', 'MAJOR', 'local:pickle-load', 'pickle 反序列化不可信数据可执行任意代码', node.lineno)
        if owner == 'yaml' and name == 'load' and 'Loader' not in kw and len(node.args) < 2:
            self.add('VULNERABILITY', 'MAJOR', 'local:yaml-load', 'yaml.load 未指定 Loader，改用 yaml.safe_load', node.lineno)
        if isinstance(fn, ast.Name) and name == 'open' and 'encoding' not in kw:
            mode = node.args[1] if len(node.args) > 1 else kw.get('mode')
            if not (isinstance(mode, ast.Constant) and 'b' in str(mode.value)):
                self.add('CODE_SMELL', 'MINOR', 'local:open-encoding', 'open() 没写 encoding，Windows 中文环境默认 GBK，读写 UTF-8 文件会乱码或报错', node.lineno)
        if isinstance(fn, ast.Attribute) and name in ('read_text', 'write_text') and 'encoding' not in kw \
                and len(node.args) < (2 if name == 'write_text' else 1):
            self.add('CODE_SMELL', 'MINOR', 'local:open-encoding', f'{name}() 没写 encoding，Windows 中文环境默认 GBK', node.lineno)
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and node.value.startswith('http://') and not node.value.startswith(SAFE_HTTP):
            self.add('SECURITY_HOTSPOT', 'MINOR', 'python:S5332', f'明文 HTTP 地址：{node.value[:60]}', node.lineno)

    def check_unused_imports(self, module):
        if self.path.name == '__init__.py': return
        imported = {}
        for stmt in module.body:
            if isinstance(stmt, ast.Import):
                for a in stmt.names: imported[a.asname or a.name.split('.')[0]] = stmt.lineno
            elif isinstance(stmt, ast.ImportFrom) and stmt.module != '__future__':
                for a in stmt.names:
                    if a.name != '*': imported[a.asname or a.name] = stmt.lineno
        used = {n.id for n in ast.walk(module) if isinstance(n, ast.Name)}
        used |= {c.value for n in ast.walk(module) if isinstance(n, ast.Assign) and any(getattr(t, 'id', '') == '__all__' for t in n.targets)
                 for c in ast.walk(n.value) if isinstance(c, ast.Constant)}
        for name, line in imported.items():
            if name not in used and not re.search(rf'\b{re.escape(name)}\b', ''.join(self.string_annotations(module))):
                self.add('CODE_SMELL', 'MINOR', 'python:S1128', f'导入了 {name} 但没有使用', line)

    @staticmethod
    def string_annotations(module):
        return [n.value for n in ast.walk(module) if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) < 80]

    def check_unused_locals(self, fn):
        stored, loaded = {}, set()
        for n in ast.walk(fn):
            if n is not fn and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                loaded |= {x.id for x in ast.walk(n) if isinstance(x, ast.Name)}; continue
            if isinstance(n, ast.Name):
                if isinstance(n.ctx, ast.Store): stored.setdefault(n.id, n.lineno)
                else: loaded.add(n.id)
        declared = {name for n in ast.walk(fn) if isinstance(n, (ast.Global, ast.Nonlocal)) for name in n.names}
        tuple_targets = {e.id for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.For, ast.comprehension))
                         for t in (n.targets if isinstance(n, ast.Assign) else [n.target]) if isinstance(t, (ast.Tuple, ast.List))
                         for e in ast.walk(t) if isinstance(e, ast.Name)}
        for name, line in stored.items():
            if name not in loaded and name not in declared and name not in tuple_targets and not name.startswith('_'):
                self.add('CODE_SMELL', 'MINOR', 'python:S1481', f'局部变量 {name} 赋值后没有使用', line)


def duplicated_strings(tree, rel):
    skip = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.JoinedStr): skip |= {id(v) for v in n.values}
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body \
                and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant):
            skip.add(id(n.body[0].value))
    counts, first = Counter(), {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) >= 10 and id(n) not in skip:
            counts[n.value] += 1; first.setdefault(n.value, n.lineno)
    return [{'type': 'CODE_SMELL', 'severity': 'MINOR', 'rule': 'python:S1192', 'file': rel, 'line': first[s],
             'message': f'字符串 “{s[:40]}” 重复出现 {c} 次，提成常量'} for s, c in counts.items() if c >= 3]


def ruff_issues(path, base):
    exe = shutil.which('ruff')
    if not exe: return None
    r = subprocess.run([exe, 'check', '--output-format', 'json', '--exit-zero', str(path)], capture_output=True, text=True, encoding='utf-8')
    try: data = json.loads(r.stdout or '[]')
    except json.JSONDecodeError: return None
    bug_codes = {'F821', 'F811', 'F823', 'F601', 'F632', 'B006', 'B008', 'E999', 'PLE'}
    out = []
    for d in data:
        code = d.get('code') or 'E999'
        rel = str(Path(d['filename']).resolve().relative_to(base)) if Path(d['filename']).resolve().is_relative_to(base) else d['filename']
        out.append({'type': 'BUG' if code in bug_codes or code.startswith('PLE') else 'CODE_SMELL',
                    'severity': 'MAJOR' if code in bug_codes else 'MINOR', 'rule': f'ruff:{code}', 'message': d['message'],
                    'file': rel, 'line': d['location']['row']})
    return out


def duplication(texts):
    windows, dup_lines, total = defaultdict(list), set(), 0
    for rel, text in texts.items():
        lines = [(i, re.sub(r'\s+', ' ', l.strip())) for i, l in enumerate(text.splitlines(), 1)]
        lines = [(i, l) for i, l in lines if l and not l.startswith('#') and len(l) > 3]
        total += len(lines)
        for k in range(len(lines) - DUP_WINDOW + 1):
            chunk = lines[k:k + DUP_WINDOW]
            windows[hashlib.md5('\n'.join(l for _, l in chunk).encode()).hexdigest()].append((rel, [i for i, _ in chunk]))
    # 同一段重复代码会被相邻的滑动窗口命中多次：起点都顺移的窗口合并成一个行区间
    runs = []
    for locs in windows.values():
        if len(locs) < 2: continue
        for rel, nums in locs: dup_lines |= {(rel, n) for n in nums}
        key = tuple(rel for rel, _ in locs)
        starts, ends = [nums[0] for _, nums in locs], [nums[-1] for _, nums in locs]
        for run in runs:
            if run['key'] == key and all(0 < s - rs <= DUP_WINDOW for s, rs in zip(starts, run['last'])):
                run['last'], run['ends'] = starts, [max(a, b) for a, b in zip(run['ends'], ends)]
                break
        else:
            runs.append({'key': key, 'starts': starts, 'last': starts, 'ends': ends})
    blocks = [[f'{rel}:{s}-{e}' for rel, s, e in zip(r['key'], r['starts'], r['ends'])] for r in runs]
    return round(100 * len(dup_lines) / total, 1) if total else 0.0, blocks


def rating_by_worst(items):
    worst = min((SEVERITIES.index(i['severity']) for i in items), default=None)
    return 'A' if worst is None else {4: 'A', 3: 'B', 2: 'C', 1: 'D', 0: 'E'}[worst]


def scan(path, use_ruff=True):
    root = Path(path).expanduser().resolve(); base = root if root.is_dir() else root.parent
    (files, truncated), issues, texts, ncloc, functions = python_files(root), [], {}, 0, 0
    for f in files:
        rel = str(f.relative_to(base)); text = f.read_text(encoding='utf-8', errors='replace'); texts[rel] = text
        ncloc += sum(1 for l in text.splitlines() if l.strip() and not l.strip().startswith('#'))
        try: tree = ast.parse(text, str(f))
        except SyntaxError as e:
            issues.append({'type': 'BUG', 'severity': 'BLOCKER', 'rule': 'python:syntax', 'message': f'语法错误：{e.msg}', 'file': rel, 'line': e.lineno}); continue
        checker = FileChecker(f, text, rel); checker.visit(tree); issues += checker.issues
        issues += duplicated_strings(tree, rel)
        functions += sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree))
        long_lines = [i for i, l in enumerate(text.splitlines(), 1) if len(l) > LINE_MAX]
        if long_lines: issues.append({'type': 'CODE_SMELL', 'severity': 'MINOR', 'rule': 'python:S103', 'file': rel, 'line': long_lines[0],
                                      'message': f'{len(long_lines)} 行超过 {LINE_MAX} 字符'})
        todos = [i for i, l in enumerate(text.splitlines(), 1) if re.search(r'#\s*(TODO|FIXME|XXX)\b', l)]
        if todos: issues.append({'type': 'CODE_SMELL', 'severity': 'INFO', 'rule': 'python:S1135', 'file': rel, 'line': todos[0],
                                 'message': f'{len(todos)} 处 TODO/FIXME 未处理'})
    ruff = ruff_issues(root, base) if use_ruff and files else None
    if ruff: issues += ruff
    seen, unique = set(), []
    for i in issues:
        key = (i['file'], i['line'], i['rule'])
        if key not in seen: seen.add(key); unique.append(i)
    issues = sorted(unique, key=lambda i: (SEVERITIES.index(i['severity']), i['file'] or '', i['line'] or 0))
    dup_density, dup_blocks = duplication(texts)
    by_type = lambda t: [i for i in issues if i['type'] == t]
    debt = sum(DEBT_MINUTES[i['severity']] for i in by_type('CODE_SMELL'))
    ratio = debt / (ncloc * 30) if ncloc else 0
    maint = next(r for r, limit in [('A', .05), ('B', .1), ('C', .2), ('D', .5), ('E', 9e9)] if ratio <= limit)
    return {'path': str(root), 'files': len(files), 'truncated': truncated, 'ncloc': ncloc, 'functions': functions, 'issues': issues,
            'counts': {t: len(by_type(t)) for t in ('BUG', 'VULNERABILITY', 'SECURITY_HOTSPOT', 'CODE_SMELL')},
            'ratings': {'reliability': rating_by_worst(by_type('BUG')), 'security': rating_by_worst(by_type('VULNERABILITY')), 'maintainability': maint},
            'technical_debt_minutes': debt, 'debt_ratio_percent': round(ratio * 100, 1),
            'duplicated_lines_density': dup_density, 'duplicated_blocks': dup_blocks,
            'ruff': 'ruff 已合并' if ruff is not None else ('未安装 ruff（pip install ruff 可增加 800+ 条规则）' if use_ruff else '未启用')}
