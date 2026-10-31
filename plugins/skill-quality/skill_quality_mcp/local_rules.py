"""本地代码质量扫描（无 SonarQube 服务时的兜底）。

Python 用 ast 语法树检查；JavaScript / TypeScript / React / Vue / Java / Go 等其他语言的规则在 multi_lang.py。
rule 字段带语言前缀（python:Sxxxx、java:Sxxxx）的表示"近似对应该 Sonar 规则"，local: 开头的是本 MCP 自己的规则。
评级口径按 SonarQube：可靠性/安全性看最严重的 Bug/漏洞，可维护性看技术债比例（债务分钟 ÷ 代码行数×30分钟）。
"""
import ast
import hashlib
import json
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

from . import multi_lang
from .languages import (CODE_SKIP_DIRS, COGNITIVE_MAX, DISPLAY, EXTRA_SOURCE, FUNCTION_LINES_MAX, GENERATED, JS_LANGS, LINE_MAX,
                        MAX_FILE_BYTES, NON_CODE_EXT, PARAMS_MAX, SECRET_NAME, SFC_LANGS, TEST_PATH,
                        code_files, is_compiled, language_of, load_source, plain_http)

SEVERITIES = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO']
DEBT_MINUTES = {'BLOCKER': 60, 'CRITICAL': 30, 'MAJOR': 15, 'MINOR': 5, 'INFO': 0}
DUP_WINDOW = 6
# 字符串内容已被抹掉，一串 'a', 'b' 这样的行会变得一模一样；token 太少的窗口不算重复代码
DUP_MIN_TOKENS = 30
DUP_TOKEN = re.compile(r'\w+|[^\w\s]')
# 测试代码里故意出现的固定字符串、假密钥、http 地址、跳过证书校验、打印输出、超长的 describe 块不算问题
TEST_EXEMPT_TYPES = {'VULNERABILITY', 'SECURITY_HOTSPOT'}
TEST_EXEMPT_RULES = {'S1192', 'S2486', 'S6479', 'S106', 'S2629', 'S138', 'S104', 'local:console-log', 'local:swallowed-exception', 'local:debug-output'}


def test_exempt(issue):
    rule = issue['rule']
    return issue['type'] in TEST_EXEMPT_TYPES or rule in TEST_EXEMPT_RULES or rule.split(':', 1)[-1] in TEST_EXEMPT_RULES


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
        if isinstance(node.value, str) and plain_http(node.value):
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


def ruff_issues(path, base, files=None):
    exe = shutil.which('ruff')
    if not exe: return None
    targets = [str(f) for f in files] if files else [str(path)]
    r = subprocess.run([exe, 'check', '--output-format', 'json', '--exit-zero', *targets], capture_output=True, text=True, encoding='utf-8')
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
            joined = '\n'.join(l for _, l in chunk)
            if len(DUP_TOKEN.findall(joined)) < DUP_MIN_TOKENS: continue
            windows[hashlib.md5(joined.encode()).hexdigest()].append((rel, [i for i, _ in chunk]))
    # 同一段重复代码会被相邻的滑动窗口命中多次：起点都顺移的窗口合并成一个行区间
    runs = []
    for locs in windows.values():
        if len(locs) < 2: continue
        # 连续相同的行会让同一文件里相互重叠的窗口彼此匹配，这不算重复代码
        kept = []
        for rel, nums in locs:
            if not any(r == rel and nums[0] <= k[-1] for r, k in kept): kept.append((rel, nums))
        locs = kept
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


def scan_python(f, text, rel):
    """一个 .py 文件 → (问题列表, 代码行数, 函数个数)。"""
    ncloc = sum(1 for l in text.splitlines() if l.strip() and not l.strip().startswith('#'))
    try: tree = ast.parse(text, str(f))
    except SyntaxError as e:
        return [{'type': 'BUG', 'severity': 'BLOCKER', 'rule': 'python:syntax', 'message': f'语法错误：{e.msg}', 'file': rel, 'line': e.lineno}], ncloc, 0
    checker = FileChecker(f, text, rel); checker.visit(tree)
    issues = checker.issues + duplicated_strings(tree, rel)
    functions = sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree))
    long_lines = [i for i, l in enumerate(text.splitlines(), 1) if len(l) > LINE_MAX]
    if long_lines: issues.append({'type': 'CODE_SMELL', 'severity': 'MINOR', 'rule': 'python:S103', 'file': rel, 'line': long_lines[0],
                                  'message': f'{len(long_lines)} 行超过 {LINE_MAX} 字符'})
    todos = [i for i, l in enumerate(text.splitlines(), 1) if re.search(r'#\s*(TODO|FIXME|XXX)\b', l)]
    if todos: issues.append({'type': 'CODE_SMELL', 'severity': 'INFO', 'rule': 'python:S1135', 'file': rel, 'line': todos[0],
                             'message': f'{len(todos)} 处 TODO/FIXME 未处理'})
    return issues, ncloc, functions


def external_linters(root, base, by_lang, restrict=False):
    """合并项目自己装的检查器：ruff（Python）、ESLint（JS/TS/Vue）、go vet（Go）。返回 (问题, 状态说明)。
    restrict：只把给定文件交给检查器（改动范围扫描时用）。"""
    issues, notes = [], []
    if by_lang.get('python'):
        ruff = ruff_issues(root, base, by_lang['python'] if restrict else None)
        issues += ruff or []
        notes.append('ruff 已合并' if ruff is not None else '未安装 ruff（pip install ruff 可增加 800+ 条 Python 规则）')
    js_files = [f for lang in (*JS_LANGS, *SFC_LANGS) for f in by_lang.get(lang, [])]
    for found, note in (multi_lang.eslint_issues(root, base, js_files, restrict), multi_lang.go_vet_issues(root, base, by_lang.get('go', []), restrict)):
        issues += found or []
        if note: notes.append(note)
    return issues, '；'.join(notes) or '无可用的外部检查器'


def _git(cwd, *args):
    return subprocess.run(['git', '-C', str(cwd), *args], capture_output=True, text=True, encoding='utf-8', errors='replace')


def git_root(path):
    """path 所在的 git 仓库根；不是仓库返回 None。"""
    start = path if path.is_dir() else path.parent
    r = _git(start, 'rev-parse', '--show-toplevel')
    return Path(r.stdout.strip()).resolve() if r.returncode == 0 and r.stdout.strip() else None


def _diff_hunks(top):
    """git diff -U0 HEAD → {绝对路径: 新文件中的改动行号}。没有 HEAD 时退回比较暂存区。"""
    r = _git(top, 'diff', '-U0', '--no-color', '--diff-filter=ACMR', 'HEAD')
    if r.returncode != 0: r = _git(top, 'diff', '-U0', '--no-color', '--diff-filter=ACMR')
    out, cur = {}, None
    if r.returncode != 0: return out
    for line in r.stdout.splitlines():
        if line.startswith('+++ '):
            spec = line[4:].strip()
            if spec.startswith('b/'): spec = spec[2:]
            if spec == '/dev/null':
                cur = None; continue
            if len(spec) >= 2 and spec[0] == spec[-1] == '"': spec = spec[1:-1]
            p = (top / spec).resolve()
            cur = p if p.is_file() else None
            if cur is not None: out.setdefault(cur, set())
        elif cur is not None and line.startswith('@@'):
            m = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line)
            if not m: continue
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count <= 0:
                if start > 0: out[cur].add(start)
            else: out[cur].update(range(start, start + count))
    return out


def changed_files(start):
    """未提交的改动。返回 (仓库根, 文件列表, {相对路径: 改动行集合或 None})。
    行集合为 None 表示整个文件都算改动（未跟踪，或 diff 里看不出具体行）。不是仓库返回 (None, [], {})。"""
    start = start.resolve()
    top = git_root(start)
    if not top: return None, [], {}
    r = _git(top, 'diff', '--name-only', '--diff-filter=ACMR', '-z', 'HEAD')
    if r.returncode != 0: r = _git(top, 'diff', '--name-only', '--diff-filter=ACMR', '-z')
    tracked = [n for n in (r.stdout.split('\0') if r.returncode == 0 else []) if n]
    u = _git(top, 'ls-files', '--others', '--exclude-standard', '-z')
    untracked = {n for n in (u.stdout.split('\0') if u.returncode == 0 else []) if n}
    hunks = _diff_hunks(top)
    files, lines, seen = [], {}, set()
    for name in tracked + list(untracked):
        p = (top / name).resolve()
        if p in seen or not p.is_file(): continue
        if start.is_file():
            if p != start: continue
        elif not p.is_relative_to(start):
            continue
        if any(part in CODE_SKIP_DIRS for part in p.relative_to(top).parts[:-1]): continue
        seen.add(p); files.append(p)
        rel = str(p.relative_to(start if start.is_dir() else start.parent))
        touched = hunks.get(p)
        lines[rel] = None if name in untracked or not touched else touched
    return top, files, lines


def _on_changed_line(issue, lines):
    """lines 为 None 时不筛选。行号对不上改动行的问题丢掉，避免把文件里的旧问题算进这次改动。"""
    if lines is None: return True
    span = lines.get(issue.get('file'))
    if span is None: return issue.get('file') in lines
    return not issue.get('line') or issue['line'] in span


def _readable(f):
    try: return f.stat().st_size <= MAX_FILE_BYTES
    except OSError: return False


def project_stack(path):
    """从仓库根 / 目标目录的清单文件判断项目用了什么技术，不限于某一种语言。"""
    start = path if path.is_dir() else path.parent
    dirs = []
    for d in (git_root(start) or start, start):
        if d.is_dir() and d not in dirs: dirs.append(d)
    found = []

    def add(name):
        if name and name not in found: found.append(name)

    for d in dirs:
        if (d/'pyproject.toml').is_file() or (d/'requirements.txt').is_file() or (d/'setup.py').is_file() or (d/'Pipfile').is_file(): add('Python')
        if (d/'go.mod').is_file(): add('Go')
        if (d/'Cargo.toml').is_file(): add('Rust')
        if (d/'composer.json').is_file(): add('PHP')
        if (d/'Gemfile').is_file(): add('Ruby')
        if (d/'Package.swift').is_file(): add('Swift')
        if (d/'pubspec.yaml').is_file(): add('Dart')
        if (d/'mix.exs').is_file(): add('Elixir')
        if (d/'pom.xml').is_file(): add('Java')
        if (d/'build.gradle.kts').is_file(): add('Kotlin/Gradle')
        elif (d/'build.gradle').is_file(): add('Java/Gradle')
        if any(d.glob('*.csproj')) or any(d.glob('*.sln')): add('C#')
        if (d/'CMakeLists.txt').is_file(): add('C/C++')
        pkg = d/'package.json'
        if pkg.is_file():
            for name in _npm_stack(pkg, d): add(name)
    return found


def _npm_stack(pkg, directory):
    try: data = json.loads(pkg.read_text(encoding='utf-8', errors='replace')[:500_000])
    except (OSError, json.JSONDecodeError): return ['JavaScript']
    deps = {}
    for key in ('dependencies', 'devDependencies', 'peerDependencies'): deps.update(data.get(key) or {})
    names = ['TypeScript' if (directory/'tsconfig.json').is_file() else 'JavaScript']
    for flag, label in (('react', 'React'), ('react-dom', 'React'), ('vue', 'Vue'), ('svelte', 'Svelte'),
                        ('@angular/core', 'Angular'), ('next', 'Next.js'), ('nuxt', 'Nuxt'), ('solid-js', 'Solid')):
        if flag in deps and label not in names: names.append(label)
    return names


def scan(path, use_linters=True, scope='all'):
    """scope=all 扫整个目录；scope=changed 只扫当前未提交的改动（工作区、暂存、未跟踪）。"""
    if scope not in ('all', 'changed'): raise ValueError('scope 只能是 all 或 changed')
    root = Path(path).expanduser().resolve(); base = root if root.is_dir() else root.parent
    stack, uncovered, note, line_map = project_stack(root), [], '', None
    if scope == 'changed':
        top, changed, line_map = changed_files(root)
        if top is None: raise ValueError('不在 git 仓库中，无法按当前改动扫描。要扫整个目录请用 scope=all。')
        candidates = [f for f in changed if language_of(f) and not GENERATED.search(f.name) and _readable(f)]
        compiled = {f for f in candidates if is_compiled(f)}
        files, truncated = [f for f in candidates if f not in compiled], False
        for f in changed:
            if f in candidates or GENERATED.search(f.name) or not _readable(f): continue
            suffix = f.suffix.lower()
            if not suffix or suffix in NON_CODE_EXT: continue
            label = EXTRA_SOURCE.get(suffix) or suffix.lstrip('.').upper()
            uncovered.append({'file': str(f.relative_to(base)) if f.is_relative_to(base) else str(f), 'language': label})
        if not files and not uncovered: note = '当前没有未提交的代码改动（对比 HEAD，含已暂存和未跟踪文件）。'
        config_only = {f.resolve() for f in changed}
    else:
        files, truncated = code_files(root)
        compiled = {f for f in files if is_compiled(f)}
        files = [f for f in files if f not in compiled]
        config_only = None
    issues, texts, ncloc, functions = [], {}, 0, 0
    by_lang, test_files = defaultdict(list), 0
    for f in files:
        lang = language_of(f); by_lang[lang].append(f)
        rel = str(f.relative_to(base))
        if lang == 'python':
            text = f.read_text(encoding='utf-8', errors='replace'); texts[rel] = text
            found, lines, funcs = scan_python(f, text, rel)
        else:
            found, lines, funcs, texts[rel] = multi_lang.scan_source(load_source(f), rel)
        if TEST_PATH.search(rel):
            test_files += 1; found = [i for i in found if not test_exempt(i)]; texts.pop(rel, None)
        issues += found; ncloc += lines; functions += funcs
    config_ext = {'.yml', '.yaml', '.properties', '.json', '.xml'}
    want_config = root.is_dir() and (config_only is None or any(p.suffix.lower() in config_ext for p in config_only))
    config, config_files = multi_lang.config_issues(root, base, config_only) if want_config else ([], 0)
    issues += config
    linter_issues, linters = external_linters(root, base, by_lang, scope == 'changed') if use_linters and files else ([], '未启用' if not use_linters else '无代码文件')
    issues += linter_issues
    seen, unique = set(), []
    for i in issues:
        key = (i['file'], i['line'], i['rule'])
        if key not in seen: seen.add(key); unique.append(i)
    issues = sorted(unique, key=lambda i: (SEVERITIES.index(i['severity']), i['file'] or '', i['line'] or 0))
    if line_map is not None: issues = [i for i in issues if _on_changed_line(i, line_map)]
    dup_density, dup_blocks = duplication(texts)
    by_type = lambda t: [i for i in issues if i['type'] == t]
    debt = sum(DEBT_MINUTES[i['severity']] for i in by_type('CODE_SMELL'))
    ratio = debt / (ncloc * 30) if ncloc else 0
    maint = next(r for r, limit in [('A', .05), ('B', .1), ('C', .2), ('D', .5), ('E', 9e9)] if ratio <= limit)
    languages = Counter({DISPLAY[lang]: len(fs) for lang, fs in by_lang.items()})
    return {'path': str(root), 'scope': scope, 'stack': stack, 'uncovered': uncovered, 'note': note,
            'files': len(files), 'test_files': test_files, 'compiled_skipped': len(compiled), 'truncated': truncated, 'languages': dict(languages.most_common()),
            'config_files': config_files,
            'ncloc': ncloc, 'functions': functions, 'issues': issues,
            'counts': {t: len(by_type(t)) for t in ('BUG', 'VULNERABILITY', 'SECURITY_HOTSPOT', 'CODE_SMELL')},
            'ratings': {'reliability': rating_by_worst(by_type('BUG')), 'security': rating_by_worst(by_type('VULNERABILITY')), 'maintainability': maint},
            'technical_debt_minutes': debt, 'debt_ratio_percent': round(ratio * 100, 1),
            'duplicated_lines_density': dup_density, 'duplicated_blocks': dup_blocks, 'linters': linters}
