"""依赖分析：Python 导入、依赖声明、内部循环依赖、外部命令、已知漏洞（OSV）。"""
import ast
import json
import re
import shutil
import sys
import importlib.metadata as md
import importlib.util
import urllib.request
from pathlib import Path

from .skills import walk_files

PY_FILE_LIMIT = 5000

KNOWN_COMMANDS = {'ffmpeg', 'ffprobe', 'git', 'node', 'npx', 'npm', 'java', 'docker', 'sonar-scanner', 'powershell', 'pwsh',
                  'python', 'pip', 'uv', 'ruff', 'magick', 'curl'}
SUBPROCESS_CALLS = {'run', 'Popen', 'call', 'check_call', 'check_output', 'system'}


def python_files(root):
    """返回 (文件列表, 是否截断)；超过 PY_FILE_LIMIT 个文件时截断，调用方必须在报告里注明。"""
    return walk_files(root, {'.py'}, PY_FILE_LIMIT)


def norm(name): return re.sub(r'[-_.]+', '-', name).lower()


def declared_dependencies(root):
    root = Path(root if Path(root).is_dir() else Path(root).parent); found, manifests = set(), []
    for req in list(root.glob('requirements*.txt')):
        manifests.append(req.name)
        for line in req.read_text(encoding='utf-8', errors='replace').splitlines():
            line = line.split('#')[0].strip()
            if line and not line.startswith('-'): found.add(norm(re.split(r'[\s<>=!~;\[]', line)[0]))
    pyproject = root/'pyproject.toml'
    if pyproject.is_file():
        try: import tomllib
        except ImportError: return found, manifests + ['pyproject.toml（Python 3.11 以下无法解析）']
        manifests.append('pyproject.toml')
        data = tomllib.loads(pyproject.read_text(encoding='utf-8'))
        deps = list(data.get('project', {}).get('dependencies', []))
        for group in data.get('project', {}).get('optional-dependencies', {}).values(): deps += group
        deps += list(data.get('tool', {}).get('poetry', {}).get('dependencies', {}).keys())
        found |= {norm(re.split(r'[\s<>=!~;\[]', d)[0]) for d in deps if d and d != 'python'}
    return found, manifests


def node_dependencies(root):
    pkg = Path(root)/'package.json'
    if not pkg.is_file(): return None
    data = json.loads(pkg.read_text(encoding='utf-8'))
    deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
    installed = (Path(root)/'node_modules').is_dir()
    return {'declared': deps, 'node_modules_present': installed,
            'missing': [d for d in deps if installed and not (Path(root)/'node_modules'/d).exists()]}


def _optional_import(node, parents):
    for p in parents:
        if isinstance(p, ast.Try):
            for h in p.handlers:
                names = [h.type] if not isinstance(h.type, ast.Tuple) else h.type.elts
                if h.type is None or any(isinstance(n, ast.Name) and n.id in ('ImportError', 'ModuleNotFoundError', 'Exception') for n in names):
                    return True
    return False


def _command_name(call):
    """subprocess.run([...]) / os.system('...') 的第一个参数里取命令名；参数（-i 之类）不算。"""
    fn = call.func
    owner = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else ''
    name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ''
    if not (owner in ('subprocess', 'os') and name in SUBPROCESS_CALLS or not owner and name in ('Popen', 'check_output', 'check_call')):
        return None
    if not call.args: return None
    a = call.args[0]
    first = a.elts[0] if isinstance(a, (ast.List, ast.Tuple)) and a.elts else a
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.strip()): return None
    token = first.value.split()[0]
    return None if token.startswith('-') else Path(token).stem.lower()


def _extra_sys_paths(tree):
    paths = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args:
            fn = node.func
            target = ast.unparse(fn.value)
            if (target == 'sys.path' and fn.attr in ('insert', 'append')) or (target == 'site' and fn.attr == 'addsitedir'):
                arg = node.args[-1]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str): paths.append(arg.value)
    return paths


def scan_imports(files, root):
    root = Path(root if Path(root).is_dir() else Path(root).parent)
    # 绝对导入只会解析到：根目录下的顶层模块/包、目标本身这个包、以及脚本所在目录的同级模块（直接运行脚本时）。
    # 包里深层的 logging.py 不会遮住标准库 logging，不能按“目录里有同名文件”判本地。
    top_level = {f.relative_to(root).parts[0].removesuffix('.py') for f in files if f.is_relative_to(root)}
    if (root/'__init__.py').exists(): top_level.add(root.name)
    sibling_cache = {}
    def siblings(d):
        if d not in sibling_cache:
            sibling_cache[d] = {p.stem for p in d.glob('*.py')} | {p.name for p in d.iterdir() if p.is_dir() and (p/'__init__.py').exists()}
        return sibling_cache[d]
    local_names = set(top_level)
    imports, graph, commands, errors = {}, {}, {}, []
    extra_paths = []
    for f in files:
        try: tree = ast.parse(f.read_text(encoding='utf-8', errors='replace'), str(f))
        except SyntaxError as e:
            errors.append({'file': str(f), 'line': e.lineno, 'message': f'语法错误：{e.msg}'}); continue
        parents_of = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent): parents_of[child] = parent
        def chain(n):
            while n in parents_of: n = parents_of[n]; yield n
        mod = f.stem; graph.setdefault(mod, set())
        file_locals = top_level | siblings(f.parent)
        local_names |= file_locals
        extra_paths += [p for p in _extra_sys_paths(tree) if p not in extra_paths]
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import): names = [a.name.split('.')[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level: graph[mod].add((node.module or '').split('.')[0] or '(package)'); continue
                names = [(node.module or '').split('.')[0]]
            for name in names:
                if not name: continue
                rec = imports.setdefault(name, {'files': set(), 'optional': True})
                rec['files'].add(str(f.relative_to(root)) if f.is_relative_to(root) else str(f))
                rec['optional'] &= _optional_import(node, chain(node))
                if name in file_locals and name != mod: graph[mod].add(name)
            if isinstance(node, ast.Call):
                cmd = _command_name(node)
                if cmd: commands.setdefault(cmd, set()).add(f'{f.name}:{node.lineno}')
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value.strip().lower()
                stem = Path(v).stem if v.endswith('.exe') else v
                if stem in KNOWN_COMMANDS: commands.setdefault(stem, set()).add(f'{f.name}:{node.lineno}')
    return imports, graph, commands, errors, local_names, extra_paths


def _find_in_paths(name, paths):
    """在代码自己加进 sys.path 的目录里找包，返回 (目录, 版本)。"""
    import importlib.machinery
    for p in paths:
        if not Path(p).is_dir(): continue
        if importlib.machinery.PathFinder.find_spec(name, [p]) is None: continue
        for dist in md.distributions(path=[p]):
            top = (dist.read_text('top_level.txt') or '').split()
            if name in top or norm(dist.metadata['Name'] or '') == norm(name): return p, dist.version, dist.metadata['Name']
        return p, None, None
    return None, None, None


def find_cycles(graph):
    cycles, state, stack = [], {}, []
    def dfs(n):
        state[n] = 1; stack.append(n)
        for m in graph.get(n, ()):
            if m not in graph: continue
            if state.get(m) == 1:
                cyc = stack[stack.index(m):] + [m]
                if sorted(cyc[:-1]) not in [sorted(c[:-1]) for c in cycles]: cycles.append(cyc)
            elif not state.get(m): dfs(m)
        stack.pop(); state[n] = 2
    for n in list(graph):
        if not state.get(n): dfs(n)
    return cycles


def osv_vulnerabilities(packages, timeout=20):
    """packages: [(dist_name, version)]，查 https://osv.dev 的 PyPI 漏洞库。"""
    if not packages: return [], None
    body = json.dumps({'queries': [{'package': {'name': n, 'ecosystem': 'PyPI'}, 'version': v} for n, v in packages]}).encode()
    req = urllib.request.Request('https://api.osv.dev/v1/querybatch', data=body, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: results = json.loads(r.read())['results']
    except Exception as e:
        return [], f'OSV 查询失败：{e}'
    found = []
    for (name, version), res in zip(packages, results):
        for v in res.get('vulns', []): found.append({'package': name, 'version': version, 'id': v['id']})
    fixed = _fixed_versions(found[:60], timeout)
    for v in found: v['fixed'] = fixed.get(v['id'], {}).get(norm(v['package']))
    return found, None


def _version_key(v):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r'[.\-+]', v))


def _fixed_versions(vulns, timeout):
    """逐条取 OSV 详情里的 fixed 版本，返回 {vuln_id: {包名: 修复版本}}。"""
    from concurrent.futures import ThreadPoolExecutor
    def fetch(vid):
        try:
            with urllib.request.urlopen(f'https://api.osv.dev/v1/vulns/{vid}', timeout=timeout) as r: data = json.loads(r.read())
        except Exception: return vid, {}
        out = {}
        for a in data.get('affected', []):
            fixes = [e['fixed'] for rg in a.get('ranges', []) for e in rg.get('events', []) if 'fixed' in e]
            if fixes: out[norm(a.get('package', {}).get('name', ''))] = max(fixes, key=_version_key)
        return vid, out
    with ThreadPoolExecutor(8) as pool: return dict(pool.map(fetch, sorted({v['id'] for v in vulns})))


def analyze(path, check_vulnerabilities=False):
    root = Path(path).expanduser().resolve()
    files, truncated = python_files(root)
    base = root if root.is_dir() else root.parent
    imports, graph, commands, errors, local_names, extra_paths = scan_imports(files, base)
    dist_map = md.packages_distributions()
    declared, manifests = declared_dependencies(base)
    third_party, missing, used_dists = [], [], set()
    for name, rec in sorted(imports.items()):
        if name in sys.stdlib_module_names or name in local_names or name == '__future__': continue
        dists = dist_map.get(name, [])
        location, version, dist_name = _find_in_paths(name, extra_paths)
        if location:
            installed = True
            if dist_name: dists = [dist_name]
        else:
            installed = importlib.util.find_spec(name) is not None
            if dists:
                try: version = md.version(dists[0])
                except md.PackageNotFoundError: pass
        used_dists |= {norm(d) for d in dists} or {norm(name)}
        entry = {'import': name, 'distribution': dists[0] if dists else None, 'version': version, 'installed': installed, 'location': location,
                 'optional': rec['optional'], 'files': sorted(rec['files']),
                 'declared': bool({norm(d) for d in dists} & declared or norm(name) in declared) if manifests else None}
        third_party.append(entry)
        if not installed and not rec['optional']: missing.append(entry)
    undeclared = [e for e in third_party if manifests and e['declared'] is False]
    unused_declared = sorted(declared - used_dists) if manifests else []
    tools = [{'command': c, 'found_on_path': bool(shutil.which(c)), 'used_at': sorted(locs)[:5]} for c, locs in sorted(commands.items())]
    vulns, vuln_error = [], None
    if check_vulnerabilities:
        vulns, vuln_error = osv_vulnerabilities(sorted({(e['distribution'], e['version']) for e in third_party if e['distribution'] and e['version']}))
    return {'path': str(root), 'python_files': len(files), 'truncated': truncated, 'manifests': manifests, 'third_party': third_party, 'extra_sys_paths': extra_paths,
            'missing': missing, 'undeclared': undeclared, 'unused_declared': unused_declared,
            'internal_graph': {k: sorted(v) for k, v in graph.items() if v}, 'cycles': find_cycles(graph),
            'external_tools': tools, 'node': node_dependencies(base), 'syntax_errors': errors,
            'vulnerabilities': vulns, 'vulnerability_check': ('未执行' if not check_vulnerabilities else vuln_error or '已查询 OSV')}
