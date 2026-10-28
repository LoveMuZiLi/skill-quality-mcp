"""Python 以外的依赖清单：npm（package.json）、Maven（pom.xml）、Gradle、Go modules、Composer、NuGet。

每种生态给出：声明了哪些包、解析到的版本（用来查 OSV）、装没装、代码里用了却没声明的、声明了却可能没用到的。
只做确定性高的判断：Java / C# / PHP 的 import 是命名空间，不能可靠映射回包名，这几种不判"用了没声明"。
"""
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .languages import CODE_SKIP_DIRS, JS_LANGS, SFC_LANGS, language_of, load_source
from .skills import walk_files

MANIFEST_SUFFIXES = {'.json', '.xml', '.gradle', '.kts', '.mod', '.csproj', '.props'}
NODE_BUILTINS = frozenset(
    'assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns domain events fs http http2 '
    'https inspector module net os path perf_hooks process punycode querystring readline repl stream string_decoder sys timers tls '
    'trace_events tty url util v8 vm wasi worker_threads zlib test'.split())
JS_IMPORTS = [re.compile(r'\bimport\s+(?:type\s+)?(?:[\w$*{}\s,]+?\s+from\s*)?(["\'])'),
              re.compile(r'\bexport\s+(?:type\s+)?(?:\*(?:\s+as\s+[\w$]+)?|\{[^}]*\})\s*from\s*(["\'])'),
              re.compile(r'(?<![\w$.])(?:require|import)\s*\(\s*(["\'])')]
AUX_SUFFIXES = {'.css', '.scss', '.sass', '.less', '.styl', '.html', '.json', '.yml', '.yaml', '.babelrc', '.postcssrc'}


def _rel(p, base):
    p = Path(p)
    return str(p.relative_to(base)) if p.is_relative_to(base) else str(p)


def _read(p):
    try: return Path(p).read_text(encoding='utf-8-sig', errors='replace')
    except OSError: return ''


def _json(p):
    try: return json.loads(_read(p) or 'null')
    except ValueError: return None


def _jsonc(p):
    """tsconfig 这类允许注释和尾逗号的 JSON。"""
    text = re.sub(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/', lambda m: m.group() if m.group().startswith('"') else '', _read(p))
    try: return json.loads(re.sub(r',(\s*[}\]])', r'\1', text) or 'null')
    except ValueError: return None


def manifests(root):
    """目标目录里（以及目标往上最近的）各种依赖清单文件，按文件名分组。"""
    files, _ = walk_files(root, MANIFEST_SUFFIXES, 20000, CODE_SKIP_DIRS) if root.is_dir() else ([], False)
    found = {}
    for f in files:
        key = 'csproj' if f.suffix == '.csproj' else 'gradle' if f.name in ('build.gradle', 'build.gradle.kts') else f.name
        found.setdefault(key, []).append(f)
    for name in ('package.json', 'go.mod', 'pom.xml', 'composer.json'):
        if found.get(name): continue
        for d in list(root.parents)[:4]:
            if (d/name).is_file(): found[name] = [d/name]; break
    return found


def _owner(f, dirs):
    """离文件最近的、包含它的清单目录。dirs 已按深度从深到浅排序。"""
    return next((d for d in dirs if f.is_relative_to(d)), None)


def js_specifiers(src):
    for rx in JS_IMPORTS:
        for m in rx.finditer(src.code):
            q = m.end() - 1
            e = src.code.find(src.code[q], q + 1)
            spec = src.script[q + 1:e] if e > 0 else ''
            if spec and '\n' not in spec: yield spec, src.line(q)


def npm_package(spec):
    """导入路径 → npm 包名；'builtin' 表示 Node 内置模块；None 表示相对路径、别名或虚拟模块。"""
    if spec.startswith(('.', '/', '~', '#', '$', 'virtual:')) or (':' in spec and not spec.startswith('node:')): return None
    first = spec.split('/')[0]
    if spec.startswith('node:') or first in NODE_BUILTINS: return 'builtin'
    if spec.startswith('@'):
        parts = spec.split('/')
        return '/'.join(parts[:2]) if len(parts) > 1 and parts[0] != '@' else None
    return first


def _node_aliases(pdir):
    prefixes, bases = set(), []
    for name in ('tsconfig.json', 'jsconfig.json', 'tsconfig.app.json', 'tsconfig.base.json'):
        cfg, seen = _jsonc(pdir/name) if (pdir/name).is_file() else None, 0
        here = pdir
        while isinstance(cfg, dict) and seen < 3:
            opts = cfg.get('compilerOptions') or {}
            for k in (opts.get('paths') or {}):
                k = k.rstrip('*').rstrip('/')
                if k: prefixes.add(k)
            if isinstance(opts.get('baseUrl'), str): bases.append(here/opts['baseUrl'])
            ext = cfg.get('extends')
            if not (isinstance(ext, str) and ext.startswith('.')): break
            nxt = (here/ext).resolve()
            if nxt.suffix != '.json': nxt = nxt.with_suffix('.json')
            here, cfg, seen = nxt.parent, _jsonc(nxt) if nxt.is_file() else None, seen + 1
    for cfg in list(pdir.glob('*.config.*')) + list(pdir.glob('.umirc*')):
        text = _read(cfg)
        for m in re.finditer(r'''['"]?([@~#$]?[\w$/.-]*)['"]?\s*:\s*(?:path\.)?(?:resolve|join|fileURLToPath)\s*\(|\bfind\s*:\s*['"]([^'"]+)['"]''', text):
            alias = (m.group(1) or m.group(2) or '').rstrip('/')
            if alias: prefixes.add(alias)
    return prefixes, bases


def _lock_versions(pdir):
    """锁文件里解析到的版本：package-lock.json > yarn.lock > pnpm-lock.yaml。返回 (锁文件名, {包: 版本})。"""
    for d in [pdir, *list(pdir.parents)[:3]]:
        lock = _json(d/'package-lock.json') if (d/'package-lock.json').is_file() else None
        if isinstance(lock, dict):
            out = {k.rsplit('node_modules/', 1)[-1]: v.get('version') for k, v in (lock.get('packages') or {}).items()
                   if k.startswith('node_modules/') and k.count('node_modules/') == 1 and isinstance(v, dict)}
            out.update({k: v.get('version') for k, v in (lock.get('dependencies') or {}).items() if isinstance(v, dict) and k not in out})
            return 'package-lock.json', {k: v for k, v in out.items() if v}
        if (d/'yarn.lock').is_file():
            out = {}
            for m in re.finditer(r'(?m)^"?(@?[^@\s"]+)@[^\n]*:\n(?:[ \t]+[^\n]*\n)*?[ \t]+version:?\s+"?([^"\s]+)"?', _read(d/'yarn.lock')):
                out.setdefault(m.group(1), m.group(2))
            return 'yarn.lock', out
        if (d/'pnpm-lock.yaml').is_file():
            out = {}
            for m in re.finditer(r"(?m)^\s+'?/?(@?[^@\s'/]+(?:/[^@\s'/]+)?)@(\d+\.\d+\.\d+[\w.+-]*)(?:\([^\n]*\))?'?:\s*$", _read(d/'pnpm-lock.yaml')):
                out.setdefault(m.group(1), m.group(2))
            return 'pnpm-lock.yaml', out
    return None, {}


def _installed(pdir, name):
    for d in [pdir, *list(pdir.parents)[:5]]:
        pkg = d/'node_modules'/name/'package.json'
        if pkg.is_file():
            data = _json(pkg)
            return True, (data or {}).get('version') if isinstance(data, dict) else None
    return False, None


def analyze_npm(pkg_files, code_files, root, base):
    projects = []
    for p in pkg_files:
        data = _json(p)
        if isinstance(data, dict): projects.append((p.parent, data))
    if not projects: return []
    dirs = sorted((d for d, _ in projects), key=lambda d: -len(d.parts))
    by_dir = dict(projects)
    workspace_names = {data.get('name') for _, data in projects if data.get('name')}
    imports = {d: {} for d in dirs}
    for f in code_files:
        lang = language_of(f)
        if lang not in JS_LANGS and lang not in SFC_LANGS: continue
        d = _owner(f, dirs)
        if d is None: continue
        try: src = load_source(f)
        except OSError: continue
        for spec, line in js_specifiers(src):
            imports[d].setdefault(spec, set()).add(f'{_rel(f, base)}:{line}')
    out = []
    for d in sorted(dirs, key=lambda d: len(d.parts)):
        data = by_dir[d]
        sections = {k: data.get(k) or {} for k in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies')}
        declared = {n for s in sections.values() if isinstance(s, dict) for n in s}
        inherited = {n for a in d.parents if a in by_dir for k in ('dependencies', 'devDependencies')
                     for n in (by_dir[a].get(k) or {}) if isinstance(by_dir[a].get(k), dict)}
        prefixes, bases = _node_aliases(d)
        lockfile, locked = _lock_versions(d)
        has_modules = any((a/'node_modules').is_dir() for a in [d, *list(d.parents)[:5]])
        used, undeclared = set(), {}
        for spec, locs in imports[d].items():
            if any(spec == a or spec.startswith(a + '/') for a in prefixes): continue
            name = npm_package(spec)
            if name in (None, 'builtin') or name == data.get('name') or name in workspace_names: continue
            if any((b/spec.split('/')[0]).exists() or any((b/(spec + e)).exists() for e in ('.ts', '.js', '.tsx', '.jsx', '.vue')) for b in bases): continue
            used.add(name)
            if name not in declared and name not in inherited and f'@types/{name}' not in declared:
                undeclared.setdefault(name, set()).update(locs)
        packages, missing, missing_dev = {}, [], []
        for name in sorted(declared):
            ok, version = _installed(d, name)
            version = version or locked.get(name)
            packages[name] = version
            optional = name in sections['peerDependencies'] or name in sections['optionalDependencies']
            if has_modules and not ok and not optional:
                (missing_dev if name in sections['devDependencies'] and name not in sections['dependencies'] else missing).append(name)
        undeclared_list = []
        for name, locs in sorted(undeclared.items()):
            ok, _ = _installed(d, name)
            undeclared_list.append({'package': name, 'installed': ok, 'files': sorted(locs)[:5]})
            if has_modules and not ok: missing.append(name)
        unused = []
        prod = [n for n in sections['dependencies'] if n not in used and not n.startswith('@types/')]
        if prod:
            corpus = _project_corpus(d, root, dirs)
            unused = [n for n in prod if n not in corpus]
        out.append({'dir': _rel(d, base) if d != base else '.', 'name': data.get('name'), 'declared': len(declared),
                    'dev': len(sections['devDependencies']), 'node_modules': has_modules, 'lockfile': lockfile,
                    'missing': sorted(set(missing)), 'missing_dev': missing_dev, 'undeclared': undeclared_list, 'unused': unused, 'versions': packages})
    return out


def _project_corpus(d, root, dirs):
    """项目里除 package.json / 锁文件外所有源码、样式、配置的原文，用来判断依赖名是否出现过。"""
    start = d if d.is_relative_to(root) else root
    files, _ = walk_files(start, None, 8000, CODE_SKIP_DIRS)
    parts = []
    for f in files:
        if f.name in ('package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml') or _owner(f, dirs) != d: continue
        if language_of(f) or f.suffix in AUX_SUFFIXES or (f.name.startswith('.') and 'rc' in f.name):
            try:
                if f.stat().st_size <= 500_000: parts.append(_read(f))
            except OSError: pass
    return '\n'.join(parts)


def _strip_ns(root):
    for el in root.iter():
        if isinstance(el.tag, str): el.tag = el.tag.split('}')[-1]
    return root


def _xml(p):
    try: return _strip_ns(ET.parse(p).getroot())
    except (ET.ParseError, OSError): return None


def analyze_maven(poms, base):
    parsed = [(p, r) for p in poms if (r := _xml(p)) is not None and r.tag == 'project']
    props, managed = {}, {}
    for _, r in parsed:
        for pr in r.findall('properties'):
            for c in pr: props.setdefault(c.tag, (c.text or '').strip())
        v = r.findtext('version') or r.findtext('parent/version')
        if v: props.setdefault('project.version', v.strip())
        for dep in r.findall('dependencyManagement/dependencies/dependency'):
            managed.setdefault(f"{(dep.findtext('groupId') or '').strip()}:{(dep.findtext('artifactId') or '').strip()}", (dep.findtext('version') or '').strip())

    def resolve(v):
        for _ in range(5):
            if '${' not in v: break
            v = re.sub(r'\$\{([^}]+)\}', lambda m: props.get(m.group(1), m.group()), v)
        return v if v and '${' not in v and not v.startswith(('[', '(')) else None

    modules = []
    for p, r in parsed:
        boot = None
        if (r.findtext('parent/groupId') or '').strip() == 'org.springframework.boot': boot = resolve((r.findtext('parent/version') or '').strip())
        boot = boot or resolve(managed.get('org.springframework.boot:spring-boot-dependencies', ''))
        deps, seen, dups = [], set(), []
        for dep in r.findall('dependencies/dependency'):
            g, a = (dep.findtext('groupId') or '').strip(), (dep.findtext('artifactId') or '').strip()
            key = f"{g}:{a}:{(dep.findtext('classifier') or '').strip()}:{(dep.findtext('type') or '').strip()}"
            if key in seen: dups.append(f'{g}:{a}')
            seen.add(key)
            raw = (dep.findtext('version') or '').strip()
            version = resolve(raw or managed.get(f'{g}:{a}', ''))
            if not version and not raw and g.startswith('org.springframework.boot'): version = boot
            deps.append({'name': f'{g}:{a}', 'version': version, 'managed': not raw, 'scope': (dep.findtext('scope') or 'compile').strip()})
        modules.append({'file': _rel(p, base), 'artifact': (r.findtext('artifactId') or '').strip(), 'deps': deps, 'duplicates': dups})
    return modules


GRADLE_CONF = (r'(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly|annotationProcessor|kapt|ksp|'
               r'compile|testCompile|developmentOnly|debugImplementation|releaseImplementation|androidTestImplementation)')
GRADLE_DEP = re.compile(GRADLE_CONF + r'''\s*\(?\s*(?:platform\s*\(\s*|enforcedPlatform\s*\(\s*)?["']([\w.\-]+):([\w.\-]+)(?::([^"'@\s]+))?["']''')
GRADLE_MAP = re.compile(GRADLE_CONF + r'''\s*\(?\s*group\s*[:=]\s*["']([^"']+)["']\s*,\s*name\s*[:=]\s*["']([^"']+)["'](?:\s*,\s*version\s*[:=]\s*["']([^"']+)["'])?''')
GRADLE_CATALOG = re.compile(GRADLE_CONF + r'\s*\(?\s*(?:platform\s*\(\s*)?libs\.([\w.]+)')


def _catalog(path):
    try: import tomllib
    except ImportError: return {}
    try: data = tomllib.loads(_read(path))
    except ValueError: return {}
    versions, libs = data.get('versions') or {}, {}
    for alias, spec in (data.get('libraries') or {}).items():
        if isinstance(spec, str):
            parts = spec.split(':'); name, version = ':'.join(parts[:2]), parts[2] if len(parts) > 2 else None
        elif isinstance(spec, dict):
            name = spec.get('module') or f"{spec.get('group')}:{spec.get('name')}"
            v = spec.get('version')
            version = versions.get(v.get('ref')) if isinstance(v, dict) else v
            if isinstance(version, dict): version = version.get('strictly') or version.get('require')
        else: continue
        libs[re.sub(r'[-_]', '.', alias)] = (name, version if isinstance(version, str) else None)
    return libs


def analyze_gradle(builds, base):
    modules = []
    for b in builds:
        text = _read(b)
        variables = dict(re.findall(r'''(?m)^\s*(?:def|val|var|ext\.)?\s*(\w+)\s*=\s*["']([^"'$]+)["']''', text))
        for d in [b.parent, *list(b.parents)[:3]]:
            gp = d/'gradle.properties'
            if gp.is_file(): variables.update(re.findall(r'(?m)^\s*([\w.]+)\s*=\s*(\S+)\s*$', _read(gp)))
        boot = re.search(r'''id\s*\(?\s*["']org\.springframework\.boot["']\s*\)?\s*version\s*["']([^"']+)''', text)
        catalog = next((_catalog(d/'gradle'/'libs.versions.toml') for d in [b.parent, *list(b.parents)[:3]] if (d/'gradle'/'libs.versions.toml').is_file()), {})

        def resolve(v):
            if not v: return None
            v = re.sub(r'\$\{?([\w.]+)\}?', lambda m: variables.get(m.group(1), m.group()), v)
            return None if '$' in v or v.endswith('+') or v.startswith(('[', '(')) else v

        deps = []
        for m in list(GRADLE_DEP.finditer(text)) + list(GRADLE_MAP.finditer(text)):
            g, a, v = m.group(1), m.group(2), m.group(3)
            version = resolve(v) or (boot.group(1) if not v and boot and g.startswith('org.springframework.boot') else None)
            deps.append({'name': f'{g}:{a}', 'version': version, 'managed': not v})
        for m in GRADLE_CATALOG.finditer(text):
            name, version = catalog.get(m.group(1), (None, None))
            if name: deps.append({'name': name, 'version': version, 'managed': version is None})
        seen, dups = set(), []
        for dep in deps:
            if dep['name'] in seen: dups.append(dep['name'])
            seen.add(dep['name'])
        modules.append({'file': _rel(b, base), 'deps': deps, 'duplicates': sorted(set(dups))})
    return modules


def _go_mod(path):
    text = _read(path)
    module = re.search(r'(?m)^module\s+(\S+)', text)
    requires, replaces = {}, set()
    for kw, store in (('require', requires), ('replace', None)):
        lines = []
        for blk in re.finditer(rf'(?m)^{kw}\s*\(([\s\S]*?)^\)', text): lines += blk.group(1).splitlines()
        lines += [m.group(1) for m in re.finditer(rf'(?m)^{kw}\s+([^(\s][^\n]*)$', text)]
        for line in lines:
            parts = line.split('//')[0].split()
            if not parts: continue
            if store is None: replaces.add(parts[0])
            elif len(parts) >= 2: store[parts[0]] = {'version': parts[1], 'indirect': 'indirect' in line}
    return (module.group(1) if module else None), requires, replaces


def go_imports(src):
    code = src.code
    spans = [m.span(1) for m in re.finditer(r'\bimport\s*\(([^)]*)\)', code)]
    spans += [(m.end() - 1, m.end() + 300) for m in re.finditer(r'\bimport\s+(?:[\w.]+\s+)?"', code)]
    for s, e in spans:
        for q in re.finditer(r'"', code[s:e]):
            k = s + q.start()
            spec = src.string_at(k)
            if spec is not None:
                yield spec
                if code[s - 1:s] != '(': break


def analyze_go(mods, code_files, base):
    infos = {m.parent: _go_mod(m) for m in mods}
    if not infos: return []
    dirs = sorted(infos, key=lambda d: -len(d.parts))
    local_modules = {info[0] for info in infos.values() if info[0]}
    imports = {d: {} for d in dirs}
    for f in code_files:
        if language_of(f) != 'go': continue
        d = _owner(f, dirs)
        if d is None: continue
        try: src = load_source(f)
        except OSError: continue
        for spec in go_imports(src): imports[d].setdefault(spec, set()).add(_rel(f, base))
    out = []
    for d in sorted(dirs, key=lambda d: len(d.parts)):
        module, requires, replaces = infos[d]
        undeclared, used = {}, set()
        for spec, files in imports[d].items():
            if '.' not in spec.split('/')[0]: continue
            if any(spec == m or spec.startswith(m + '/') for m in local_modules): continue
            req = next((r for r in requires if spec == r or spec.startswith(r + '/')), None)
            if req: used.add(req)
            elif not any(spec == r or spec.startswith(r + '/') for r in replaces): undeclared.setdefault(spec, set()).update(files)
        unused = [r for r, info in requires.items() if not info['indirect'] and r not in used] if imports[d] else []
        out.append({'file': _rel(d/'go.mod', base), 'module': module, 'requires': requires,
                    'undeclared': [{'package': k, 'files': sorted(v)[:5]} for k, v in sorted(undeclared.items())], 'unused': sorted(unused)})
    return out


def analyze_composer(files, base):
    out = []
    for p in files:
        data = _json(p)
        if not isinstance(data, dict): continue
        declared = {k: v for sec in ('require', 'require-dev') for k, v in (data.get(sec) or {}).items()
                    if '/' in k and not k.startswith(('ext-', 'lib-'))}
        lock = _json(p.parent/'composer.lock') if (p.parent/'composer.lock').is_file() else None
        locked = {pk['name']: str(pk.get('version', '')).lstrip('v') for sec in ('packages', 'packages-dev')
                  for pk in ((lock or {}).get(sec) or []) if isinstance(pk, dict) and pk.get('name')} if isinstance(lock, dict) else {}
        vendor = (p.parent/'vendor').is_dir()
        out.append({'file': _rel(p, base), 'declared': len(declared), 'vendor': vendor, 'lockfile': bool(locked),
                    'missing': [n for n in declared if vendor and not (p.parent/'vendor'/n).is_dir()],
                    'versions': {n: locked.get(n) for n in declared}})
    return out


def analyze_nuget(projects, central, base):
    central_versions = {}
    for c in central:
        r = _xml(c)
        if r is None: continue
        for pv in r.iter('PackageVersion'):
            if pv.get('Include'): central_versions[pv.get('Include')] = pv.get('Version')
    out = []
    for p in projects:
        r = _xml(p)
        if r is None: continue
        refs = {}
        for ref in r.iter('PackageReference'):
            name = ref.get('Include') or ref.get('Update')
            if not name: continue
            v = ref.get('Version') or ref.findtext('Version') or central_versions.get(name)
            refs[name] = v if v and not v.startswith(('$', '[', '(')) and '*' not in v else None
        out.append({'file': _rel(p, base), 'versions': refs})
    return out


def analyze(root, base, code_files):
    """返回 {生态: 结果} 和用来查 OSV 的 [(生态, 包名, 版本)]。"""
    found = manifests(root)
    result = {}
    npm = analyze_npm(found.get('package.json', []), code_files, root, base)
    if npm: result['npm'] = npm
    maven = analyze_maven(found.get('pom.xml', []), base)
    if maven: result['maven'] = maven
    gradle = analyze_gradle(found.get('gradle', []), base)
    if gradle: result['gradle'] = gradle
    go = analyze_go(found.get('go.mod', []), code_files, base)
    if go: result['go'] = go
    composer = analyze_composer(found.get('composer.json', []), base)
    if composer: result['composer'] = composer
    nuget = analyze_nuget(found.get('csproj', []), found.get('Directory.Packages.props', []), base)
    if nuget: result['nuget'] = nuget
    packages = set()
    for proj in npm: packages |= {('npm', n, v) for n, v in proj['versions'].items() if v}
    for mod in maven + gradle: packages |= {('Maven', d['name'], d['version']) for d in mod['deps'] if d['version']}
    for mod in go: packages |= {('Go', n, info['version']) for n, info in mod['requires'].items()}
    for c in composer: packages |= {('Packagist', n, v) for n, v in c['versions'].items() if v}
    for n in nuget: packages |= {('NuGet', k, v) for k, v in n['versions'].items() if v}
    return result, sorted(packages)
