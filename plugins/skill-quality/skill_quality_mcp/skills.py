"""发现并校验 Cursor / Codex Agent Skills（SKILL.md）。"""
import hashlib
import os
import re
from pathlib import Path

NAME_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,63}$')
DESCRIPTION_MAX, BODY_LINES_MAX = 1024, 500
LINK_RE = re.compile(r'(?<!!)\[[^\]]*\]\(([^)\s]+)\)')
CODE_PATH_RE = re.compile(r'`((?:scripts|references|assets|agents)/[^`\s]+)`')
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'site-packages'}


def walk_files(root, suffixes=None, limit=None, skip_dirs=SKIP_DIRS):
    """遍历 root 下的文件，返回 (文件列表, 是否因 limit 截断)。
    skip_dirs 只对 root 以下的目录生效：目标本身位于 site-packages 里时照样扫描。"""
    root = Path(root)
    if root.is_file(): return ([root] if not suffixes or root.suffix in suffixes else []), False
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
        for name in sorted(filenames):
            if suffixes and Path(name).suffix not in suffixes: continue
            out.append(Path(dirpath)/name)
            if limit and len(out) >= limit: return out, True
    return out, False


def default_roots():
    """Cursor、Codex、Claude 的用户级技能目录和插件目录，加上 SKILL_DIRS / WORKSPACE_DIRS 和当前工作目录。"""
    home = Path.home()
    roots = [home/'.cursor'/'skills', home/'.cursor'/'skills-cursor', home/'.cursor'/'plugins'/'local', home/'.cursor'/'plugins'/'cache',
             home/'.agents'/'skills', home/'.codex'/'skills', home/'.codex'/'plugins'/'cache', home/'.claude'/'skills']
    def env_list(name):
        return [p.strip() for p in os.environ.get(name, '').split(os.pathsep) if p.strip() and not p.strip().startswith('${')]
    roots += [Path(p) for p in env_list('SKILL_DIRS')]
    workspaces = env_list('WORKSPACE_DIRS')
    cwd = Path.cwd()
    if cwd != home and not (cwd/'.cursor-plugin').exists() and not (cwd/'.codex-plugin').exists(): workspaces.append(str(cwd))
    for ws in workspaces:
        roots += [Path(ws)/'.cursor'/'skills', Path(ws)/'.agents'/'skills', Path(ws)/'.codex'/'skills', Path(ws)/'.claude'/'skills']
    return roots


def find_skill_files(root, max_depth=6):
    root = Path(root)
    if root.is_file() and root.name == 'SKILL.md': return [root]
    if not root.is_dir(): return []
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if len(Path(dirpath).relative_to(root).parts) >= max_depth: dirnames[:] = []
        if 'SKILL.md' in filenames: found.append(Path(dirpath)/'SKILL.md')
    return found


def parse_frontmatter(text):
    """极简 YAML：支持 key: value 和 key: >- / | 多行块，够用来读 SKILL.md。"""
    if not text.startswith('---'): return None, text
    end = text.find('\n---', 3)
    if end < 0: return None, text
    head, body = text[3:end].strip('\n'), text[end+4:].lstrip('\n')
    meta, key, block = {}, None, []
    for line in head.splitlines():
        m = re.match(r'^([A-Za-z_][\w-]*):\s*(.*)$', line)
        if m and not line.startswith((' ', '\t')):
            if key and block: meta[key] = ' '.join(block).strip()
            key, value, block = m[1], m[2].strip(), []
            if value in ('>', '>-', '|', '|-', ''): continue
            meta[key] = value.strip('"\''); key = None
        elif key: block.append(line.strip())
    if key and block: meta[key] = ' '.join(block).strip()
    return meta, body


def list_skills(extra_dirs=''):
    roots = default_roots() + [Path(p.strip()) for p in extra_dirs.split(',') if p.strip()]
    skills, seen = [], set()
    for root in roots:
        for f in find_skill_files(root):
            key = str(f.resolve()).lower()
            if key in seen: continue
            seen.add(key)
            raw = f.read_bytes()
            meta, _ = parse_frontmatter(raw.decode('utf-8', errors='replace'))
            meta = meta or {}
            skills.append({'name': meta.get('name') or f.parent.name, 'description': meta.get('description', ''),
                           'path': str(f.parent), 'root': str(root),
                           'digest': hashlib.sha1(raw.replace(b'\r\n', b'\n')).hexdigest()[:12]})
    return skills


def name_conflicts(skills):
    """同名技能分两类：内容完全相同的镜像（如 Cursor 与 Codex 各装一份）和内容不同的真冲突。"""
    by_name = {}
    for s in skills: by_name.setdefault(s['name'], []).append(s)
    mirrors, conflicts = {}, {}
    for name, group in by_name.items():
        if len(group) < 2: continue
        (mirrors if len({s['digest'] for s in group}) == 1 else conflicts)[name] = group
    return mirrors, conflicts


def skill_matches(target):
    return [s for s in list_skills() if s['name'] == target or Path(s['path']).name == target]


def resolve_skill(target):
    """target 可以是 SKILL.md 路径、技能目录或技能名。"""
    p = Path(target).expanduser()
    if p.is_file() and p.name == 'SKILL.md': return p.parent
    if p.is_dir() and (p/'SKILL.md').is_file(): return p
    matches = skill_matches(target)
    return Path(matches[0]['path']) if matches else None


def slugify(heading):
    heading = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', heading.strip().lower())
    return re.sub(r'[^\w\- ]', '', heading).replace(' ', '-')


def anchors_of(md_file):
    slugs, counts = set(), {}
    in_code = False
    for line in md_file.read_text(encoding='utf-8', errors='replace').splitlines():
        if line.lstrip().startswith('```'): in_code = not in_code
        if in_code: continue
        m = re.match(r'^#{1,6}\s+(.*?)\s*#*\s*$', line)
        if m:
            s = slugify(m[1]); n = counts.get(s, 0); counts[s] = n + 1
            slugs.add(s if n == 0 else f'{s}-{n}')
    return slugs


def issue(severity, rule, message, file=None, line=None):
    return {'severity': severity, 'rule': rule, 'message': message, 'file': str(file) if file else None, 'line': line}


def validate_skill(skill_dir):
    skill_dir = Path(skill_dir); skill_md = skill_dir/'SKILL.md'; issues = []
    if not skill_md.is_file():
        return {'skill': str(skill_dir), 'issues': [issue('BLOCKER', 'skill:missing-skill-md', '目录里没有 SKILL.md')]}
    text = skill_md.read_text(encoding='utf-8', errors='replace')
    meta, body = parse_frontmatter(text)
    if meta is None:
        issues.append(issue('BLOCKER', 'skill:frontmatter', 'SKILL.md 开头缺少 --- YAML frontmatter', skill_md, 1)); meta = {}
    name, desc = meta.get('name', ''), meta.get('description', '')
    if not name: issues.append(issue('CRITICAL', 'skill:name', 'frontmatter 缺少 name', skill_md, 1))
    elif not NAME_RE.match(name): issues.append(issue('MAJOR', 'skill:name', f'name “{name}” 应为小写字母、数字、连字符，≤64字符', skill_md, 1))
    elif name != skill_dir.name: issues.append(issue('MINOR', 'skill:name-folder', f'name “{name}” 与目录名 “{skill_dir.name}” 不一致', skill_md, 1))
    if not desc: issues.append(issue('CRITICAL', 'skill:description', 'frontmatter 缺少 description，Agent 无法判断何时触发', skill_md, 1))
    else:
        if len(desc) > DESCRIPTION_MAX: issues.append(issue('MAJOR', 'skill:description-length', f'description {len(desc)} 字符，超过 {DESCRIPTION_MAX}', skill_md, 1))
        if not re.search(r'use (this )?(skill )?when|when (the )?user|触发|使用场景|用于', desc, re.I):
            issues.append(issue('MINOR', 'skill:description-trigger', 'description 没写触发条件（如 “Use when …”），Agent 可能不会自动选用', skill_md, 1))
    body_lines = body.count('\n') + 1
    if body_lines > BODY_LINES_MAX:
        issues.append(issue('MAJOR', 'skill:body-length', f'SKILL.md 正文 {body_lines} 行，超过 {BODY_LINES_MAX} 行，细节应拆到 references/', skill_md))
    all_files, _ = walk_files(skill_dir)
    md_files = [f for f in all_files if f.suffix == '.md']
    anchor_cache = {}
    for md in md_files:
        lines = md.read_text(encoding='utf-8', errors='replace').splitlines(); in_code = False
        for no, line in enumerate(lines, 1):
            if line.lstrip().startswith('```'): in_code = not in_code
            if in_code: continue
            for link in LINK_RE.findall(line):
                if re.match(r'^[a-z][a-z0-9+.-]*:', link, re.I): continue
                path_part, _, anchor = link.partition('#')
                target = (md.parent/path_part).resolve() if path_part else md
                if not target.exists():
                    issues.append(issue('MAJOR', 'skill:broken-link', f'链接目标不存在：{link}', md, no)); continue
                if anchor and target.suffix == '.md':
                    if target not in anchor_cache: anchor_cache[target] = anchors_of(target)
                    if anchor.lower() not in anchor_cache[target]:
                        issues.append(issue('MINOR', 'skill:broken-anchor', f'锚点 #{anchor} 在 {target.name} 里找不到对应标题', md, no))
            for ref in CODE_PATH_RE.findall(line):
                clean = ref.split('#')[0].rstrip('.,;:)')
                if any(ch in clean for ch in '*<>{}') or (skill_dir/clean).exists(): continue
                issues.append(issue('MINOR', 'skill:missing-file', f'文中提到的 `{clean}` 在技能目录里不存在', md, no))
    files = sorted(str(f.relative_to(skill_dir)) for f in all_files)
    for i in issues:
        if i['file'] and Path(i['file']).is_relative_to(skill_dir): i['file'] = str(Path(i['file']).relative_to(skill_dir))
    return {'skill': str(skill_dir), 'name': name, 'description': desc, 'body_lines': body_lines, 'files': files, 'issues': issues}
