"""多语言基础：按扩展名识别语言、遍历代码文件、把注释和字符串抹成空格、拆 Vue / Svelte 单文件组件。

规则匹配用“抹掉后的代码”：注释和字符串里的 if、{、password= 不会误触发。
抹掉时只换成空格、保留换行和引号，长度和原文完全一致，偏移量可以直接换算成原文的行号。
"""
import bisect
import functools
import re
from pathlib import Path

from .skills import SKIP_DIRS, walk_files

LANG_BY_EXT = {
    '.py': 'python',
    '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'jsx',
    '.ts': 'typescript', '.mts': 'typescript', '.cts': 'typescript', '.tsx': 'tsx',
    '.vue': 'vue', '.svelte': 'svelte',
    '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin', '.go': 'go', '.cs': 'csharp', '.php': 'php',
}
# 本地规则还没覆盖、但改动里出现时要告诉调用方自己按该语言检查的源文件
EXTRA_SOURCE = {
    '.rs': 'Rust', '.rb': 'Ruby', '.erb': 'Ruby', '.swift': 'Swift', '.dart': 'Dart',
    '.c': 'C', '.h': 'C/C++', '.hh': 'C++', '.cc': 'C++', '.cpp': 'C++', '.cxx': 'C++', '.hpp': 'C++', '.hxx': 'C++',
    '.m': 'Objective-C', '.mm': 'Objective-C++', '.scala': 'Scala', '.sc': 'Scala', '.groovy': 'Groovy',
    '.ex': 'Elixir', '.exs': 'Elixir', '.erl': 'Erlang', '.hrl': 'Erlang', '.hs': 'Haskell', '.lua': 'Lua',
    '.r': 'R', '.sql': 'SQL', '.sh': 'Shell', '.bash': 'Shell', '.zsh': 'Shell', '.ps1': 'PowerShell',
    '.tf': 'Terraform', '.proto': 'Protobuf', '.zig': 'Zig', '.nim': 'Nim', '.clj': 'Clojure', '.cljs': 'ClojureScript',
    '.fs': 'F#', '.fsx': 'F#', '.vb': 'Visual Basic', '.pl': 'Perl', '.pm': 'Perl', '.sol': 'Solidity',
}
DISPLAY = {'python': 'Python', 'javascript': 'JavaScript', 'jsx': 'JSX', 'typescript': 'TypeScript', 'tsx': 'TSX',
           'vue': 'Vue', 'svelte': 'Svelte', 'java': 'Java', 'kotlin': 'Kotlin', 'go': 'Go', 'csharp': 'C#', 'php': 'PHP'}
JS_LANGS = frozenset({'javascript', 'jsx', 'typescript', 'tsx'})
SFC_LANGS = frozenset({'vue', 'svelte'})
CODE_SKIP_DIRS = SKIP_DIRS | {'dist', 'build', 'out', 'target', 'coverage', 'vendor', 'obj', 'bower_components', '.next', '.nuxt',
                              '.output', '.svelte-kit', '.turbo', '.cache', '.parcel-cache', '.gradle', '.mvn', '.idea', '.vscode',
                              '.pytest_cache', '.mypy_cache', '.ruff_cache', '.tox'}
# 改动里出现、但既不是代码也不是要单独报的资源
NON_CODE_EXT = {
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.pdf', '.zip', '.gz', '.woff', '.woff2', '.ttf', '.eot',
    '.lock', '.md', '.txt', '.rst', '.json', '.yml', '.yaml', '.xml', '.html', '.css', '.scss', '.less', '.map', '.snap',
    '.csv', '.tsv', '.log', '.toml', '.ini', '.cfg', '.conf', '.env', '.sum', '.mod', '.gradle', '.plist', '.pbxproj',
}
FILE_LIMIT, MAX_FILE_BYTES = 5000, 1_000_000
GENERATED = re.compile(r'\.(?:min|bundle|chunk)\.[cm]?js$|\.d\.[cm]?ts$|\.(?:pb|g|generated)\.\w+$|_pb2(?:_grpc)?\.py$', re.I)
TEST_PATH = re.compile(r'(?:^|[\\/])(?:__tests__|__mocks__|tests?|spec|testdata|e2e)[\\/]|(?:^|[\\/])test_[^\\/]*\.py$|_test\.(?:py|go)$'
                       r'|\.(?:test|spec|e2e)\.[cm]?[jt]sx?$|(?:Tests?|IT|Spec)\.(?:java|kt|cs)$', re.I)

# Python 与其他语言规则共用的阈值和判定
COGNITIVE_MAX, FUNCTION_LINES_MAX, PARAMS_MAX, LINE_MAX = 15, 100, 7, 160
SECRET_NAME = re.compile(r'(pass(word|wd)?|secret([_-]?key)?|token|api[_-]?key|access[_-]?key|private[_-]?key)$', re.I)
SAFE_HTTP = ('http://localhost', 'http://127.0.0.1', 'http://www.w3.org', 'http://schemas.', 'http://0.0.0.0', 'http://[::1]',
             # XML 命名空间和解析器特性名只是标识符，不会发起请求
             'http://xml.org/sax/', 'http://apache.org/xml/', 'http://javax.xml.', 'http://java.sun.com/xml/', 'http://xmlns.',
             'http://www.springframework.org/schema', 'http://maven.apache.org/POM', 'http://ns.adobe.com', 'http://purl.org/')
SCHEMA_URI = re.compile(r'^http://[^/\s]+/(?:[^\s]*/)?(?:schemas?|ns|xmlns)(?:/|$)|\.(?:xsd|dtd)$', re.I)


def plain_http(url):
    """明文 http 地址，排除本机地址和 XML/JSON Schema 命名空间这类只做标识符的 URI。"""
    return url.startswith('http://') and not url.startswith(SAFE_HTTP) and not SCHEMA_URI.search(url)


def language_of(path): return LANG_BY_EXT.get(Path(path).suffix.lower())


def _small(f):
    try: return f.stat().st_size <= MAX_FILE_BYTES
    except OSError: return False


def code_files(root, langs=None):
    """返回 (文件列表, 是否截断)；跳过依赖、构建产物目录和压缩/生成的文件。langs 限定语言。"""
    exts = {e for e, lang in LANG_BY_EXT.items() if langs is None or lang in langs}
    files, truncated = walk_files(root, exts, FILE_LIMIT, CODE_SKIP_DIRS)
    return [f for f in files if not GENERATED.search(f.name) and _small(f)], truncated


def is_compiled(path):
    """打包/转译产物：JS 文件末尾带 sourceMappingURL 注释。"""
    if language_of(path) not in JS_LANGS: return False
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2); f.seek(max(0, f.tell() - 300))
            return b'sourceMappingURL=' in f.read()
    except OSError: return False


def blank(s): return re.sub(r'[^\n]', ' ', s)


_TOKENS = {
    'js': re.compile(r'//|/\*|[`"\'/{}]'),
    'java': re.compile(r'//|/\*|"""|["\']'),
    'kotlin': re.compile(r'//|/\*|"""|["\'`]'),
    'csharp': re.compile(r'//|/\*|"""|@\$?"|["\']'),
    'go': re.compile(r'//|/\*|["\'`]'),
    'php': re.compile(r'//|/\*|#(?!\[)|["\']'),
}
_LITERAL = {
    '"': re.compile(r'"(?:\\[\s\S]|[^"\\\n])*"?'),
    "'": re.compile(r"'(?:\\[\s\S]|[^'\\\n])*'?"),
    '"""': re.compile(r'"""[\s\S]*?(?:"""|\Z)'),
    '`': re.compile(r'`[^`]*`?'),
    '@': re.compile(r'@\$?"(?:""|[^"])*"?'),
}
_REGEX = re.compile(r'/(?![*/])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/[a-z]*')
_REGEX_AFTER_WORD = re.compile(r'(?:^|[^\w$])(?:return|typeof|case|do|else|in|of|void|yield|await|delete|throw|new)$')
_TEMPLATE = re.compile(r'(?:\\[\s\S]|[^`\\$]|\$(?!\{))*')


def mask(text, lang):
    """返回 (code, strings, comments)：code 里注释和字符串内容都换成空格；strings、comments 是原文里的 (起, 止) 区间。
    JS 模板字符串里 ${...} 的表达式按代码保留；/ 是除号还是正则字面量按前一个有效字符判断；
    JS 里到行尾都没闭合的引号只可能是 JSX 文本里的撇号（Don't），按普通字符处理。"""
    fam = 'js' if lang in JS_LANGS or lang in SFC_LANGS else lang
    tok = _TOKENS.get(fam, _TOKENS['java'])
    out, strings, comments, tpl = [], [], [], []
    i, n, tail = 0, len(text), ''

    def code(s):
        nonlocal tail
        out.append(s)
        t = s.strip()
        if t: tail = (tail + ' ' + t)[-16:]

    def template(k):
        nonlocal tail
        e = _TEMPLATE.match(text, k).end()
        if e < n and text[e] == '`':
            out.append(blank(text[k:e]) + '`'); strings.append((k - 1, e + 1)); tail += '"'; return e + 1
        if e < n:
            out.append(blank(text[k:e]) + '  '); strings.append((k - 1, e + 2)); tpl.append(0); tail += '('; return e + 2
        out.append(blank(text[k:])); strings.append((k - 1, n)); return n

    while i < n:
        m = tok.search(text, i)
        if not m:
            code(text[i:]); break
        s, t = m.start(), m.group()
        if s > i: code(text[i:s])
        if t == '{':
            if tpl: tpl[-1] += 1
            code('{'); i = s + 1
        elif t == '}':
            if tpl and tpl[-1] == 0:
                tpl.pop(); out.append(' '); i = template(s + 1)
            else:
                if tpl: tpl[-1] -= 1
                code('}'); i = s + 1
        elif t in ('//', '#', '/*'):
            e = text.find('*/', s + 2) if t == '/*' else text.find('\n', s)
            e = n if e < 0 else (e + 2 if t == '/*' else e)
            out.append(blank(text[s:e])); comments.append((s, e)); i = e
        elif t == '/':
            r = _REGEX.match(text, s) if not tail or tail[-1] in '(,=:[!&|?;{+-*%~^' or _REGEX_AFTER_WORD.search(tail) else None
            if r:
                g = r.group(); j = g.rindex('/')
                out.append('/' + blank(g[1:j]) + g[j:]); tail += '"'; i = r.end()
            else:
                code('/'); i = s + 1
        elif t == '`' and fam == 'js':
            out.append('`'); i = template(s + 1)
        else:
            raw = _LITERAL['@' if t.startswith('@') else t].match(text, s).group()
            opening = len(t)
            closing = 3 if t == '"""' else 1
            if len(raw) < opening + closing or not raw.endswith(t[-1] * closing): closing = 0
            if fam == 'js' and not closing and t in '"\'':
                code(t); i = s + 1; continue
            out.append(raw[:opening] + blank(raw[opening:len(raw) - closing]) + raw[len(raw) - closing:])
            strings.append((s, s + len(raw))); tail += '"'; i = s + len(raw)
    return ''.join(out), strings, comments


_SCRIPT = re.compile(r'(<script\b[^>]*>)([\s\S]*?)</script\s*>', re.I)
_STYLE = re.compile(r'<style\b[^>]*>[\s\S]*?</style\s*>', re.I)
_HTML_COMMENT = re.compile(r'<!--[\s\S]*?-->')


def split_sfc(text):
    """Vue / Svelte 单文件组件 → (只留 <script> 内容的文本, 只留模板的文本, 脚本语言)，两者都与原文等长。"""
    parts, pos, lang = [], 0, 'javascript'
    for m in _SCRIPT.finditer(text):
        parts += [blank(text[pos:m.start(2)]), m.group(2)]; pos = m.end(2)
        if re.search(r'\blang\s*=\s*["\']?tsx?\b', m.group(1), re.I): lang = 'typescript'
    parts.append(blank(text[pos:]))
    markup = _SCRIPT.sub(lambda m: blank(m.group()), text)
    markup = _STYLE.sub(lambda m: blank(m.group()), markup)
    return ''.join(parts), _HTML_COMMENT.sub(lambda m: blank(m.group()), markup), lang


class Source:
    """一个源文件：text 原文，script 规则作用的文本（单文件组件只留 <script>），code 抹掉注释和字符串的 script，
    template 单文件组件的模板，script_lang 规则按哪种语言走（<script lang="ts"> 按 TypeScript）。"""

    def __init__(self, text, lang):
        self.text, self.lang = text, lang
        if lang in SFC_LANGS: self.script, self.template, self.script_lang = split_sfc(text)
        else: self.script, self.template, self.script_lang = text, '', lang
        self.code, self.strings, self.comments = mask(self.script, self.script_lang)
        self._string_starts = [s for s, _ in self.strings]
        self._comment_starts = [s for s, _ in self.comments]
        self._line_starts = [0] + [m.end() for m in re.finditer('\n', text)]

    def line(self, off): return bisect.bisect_right(self._line_starts, off)

    @staticmethod
    def _inside(starts, spans, off):
        k = bisect.bisect_right(starts, off) - 1
        return k >= 0 and spans[k][0] <= off < spans[k][1]

    def in_string(self, off): return self._inside(self._string_starts, self.strings, off)

    def in_comment(self, off): return self._inside(self._comment_starts, self.comments, off)

    def in_code(self, off): return not self.in_string(off) and not self.in_comment(off)

    def string_at(self, off):
        """off 处开始的字符串字面量 → 去掉引号的内容；不是字符串起点返回 None。"""
        k = bisect.bisect_left(self._string_starts, off)
        if k == len(self.strings) or self.strings[k][0] != off: return None
        return string_body(self.script[off:self.strings[k][1]])


def string_body(raw):
    raw = re.sub(r'^(?:@\$?|\$@?)?(?:"""|["\'`}])', '', raw)
    return re.sub(r'(?:"""|["\'`]|\$\{)$', '', raw)


@functools.lru_cache(maxsize=2048)
def _load(path, _mtime, _size, lang):
    return Source(Path(path).read_text(encoding='utf-8', errors='replace'), lang)


def load_source(path):
    """读文件并抹掉注释和字符串；按修改时间缓存，依赖分析和质量扫描读同一批文件时不重复处理。"""
    st = Path(path).stat()
    return _load(str(path), st.st_mtime_ns, st.st_size, language_of(path))
