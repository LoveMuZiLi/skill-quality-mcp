"""JavaScript / TypeScript / React / Vue / Svelte / Java / Kotlin / Go / C# / PHP 的本地规则。

这些语言在标准库里没有语法树，规则建立在 languages.Source 抹掉注释和字符串后的代码上：
函数靠花括号配对和函数头的形状识别，认知复杂度按控制关键字和花括号嵌套近似计算。
只收确定性高的模式；要类型推断、数据流的问题交给 ESLint / go vet / SonarQube。
rule 带语言前缀的（javascript:S1440、java:S106）表示近似对应该 SonarQube 规则，local: 开头的是本 MCP 自己的规则。
"""
import json
import os
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from .languages import (CODE_SKIP_DIRS, COGNITIVE_MAX, FUNCTION_LINES_MAX, JS_LANGS, LINE_MAX, PARAMS_MAX,
                        SECRET_NAME, SFC_LANGS, blank, plain_http, string_body)
from .skills import walk_files

JS_FUNCTION_LINES_MAX, FILE_LINES_MAX = 200, 1000
SONAR_LANG = {'javascript': 'javascript', 'jsx': 'javascript', 'typescript': 'typescript', 'tsx': 'typescript',
              'java': 'java', 'kotlin': 'kotlin', 'go': 'go', 'csharp': 'csharpsquid', 'php': 'php'}
JVM, SEMICOLON = {'java', 'kotlin'}, JS_LANGS | {'java', 'csharp', 'php'}
REACT_IMPORT = re.compile(r'''from\s+['"](?:react|preact)(?:/[\w-]+)?['"]|require\(\s*['"]react['"]\s*\)''')

# (适用语言, 类型, 严重度, 规则, 正则, 说明, 在哪匹配)。'code'：抹掉注释和字符串后的代码；
# 'text'：原文，但匹配起点必须在代码里（规则要看字符串内容，比如算法名）；'react'/'ui' 是附加条件。
PATTERNS = [
    (JS_LANGS, 'SECURITY_HOTSPOT', 'CRITICAL', 'S1523', r'(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*["\'`]',
     'eval / new Function / 字符串形式的定时器会动态执行代码，确认输入可信', 'code'),
    (JS_LANGS, 'CODE_SMELL', 'MAJOR', 'S1525', r'(?<![\w$.])debugger\b', 'debugger 语句不要提交', 'code'),
    (JS_LANGS, 'CODE_SMELL', 'MINOR', 'S3504', r'(?<![\w$.])var\s+[A-Za-z_$]', '用 let / const 代替 var', 'code'),
    (JS_LANGS, 'SECURITY_HOTSPOT', 'MAJOR', 'local:dom-xss', r'\.(?:innerHTML|outerHTML)\s*=(?!=)|\bdocument\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\(',
     '直接写入 HTML，内容含用户输入会导致 XSS', 'code'),
    (JS_LANGS, 'SECURITY_HOTSPOT', 'MAJOR', 'local:react-dangerous-html', r'\bdangerouslySetInnerHTML\b',
     'dangerouslySetInnerHTML 绕过了 React 的转义，内容必须先消毒（如 DOMPurify）', 'code'),
    (JS_LANGS, 'SECURITY_HOTSPOT', 'MAJOR', 'S6268', r'\bbypassSecurityTrust\w*\s*\(', 'Angular bypassSecurityTrust* 关闭了 XSS 防护，确认内容可信', 'code'),
    (JS_LANGS, 'VULNERABILITY', 'CRITICAL', 'S4830', r'\brejectUnauthorized\s*:\s*false\b', 'rejectUnauthorized: false 关闭了 TLS 证书校验', 'code'),
    (JS_LANGS, 'VULNERABILITY', 'CRITICAL', 'S4830', r'\bNODE_TLS_REJECT_UNAUTHORIZED\W{0,4}=\s*["\']?0', 'NODE_TLS_REJECT_UNAUTHORIZED=0 关闭了全局 TLS 证书校验', 'text'),
    (JS_LANGS, 'SECURITY_HOTSPOT', 'MINOR', 'S4790', r'\bcreateHash\s*\(\s*["\'](?:md5|sha1)["\']', 'MD5 / SHA-1 已不安全，密码和签名改用 SHA-256 以上或 bcrypt', 'text'),
    (JS_LANGS, 'VULNERABILITY', 'CRITICAL', 'S5547', r'\bcreateCipher(?:iv)?\s*\(\s*["\'](?:des|rc4|rc2|bf|aes-\d+-ecb)', '弱加密算法或 ECB 模式，改用 AES-GCM', 'text'),
    (JS_LANGS, 'SECURITY_HOTSPOT', 'MAJOR', 'S4721', r'\bshell\s*:\s*true\b', '子进程开启 shell: true，有命令注入风险', 'code'),
    (JS_LANGS, 'SECURITY_HOTSPOT', 'MINOR', 'S5122', r'(?<![\w$.])cors\s*\(\s*\)|\borigin\s*:\s*(?:["\']\*["\']|true\b)',
     'CORS 允许任意来源，确认接口不需要限制来源', 'text'),
    (JS_LANGS, 'CODE_SMELL', 'MAJOR', 'local:swallowed-exception', r'\.catch\s*\(\s*(?:\(\s*[\w$]*\s*\)|[\w$]+)\s*=>\s*\{\s*\}\s*\)',
     'Promise 错误被空的 .catch() 吞掉，出错时无从排查', 'code'),
    (JS_LANGS, 'BUG', 'MAJOR', 'local:react-async-effect', r'\buseEffect\s*\(\s*async\b',
     'useEffect 的回调不能是 async：返回的 Promise 会被当成清理函数，在回调里定义 async 函数再调用', 'react'),
    (JS_LANGS, 'BUG', 'MAJOR', 'local:react-state-mutation', r'\bthis\.state\.[\w$]+\s*(?:=(?!=)|\+\+|--|[+\-*/]=)',
     '直接修改 this.state 不会触发重新渲染，改用 setState', 'react'),
    (JS_LANGS, 'CODE_SMELL', 'MINOR', 'S6479', r'\bkey=\{\s*(?:index|idx|i)\s*\}', '用数组下标做 key，列表增删时组件状态会错位，改用数据的唯一 id', 'react'),
    (JS_LANGS, 'CODE_SMELL', 'MINOR', 'S1442', r'(?<![\w$.])alert\s*\(', 'alert() 会阻塞页面，改用页面内提示组件', 'ui'),
    ({'typescript', 'tsx'}, 'CODE_SMELL', 'MINOR', 'S4204', r'(?::\s*|\bas\s+|<\s*)any\b(?![\w$.(])', '用了 any，类型检查失效，写明具体类型或 unknown', 'code'),

    ({'java'}, 'CODE_SMELL', 'MINOR', 'S106', r'\bSystem\.(?:out|err)\.print', '用日志框架（SLF4J 等）代替 System.out / System.err', 'code'),
    ({'java'}, 'CODE_SMELL', 'MINOR', 'S1148', r'\.printStackTrace\s*\(\s*\)', 'printStackTrace() 绕过了日志框架，改用 log.error("…", e)', 'code'),
    ({'java'}, 'CODE_SMELL', 'MAJOR', 'S1181', r'\bcatch\s*\(\s*(?:final\s+)?(?:Throwable|Error)\s+\w+\s*\)', '不要 catch Throwable / Error，会连 OutOfMemoryError 一起吞掉', 'code'),
    ({'java'}, 'BUG', 'MAJOR', 'S4973', r'[!=]=\s*"|"\s*[!=]=', '字符串用 == 比较的是引用，改用 equals()', 'code'),
    ({'java'}, 'BUG', 'MAJOR', 'S2111', r'\bnew\s+BigDecimal\s*\(\s*-?\d+\.\d*', 'new BigDecimal(double) 有精度误差，改用 BigDecimal.valueOf() 或字符串构造', 'code'),
    ({'java'}, 'BUG', 'MAJOR', 'S2885', r'\bstatic\s+(?:final\s+)?(?:SimpleDateFormat|DateFormat)\b', 'SimpleDateFormat 不是线程安全的，不能做成 static 共享，改用 DateTimeFormatter', 'code'),
    ({'java'}, 'BUG', 'MAJOR', 'S2230', r'@(?:Transactional|Async)\b(?:\s*\([^()]*\))?(?:\s*@\w+(?:\s*\([^()]*\))?)*\s+(?:(?:static|final|synchronized)\s+)*private\b',
     '@Transactional / @Async 加在 private 方法上不生效（Spring 代理只拦截 public 方法）', 'code'),
    ({'java'}, 'CODE_SMELL', 'MINOR', 'S6813', r'@Autowired\b(?:\s*\([^()]*\))?\s+(?:@\w+(?:\s*\([^()]*\))?\s+)*(?:(?:private|protected|public|static|final)\s+)*[\w.]+(?:<[^;(){}]*>)?\s+\w+\s*;',
     '字段注入（@Autowired 加在字段上），推荐构造器注入，便于测试且依赖不可变', 'code'),
    ({'java'}, 'CODE_SMELL', 'MINOR', 'S2629', r'\blog(?:ger)?\.(?:trace|debug|info|warn|error)\s*\(\s*"[^"\n]*"\s*\+',
     '日志参数用 {} 占位符，不要字符串拼接', 'text'),
    ({'java'}, 'SECURITY_HOTSPOT', 'MAJOR', 'local:java-deserialization', r'\bnew\s+ObjectInputStream\s*\(', 'Java 原生反序列化不可信数据可执行任意代码', 'code'),
    ({'java'}, 'VULNERABILITY', 'CRITICAL', 'S4830', r'\bcheckServerTrusted\s*\([^()]*\)\s*(?:throws[^{]*)?\{\s*\}', '空的 checkServerTrusted() 等于信任所有证书', 'code'),
    (JVM, 'SECURITY_HOTSPOT', 'MINOR', 'S4790', r'\bMessageDigest\.getInstance\s*\(\s*"(?:MD2|MD5|SHA-?1)"', 'MD5 / SHA-1 已不安全，改用 SHA-256 以上；存密码用 BCrypt', 'text'),
    (JVM, 'VULNERABILITY', 'CRITICAL', 'S5547', r'\bCipher\.getInstance\s*\(\s*"(?:(?:DES|DESede|RC2|RC4|Blowfish)(?:/[^"]*)?|AES(?:/ECB[^"]*)?)"',
     '弱加密算法或 ECB 模式（"AES" 不写模式默认 ECB），改用 AES/GCM/NoPadding', 'text'),
    (JVM, 'SECURITY_HOTSPOT', 'MAJOR', 'S4721', r'\bRuntime\.getRuntime\(\)\.exec\s*\(|\bnew\s+ProcessBuilder\s*\(', '执行系统命令，确认命令和参数不拼接外部输入', 'code'),
    (JVM, 'VULNERABILITY', 'CRITICAL', 'S5527', r'\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bNoopHostnameVerifier\b|\bTrustAllStrategy\b|\bsetHostnameVerifier\s*\(\s*\(?[^()]*\)?\s*->\s*true\b',
     '关闭了 TLS 主机名 / 证书校验', 'code'),
    (JVM, 'SECURITY_HOTSPOT', 'MINOR', 'S5122', r'@CrossOrigin\b(?!\s*\()|@CrossOrigin\s*\(\s*\)|@CrossOrigin\s*\([^)]*"\*"|\b(?:allowedOrigins|allowedOriginPatterns|addAllowedOrigin)\s*\(\s*"\*"',
     'CORS 允许任意来源，确认接口不需要限制来源', 'text'),
    ({'kotlin'}, 'CODE_SMELL', 'MINOR', 'local:kotlin-not-null-assertion', r'(?<=[\w)\]])!!', '!! 遇到 null 直接抛 NPE，改用 ?. / ?: 或先判空', 'code'),

    ({'go'}, 'VULNERABILITY', 'CRITICAL', 'S4830', r'\bInsecureSkipVerify\s*:\s*true\b', 'InsecureSkipVerify: true 关闭了 TLS 证书校验', 'code'),
    ({'go'}, 'SECURITY_HOTSPOT', 'MINOR', 'S4790', r'\b(?:md5|sha1)\.(?:New|Sum)\b', 'MD5 / SHA-1 已不安全，改用 sha256 以上；存密码用 bcrypt', 'code'),
    ({'go'}, 'SECURITY_HOTSPOT', 'MAJOR', 'S4721', r'\bexec\.Command(?:Context)?\s*\(', '执行系统命令，确认命令和参数不拼接外部输入', 'code'),
    ({'go'}, 'VULNERABILITY', 'CRITICAL', 'S5547', r'\b(?:des|rc4)\.New(?:TripleDES)?Cipher\b', '弱加密算法，改用 AES-GCM', 'code'),

    ({'csharp'}, 'VULNERABILITY', 'CRITICAL', 'S4830', r'\b(?:ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|RemoteCertificateValidationCallback)\s*\+?=[^;]*=>\s*true\b',
     '证书校验回调直接返回 true，等于信任所有证书', 'code'),
    ({'csharp'}, 'SECURITY_HOTSPOT', 'MINOR', 'S4790', r'\b(?:MD5|SHA1)\.Create\s*\(|\bnew\s+(?:MD5|SHA1)CryptoServiceProvider\b', 'MD5 / SHA-1 已不安全，改用 SHA256 以上', 'code'),
    ({'csharp'}, 'VULNERABILITY', 'CRITICAL', 'S5547', r'\b(?:DES|TripleDES|RC2)(?:CryptoServiceProvider\b|\.Create\s*\()', '弱加密算法，改用 AES-GCM', 'code'),
    ({'csharp'}, 'SECURITY_HOTSPOT', 'MAJOR', 'S4721', r'\bProcess\.Start\s*\(', '执行系统命令，确认命令和参数不拼接外部输入', 'code'),
    ({'csharp'}, 'VULNERABILITY', 'MAJOR', 'S5773', r'\bnew\s+BinaryFormatter\s*\(', 'BinaryFormatter 反序列化不安全，已被 .NET 弃用', 'code'),
    ({'csharp'}, 'BUG', 'MAJOR', 'S3168', r'\basync\s+void\s+\w+\s*\((?![^)]*EventArgs)', 'async void 方法的异常调用方捕获不到，改成 async Task', 'code'),
    ({'csharp'}, 'SECURITY_HOTSPOT', 'MINOR', 'S5122', r'\.AllowAnyOrigin\s*\(\s*\)', 'CORS 允许任意来源，确认接口不需要限制来源', 'code'),

    ({'php'}, 'SECURITY_HOTSPOT', 'CRITICAL', 'S1523', r'(?<![\w$>:])(?:eval|create_function)\s*\(', 'eval 动态执行代码，确认输入可信', 'code'),
    ({'php'}, 'SECURITY_HOTSPOT', 'MAJOR', 'S4721', r'(?<![\w$>:])(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec)\s*\(', '执行系统命令，确认命令和参数不拼接外部输入', 'code'),
    ({'php'}, 'SECURITY_HOTSPOT', 'MAJOR', 'local:php-unserialize', r'(?<![\w$>:])unserialize\s*\(', 'unserialize 不可信数据可触发对象注入，改用 json_decode', 'code'),
    ({'php'}, 'SECURITY_HOTSPOT', 'MINOR', 'S4790', r'(?<![\w$>:])(?:md5|sha1)\s*\(', 'MD5 / SHA-1 已不安全，存密码用 password_hash()', 'code'),
    ({'php'}, 'CODE_SMELL', 'MINOR', 'local:debug-output', r'(?<![\w$>:])(?:var_dump|print_r|var_export|dd|dump)\s*\(', '调试输出不要提交', 'code'),
    ({'php'}, 'BUG', 'MAJOR', 'local:php-mysql-removed', r'(?<![\w$>:])mysql_\w+\s*\(', 'mysql_* 函数在 PHP 7 已移除，改用 PDO 或 mysqli', 'code'),
    ({'php'}, 'VULNERABILITY', 'MAJOR', 'S5131', r'\b(?:echo|print)\b[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b', '请求参数原样输出到页面，存在 XSS，先 htmlspecialchars()', 'code'),
    ({'php'}, 'VULNERABILITY', 'CRITICAL', 'S4830', r'\bCURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b', '关闭了 cURL 的 TLS 证书校验', 'code'),
]
_COMPILED = [(langs, t, sev, rule, re.compile(rx), msg, where) for langs, t, sev, rule, rx, msg, where in PATTERNS]

CORS_HEADER = re.compile(r'Access-Control-Allow-Origin["\']?\s*[,:=]\s*["\']\*["\']')
CHILD_EXEC = re.compile(r'(?<![\w$])(?:exec|execSync)\s*\(')
SECRET_ASSIGN = re.compile(r'(?<![\w$])(\$?[A-Za-z_][\w$]*)\s*(?::\s*[\w<>\[\].?|]+\s*)?(?::=|=>|=|:)\s*(?=["\'`])')
SQL_START = re.compile(r'^\s*(?:select\s[\s\S]+?\sfrom\s|insert\s+into\s|update\s+\S+\s+set\s|delete\s+from\s)', re.I)
JUMP = re.compile(r'(?<=[{};:])\s*\b(return|throw|break|continue)\b')
SELF_ASSIGN = re.compile(r'(?<![\w$.>])((?:[A-Za-z_$][\w$]*)(?:(?:\.|->)[A-Za-z_$][\w$]*)*)\s*=(?![=>])\s*\1\s*;')
SAME_OPERANDS = re.compile(r'(?:(?<=[(,;{}?:|&])|(?<=[^=!<>]=)|(?<=\breturn)|(?<=\bif))\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*(===|==|&&|\|\|)\s*\1(?=\s*(?:[),;}:\]|&{]|\?(?![.?])|$))', re.M)
LOOSE_EQ = re.compile(r'(?<![=!<>])[!=]=(?!=)')
EMPTY_CATCH = re.compile(r'\bcatch\b\s*(?:\([^()]*(?:\([^()]*\)[^()]*)*\))?\s*\{')
IGNORED_CATCH = re.compile(r'\(\s*(?:[\w.|\s]+\s+)?\$?(?:_+|ignored?|expected|unused)\s*(?::\s*[\w.]+\s*)?\)\s*\{$', re.I)
LOG_GUARD = re.compile(r'\bis(?:Trace|Debug|Info|Warn|Error)Enabled\s*\(')
NO_PLACEHOLDER_LOG = re.compile(r'^\s*import\s+org\.apache\.commons\.logging\.', re.M)
JSX_TAG = re.compile(r'<(a|img)\b')
MAP_JSX = re.compile(r'\.map\(\s*(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\(?\s*<([A-Za-z][\w.]*)')
HTML_TAG = re.compile(r'<([A-Za-z][\w.:-]*)((?:\s+[^\s=/>"\']+(?:\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>"\']+))?)*)\s*/?>')
HTML_ATTR = re.compile(r'([^\s=/>"\']+)(?:\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>"\']+))?')
TODO = re.compile(r'\b(?:TODO|FIXME|XXX)\b')

CONTROL = {'if', 'for', 'foreach', 'while', 'switch', 'catch', 'with', 'synchronized', 'using', 'lock', 'fixed', 'return', 'elseif',
           'when', 'select', 'match', 'do', 'else', 'try', 'finally', 'new', 'typeof', 'await', 'yield', 'throw', 'case', 'sizeof', 'delete', 'void'}
ANON = {'function', 'func', 'fun'}
NEED_KEYWORD = {'go': 'func', 'kotlin': 'fun', 'php': 'function'}
ANNOTATION = re.compile(r'@[\w.]+(?:\s*\([^()]*(?:\([^()]*\)[^()]*)*\))?')
IDENT_BEFORE = re.compile(r'([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*(?:<[^<>()]*>[^<>()]*)*>)?\s*\*?\s*$')
TAIL_OK = re.compile(r'[\s\w$.:<>\[\]?,|&*\'"()!]*')
PREFIX_OK = re.compile(r'[\s\w$.<>\[\]?,*&:]*')
DECL = re.compile(r'\b(?:class|interface|enum|struct|record|object|namespace|new|return|throw|await|typeof|import|case)\b')

FLOW = re.compile(r'\belse\s+if\b|\b(?:if|elseif|for|foreach|while|do|switch|when|select|match|catch|try|finally|else)\b'
                  r'|&&|\|\||\?\?|[{}();]|(?<=\s)\?(?=\s)|\buse[A-Z]\w*(?=\s*\()')
FLOW_WORDS = {'go': {'if', 'for', 'switch', 'select'}, 'kotlin': {'if', 'for', 'while', 'do', 'when', 'catch'},
              'php': {'if', 'elseif', 'for', 'foreach', 'while', 'do', 'switch', 'match', 'catch'},
              'csharp': {'if', 'for', 'foreach', 'while', 'do', 'switch', 'catch'}}
DEFAULT_FLOW_WORDS = {'if', 'for', 'while', 'do', 'switch', 'catch'}


def brace_pairs(code):
    pairs, stack = {}, []
    for m in re.finditer(r'[{}]', code):
        if m.group() == '{': stack.append(m.start())
        elif stack: pairs[stack.pop()] = m.start()
    return pairs


def _header_start(code, p, limit=1500):
    """函数体 { 往前找函数头的起点：同层的 ; { }，或者所在调用实参的左括号。"""
    depth, k, stop = 0, p - 1, max(-1, p - limit)
    while k > stop:
        c = code[k]
        if c in ')]': depth += 1
        elif c in '([':
            if depth == 0: return k + 1
            depth -= 1
        elif depth == 0 and c in '{};': return k + 1
        k -= 1
    return k + 1


def _paren_groups(s):
    groups, depth, start = [], 0, 0
    for k, c in enumerate(s):
        if c == '(':
            if depth == 0: start = k
            depth += 1
        elif c == ')' and depth:
            depth -= 1
            if depth == 0: groups.append((start, k))
    return groups


def _match_open(s, close):
    depth = 0
    for k in range(close, -1, -1):
        if s[k] == ')': depth += 1
        elif s[k] == '(':
            depth -= 1
            if depth == 0: return k
    return None


def _count_params(s):
    parts, depth, cur = [], 0, ''
    for c in s:
        if c in '([{<': depth += 1
        elif c in ')]}>': depth -= 1
        if c == ',' and depth == 0: parts.append(cur); cur = ''
        else: cur += c
    parts.append(cur)
    return sum(1 for p in parts if p.strip() and not re.match(r'\s*this\b', p))


def _callback_name(pre):
    pre = re.sub(r'(?:\basync\s*|\bfunction\s*\*?\s*|\bfunc\s*|\bfun\s*)$', '', pre.rstrip()).rstrip()
    m = re.search(r'([A-Za-z_$][\w$]*)\s*(?::\s*[^=:(){};,]+?)?\s*(?::=|=|:)\s*$', pre)
    if m: return m.group(1)
    m = re.search(r'([A-Za-z_$][\w$-]*)=\{$', pre)
    if m: return f'{m.group(1)} 回调'
    m = re.search(r'([A-Za-z_$][\w$.]*)\s*\((?:[^()]*,)?\s*$', pre)
    return f'{m.group(1)}() 回调' if m else '匿名函数'


def _arrow(code, hs, s):
    before = s[:-2].rstrip()
    mt = re.search(r'\)\s*:[^()]*$', before)
    if mt: before = before[:mt.start() + 1]
    if before.endswith(')'):
        o = _match_open(before, len(before) - 1)
        if o is None: return None
        params, po = before[o + 1:-1], o
    else:
        mi = re.search(r'[A-Za-z_$][\w$]*$', before)
        if not mi or mi.group() in CONTROL or mi.group() == 'default': return None
        params, po = mi.group(), mi.start()
    if re.search(r'\bcase\b', before[:po]): return None
    return _callback_name(code[max(0, hs - 120):hs] + before[:po]), _count_params(params), hs + po


def _parse_header(code, hs, p, lang):
    h = code[hs:p]
    s = h.rstrip()
    if lang != 'kotlin' and (s.endswith('=>') or (lang == 'java' and s.endswith('->'))): return _arrow(code, hs, s)
    h2 = ANNOTATION.sub(lambda m: blank(m.group()), h)
    if lang == 'go': h2 = re.sub(r'\bfunc\s*\([^()]*\)', lambda m: 'func' + blank(m.group()[4:]), h2)
    for o, c in reversed(_paren_groups(h2)):
        mi = IDENT_BEFORE.search(h2[:o])
        if not mi: continue
        ident = mi.group(1)
        if ident in ('base', 'this', 'super', 'use', 'where'): continue
        if ident in CONTROL or not TAIL_OK.fullmatch(h2, c + 1): return None
        prefix = h2[:mi.start()]
        if ident in ANON:
            name = _callback_name(code[max(0, hs - 120):hs] + prefix)
        else:
            if not PREFIX_OK.fullmatch(prefix) or DECL.search(prefix): return None
            kw = NEED_KEYWORD.get(lang)
            if kw and not re.search(rf'\b{kw}\b', prefix) and not (lang == 'kotlin' and ident == 'constructor'): return None
            name = ident
        return name, _count_params(h2[o + 1:c]), hs + mi.start(1)
    return None


def find_functions(code, lang, pairs):
    funcs = []
    for p, end in pairs.items():
        r = _parse_header(code, _header_start(code, p), p, lang)
        if r: funcs.append({'name': r[0], 'params': r[1], 'off': r[2], 'body': p, 'end': end})
    return sorted(funcs, key=lambda f: f['body'])


def walk(code, start, end, func_braces, lang, hooks=False):
    """在 (start, end) 之间按 SonarQube 认知复杂度的口径累计：分支/循环 +1+嵌套深度，else / 逻辑运算符序列 +1。
    hooks=True 时同时返回写在条件或循环里的 React Hook 调用位置。"""
    words = FLOW_WORDS.get(lang, DEFAULT_FLOW_WORDS)
    total, stack, nest, ctrl, funcs, paren = 0, [], 0, 0, 0, 0
    pending, last_logic, after_do, hook_hits = None, None, False, []
    for m in FLOW.finditer(code, start + 1, end):
        t, pos = m.group(), m.start()
        closed_do, after_do = after_do, False
        if t == '(':
            paren += 1; continue
        if t == ')':
            paren -= 1
            if pending and paren == pending[0] and lang != 'go' and not code[m.end():m.end() + 200].lstrip().startswith('{'): pending = None
            continue
        if t == ';':
            last_logic = None
            if pending and paren <= pending[0] and lang != 'go': pending = None
            continue
        if t == '{':
            kind = 'func' if pos in func_braces else ('do' if pending and pending[1] else 'ctrl') if pending and paren == pending[0] else 'block'
            stack.append(kind); pending = None; last_logic = None
            nest += kind != 'block'; ctrl += kind in ('ctrl', 'do'); funcs += kind == 'func'
            continue
        if t == '}':
            if stack:
                kind = stack.pop()
                nest -= kind != 'block'; ctrl -= kind in ('ctrl', 'do'); funcs -= kind == 'func'
                after_do = kind == 'do'
            last_logic = None
            continue
        if t in ('&&', '||', '??'):
            if t != last_logic: total += 1
            last_logic = t; continue
        if t == '?':
            total += 1 + nest; continue
        if t.startswith('use'):
            before = code[max(0, pos - 12):pos]
            if hooks and ctrl and funcs and not re.search(r'(?:function\s+|(?<!React)\.)$', before): hook_hits.append(pos)
            continue
        if pos and code[pos - 1] == '.': continue
        last_logic = None
        if t.startswith('else') and t.endswith('if'):
            total += 1; pending = (paren, False)
        elif t == 'else':
            total += 1
            pending = (paren, False) if code[m.end():m.end() + 200].lstrip().startswith('{') else None
        elif t in words:
            if t == 'while' and closed_do: continue
            total += 1 + nest; pending = (paren, t == 'do')
        elif t in ('try', 'finally'):
            pending = None
    return (total, hook_hits) if hooks else total


class Checker:
    def __init__(self, src, rel):
        self.src, self.rel, self.issues = src, rel, []
        self.lang, self.sl = src.lang, src.script_lang
        self.prefix = SONAR_LANG.get(self.sl, 'javascript')
        self.js = self.sl in JS_LANGS
        self.ui = self.lang in ('jsx', 'tsx', 'vue', 'svelte')
        self.react = self.lang in ('jsx', 'tsx') or (self.js and self.lang not in SFC_LANGS and bool(REACT_IMPORT.search(src.text)))
        self.pairs = brace_pairs(src.code)

    def add(self, type_, severity, rule, message, off=None, line=None):
        self.issues.append({'type': type_, 'severity': severity, 'rule': rule if ':' in rule else f'{self.prefix}:{rule}',
                            'message': message, 'file': self.rel, 'line': line if line is not None else self.src.line(off)})

    def run(self):
        self.patterns(); self.secrets_and_strings(); self.structure(); self.unused_imports()
        if self.js: self.javascript()
        if self.lang in SFC_LANGS: self.markup()
        return self.issues

    def patterns(self):
        code, script = self.src.code, self.src.script
        for langs, type_, sev, rule, rx, msg, where in _COMPILED:
            if self.sl not in langs or (where == 'react' and not self.react) or (where == 'ui' and not self.ui): continue
            if rule == 'S2629' and NO_PLACEHOLDER_LOG.search(script): continue
            for m in rx.finditer(script if where == 'text' else code):
                if where == 'text' and not self.src.in_code(m.start()): continue
                if rule == 'S2629' and log_guarded(code, m.start()): continue
                self.add(type_, sev, rule, msg, m.start())
        if self.js and 'child_process' in script:
            for m in CHILD_EXEC.finditer(code): self.add('SECURITY_HOTSPOT', 'MAJOR', 'S4721', '执行系统命令，确认命令和参数不拼接外部输入', m.start())
        for m in CORS_HEADER.finditer(script):
            if not self.src.in_comment(m.start()): self.add('SECURITY_HOTSPOT', 'MINOR', 'S5122', 'CORS 允许任意来源，确认接口不需要限制来源', m.start())

    def secrets_and_strings(self):
        src, code = self.src, self.src.code
        for m in SECRET_ASSIGN.finditer(code):
            value = src.string_at(m.end())
            if value is not None and SECRET_NAME.search(m.group(1).lstrip('$')) and looks_secret(value):
                self.add('VULNERABILITY', 'CRITICAL', 'S2068', f'{m.group(1)} 疑似硬编码密钥/密码，改为环境变量或配置中心读取', m.start(1))
        counts, first = Counter(), {}
        for s, e in src.strings:
            raw = src.script[s:e]; body = string_body(raw)
            if plain_http(body):
                self.add('SECURITY_HOTSPOT', 'MINOR', 'S5332', f'明文 HTTP 地址：{body[:60]}', s)
            if SQL_START.match(body) and self.dynamic_string(s, e, raw, body):
                self.add('SECURITY_HOTSPOT', 'MAJOR', 'S2077', 'SQL 用字符串拼接/插值构造，有 SQL 注入风险，改用参数化查询', s)
            if len(body) >= 10 and not raw.startswith('}') and not raw.endswith('${') and not self.literal_context(s):
                counts[body] += 1; first.setdefault(body, s)
        for body, c in counts.items():
            if c >= 3: self.add('CODE_SMELL', 'MINOR', 'S1192', f'字符串 “{body[:40]}” 重复出现 {c} 次，提成常量', first[body])

    def dynamic_string(self, s, e, raw, body):
        code = self.src.code
        after, before = code[e:e + 40].lstrip(), code[max(0, s - 40):s].rstrip()
        concat = '.' if self.sl == 'php' else '+'
        if after.startswith(concat) or before.endswith(concat) or raw.endswith('${'): return True
        if self.sl in ('php', 'kotlin') and raw.startswith('"') and re.search(r'\$\{?[A-Za-z_]', body): return True
        if self.sl == 'csharp' and (before.endswith('$') or raw.startswith('@$')) and '{' in body: return True
        return bool(re.search(r'(?:Sprintf|format|formatted)\s*\(\s*$', before) and re.search(r'%[sdv]', body))

    def literal_context(self, s):
        """import 路径、JSX 属性值、注解参数里的字符串不算“重复字符串”。"""
        before = self.src.code[max(0, s - 80):s]
        return bool(re.search(r'(?:\bfrom|\bimport|\brequire\s*\(|\bimport\s*\()\s*$|[\w-]=$|@[\w.]+\s*\([^()]*$', before))

    def structure(self):
        src, code, lang = self.src, self.src.code, self.sl
        funcs = find_functions(code, lang, self.pairs)
        bodies = {f['body'] for f in funcs}
        limit = JS_FUNCTION_LINES_MAX if self.js else FUNCTION_LINES_MAX
        for f in funcs:
            name, line = f['name'], src.line(f['off'])
            cc = walk(code, f['body'], f['end'], bodies, lang)
            if cc > COGNITIVE_MAX: self.add('CODE_SMELL', 'CRITICAL', 'S3776', f'函数 {name} 认知复杂度 {cc}，超过 {COGNITIVE_MAX}', line=line)
            length = src.line(f['end']) - line + 1
            if length > limit: self.add('CODE_SMELL', 'MAJOR', 'S138', f'函数 {name} 有 {length} 行，超过 {limit}', line=line)
            if f['params'] > PARAMS_MAX: self.add('CODE_SMELL', 'MAJOR', 'S107', f'函数 {name} 有 {f["params"]} 个参数，超过 {PARAMS_MAX}', line=line)
        self.functions = len(funcs)
        if self.react:
            _, hits = walk(code, -1, len(code), bodies, lang, hooks=True)
            for pos in hits: self.add('BUG', 'MAJOR', 'S6440', 'React Hook 写在条件或循环里，每次渲染的调用顺序会变，必须在组件顶层调用', pos)
        for m in EMPTY_CATCH.finditer(code):
            o = m.end() - 1; c = self.pairs.get(o)
            if c and not src.script[o + 1:c].strip() and not IGNORED_CATCH.search(m.group()): self.add('CODE_SMELL', 'MAJOR', 'S2486', '空的 catch 把异常静默吞掉，至少记录日志', m.start())
        if lang in JS_LANGS or lang == 'php': self.unreachable()
        if lang in SEMICOLON:
            for m in SELF_ASSIGN.finditer(code): self.add('BUG', 'MAJOR', 'S1656', f'{m.group(1)} 自己赋值给自己，没有效果', m.start())
        for m in SAME_OPERANDS.finditer(code):
            self.add('BUG', 'MAJOR', 'S1764', f'{m.group(2)} 两边是同一个表达式 {m.group(1)}', m.start(1))
        lines = src.script.splitlines()
        long_lines = [i for i, l in enumerate(lines, 1) if len(l.rstrip()) > LINE_MAX]
        if long_lines: self.add('CODE_SMELL', 'MINOR', 'S103', f'{len(long_lines)} 行超过 {LINE_MAX} 字符', line=long_lines[0])
        todos = [s for s, e in src.comments if TODO.search(src.script, s, e)]
        if todos: self.add('CODE_SMELL', 'INFO', 'S1135', f'{len(todos)} 处 TODO/FIXME 未处理', todos[0])
        self.ncloc = sum(1 for l in code.splitlines() if l.strip()) + sum(1 for l in src.template.splitlines() if l.strip())
        if self.ncloc > FILE_LINES_MAX: self.add('CODE_SMELL', 'MAJOR', 'S104', f'文件有 {self.ncloc} 行代码，超过 {FILE_LINES_MAX}，考虑拆分', line=1)

    def unreachable(self):
        code = self.src.code
        for m in JUMP.finditer(code):
            depth, k, end = 0, m.end(), min(len(code), m.end() + 3000)
            while k < end:
                c = code[k]
                if c in '([{': depth += 1
                elif c in ')]}':
                    if depth == 0: break
                    depth -= 1
                elif depth == 0 and c in ';\n': break
                k += 1
            if k >= end or code[k] != ';': continue
            nxt = re.compile(r'\s*').match(code, k + 1).end()
            rest = code[nxt:nxt + 40]
            if not rest or rest[0] == '}' or rest.startswith('?>') or re.match(r'(?:case|default|function|async\s+function|type|interface|declare)\b', rest): continue
            self.add('BUG', 'MAJOR', 'S1763', f'{m.group(1)} 后面的代码永远执行不到', nxt)

    def unused_imports(self):
        code, src = self.src.code, self.src
        if self.js:
            spans, names = [], []
            for m in re.finditer(r'(?m)^[ \t]*import\s+(?:type\s+)?([\w$*{}\s,]+?)\s+from\s*["\']', code):
                spans.append((m.start(), m.end()))
                clause = re.sub(r'\btype\s+', '', m.group(1))
                for part in re.split(r'[,{}]', clause):
                    part = part.strip()
                    if part: names.append((part.split(' as ')[-1].strip(), m.start()))
        elif self.sl in JVM:
            spans, names = [], []
            for m in re.finditer(r'(?m)^[ \t]*import\s+(?:static\s+)?([\w.]+(?:\.\*)?)(?:\s+as\s+(\w+))?\s*;?[ \t]*$', code):
                spans.append((m.start(), m.end()))
                name = m.group(2) or m.group(1).rsplit('.', 1)[-1]
                if name != '*' and name not in ('getValue', 'setValue', 'provideDelegate'): names.append((name, m.start()))
        else:
            return
        if not names: return
        rest = list(src.script)
        for s, e in spans: rest[s:e] = ' ' * (e - s)
        rest = ''.join(rest) + '\n' + src.template
        for name, off in names:
            if not re.fullmatch(r'[A-Za-z_$][\w$]*', name) or name == 'React': continue
            pattern = rf'(?<![\w$]){re.escape(name)}(?![\w$])'
            if self.lang in SFC_LANGS:
                kebab = re.sub(r'(?<!^)(?=[A-Z])', '-', name).lower()
                pattern += rf'|<{re.escape(kebab)}\b|\${re.escape(name)}\b'
            if not re.search(pattern, rest): self.add('CODE_SMELL', 'MINOR', 'S1128', f'导入了 {name} 但没有使用', off)

    def javascript(self):
        code = self.src.code
        for m in LOOSE_EQ.finditer(code):
            after, before = code[m.end():m.end() + 12].lstrip(), code[max(0, m.start() - 40):m.start()].rstrip()
            if after.startswith('null') or before.endswith('null') or re.search(r'typeof\s+[\w$.]+$', before): continue
            self.add('CODE_SMELL', 'MINOR', 'S1440', f'用 {m.group()}= 代替 {m.group()}，避免隐式类型转换', m.start())
        for m in re.finditer(r'(?<![\w$.])console\.(?:log|debug)\s*\(', code):
            self.add('CODE_SMELL', 'MINOR' if self.ui else 'INFO', 'local:console-log', 'console.log 调试输出不要提交', m.start())
        for s, e in self.src.comments:
            mt = re.search(r'@ts-(?:ignore|nocheck)\b', self.src.script[s:e])
            if mt: self.add('CODE_SMELL', 'MINOR', 'local:ts-ignore', f'{mt.group()} 屏蔽了类型检查，修好类型或改用 @ts-expect-error 并写明原因', s)
        if self.react:
            for m in MAP_JSX.finditer(code):
                end = jsx_tag_end(code, m.start(1) - 1)
                if end and not re.search(r'\bkey\s*=|\{\s*\.\.\.', code[m.start(1):end]):
                    self.add('BUG', 'MINOR', 'S6477', f'map 生成的 <{m.group(1)}> 没有 key，列表更新时会错位复用', m.start(1))
            for m in JSX_TAG.finditer(code):
                end = jsx_tag_end(code, m.start())
                if end: self.check_tag(m.group(1), self.src.script[m.start():end], m.start())

    def check_tag(self, tag, raw, off):
        if '{...' in raw.replace(' ', ''): return
        if tag == 'a' and re.search(r'\btarget\s*=\s*\{?\s*["\']_blank', raw) and not re.search(r'\brel\s*=', raw):
            self.add('SECURITY_HOTSPOT', 'MINOR', 'S5148', 'target="_blank" 没写 rel="noopener noreferrer"，新页面可通过 window.opener 控制本页', off)
        if tag == 'img' and not re.search(r'(?<![\w-])(?::|v-bind:)?alt\s*=|(?<![\w-])alt(?=[\s/>])', raw):
            self.add('CODE_SMELL', 'MINOR', 'S1077', '<img> 缺少 alt 属性（读屏软件和图片加载失败时需要）', off)

    def markup(self):
        """Vue / Svelte 模板。"""
        src = self.src
        for m in HTML_TAG.finditer(src.template):
            tag, attrs = m.group(1), dict((a.lower(), (v or '').strip('"\'')) for a, v in HTML_ATTR.findall(m.group(2)))
            if tag in ('a', 'img'): self.check_tag(tag, m.group(), m.start())
            if self.lang != 'vue': continue
            if 'v-html' in attrs: self.add('SECURITY_HOTSPOT', 'MAJOR', 'local:vue-v-html', 'v-html 不转义内容，含用户输入会导致 XSS', m.start())
            if 'v-for' not in attrs: continue
            key = next((attrs[k] for k in (':key', 'v-bind:key', 'key') if k in attrs), None)
            if key is None and tag != 'template':
                self.add('BUG', 'MINOR', 'local:vue-for-key', f'<{tag} v-for> 没有 :key，列表更新时会错位复用元素', m.start())
            elif key in ('index', 'idx', 'i'):
                self.add('CODE_SMELL', 'MINOR', 'local:vue-index-key', '用下标做 :key，列表增删时组件状态会错位，改用数据的唯一 id', m.start())
            if 'v-if' in attrs:
                self.add('CODE_SMELL', 'MAJOR', 'local:vue-if-with-for', 'v-if 和 v-for 写在同一个元素上（Vue 3 里 v-if 先执行，拿不到循环变量），改用 computed 过滤或外包 <template>', m.start())
        for m in re.finditer(r'\{@html\b', src.template):
            self.add('SECURITY_HOTSPOT', 'MAJOR', 'local:svelte-html', '{@html} 不转义内容，含用户输入会导致 XSS', m.start())
        if self.lang == 'vue': self.vue_data_object()

    def vue_data_object(self):
        code = self.src.code
        m = re.search(r'\bexport\s+default\s+(?:defineComponent\s*\(\s*)?\{', code)
        if not m: return
        o = m.end() - 1; c = self.pairs.get(o, len(code))
        for d in re.finditer(r'\bdata\s*:\s*\{', code[o:c]):
            inner = code[o + 1:o + d.start()]
            if inner.count('{') == inner.count('}'):
                self.add('BUG', 'MAJOR', 'local:vue-data-object', '组件的 data 必须是函数（data() { return {…} }），写成对象会被所有实例共享', o + d.start())


def _statement_start(code, pos): return max(code.rfind(c, 0, pos) for c in ';{}') + 1


def log_guarded(code, pos):
    """日志调用是否包在 if (log.isXxxEnabled()) 里（单行 if 或所在代码块的 if 条件）。"""
    if LOG_GUARD.search(code, _statement_start(code, pos), pos): return True
    depth, k = 0, pos - 1
    while k >= 0:
        if code[k] == '}': depth += 1
        elif code[k] == '{':
            if not depth: return bool(LOG_GUARD.search(code, _statement_start(code, k), k))
            depth -= 1
        k -= 1
    return False


def jsx_tag_end(code, start, limit=3000):
    """从 < 开始找 JSX 开始标签的结尾 >（跳过属性里 {…} 中的 >）。"""
    depth = 0
    for k in range(start + 1, min(len(code), start + limit)):
        c = code[k]
        if c == '{': depth += 1
        elif c == '}': depth -= 1
        elif c == '>' and depth == 0 and code[k - 1] != '=': return k + 1
        elif c == '<' and depth == 0: return None
    return None


def looks_secret(v):
    if not 6 <= len(v) <= 200 or re.search(r'\s', v) or not v.isascii(): return False
    if re.search(r'\$\{|\{\{|%[sd]|^[<#*]|^(?:your|my|change|replace|example|placeholder|dummy|test|xxx)|^x+$', v, re.I): return False
    return not re.fullmatch(r'[A-Za-z_.:/\-]+', v)


def dup_text(src):
    """查重复代码用的文本：去掉注释、字符串内容，以及各文件开头大同小异的 import / package / using。"""
    code = re.sub(r'(?m)^[ \t]*import\b[^;]*?\bfrom\s*(["\'])\s*\1;?', lambda m: blank(m.group()), src.code)
    code = re.sub(r'(?m)^[ \t]*import\s*\([^)]*\)', lambda m: blank(m.group()), code)
    return re.sub(r'(?m)^[ \t]*(?:import|package|using|use|namespace)\b[^\n]*', '', code)


def scan_source(src, rel):
    """一个非 Python 源文件 → (问题列表, 代码行数, 函数个数, 查重用文本)。"""
    ch = Checker(src, rel)
    try:
        issues = ch.run()
    except (RecursionError, IndexError, ValueError) as e:
        return [{'type': 'CODE_SMELL', 'severity': 'INFO', 'rule': 'local:analyzer-error', 'message': f'本地规则没能分析完这个文件：{e}',
                 'file': rel, 'line': 1}], getattr(ch, 'ncloc', 0), getattr(ch, 'functions', 0), ''
    return issues, ch.ncloc, ch.functions, dup_text(src)


CONFIG_NAME = re.compile(r'^(?:application|bootstrap)(?:-[\w.-]+)?\.(?:ya?ml|properties)$|^appsettings(?:\.[\w-]+)?\.json$', re.I)
CONFIG_PLACEHOLDER = re.compile(r'^(?:\$\{|#\{|ENC\(|\{cipher\}|<|%|\{\{)|^(?:true|false|null|~|none)$', re.I)


def config_issues(root, base, only=None):
    """Spring / .NET 配置文件里写死的密码、密钥；MyBatis Mapper XML 里的 ${} 拼接。返回 (问题, 检查的文件数)。
    only：只检查这些绝对路径（改动范围扫描时用），None 表示目录下全部。"""
    files, _ = walk_files(root, {'.yml', '.yaml', '.properties', '.json', '.xml'}, 3000, CODE_SKIP_DIRS)
    issues, checked = [], 0
    for f in files:
        if only is not None and f.resolve() not in only: continue
        is_config = bool(CONFIG_NAME.match(f.name))
        if not is_config and f.suffix != '.xml': continue
        try:
            if f.stat().st_size > 1_000_000: continue
            text = f.read_text(encoding='utf-8', errors='replace')
        except OSError: continue
        rel = str(f.relative_to(base)) if f.is_relative_to(base) else str(f)
        if f.suffix == '.xml':
            if '<mapper' not in text: continue
            checked += 1
            body = re.sub(r'<!--[\s\S]*?-->', lambda m: blank(m.group()), text)
            for m in re.finditer(r'\$\{[^}]+\}', body):
                issues.append({'type': 'SECURITY_HOTSPOT', 'severity': 'MAJOR', 'rule': 'local:mybatis-dollar', 'file': rel, 'line': text.count('\n', 0, m.start()) + 1,
                               'message': f'MyBatis 的 {m.group()} 是字符串拼接，有 SQL 注入风险；参数改用 #{{}}，表名/排序字段要白名单校验'})
            continue
        checked += 1
        for no, line in enumerate(text.splitlines(), 1):
            if f.suffix == '.json':
                pairs = re.findall(r'"([\w.\-]+)"\s*:\s*"([^"]*)"', line)
                pairs += [('Password', v) for v in re.findall(r'(?:Password|Pwd)\s*=\s*([^;"]+)', line, re.I)]
            else:
                if line.lstrip().startswith(('#', '!')): continue
                m = re.match(r'^\s*([\w.\-\[\]]+)\s*[=:]\s*(.*?)\s*$', line)
                pairs = [(m.group(1), re.sub(r'\s+#.*$', '', m.group(2)).strip().strip('"\''))] if m else []
            for key, value in pairs:
                if value and not CONFIG_PLACEHOLDER.search(value) and SECRET_NAME.search(key.split('.')[-1].replace('-', '_')):
                    issues.append({'type': 'VULNERABILITY', 'severity': 'MAJOR', 'rule': 'local:config-secret', 'file': rel, 'line': no,
                                   'message': f'配置项 {key} 写死了密码/密钥，改用环境变量（如 ${{DB_PASSWORD}}）或配置中心'})
    return issues, checked


ESLINT_CONFIGS = ('eslint.config.js', 'eslint.config.mjs', 'eslint.config.cjs', 'eslint.config.ts', 'eslint.config.mts', 'eslint.config.cts',
                  '.eslintrc', '.eslintrc.js', '.eslintrc.cjs', '.eslintrc.json', '.eslintrc.yml', '.eslintrc.yaml')
ESLINT_BUGS = {'no-undef', 'no-unreachable', 'no-dupe-keys', 'no-dupe-args', 'no-dupe-else-if', 'no-duplicate-case', 'no-self-assign',
               'no-self-compare', 'no-unsafe-finally', 'no-unsafe-negation', 'no-cond-assign', 'no-func-assign', 'no-import-assign',
               'no-obj-calls', 'no-sparse-arrays', 'no-unsafe-optional-chaining', 'use-isnan', 'valid-typeof', 'getter-return',
               'no-setter-return', 'constructor-super', 'no-this-before-super', 'no-const-assign', 'no-class-assign',
               'no-async-promise-executor', 'react-hooks/rules-of-hooks', 'react/jsx-key', 'vue/require-v-for-key', 'vue/no-mutating-props',
               'vue/no-side-effects-in-computed-properties', 'vue/no-dupe-keys', '@typescript-eslint/no-floating-promises',
               '@typescript-eslint/no-misused-promises'}


def _eslint_projects(root, files):
    """含 eslint 和 ESLint 配置的 Node 项目目录：目标往上找，再加上目标里各个子项目。"""
    candidates = set()
    for d in [root, *list(root.parents)[:5]]:
        candidates.add(d)
    for f in files:
        for d in f.parents:
            if d == root or not d.is_relative_to(root): break
            candidates.add(d)
    out = []
    for d in candidates:
        if not (d/'node_modules'/'eslint'/'bin'/'eslint.js').is_file(): continue
        pkg = d/'package.json'
        has_cfg = any((d/c).is_file() for c in ESLINT_CONFIGS) or (pkg.is_file() and '"eslintConfig"' in pkg.read_text(encoding='utf-8', errors='replace'))
        if has_cfg: out.append(d)
    return sorted(out, key=lambda d: len(d.parts))


def eslint_issues(root, base, files, restrict=False):
    node = shutil.which('node')
    if not node or not files: return None, ''
    projects = _eslint_projects(root, files)
    if not projects: return None, '没有找到项目里安装的 ESLint 和配置'
    issues, notes = [], []
    allowed = {str(f.resolve()) for f in files} if restrict else None
    for proj in projects:
        target = root if root.is_relative_to(proj) else proj
        if restrict:
            mine = [str(f) for f in files if f.resolve().is_relative_to(proj)]
            if not mine: continue
            targets = mine
        else:
            targets = [str(target)]
        try:
            r = subprocess.run([node, str(proj/'node_modules'/'eslint'/'bin'/'eslint.js'), '-f', 'json', '--no-error-on-unmatched-pattern', *targets],
                               cwd=proj, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=300)
        except subprocess.TimeoutExpired:
            notes.append(f'{proj.name} 超时'); continue
        try: data = json.loads(r.stdout or '[]')
        except json.JSONDecodeError:
            notes.append(f"{proj.name} 运行失败：{(r.stderr or r.stdout).strip().splitlines()[-1][:120] if (r.stderr or r.stdout).strip() else '无输出'}"); continue
        for fr in data:
            fp = Path(fr['filePath'])
            if allowed is not None and str(fp.resolve()) not in allowed: continue
            rel = str(fp.relative_to(base)) if fp.is_relative_to(base) else str(fp)
            for msg in fr.get('messages', []):
                rid = msg.get('ruleId')
                type_ = 'BUG' if rid is None or rid in ESLINT_BUGS else 'SECURITY_HOTSPOT' if rid.startswith('security/') else 'CODE_SMELL'
                sev = 'BLOCKER' if rid is None else 'MAJOR' if msg.get('severity') == 2 else 'MINOR'
                issues.append({'type': type_, 'severity': sev, 'rule': f"eslint:{rid or 'parse-error'}", 'message': msg.get('message', ''),
                               'file': rel, 'line': msg.get('line')})
    return issues, 'ESLint 已合并' + (f"（{'；'.join(notes)}）" if notes else '')


def go_vet_issues(root, base, files, restrict=False):
    go = shutil.which('go')
    if not files: return None, ''
    allowed = {str(f.resolve()) for f in files} if restrict else None
    if not go: return None, '未安装 go，跳过 go vet'
    mods, seen = set(), {}
    for d in {f.parent for f in files}:
        chain = [d, *d.parents][:8]
        for c in chain:
            if c not in seen: seen[c] = (c/'go.mod').is_file()
            if seen[c]: mods.add(c); break
    mods = sorted(mods, key=lambda d: len(d.parts))
    if not mods: return None, '没有 go.mod，跳过 go vet'
    issues, notes = [], []
    env = {**os.environ, 'GOPROXY': 'off', 'GOTOOLCHAIN': 'local'}
    for mod in mods[:10]:
        try:
            r = subprocess.run([go, 'vet', './...'], cwd=mod, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=300, env=env)
        except subprocess.TimeoutExpired:
            notes.append(f'{mod.name} 超时'); continue
        out = r.stderr + r.stdout
        if re.search(r'cannot find module|missing go\.sum entry|module lookup disabled', out):
            notes.append(f'{mod.name} 依赖未下载（先 go mod download）'); continue
        for m in re.finditer(r'(?m)^(?:vet: )?(.+?\.go):(\d+):(?:\d+:)?\s*(.+)$', out):
            fp = (mod/m.group(1)).resolve()
            if allowed is not None and str(fp) not in allowed: continue
            rel = str(fp.relative_to(base)) if fp.is_relative_to(base) else m.group(1)
            issues.append({'type': 'BUG', 'severity': 'MAJOR', 'rule': 'govet', 'message': m.group(3).strip(), 'file': rel, 'line': int(m.group(2))})
    return issues, 'go vet 已合并' + (f"（{'；'.join(notes)}）" if notes else '')
