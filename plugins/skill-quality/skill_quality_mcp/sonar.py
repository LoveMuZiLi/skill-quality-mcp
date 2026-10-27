"""SonarQube / SonarCloud Web API 客户端，以及可选的 sonar-scanner 扫描。

环境变量：
  SONAR_HOST_URL      SonarQube 地址，如 http://localhost:9000；SonarCloud 用 https://sonarcloud.io
  SONAR_TOKEN         用户令牌（My Account → Security 生成）
  SONAR_PROJECT_KEY   默认项目 key，工具参数可覆盖
  SONAR_ORGANIZATION  SonarCloud 组织 key（SonarQube 自建不需要）
  SONAR_SCANNER       sonar-scanner 可执行文件路径（不在 PATH 时填）
"""
import base64
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

METRICS = ['bugs', 'vulnerabilities', 'security_hotspots', 'code_smells', 'coverage', 'duplicated_lines_density', 'ncloc',
           'reliability_rating', 'security_rating', 'sqale_rating', 'sqale_index', 'cognitive_complexity', 'alert_status']
RATING = {'1.0': 'A', '2.0': 'B', '3.0': 'C', '4.0': 'D', '5.0': 'E'}


def env(name):
    """读环境变量；客户端没展开的 ${env:X} 占位符按未设置处理。"""
    value = os.environ.get(name, '').strip()
    return '' if value.startswith('${') else value


def config():
    host = env('SONAR_HOST_URL').rstrip('/')
    if not host and env('SONAR_ORGANIZATION'): host = 'https://sonarcloud.io'
    return {'host': host, 'token': env('SONAR_TOKEN'), 'project': env('SONAR_PROJECT_KEY'), 'organization': env('SONAR_ORGANIZATION')}


def configured():
    c = config(); return bool(c['host'] and c['token'])


def api(path, params=None, timeout=30):
    c = config()
    if not c['host']: raise RuntimeError('未配置 SONAR_HOST_URL（或 SonarCloud 的 SONAR_ORGANIZATION）')
    params = {k: v for k, v in (params or {}).items() if v not in (None, '')}
    url = f"{c['host']}/{path.lstrip('/')}" + ('?' + urllib.parse.urlencode(params) if params else '')
    req = urllib.request.Request(url)
    if c['token']: req.add_header('Authorization', 'Basic ' + base64.b64encode(f"{c['token']}:".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: return json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        detail = e.read().decode('utf-8', errors='replace')[:300]
        raise RuntimeError(f'SonarQube 返回 HTTP {e.code}：{detail}') from None
    except urllib.error.URLError as e:
        raise RuntimeError(f'连不上 SonarQube（{c["host"]}）：{e.reason}') from None


def check_connection():
    c = config()
    out = {'host': c['host'] or '(未配置)', 'token': '已配置' if c['token'] else '未配置', 'project_key': c['project'] or '(未配置)',
           'organization': c['organization'] or '(无)', 'scanner': scanner_path() or '(未找到 sonar-scanner)'}
    if not c['host']: out['status'] = '未配置，质量报告会只用本地规则'; return out
    try:
        out['server_status'] = api('api/system/status').get('status', '?')
        out['token_valid'] = api('api/authentication/validate').get('valid', False)
        out['status'] = '可用' if out['token_valid'] else '服务可达，但令牌无效'
    except RuntimeError as e:
        out['status'] = str(e)
    return out


def project_key(key=''):
    key = key or config()['project']
    if not key: raise RuntimeError('没有项目 key：传 project_key 参数或设置 SONAR_PROJECT_KEY')
    return key


def issues(key='', types='BUG,VULNERABILITY', severities='', limit=50):
    key = project_key(key); limit = max(1, min(int(limit), 500))
    data = api('api/issues/search', {'componentKeys': key, 'types': types, 'severities': severities, 'resolved': 'false',
                                     'ps': limit, 's': 'SEVERITY', 'asc': 'false', 'organization': config()['organization']})
    out = []
    for i in data.get('issues', []):
        comp = i.get('component', '').split(':', 1)[-1]
        out.append({'type': i.get('type'), 'severity': i.get('severity'), 'rule': i.get('rule'), 'message': i.get('message'),
                    'file': comp, 'line': i.get('line'), 'effort': i.get('effort'), 'key': i.get('key')})
    return {'project': key, 'total': data.get('total', len(out)), 'issues': out}


def hotspots(key='', limit=50):
    key = project_key(key)
    data = api('api/hotspots/search', {'projectKey': key, 'status': 'TO_REVIEW', 'ps': max(1, min(int(limit), 500)),
                                       'organization': config()['organization']})
    return [{'type': 'SECURITY_HOTSPOT', 'severity': h.get('vulnerabilityProbability'), 'rule': h.get('ruleKey'),
             'message': h.get('message'), 'file': h.get('component', '').split(':', 1)[-1], 'line': h.get('line')}
            for h in data.get('hotspots', [])]


def metrics(key=''):
    key = project_key(key)
    data = api('api/measures/component', {'component': key, 'metricKeys': ','.join(METRICS), 'organization': config()['organization']})
    values = {m['metric']: m.get('value') for m in data.get('component', {}).get('measures', [])}
    for k in ('reliability_rating', 'security_rating', 'sqale_rating'):
        if values.get(k): values[k] = RATING.get(values[k], values[k])
    try: gate = api('api/qualitygates/project_status', {'projectKey': key, 'organization': config()['organization']}).get('projectStatus', {})
    except RuntimeError: gate = {}
    values['quality_gate'] = gate.get('status', values.get('alert_status'))
    values['failed_conditions'] = [f"{c['metricKey']} {c.get('actualValue')}（阈值 {c.get('errorThreshold')}）"
                                   for c in gate.get('conditions', []) if c.get('status') == 'ERROR']
    return {'project': key, 'metrics': values}


def scanner_path():
    custom = env('SONAR_SCANNER')
    if custom and Path(custom).exists(): return custom
    return shutil.which('sonar-scanner') or shutil.which('sonar-scanner.bat')


def run_scan(path, key='', wait=True, use_npx=False, timeout=1800):
    c = config(); key = project_key(key); base = Path(path).expanduser().resolve()
    if not configured(): raise RuntimeError('先配置 SONAR_HOST_URL 和 SONAR_TOKEN')
    exe = scanner_path()
    if exe: cmd = [exe]
    elif use_npx and shutil.which('npx'): cmd = [shutil.which('npx'), '--yes', '@sonar/scan']
    else: raise RuntimeError('没找到 sonar-scanner：安装 SonarScanner CLI，或传 use_npx=true 用 npx @sonar/scan（首次会下载扫描器和 JRE）')
    props = {'sonar.projectKey': key, 'sonar.sources': '.', 'sonar.host.url': c['host'], 'sonar.token': c['token'],
             'sonar.sourceEncoding': 'UTF-8', 'sonar.exclusions': '**/node_modules/**,**/.venv/**,**/__pycache__/**'}
    if c['organization']: props['sonar.organization'] = c['organization']
    r = subprocess.run(cmd + [f'-D{k}={v}' for k, v in props.items()], cwd=base, capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=timeout)
    log = (r.stdout + r.stderr).replace(c['token'], '***')
    if r.returncode != 0: raise RuntimeError('sonar-scanner 失败：\n' + log[-2000:])
    result = {'project': key, 'scanner_exit': 0, 'log_tail': log[-800:]}
    report = base/'.scannerwork'/'report-task.txt'
    if wait and report.is_file():
        task = dict(l.split('=', 1) for l in report.read_text(encoding='utf-8').splitlines() if '=' in l).get('ceTaskId')
        deadline = time.time() + 300
        while task and time.time() < deadline:
            status = api('api/ce/task', {'id': task}).get('task', {}).get('status')
            if status in ('SUCCESS', 'FAILED', 'CANCELED'): result['analysis'] = status; break
            time.sleep(3)
        else: result['analysis'] = '等待超时，稍后用 sonar_project_metrics 查看'
    return result
