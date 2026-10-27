"""插件启动入口：Cursor / Codex 插件的 MCP 配置都指向这个文件。

缺少 mcp SDK 时自动 pip install --user 一次，免得用户手动装依赖。
"""
import importlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
REQUIREMENT = 'mcp>=2.3'


def ensure_mcp():
    try:
        from mcp.server.mcpserver import MCPServer  # noqa: F401
        return
    except ImportError:
        pass
    print(f'[skill-quality] 未找到 {REQUIREMENT}，正在安装到用户目录…', file=sys.stderr, flush=True)
    r = subprocess.run([sys.executable, '-m', 'pip', 'install', '--user', '--quiet', REQUIREMENT], stdout=sys.stderr, stderr=sys.stderr)
    if r.returncode != 0:
        sys.exit(f'[skill-quality] 安装 {REQUIREMENT} 失败，请手动运行：{sys.executable} -m pip install "{REQUIREMENT}"')
    importlib.invalidate_caches()
    import site
    if site.getusersitepackages() not in sys.path: sys.path.append(site.getusersitepackages())


if __name__ == '__main__':
    ensure_mcp()
    from skill_quality_mcp.server import main
    main()
