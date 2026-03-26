"""
WardenStrike - Helper Utilities
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin


def is_tool_installed(tool_name: str) -> bool:
    """Check if a command-line tool is installed."""
    return shutil.which(tool_name) is not None


def check_tools(tools: list[str]) -> dict[str, bool]:
    """Check multiple tools and return availability map."""
    return {tool: is_tool_installed(tool) for tool in tools}


def required_tools_check(tools: list[str]) -> list[str]:
    """Return list of missing required tools."""
    return [t for t in tools if not is_tool_installed(t)]


def run_command(
    cmd: str | list[str],
    timeout: int = 300,
    cwd: str | None = None,
    env: dict | None = None,
    capture: bool = True,
    shell: bool = False,
) -> dict:
    """Run a shell command safely and return structured output."""
    try:
        if isinstance(cmd, str) and not shell:
            import shlex
            cmd = shlex.split(cmd)

        merged_env = {**os.environ, **(env or {})}

        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=merged_env,
            shell=shell,
        )
        return {
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout.strip() if result.stdout else "",
            "stderr": result.stderr.strip() if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "returncode": -1, "stdout": "", "stderr": f"Command timed out after {timeout}s"}
    except FileNotFoundError:
        return {"success": False, "returncode": -1, "stdout": "", "stderr": f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd}"}
    except Exception as e:
        return {"success": False, "returncode": -1, "stdout": "", "stderr": str(e)}


def run_command_stream(cmd: str | list[str], timeout: int = 600, cwd: str | None = None):
    """Run command and yield output lines in real-time."""
    if isinstance(cmd, str):
        import shlex
        cmd = shlex.split(cmd)

    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, cwd=cwd, env=os.environ
    )
    try:
        for line in iter(process.stdout.readline, ""):
            yield line.rstrip()
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        yield f"[TIMEOUT] Process killed after {timeout}s"
    finally:
        if process.poll() is None:
            process.kill()


def normalize_url(url: str) -> str:
    """Normalize a URL for consistent comparison."""
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path.rstrip("/") or "/"

    if port and port not in (80, 443):
        netloc = f"{host}:{port}"
    else:
        netloc = host

    return f"{scheme}://{netloc}{path}"


def extract_domain(url: str) -> str:
    """Extract the root domain from a URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def is_in_scope(url: str, scope_domains: list[str], strict: bool = False) -> bool:
    """Check if a URL is within the defined scope."""
    domain = extract_domain(url)
    if not domain:
        return False

    for scope in scope_domains:
        scope = scope.lstrip("*.")
        if strict:
            if domain == scope:
                return True
        else:
            if domain == scope or domain.endswith(f".{scope}"):
                return True
    return False


def hash_finding(title: str, url: str, vuln_type: str) -> str:
    """Generate a unique hash for a finding to detect duplicates."""
    normalized = normalize_url(url) if url else ""
    content = f"{vuln_type}:{title}:{normalized}".lower()
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def parse_nmap_ports(port_string: str) -> list[int]:
    """Parse nmap-style port specification into list of ports."""
    ports = []
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def sanitize_filename(name: str) -> str:
    """Create a safe filename from arbitrary string."""
    name = re.sub(r'[^\w\s\-.]', '', name)
    name = re.sub(r'\s+', '_', name)
    return name[:200]


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def sizeof_fmt(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num) < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


def load_json(path: str | Path) -> dict | list:
    with open(path) as f:
        return json.load(f)


def save_json(data: dict | list, path: str | Path, indent: int = 2):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=indent, default=str)


def load_lines(path: str | Path) -> list[str]:
    """Load a file as a list of non-empty lines."""
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def dedup_list(items: list) -> list:
    """Remove duplicates while preserving order."""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def extract_urls_from_text(text: str) -> list[str]:
    """Extract URLs from arbitrary text."""
    pattern = r'https?://[^\s<>"\')\]}]+'
    return list(set(re.findall(pattern, text)))


def extract_endpoints_from_js(js_content: str) -> list[dict]:
    """Extract API endpoints and sensitive patterns from JavaScript content."""
    findings = []

    # API endpoint patterns
    endpoint_patterns = [
        (r'["\'](/api/[^\s"\']+)["\']', "API Endpoint"),
        (r'["\'](/v[0-9]+/[^\s"\']+)["\']', "Versioned API"),
        (r'["\']/(graphql|gql)["\']', "GraphQL Endpoint"),
        (r'fetch\s*\(\s*["\']([^"\']+)["\']', "Fetch Request"),
        (r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']', "Axios Request"),
        (r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', "jQuery AJAX"),
        (r'XMLHttpRequest.*?open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']', "XHR Request"),
        (r'["\'](/ws[s]?/[^\s"\']+)["\']', "WebSocket Endpoint"),
    ]

    for pattern, etype in endpoint_patterns:
        for match in re.finditer(pattern, js_content):
            findings.append({"type": etype, "value": match.group(1), "context": match.group(0)[:200]})

    # Sensitive data patterns
    sensitive_patterns = [
        (r'["\']([a-zA-Z0-9]{20,40})["\']', "Potential API Key"),
        (r'(?:api[_-]?key|apikey|api_secret|token|secret|password|auth)\s*[=:]\s*["\']([^"\']{8,})["\']', "Hardcoded Secret"),
        (r'(?:AWS|aws)[_-]?(?:ACCESS|access)[_-]?(?:KEY|key)[_-]?(?:ID|id)?\s*[=:]\s*["\']([A-Z0-9]{16,})["\']', "AWS Key"),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private Key"),
        (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub Token"),
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/Stripe Secret Key"),
        (r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+', "JWT Token"),
    ]

    for pattern, stype in sensitive_patterns:
        for match in re.finditer(pattern, js_content):
            findings.append({"type": stype, "value": match.group(0)[:100], "context": match.group(0)[:200]})

    # Admin/debug patterns
    admin_patterns = [
        (r'["\'](/admin[^\s"\']*)["\']', "Admin Path"),
        (r'["\'](/debug[^\s"\']*)["\']', "Debug Path"),
        (r'["\'](/internal[^\s"\']*)["\']', "Internal Path"),
        (r'(?:isAdmin|is_admin|isDebug|debug_mode)\s*[=:]\s*(true|false)', "Debug/Admin Flag"),
        (r'(?:TODO|FIXME|HACK|XXX|BUG)\s*:?\s*(.{10,80})', "Dev Comment"),
    ]

    for pattern, atype in admin_patterns:
        for match in re.finditer(pattern, js_content, re.IGNORECASE):
            findings.append({"type": atype, "value": match.group(1) if match.lastindex else match.group(0), "context": match.group(0)[:200]})

    return findings
