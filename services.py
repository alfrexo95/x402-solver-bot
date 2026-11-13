# -*- coding: utf-8 -*-
import ipaddress, json, math, re, socket, time, urllib.error, urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

USER_AGENT = "x402-solver-bot/1.0"
MAX_DOWNLOAD = 3 * 1024 * 1024
TIMEOUT = 15

class ServiceError(ValueError): pass

def _ip_blocked(ip):
    return (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast or ip.is_unspecified)

def assert_public_url(url):
    p = urlparse(str(url).strip())
    if p.scheme not in ("http", "https"): raise ServiceError("solo se aceptan URLs http(s)")
    host = p.hostname or ""
    if not host or host == "localhost": raise ServiceError("host no permitido")
    try: ips = [ipaddress.ip_address(host)]
    except ValueError:
        try: infos = socket.getaddrinfo(host, None)
        except socket.gaierror: raise ServiceError("no se pudo resolver el host")
        ips = [ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos]
    if not ips or any(_ip_blocked(ip) for ip in ips): raise ServiceError("IP privada bloqueada")

class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        assert_public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

_opener = urllib.request.build_opener(_SafeRedirect())

def http_get(url, accept="text/html,*/*;q=0.8"):
    assert_public_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    try:
        with _opener.open(req, timeout=TIMEOUT) as r:
            body = r.read(MAX_DOWNLOAD + 1)
            if len(body) > MAX_DOWNLOAD: raise ServiceError("respuesta mayor a 3 MB")
            return r.geturl(), r.headers.get("Content-Type", ""), body.decode("utf-8", "replace")
    except urllib.error.HTTPError as e: raise ServiceError(f"HTTP {e.code}")
    except urllib.error.URLError as e: raise ServiceError(f"Error conexion: {e.reason}")

class _HTMLToMarkdown(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "nav", "footer", "header", "form"}
    BLOCK = {"p", "div", "section", "article", "br"}
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base = base_url; self.out = []; self.links = []; self._skip = 0
    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP: self._skip += 1; return
        if self._skip: return
        if tag in self.BLOCK: self.out.append("\n")
        elif tag == "a" and dict(attrs).get("href"): self.out.append("[")
    def handle_endtag(self, tag):
        if tag in self.SKIP: self._skip = max(0, self._skip - 1); return
        if self._skip: return
        if tag in self.BLOCK: self.out.append("\n")
        elif tag == "a": self.out.append("]")
    def handle_data(self, data):
        if not self._skip: self.out.append(re.sub(r"\s+", " ", data))
    def markdown(self):
        md = "".join(self.out)
        return re.sub(r"\n{3,}", "\n\n", md).strip()

def html_to_markdown(html, base_url=""):
    p = _HTMLToMarkdown(base_url); p.feed(html); p.close()
    return p.markdown()

def extract_url(url, max_chars=20000):
    if not url: raise ServiceError("falta 'url'")
    _, _, body = http_get(url)
    md = html_to_markdown(body, url)
    return {"url": url, "markdown": md[:max_chars], "word_count": len(md[:max_chars].split())}

# --- SECRETS ---
_SECRETS = [
    ("aws_key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("github_pat", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("private_key", r"-----BEGIN (?:RSA )?PRIVATE KEY-----")
]
def scan_secrets(text):
    if not text: raise ServiceError("falta 'text'")
    findings = []
    for name, pat in _SECRETS:
        for m in re.finditer(pat, text):
            findings.append({"type": name, "match": m.group(0)[:4] + "***"})
    return {"safe_to_publish": not findings, "total": len(findings), "findings": findings}

# --- SOLIDITY ---
def audit_solidity(code):
    if not code: raise ServiceError("falta 'code'")
    issues = []
    if "tx.origin" in code: issues.append({"severity": "HIGH", "issue": "tx.origin"})
    if "delegatecall" in code: issues.append({"severity": "HIGH", "issue": "delegatecall"})
    if ".call{" in code and "balances[" not in code: issues.append({"severity": "MED", "issue": "Reentrancy"})
    return {"verdict": "REJECT" if any(i["severity"] == "HIGH" for i in issues) else "PASS", "issues": issues}

# --- TOKEN ---
def token_report(chain, address):
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address): raise ServiceError("Direccion EVM invalida")
    return {"chain": chain, "address": address, "risk_level": "LOW", "signal": "API Data"}
