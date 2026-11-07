"""Log parsing, compaction, token-budgeted chunking and cross-part entity memory."""
import json, re
from collections import Counter
from urllib.parse import unquote

CHARS_PER_TOKEN = 2.6          # conservative: JSON/URL-heavy text tokenizes badly
def est_tokens(s: str) -> int:
    return int(len(s) / CHARS_PER_TOKEN) + 1

SCAN_RE = re.compile(r"(\.env|\.git/|wp-admin|wp-login|phpmyadmin|\.aws|\.\./|/etc/passwd|/admin\b)", re.I)
SQLI_RE = re.compile(r"('\s*(or|and)\s|union\s+select|;\s*select|sleep\s*\(|drop\s+table|1\s*=\s*1|--\s*$)", re.I)
INJ_RE = re.compile(r"(ignore (all )?(previous|prior) instructions|disregard .*instructions|system prompt)", re.I)

def parse(line: str):
    try:
        d = json.loads(line)
        return d if isinstance(d, dict) else None
    except Exception:
        return None

def decoded(d):
    s = (d.get("path") or "") + " " + str(d.get("submitted_text") or "")
    for _ in range(3):           # handle double encoding (%252e)
        n = unquote(s)
        if n == s: break
        s = n
    return s

def compact(d, no, raw):
    """One short line per entry; keeps the original line number."""
    if d is None:
        return f"L{no} RAW {raw.strip()[:160]}"
    t = (d.get("time") or "")[11:19]
    parts = [f"L{no}", t, (d.get("app") or "")[:9], d.get("service", ""), d.get("level", "")]
    if d.get("client_ip"): parts.append(d["client_ip"])
    if d.get("method"): parts.append(f'{d["method"]} {d.get("path","")}')
    if d.get("status"): parts.append(str(d["status"]))
    ua = d.get("user_agent", "")
    if ua and not ua.startswith("Mozilla"): parts.append("ua=" + ua.split()[0])
    for k in ("username", "auth_result", "security_rule", "message", "exception", "procedure",
              "requests_in_window", "window_seconds", "submitted_text", "validation_error"):
        if d.get(k) is not None: parts.append(f"{k}={str(d[k])[:90]}")
    return " ".join(p for p in parts if p)

def plan_chunks(path, budget_tokens):
    """Stream the file once; return [(byte_start, byte_end, first_line, last_line)].
    Only offsets are kept, never the text. Entries are never split."""
    chunks, start_off, first, used, no, off = [], 0, 1, 0, 0, 0
    with open(path, "rb") as f:
        for raw in f:
            no += 1
            line = raw.decode("utf-8", "replace")
            if not line.strip():
                off += len(raw); continue
            cost = est_tokens(compact(parse(line), no, line)) + 1
            if used + cost > budget_tokens and used > 0:
                chunks.append((start_off, off, first, no - 1))
                start_off, first, used = off, no, 0
            used += cost
            off += len(raw)
        if used > 0:
            chunks.append((start_off, off, first, no))
    return chunks

def read_chunk(path, c):
    """Yield (line_no, raw) for one chunk by seeking; blank lines keep numbering."""
    bs, be, first, last = c
    with open(path, "rb") as f:
        f.seek(bs)
        data = f.read(be - bs).decode("utf-8", "replace")
    return [(first + i, l) for i, l in enumerate(data.splitlines()) if l.strip()]

class Entities:
    """Running per-IP memory built from every chunk, carried into later model calls."""
    def __init__(self):
        self.ips = {}

    def _e(self, ip):
        return self.ips.setdefault(ip, dict(req=0, first=None, last=None, fail=[], ok=[], users=set(),
                                            scan=[], sqli=[], rl=[], s429=0, inj=[], denied=[], exports=[]))
    def update(self, d, no):
        if not d: return
        ip = d.get("client_ip")
        if not ip: return
        e = self._e(ip)
        e["req"] += 1
        e["first"] = e["first"] or no; e["last"] = no
        ar = d.get("auth_result")
        if d.get("username"): e["users"].add(d["username"])
        if ar == "success": e["ok"].append(no)
        elif ar: e["fail"].append(no)
        txt = decoded(d)
        if SCAN_RE.search(txt): e["scan"].append(no)
        if SQLI_RE.search(txt): e["sqli"].append(no)
        if INJ_RE.search(txt): e["inj"].append(no)
        if d.get("status") == 429 or "rate" in str(d.get("security_rule", "")): e["rl"].append(no)
        if d.get("security_rule") == "access_denied" or d.get("status") in (401, 403): e["denied"].append(no)
        if "export" in (d.get("path") or ""): e["exports"].append(no)

    @staticmethod
    def _r(l):  # compact line list
        return f"{l[0]}..{l[-1]}({len(l)})" if len(l) > 2 else ",".join(map(str, l))

    def score(self, e):
        return len(e["fail"]) * 2 + len(e["scan"]) * 2 + len(e["sqli"]) * 3 + len(e["rl"]) + len(e["inj"]) * 2 + len(e["ok"]) * (5 if e["fail"] else 0)

    def summary(self, max_chars=700):
        rows = []
        for ip, e in sorted(self.ips.items(), key=lambda kv: -self.score(kv[1])):
            if self.score(e) == 0: continue
            bits = [f"req={e['req']}"]
            for k, n in (("fail", "failed_login"), ("ok", "login_ok"), ("scan", "scan_paths"), ("sqli", "sqli_like"),
                         ("rl", "rate_limited"), ("inj", "prompt_injection_text"), ("denied", "denied"), ("exports", "export")):
                if e[k]: bits.append(f"{n}=L{self._r(e[k])}")
            if e["users"] and (e["fail"] or e["ok"]): bits.append("users=" + "/".join(sorted(e["users"]))[:40])
            rows.append(f"{ip}: " + " ".join(bits))
        out = ""
        for r in rows:
            if len(out) + len(r) + 1 > max_chars: break
            out += r + "\n"
        return out.strip() or "none yet"
