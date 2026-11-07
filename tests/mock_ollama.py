"""TEST ONLY: tiny fake Ollama server so the pipeline can be tested without a model. Not used in real analysis."""
import json, re
from http.server import BaseHTTPRequestHandler, HTTPServer
n = {"c": 0}
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        user = body["messages"][1]["content"]; n["c"] += 1
        f = []
        for m in re.finditer(r"L(\d+) .*?(\d+\.\d+\.\d+\.\d+) GET (\S*(?:UNION|OR%201)\S*)", user):
            f.append({"attack_type": "SQL Injection", "severity": "High", "entity": m.group(2), "lines": [int(m.group(1))], "reason": "SQLi payload", "action": "Block"})
        txt = json.dumps({"findings": f})
        if n["c"] == 3: txt = txt[:-5]          # simulate truncated JSON
        out = json.dumps({"message": {"content": txt}, "prompt_eval_count": 1500, "eval_count": 60}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 11434), H).serve_forever()
