"""A fake Ollama server for tests: predictable answers, no real AI needed.

  - the action mentions "evil"  -> {"risk": 9, ...}
  - anything else               -> {"risk": 1, ...}
  - mode "garbage"              -> an answer that is not valid JSON
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeOllama:
    def __init__(self, mode: str = "normal", port: int = 0) -> None:
        self.mode = mode
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep test output quiet
                pass

            def do_GET(self):                              # "is Ollama running?" check
                data = json.dumps({"models": [{"name": "qwen3:8b"}]}).encode()
                self.send_response(200 if self.path == "/api/tags" else 404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(body)
                if self.path == "/api/generate":          # warm-up
                    reply = {"done": True}
                else:
                    action = body["messages"][-1]["content"].split("ACTION TO JUDGE:")[-1]
                    if outer.mode == "garbage":
                        content = "I think it is probably fine?"
                    elif "evil" in action:
                        content = json.dumps({"risk": 9, "reason": "Sends data to an unknown outside address."})
                    else:
                        content = json.dumps({"risk": 1, "reason": "Routine action."})
                    reply = {"message": {"role": "assistant", "content": content}}
                data = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)   # port 0 = any free port
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
