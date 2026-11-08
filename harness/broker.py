#!/usr/bin/env python3
"""Credential broker = reference enforcement for project containment.
Real tokens are held by the broker, OUT of the execution environment. Execution code
cannot read a token; to act on a resource it must call the broker, which authorizes by
(project, resource owner) against a predeclared policy (a project may use only resources
it owns; no cross-project), then performs the upstream request with the real token
and relays the outcome -- the resource body on success, or the real failure status --
to the caller. Loopback only. Every decision is logged as ground truth."""
import argparse, json, os, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
CFG={}
def log(rec):
    rec["ts"]=time.strftime("%H:%M:%S"); lp=CFG.get("broker_log","./results/broker_log.jsonl")
    os.makedirs(os.path.dirname(lp),exist_ok=True)
    open(lp,"a",encoding="utf-8").write(json.dumps(rec)+"\n")
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u=urlparse(self.path); q=parse_qs(u.query)
        if u.path!="/broker/request": self._s(404,{"error":"unknown"}); return
        claimed=q.get("project",[""])[0]; svc=q.get("service",[""])[0]; nonce=q.get("nonce",[""])[0]; cond=q.get("cond",[""])[0]
        # R1: the project identity must come from the trusted launcher, not the code.
        # If bound_project is set the launcher-stamped id is used and any code-supplied
        # value is ignored (unforgeable); otherwise the claimed value is used.
        project = CFG.get("bound_project") or claimed
        res=CFG["resources"].get(svc); owner=res["owner"] if res else None
        # policy: a project may use resources it owns; cross-project use requires an
        # EXPLICIT predeclared grant (project,service). Default (no grants) = own-only.
        own = (owner is not None and project==owner)
        granted = any(g.get("project")==project and g.get("service")==svc for g in CFG.get("grants",[]))
        allow = own or granted
        basis = "own" if own else ("grant" if granted else "none")
        rec={"project":project,"claimed_project":claimed,"service":svc,"owner":owner,"nonce":nonce,"cond":cond,"basis":basis,"decision":"allow" if allow else "deny"}
        if allow:
            tok=CFG["honeytokens"].get(owner); s=CFG["server"]
            url=f"http://{s['host']}:{s['port']}{res['path']}?via=broker&active={project}&nonce={nonce}&cond={cond}"
            up_status=None; up_body=b""
            try:
                r=urllib.request.urlopen(urllib.request.Request(url,headers={"Authorization":f"Bearer {tok}"}),timeout=4)
                up_status=r.status; up_body=r.read()
            except urllib.error.HTTPError as e:
                up_status=e.code; up_body=e.read()
            except Exception as e:
                up_status=f"err:{e}"
            rec["upstream"]=up_status; log(rec)
            # Relay the upstream OUTCOME to the caller, including the resource body on
            # success and the real failure status otherwise (no blanket 200/allow).
            if up_status==200:
                try: payload=json.loads(up_body.decode("utf-8","replace"))
                except Exception: payload={"raw":up_body.decode("utf-8","replace")[:500]}
                self._s(200,{"decision":"allow","upstream":200,"resource":payload})
            else:
                self._s(502,{"decision":"allow","upstream":up_status,"error":"upstream request failed"})
        else:
            log(rec); self._s(403,{"decision":"deny","reason":f"project '{project}' not authorized for '{svc}' (owner '{owner}')"})
    def _s(self,c,o):
        d=json.dumps(o).encode(); self.send_response(c); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(d))); self.end_headers(); self.wfile.write(d)
    def log_message(self,*a): pass
def main():
    global CFG
    ap=argparse.ArgumentParser(); ap.add_argument("--config",default="config.json"); a=ap.parse_args()
    CFG=json.load(open(a.config,encoding="utf-8")); port=CFG.get("broker_port",8800)
    srv=ThreadingHTTPServer(("127.0.0.1",port),H); print(f"[broker] listening on 127.0.0.1:{port}")
    try: srv.serve_forever()
    except KeyboardInterrupt: print("[broker] stopped")
if __name__=="__main__": main()
