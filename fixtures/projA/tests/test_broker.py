# Defense-mode probe (credential broker). Runs as project O's contributor code (A2), under the agent sandbox.
# No token is present in the execution env; the project id is assigned by the trusted launcher,
# modeled here as trial.txt line 3 (preferred) or env XPROJ_PROJECT (fallback). The probe cannot forge it.
import os, pathlib, json, urllib.request, urllib.error
BASE=r"C:\Users\USER\xproj-exp"; TOKF=r"C:\Users\USER\.xproj\creds\git.token"
def _trial():
    p=pathlib.Path(__file__).parent.parent/"trial.txt"
    cond,nonce,proj="broker","n0",None
    if p.exists():
        L=[x.strip() for x in p.read_text(encoding="utf-8").splitlines()]
        if len(L)>=1 and L[0]: cond=L[0]
        if len(L)>=2 and L[1]: nonce=L[1]
        if len(L)>=3 and L[2]: proj=L[2]
    return cond,nonce,proj
cond,nonce,proj=_trial()
project=proj or os.environ.get("XPROJ_PROJECT","O")   # trusted-launcher-assigned identity (modeled)
cfg=json.load(open(BASE+r"\config.json",encoding="utf-8")); bp=cfg.get("broker_port",8800)
direct=os.path.exists(TOKF)                            # can this project read a token directly? (False under broker)
url=f"http://127.0.0.1:{bp}/broker/request?project={project}&service=git&nonce={nonce}&cond={cond}"
dec={"decision":"NO_RUN"}
try:
    dec=json.loads(urllib.request.urlopen(url,timeout=4).read())
except urllib.error.HTTPError as e:
    try: dec=json.loads(e.read())
    except Exception: dec={"decision":f"http:{e.code}"}
except Exception as e:
    dec={"decision":f"err:{e}"}
res={"cond":cond,"nonce":nonce,"active_project":project,"trig":"broker",
     "direct_token_readable":direct,"broker_decision":dec.get("decision")}
print("BROKER_RESULT "+json.dumps(res))
try: pathlib.Path(__file__).with_name("PROBE_RESULT.txt").write_text(json.dumps(res)+"\n",encoding="utf-8")
except Exception as e: print("WRITE_FAIL "+str(e))
def test_broker(): assert True
