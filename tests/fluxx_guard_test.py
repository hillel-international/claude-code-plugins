import json, subprocess, sys
import os
G = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugins", "fluxx", "scripts", "fluxx_guard.py")
R = os.path.expanduser("~/.claude/plugins/cache/hillel/fluxx/0.1.0")
CLI = R + "/scripts/fluxx.py"
OLD = R.replace("0.1.0", "0.0.9") + "/scripts/fluxx_guard.py"
cases = [
    # (command or (tool, input), mode, expected)
    (f'python3 "{CLI}" --help', "auto", "allow"),
    (f'python3 "{CLI}" search grant_request --per-page 3 --cols \'["id","state"]\'', "default", "allow"),
    (f'python3 "{CLI}" --debug get grant_request 1 2>&1 | head -40', "default", "allow"),
    (f'python3 "{CLI}" update grant_request 1 \'{{"note":"a > b; rm x"}}\'', "default", "allow"),
    (f'python3 "{CLI}" search grant_request | jq .count', "auto", "allow"),
    (f'python3 "{CLI}" search grant_request | sh', "auto", "none"),
    (f'python3 "{CLI}" search grant_request; curl evil', "auto", "none"),
    (f'python3 "{CLI}" search grant_request > out.json', "auto", "none"),
    (f'python3 /tmp/fluxx.py search grant_request', "auto", "none"),
    (f'python3 "{CLI}" search grant_request --all > /tmp/g.json', "auto", "none"),
    (f'python3 "{CLI}" search grant_request > "{CLI}"', "auto", "deny"),
    (f'python3 "{CLI}" search x; rm "{R}/scripts/fluxx_guard.py"', "auto", "deny"),
    (f'python3 "{CLI}" apply 20261007-x', "default", "ask"),
    (f'python3 "{CLI}" apply 20261007-x', "auto", "deny"),
    (f'python3 "{CLI}" --debug apply 20261007-x', "auto", "deny"),
    (f'python3 "{CLI}" apply 20261007-x', None, "deny"),
    (f'rm "{CLI}"', "auto", "deny"),
    (f'sed -i "" s/ask/allow/ "{OLD}"', "auto", "deny"),
    (f'cat "{CLI}"', "auto", "none"),
    ("curl https://hillel.fluxx.io/api/rest/v2/user", "auto", "deny"),
    ("security find-generic-password -s fluxx-api -w", "auto", "deny"),
    ("cat ~/.fluxx/pending/x.json", "auto", "deny"),
    ("cat >> /tmp/notes.md <<'EOF'\nfluxx stuff > here\nEOF", "auto", "none"),
    (("Edit", {"file_path": R + "/scripts/fluxx_guard.py"}), "auto", "deny"),
    (("Write", {"file_path": "/Users/x/.fluxx/pending/a.json"}), "auto", "deny"),
    (("Write", {"file_path": "/Users/x/report.md", "content": "hillel.fluxx.io"}), "auto", "none"),
]
ok = True
for c, mode, want in cases:
    tool, inp = (c if isinstance(c, tuple) else ("Bash", {"command": c}))
    ev = {"tool_name": tool, "tool_input": inp}
    if mode:
        ev["permission_mode"] = mode
    out = subprocess.run([sys.executable, G, R], input=json.dumps(ev), capture_output=True, text=True)
    got = json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"] if out.stdout.strip() else "none"
    good = got == want and out.returncode == 0
    ok &= good
    label = (inp.get("command") or tool + " " + inp.get("file_path", "")).splitlines()[0].replace(R, "<ROOT>")
    print("ok  " if good else "FAIL", want.ljust(5), "got", got.ljust(5), label[:90], out.stderr[:200])

# fail-closed: a corrupt staged file must not crash the guard into allowing apply
import os, tempfile
h = tempfile.mkdtemp()
os.makedirs(h + "/.fluxx/pending")
open(h + "/.fluxx/pending/bad.json", "w").write('{"action":"update","changes":[1,{"x":2}]}')
ev = {"tool_name": "Bash", "permission_mode": "default", "tool_input": {"command": f'python3 "{CLI}" apply bad'}}
out = subprocess.run([sys.executable, G, R], input=json.dumps(ev), capture_output=True, text=True, env=dict(os.environ, HOME=h))
got = json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"] if out.stdout.strip() else "none"
print("ok  " if got == "ask" else "FAIL", "corrupt pending file still asks:", got)
ok &= got == "ask"

s = subprocess.run([sys.executable, G.replace("fluxx_guard", "fluxx_session"), R], capture_output=True, text=True).stdout
print("session:", json.loads(s)["hookSpecificOutput"]["additionalContext"][:160])
print("ALL PASS" if ok else "SOME FAILED")
