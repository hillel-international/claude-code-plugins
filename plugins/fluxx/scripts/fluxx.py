#!/usr/bin/env python3
"""fluxx.py - staged-write CLI for the Fluxx v2 REST API (Hillel).

Reads run immediately. Every write (create / update / delete) is only STAGED
with a preview; nothing reaches Fluxx until `apply <pending_id>` is run.
Python 3 standard library only; runs on macOS and Windows.

Output is JSON on stdout. Errors are JSON on stderr with a non-zero exit:
  1 = general failure   2 = usage / credentials   3 = stale (record changed
  since it was staged).
The token, client secret and Authorization header are never printed.
"""
import argparse
import getpass
import json
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE_URL = "https://hillel.fluxx.io"
SERVICE = "fluxx-api"
LONG_URL = 1500
EXIT_GENERAL, EXIT_USAGE, EXIT_STALE = 1, 2, 3

DEBUG = False
_SECRETS = set()  # every secret/token seen this run; scrubbed from all output


class FluxxError(Exception):
    def __init__(self, message, code=EXIT_GENERAL, extra=None):
        super().__init__(message)
        self.code = code
        self.extra = extra or {}


# ---------------------------------------------------------------- output ----
def scrub(text):
    text = str(text)
    for s in _SECRETS:
        if s:
            text = text.replace(s, "***")
    return text


def emit(obj):
    print(scrub(json.dumps(obj, indent=2, default=str)))


def warn(msg):
    print(scrub(msg), file=sys.stderr)


def debug(msg):
    if DEBUG:
        warn("DEBUG " + msg)


# ----------------------------------------------------------- local state ----
def state_dir():
    return Path.home() / ".fluxx"


def _ensure(sub):
    d = state_dir() / sub
    d.mkdir(parents=True, exist_ok=True)
    return d


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit(entry):
    state_dir().mkdir(parents=True, exist_ok=True)
    entry = dict(entry, ts=now_iso())
    with open(state_dir() / "audit.log", "a", encoding="utf-8") as f:
        f.write(scrub(json.dumps(entry, default=str)) + "\n")


def new_pending_id():
    return time.strftime("%Y%m%d%H%M%S", time.gmtime()) + "-" + secrets.token_hex(3)


def pending_path(pid, sub="pending"):
    if not re.fullmatch(r"[0-9A-Za-z_-]+", pid or ""):
        raise FluxxError("invalid pending_id", EXIT_USAGE)
    return state_dir() / sub / (pid + ".json")


def save_pending(pid, obj):
    _ensure("pending")
    p = pending_path(pid)
    p.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass


def load_pending(pid):
    p = pending_path(pid)
    if not p.exists():
        raise FluxxError("no such pending change: %s" % pid, EXIT_USAGE)
    return json.loads(p.read_text(encoding="utf-8"))


# ----------------------------------------------------------- credentials ----
def _mac_get():
    r = subprocess.run(["security", "find-generic-password", "-s", SERVICE, "-w"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    secret = r.stdout.rstrip("\n")
    r2 = subprocess.run(["security", "find-generic-password", "-s", SERVICE],
                        capture_output=True, text=True)
    m = re.search(r'"acct"<blob>="([^"]*)"', r2.stdout)
    if not m:
        return None
    return m.group(1), secret


def _mac_set(client_id, secret):
    r = subprocess.run(["security", "add-generic-password", "-U", "-s", SERVICE,
                        "-a", client_id, "-w", secret],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise FluxxError("could not store credentials in the macOS keychain")


def _win_structs():
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                    ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                    ("LastWritten", wintypes.FILETIME),
                    ("CredentialBlobSize", wintypes.DWORD),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                    ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
                    ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
                    ("UserName", wintypes.LPWSTR)]
    return ctypes, CREDENTIAL


def _win_set(client_id, secret):
    ctypes, CREDENTIAL = _win_structs()
    blob = secret.encode("utf-16-le")
    buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    cred = CREDENTIAL()
    cred.Type = 1  # CRED_TYPE_GENERIC
    cred.TargetName = SERVICE
    cred.UserName = client_id
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
    cred.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE
    if not ctypes.windll.advapi32.CredWriteW(ctypes.byref(cred), 0):
        raise FluxxError("could not store credentials in Windows Credential Manager")


def _win_get():
    ctypes, CREDENTIAL = _win_structs()
    pcred = ctypes.POINTER(CREDENTIAL)()
    if not ctypes.windll.advapi32.CredReadW(SERVICE, 1, 0, ctypes.byref(pcred)):
        return None
    try:
        c = pcred.contents
        secret = bytes(bytearray(c.CredentialBlob[:c.CredentialBlobSize])).decode("utf-16-le")
        return c.UserName, secret
    finally:
        ctypes.windll.advapi32.CredFree(pcred)


def store_credentials(client_id, secret):
    if sys.platform == "darwin":
        _mac_set(client_id, secret)
    elif sys.platform == "win32":
        _win_set(client_id, secret)
    else:
        raise FluxxError("no secure credential store available on this platform; "
                         "refusing to write credentials to a file", EXIT_USAGE)


def get_credentials():
    """Return (client_id, secret). Raises FluxxError if none are stored."""
    got = None
    if sys.platform == "darwin":
        got = _mac_get()
    elif sys.platform == "win32":
        got = _win_get()
    else:
        raise FluxxError("no secure credential store available on this platform", EXIT_USAGE)
    if not got:
        raise FluxxError("no stored credentials; run `fluxx.py setup` first", EXIT_USAGE)
    _SECRETS.update(got)
    return got


# ------------------------------------------------------------------ HTTP ----
def multipart(fields):
    boundary = "----fluxx" + secrets.token_hex(12)
    parts = []
    for name, value in fields:
        parts.append(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
                      % (boundary, name, value)).encode("utf-8"))
    parts.append(("--%s--\r\n" % boundary).encode("utf-8"))
    return b"".join(parts), "multipart/form-data; boundary=" + boundary


def _jd(v):
    return json.dumps(v, separators=(",", ":"))


class Client:
    def __init__(self):
        self._token = None

    def token(self):
        if self._token:
            return self._token
        client_id, secret = get_credentials()
        body = urllib.parse.urlencode({"grant_type": "client_credentials",
                                       "client_id": client_id,
                                       "client_secret": secret}).encode()
        req = urllib.request.Request(BASE_URL + "/oauth/token", data=body, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        debug("POST /oauth/token")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                payload = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise FluxxError("token request failed: HTTP %s" % e.code)
        except (urllib.error.URLError, ValueError) as e:
            raise FluxxError("token request failed: %s" % type(e).__name__)
        tok = payload.get("access_token") if isinstance(payload, dict) else None
        if not tok:
            raise FluxxError("token response had no access_token")
        self._token = tok
        _SECRETS.add(tok)
        return tok

    def request(self, method, path, query=None, form=None, mp=None, retry_5xx=True):
        """Send a request; return (http_status, parsed_json). Raises on HTTP errors
        and on a 200 response carrying a top-level `error`."""
        url = BASE_URL + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data, headers = None, {"Authorization": "Bearer " + self.token(),
                               "Accept": "application/json"}
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif mp is not None:
            data, headers["Content-Type"] = multipart(mp)
        for attempt in (1, 2):
            debug("%s %s" % (method, url))
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    status, text = getattr(r, "status", 200), r.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                retryable = e.code == 429 or (e.code >= 500 and retry_5xx)
                if attempt == 1 and retryable:
                    time.sleep(1)
                    continue
                detail = ""
                try:
                    detail = e.read().decode("utf-8", "replace")[:500]
                except Exception:
                    pass
                raise FluxxError("HTTP %s from Fluxx: %s" % (e.code, detail),
                                 extra={"http_status": e.code})
            except urllib.error.URLError as e:
                raise FluxxError("network error: %s" % getattr(e, "reason", e))
            break
        debug("-> %s" % status)
        if not text.strip():
            body = {}
        else:
            try:
                body = json.loads(text)
            except ValueError:
                body = {"_raw": text[:500]}
        if isinstance(body, dict) and body.get("error"):
            raise FluxxError("Fluxx returned an error: %s" % _jd(body["error"]),
                             extra={"http_status": status})
        return status, body

    def list_query(self, model, params):
        """GET if the URL is short enough, otherwise POST /<model>/list (form-encoded)."""
        q = [(k, v) for k, v in params if v is not None]
        path = "/api/rest/v2/" + model
        if len(BASE_URL + path + "?" + urllib.parse.urlencode(q)) > LONG_URL:
            return self.request("POST", path + "/list", form=q)
        return self.request("GET", path, query=q)


def records_of(body, model):
    """Normalise both response shapes to a list of record dicts."""
    if not isinstance(body, dict):
        return []
    recs = body.get("records")
    if isinstance(recs, dict):
        v = recs.get(model, [])
        return v if isinstance(v, list) else [v]
    if isinstance(recs, list):
        return recs
    v = body.get(model)
    if isinstance(v, dict):
        return [v]
    if isinstance(v, list):
        return v
    return []


# Fluxx requires `cols` on every read and silently drops names a model doesn't have,
# so this list is safe for any model. `updated_at` drives the delete stale check.
DEFAULT_COLS = ["id", "updated_at", "created_at", "name", "state", "project_title",
                "amount_requested", "amount_recommended", "program_organization_id",
                "first_name", "last_name", "email"]


def fetch_one(client, model, rid, cols=None):
    q = [("cols", _jd(cols if cols is not None else DEFAULT_COLS))]
    _, body = client.request("GET", "/api/rest/v2/%s/%s" % (model, rid), query=q)
    recs = records_of(body, model)
    if recs:
        return recs[0]
    if isinstance(body, dict) and "id" in body:
        return body
    raise FluxxError("record %s/%s not found" % (model, rid))


def parse_json(text, what, want=None):
    try:
        v = json.loads(text)
    except ValueError as e:
        raise FluxxError("%s is not valid JSON: %s" % (what, e), EXIT_USAGE)
    if want and not isinstance(v, want):
        raise FluxxError("%s must be a JSON %s" % (what, want.__name__), EXIT_USAGE)
    return v


def same(a, b):
    if a == b:
        return True
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return False
    return str(a) == str(b) and a is not None and b is not None


# -------------------------------------------------------------- commands ----
def cmd_setup(args):
    client_id = getpass.getpass("Fluxx client_id (hidden): ").strip()
    secret = getpass.getpass("Fluxx client_secret (hidden): ").strip()
    if not client_id or not secret:
        raise FluxxError("client_id and client_secret are both required", EXIT_USAGE)
    _SECRETS.update([client_id, secret])
    store_credentials(client_id, secret)
    emit({"ok": True, "stored": True, "service": SERVICE})


def cmd_whoami(args):
    c = Client()
    c.list_query("organization", [("per_page", "1"), ("cols", _jd(["id"]))])
    emit({"ok": True})


def cmd_get(args):
    c = Client()
    cols = parse_json(args.cols, "--cols", list) if args.cols else DEFAULT_COLS
    q = [("cols", _jd(cols))]
    if args.relation:
        q.append(("relation", _jd(parse_json(args.relation, "--relation"))))
    _, body = c.request("GET", "/api/rest/v2/%s/%s" % (args.model, args.id), query=q)
    recs = records_of(body, args.model)
    emit({"model": args.model, "record": recs[0] if recs else body})


def cmd_search(args):
    c = Client()
    base = []
    if args.filter:
        base.append(("filter", _jd(parse_json(args.filter, "--filter"))))
    base.append(("cols", _jd(parse_json(args.cols, "--cols", list) if args.cols else DEFAULT_COLS)))
    if args.relation:
        base.append(("relation", _jd(parse_json(args.relation, "--relation"))))
    per_page = args.per_page or (100 if args.all else 25)
    page = args.page or 1
    out, total, capped = [], None, False
    while True:
        _, body = c.list_query(args.model, base + [("per_page", str(per_page)),
                                                    ("page", str(page))])
        recs = records_of(body, args.model)
        if isinstance(body, dict) and body.get("total_entries") is not None:
            total = int(body["total_entries"])
        out.extend(recs)
        if not args.all:
            break
        if len(out) >= args.max:
            capped = total is None or total > args.max
            out = out[:args.max]
            break
        if not recs or total is None or len(out) >= total:
            break
        page += 1
    emit({"model": args.model, "total_entries": total, "count": len(out),
          "capped": capped, "max": args.max if args.all else None, "records": out})


def cmd_pending(args):
    d = state_dir() / "pending"
    items = []
    for p in sorted(d.glob("*.json")) if d.exists() else []:
        o = json.loads(p.read_text(encoding="utf-8"))
        items.append({"pending_id": o["pending_id"], "action": o["action"],
                      "model": o["model"], "id": o.get("id"), "staged_at": o["staged_at"],
                      "changes": o.get("changes"), "payload": o.get("payload")})
    emit({"count": len(items), "pending": items})


def cmd_log(args):
    p = state_dir() / "audit.log"
    lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    lines = lines[-args.tail:] if args.tail > 0 else lines
    emit({"entries": [json.loads(x) for x in lines if x.strip()]})


def _stage(obj):
    pid = new_pending_id()
    obj.update(pending_id=pid, staged_at=now_iso())
    save_pending(pid, obj)
    return pid


def cmd_update(args):
    data = parse_json(args.data, "data-json", dict)
    if not data:
        raise FluxxError("data-json is empty", EXIT_USAGE)
    c = Client()
    cur = fetch_one(c, args.model, args.id, cols=list(data.keys()))
    before = {k: cur.get(k) for k in data}
    changes = [{"field": k, "before": before[k], "after": data[k]}
               for k in data if not same(before[k], data[k])]
    if not changes:
        emit({"staged": False, "message": "no changes: record already has these values; "
              "nothing staged", "model": args.model, "id": args.id})
        return
    missing = [k for k in data if k not in cur]
    state_change = any(ch["field"] == "state" for ch in changes) or "state" in data
    pid = _stage({"action": "update", "model": args.model, "id": args.id,
                  "payload": data, "before": before, "changes": changes})
    out = {"pending_id": pid, "action": "update", "model": args.model, "id": args.id,
           "changes": changes, "next": "fluxx apply %s" % pid}
    if missing:
        out["unknown_fields"] = missing
        warn("WARNING: Fluxx did not return %s for this record; check the field name "
             "(a misspelled field may be ignored or rejected on apply)" % ", ".join(missing))
    if state_change:
        msg = ("WARNING: payload changes `state`; this moves the record through its "
               "Fluxx workflow (may trigger transitions, emails, and downstream automation)")
        out["warning"] = msg
        warn(msg)
    emit(out)


def cmd_create(args):
    data = parse_json(args.data, "data-json", dict)
    if not data:
        raise FluxxError("data-json is empty", EXIT_USAGE)
    pid = _stage({"action": "create", "model": args.model, "id": None, "payload": data})
    out = {"pending_id": pid, "action": "create", "model": args.model, "payload": data,
           "next": "fluxx apply %s" % pid}
    if "state" in data:
        out["warning"] = "payload sets `state`; this places the new record in that workflow state"
        warn("WARNING: " + out["warning"])
    emit(out)


def cmd_delete(args):
    c = Client()
    snap = fetch_one(c, args.model, args.id)
    pid = _stage({"action": "delete", "model": args.model, "id": args.id,
                  "before": snap, "changes": None})
    summary = {k: v for k, v in snap.items() if not isinstance(v, (dict, list))}
    summary = dict(list(summary.items())[:12])
    out = {"pending_id": pid, "action": "delete", "model": args.model, "id": args.id,
           "summary": summary, "warning": "Deletes cannot be undone in Fluxx",
           "next": "fluxx apply %s" % pid}
    warn("WARNING: Deletes cannot be undone in Fluxx")
    emit(out)


def cmd_apply(args):
    p = load_pending(args.pending_id)
    action, model, rid = p["action"], p["model"], p.get("id")
    c = Client()
    log = {"action": action, "model": model, "id": rid, "pending_id": p["pending_id"]}
    if action in ("update", "delete"):
        before = p["before"]
        cur = fetch_one(c, model, rid, cols=list(before.keys()) if action == "update" else None)
        drift = [k for k in before if not same(before[k], cur.get(k))]
        if action == "delete":
            drift += [k for k in cur if k not in before]
        if drift:
            audit(dict(log, before=before, http_status=None, result="refused: stale",
                       stale_fields=drift))
            raise FluxxError("stale: record changed since staging; re-stage it",
                             EXIT_STALE, {"stale_fields": drift})
    try:
        if action == "create":
            status, body = c.request("POST", "/api/rest/v2/" + model,
                                     mp=[("data", _jd(p["payload"]))], retry_5xx=False)
        elif action == "update":
            status, body = c.request("PUT", "/api/rest/v2/%s/%s" % (model, rid),
                                     mp=[("data", _jd(p["payload"]))])
        elif action == "delete":
            status, body = c.request("DELETE", "/api/rest/v2/%s/%s" % (model, rid))
        else:
            raise FluxxError("unknown pending action: %s" % action)
    except FluxxError as e:
        audit(dict(log, before=p.get("before"), after=p.get("payload"),
                   http_status=e.extra.get("http_status"), result="error: " + str(e)))
        raise
    new_id = rid
    if action == "create":
        recs = records_of(body, model)
        if recs and isinstance(recs[0], dict):
            new_id = recs[0].get("id")
        log["id"] = new_id
    audit(dict(log, before=p.get("before"), after=p.get("payload"),
               http_status=status, result="ok"))
    _ensure("applied")
    dest = pending_path(p["pending_id"], "applied")
    p.update(applied_at=now_iso(), http_status=status)
    dest.write_text(json.dumps(p, indent=2, default=str), encoding="utf-8")
    pending_path(p["pending_id"]).unlink()
    emit({"applied": True, "action": action, "model": model, "id": new_id,
          "http_status": status, "response": body})


def cmd_discard(args):
    path = pending_path(args.pending_id)
    if not path.exists():
        raise FluxxError("no such pending change: %s" % args.pending_id, EXIT_USAGE)
    p = json.loads(path.read_text(encoding="utf-8"))
    path.unlink()
    audit({"action": "discard", "model": p["model"], "id": p.get("id"),
           "pending_id": p["pending_id"], "http_status": None, "result": "discarded"})
    emit({"discarded": args.pending_id})


# ------------------------------------------------------------------- CLI ----
def build_parser():
    ap = argparse.ArgumentParser(
        prog="fluxx.py",
        description="Fluxx v2 API tool. Reads run immediately; writes are STAGED with a "
                    "preview and only sent by `apply <pending_id>`. JSON on stdout.",
        epilog="Credentials are stored in the OS keychain (service 'fluxx-api') by `setup`. "
               "Local state lives in ~/.fluxx/. Exit codes: 1 error, 2 usage/credentials, "
               "3 stale.")
    ap.add_argument("--debug", action="store_true",
                    help="log method/URL/status to stderr (never credentials)")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="command")

    def add(name, fn, help_, *pos):
        sp = sub.add_parser(name, help=help_, description=help_)
        for a in pos:
            sp.add_argument(a)
        sp.set_defaults(fn=fn)
        return sp

    add("setup", cmd_setup, "store client_id/secret in the OS credential store (hidden prompts)")
    add("whoami", cmd_whoami, "prove credentials work (token + 1-row read); prints {\"ok\": true}")
    s = add("get", cmd_get, "[read] fetch one record", "model", "id")
    s.add_argument("--cols", help="JSON array of columns")
    s.add_argument("--relation", help="JSON relation spec")
    s = add("search", cmd_search, "[read] list/search records", "model")
    s.add_argument("--filter", help='JSON filter, e.g. [["state","eq","granted"]]')
    s.add_argument("--cols", help="JSON array of columns")
    s.add_argument("--relation", help="JSON relation spec")
    s.add_argument("--per-page", type=int, help="page size (default 25; 100 with --all)")
    s.add_argument("--page", type=int, help="start page (default 1)")
    s.add_argument("--all", action="store_true", help="page through all results up to --max")
    s.add_argument("--max", type=int, default=5000, help="record cap for --all (default 5000)")
    add("pending", cmd_pending, "[read] list staged changes")
    s = add("log", cmd_log, "[read] show the audit log")
    s.add_argument("--tail", type=int, default=20, help="last N entries (default 20; 0 = all)")
    add("update", cmd_update, "[stage] preview a field update (before/after); does NOT send",
        "model", "id", "data")
    add("create", cmd_create, "[stage] preview a create; does NOT send", "model", "data")
    add("delete", cmd_delete, "[stage] snapshot + preview a delete; does NOT send", "model", "id")
    add("apply", cmd_apply, "SEND one staged change (re-checks staleness first)", "pending_id")
    add("discard", cmd_discard, "drop a staged change without sending", "pending_id")
    return ap


def main(argv=None):
    global DEBUG
    args = build_parser().parse_args(argv)
    DEBUG = args.debug
    try:
        # model and id go into the URL path, so only accept plain names and numeric ids
        if getattr(args, "model", None) is not None and not re.fullmatch(r"[a-z][a-z0-9_]*", args.model):
            raise FluxxError("invalid model name: %r" % args.model, EXIT_USAGE)
        if getattr(args, "id", None) is not None and not re.fullmatch(r"\d+", str(args.id)):
            raise FluxxError("invalid record id: %r" % args.id, EXIT_USAGE)
        args.fn(args)
        return 0
    except FluxxError as e:
        err = {"error": str(e)}
        err.update(e.extra)
        print(scrub(json.dumps(err)), file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
