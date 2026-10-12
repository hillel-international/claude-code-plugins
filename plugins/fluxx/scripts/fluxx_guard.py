"""PreToolUse hook for the Fluxx plugin.

- Read and stage commands of this plugin's fluxx.py -> allow (a plugin can't ship
  permission rules, so the hook grants them; nothing reaches Fluxx without `apply`).
- `fluxx.py apply <id>` -> in default/acceptEdits/plan mode, ask the human and show the
  staged change in the prompt. In auto, bypass, or an unknown mode, deny: those modes
  can approve an `ask` without a human, so the person switches to Default mode or runs it
  themselves in Terminal (`! ...` only works in the CLI, not the desktop Code tab).
- Shell commands that modify the plugin's files -> deny (protects this hook from Claude).
- Shell commands that call the Fluxx API directly, read the stored secret,
  or touch ~/.fluxx/pending|applied|audit without going through fluxx.py -> deny.
- Edit/Write tools on the plugin or its staged changes -> deny.
- If this hook itself fails while an `apply` is in the command -> deny (fail closed).
Everything else: no opinion (normal permission rules apply).
"""
import json
import os
import re
import sys
from pathlib import Path

PROMPTING_MODES = ("default", "acceptEdits", "plan")
SAFE_SUBCOMMANDS = ("get", "search", "pending", "log", "update", "create", "delete",
                    "discard", "whoami", "--help", "-h")
PIPE_OK = ("head", "tail", "jq")
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")

APPLY = re.compile(r"fluxx\.py[\"']?\s+(?:--debug\s+)?apply\s+([0-9A-Za-z_-]+)")
DIRECT = re.compile(
    r"hillel\.fluxx\.io"                       # raw API / token calls
    r"|find-generic-password[^\n]*fluxx-api"    # macOS Keychain read
    r"|CredRead[^\n]*fluxx-api"                 # Windows Credential Manager read
    r"|keyring[^\n]*fluxx-api",
    re.IGNORECASE,
)
PENDING = re.compile(r"\.fluxx[\\/]+(pending|applied|audit)", re.IGNORECASE)
MODIFIES = re.compile(r">|<<|\btee\b|\bsed\s+-i|\bperl\s+-i|\brm\b|\bmv\b|\bcp\b|\bchmod\b"
                      r"|\btruncate\b|\bln\b|open\(|write"
                      # inline interpreter code: `python3 -c`, `python3 -` (stdin), `py -c`
                      r"|(?:^|[;&|(]\s*|\s)(?:python3?|py)\s+-(?:c\b|\s|$)")
# redirects that can't modify anything: fd duplication and /dev/null
HARMLESS_REDIRECT = re.compile(r"\d?>&\d|\d?>>?\s*/dev/null")
HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n.*?^\s*\1\s*$", re.DOTALL | re.MULTILINE)
QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")
CHAINING = re.compile(r";|&&|\|\||`|\$\(|[<>]|\n")


def no_heredoc(cmd):
    return HEREDOC.sub("<<HEREDOC", cmd)


def bare(cmd):
    """The command with heredoc bodies, quoted strings and harmless redirects removed."""
    return HARMLESS_REDIRECT.sub(" ", QUOTED.sub("''", no_heredoc(cmd)))


def decide(decision, reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}))


def plugin_root():
    root = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    return os.path.normpath(root) if root else ""


def path_pattern(path):
    """Regex for `path`, matching either slash direction."""
    parts = re.split(r"[\\/]+", path.strip("\\/"))
    return re.compile(r"[\\/]*".join(re.escape(p) for p in parts if p), re.IGNORECASE)


def describe(pid):
    """One-paragraph summary of a staged change, for the approval prompt."""
    path = Path.home() / ".fluxx" / "pending" / (pid + ".json")
    try:
        p = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "No staged change %s was found. Don't approve this." % pid
    action, model, rid = p.get("action"), p.get("model"), p.get("id")
    if action == "delete":
        return "DELETE %s %s (this can't be undone)." % (model, rid)
    if action == "create":
        return "CREATE %s with %s" % (model, json.dumps(p.get("payload"))[:600])
    lines = ["%s: %s -> %s" % (c.get("field"), json.dumps(c.get("before")), json.dumps(c.get("after")))
             for c in p.get("changes") or [] if isinstance(c, dict)]
    warn = " WARNING: this changes `state`, which moves the record through its workflow." \
        if "state" in (p.get("payload") or {}) else ""
    return ("UPDATE %s %s: " % (model, rid) + "; ".join(lines))[:900] + warn


def outside_cli_call(cmd, cli):
    """cmd minus heredoc bodies and minus the CLI path of a leading `python3 <cli>`, so
    `fluxx.py search ... > out.json` isn't mistaken for modifying the plugin."""
    text = no_heredoc(cmd)
    if cli and re.match(r"\s*(?:python3?|py)(?:\.exe)?\s", text):
        text = path_pattern(cli).sub("", text, count=1)
    return text


def is_safe_cli_call(cmd, cli):
    """True if cmd is one read/stage call of this plugin's CLI, optionally piped to head/tail/jq."""
    segments = cmd.split("|")
    first = segments[0].strip()
    m = re.match(r"(?:python3?|py)(?:\.exe)?\s+([\"']?)(.+?)\1(?:\s+(.*))?$", first, re.DOTALL)
    if not m or not cli or os.path.normcase(os.path.normpath(m.group(2))) != os.path.normcase(cli):
        return False
    args = (m.group(3) or "").split()
    if args[:1] == ["--debug"]:
        args = args[1:]
    if not args or args[0] not in SAFE_SUBCOMMANDS:
        return False
    if CHAINING.search(bare(cmd)):
        return False
    return all(s.strip().split()[:1] and s.strip().split()[0] in PIPE_OK for s in segments[1:])


def main(event):
    root = plugin_root()
    cli = os.path.normpath(os.path.join(root, "scripts", "fluxx.py")) if root else ""
    # all versions of this plugin share the parent folder; protect it, not just this version
    protected = path_pattern(os.path.dirname(root)) if root else None
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    if tool == "Bash":
        cmd = tool_input.get("command") or ""
        m = APPLY.search(cmd)
        if m:
            if event.get("permission_mode") in PROMPTING_MODES:
                decide("ask", "Send to Fluxx? " + describe(m.group(1)))
            else:
                decide("deny", "This session's permission mode (%s) can't guarantee a human approves "
                       "Fluxx writes. Show the user this change and give them two ways to send it: "
                       "(1) switch this session to Default mode and ask again, which shows an approval "
                       "prompt; or (2) paste this command into a separate Terminal window (in the Claude "
                       "Code CLI they can instead type it here after `! `; that does NOT work in the "
                       "desktop app): %s   -- %s" % (event.get("permission_mode"), cmd.strip(), describe(m.group(1))))
        elif protected and protected.search(outside_cli_call(cmd, cli)) and MODIFIES.search(bare(cmd)):
            decide("deny", "The Fluxx plugin's files can't be modified from Claude.")
        elif DIRECT.search(cmd) or (PENDING.search(cmd) and "fluxx.py" not in cmd):
            decide("deny", "Use the Fluxx plugin's fluxx.py for Fluxx; direct API, secret, or "
                   "staged-file access is blocked.")
        elif is_safe_cli_call(cmd, cli):
            decide("allow", "Fluxx read or staging command (nothing is sent to Fluxx without apply).")
    elif tool in EDIT_TOOLS:
        target = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if (protected and protected.search(target)) or re.search(r"[\\/]\.fluxx[\\/]", target):
            decide("deny", "The Fluxx plugin and its staged changes are not editable from Claude.")


if __name__ == "__main__":
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
    except ValueError:
        sys.exit(0)
    try:
        main(event)
    except Exception:
        # fail closed for writes, open for everything else
        cmd = str((event.get("tool_input") or {}).get("command") or "")
        if "fluxx.py" in cmd and "apply" in cmd:
            decide("deny", "The Fluxx safety hook hit an error, so this write was blocked. Tell Jerry.")
        sys.exit(0)
