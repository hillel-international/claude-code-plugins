"""SessionStart hook for the Fluxx plugin: tells Claude where this version's CLI lives.

The plugin's install path changes with every version, so the skill can't hard-code it.
"""
import json
import os
import sys


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    cli = os.path.join(root, "scripts", "fluxx.py")
    py = "py" if sys.platform == "win32" else "python3"
    run = '%s "%s"' % (py, cli)
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "additionalContext": (
            "Fluxx plugin: run the Fluxx CLI as exactly `%s <command>` (see the fluxx skill). "
            "First-time credential setup is done by the user in a separate Terminal window, not in Claude: "
            "`%s setup`." % (run, run)),
    }}))


if __name__ == "__main__":
    main()
