# Hillel Claude Code plugins

Claude Code plugin marketplace for Hillel International staff. Maintained by Technology Services (Jerry Feth). The repo is public and contains no credentials or Fluxx data: each person uses their own Fluxx API client, stored on their own machine.

These plugins are for **Claude Code**: the CLI, or the desktop app's Code tab with the **Local** environment. They don't work in chat, Cowork, or cloud Code sessions.

## Plugins

### `fluxx`
Read Fluxx grants data, and change it with your approval, using **your own** Fluxx API client. Claude sees only what your Fluxx role allows. Every write is staged with a before/after preview and sent only when you approve it:
- **Default mode:** Claude Code shows an approval prompt.
- **Auto mode:** the hook blocks the write and Claude gives you a `!` command to run yourself.

All sent changes are logged in `~/.fluxx/audit.log`.

**Setup (once per person, about 10 minutes, with Jerry):**
1. You need `git` installed. On a Mac, the first `git` command offers to install it. You don't need a GitHub account.
2. In Fluxx, create an API client for yourself and copy the Client ID and Secret.
3. In Claude Code:
   ```
   /plugin marketplace add hillel-international/claude-code-plugins
   /plugin install fluxx@hillel
   ```
   Then start a new session.
4. Ask Claude "what's the Fluxx setup command?" Run that command in a separate **Terminal** window, not in Claude, and paste your Client ID and Secret when asked. They're stored in your Mac Keychain or Windows Credential Manager.

**Updates:** run `/plugin marketplace update hillel`, then start a new session.

## Maintaining
- Bump `version` in `plugins/<name>/.claude-plugin/plugin.json` on every change.
- Run `python3 tests/fluxx_guard_test.py` (it must print ALL PASS) and `claude plugin validate .` before pushing.
- Windows has not been tested yet: credential storage, and `python3` in `hooks/hooks.json`.
