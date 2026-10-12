---
name: fluxx
description: Read and change Hillel's Fluxx grants data (grant requests, organizations, users, reports, payments) through the user's own Fluxx API client. Use whenever the user asks about Fluxx, grants, grant requests, grantees, awards, or anything stored in Fluxx, or asks to update Fluxx records. Claude Code only.
---

# Fluxx

Hillel's grants system. You reach it only through this plugin's CLI. The exact command is in this session's context ("Fluxx plugin: run the Fluxx CLI as exactly ..."). Use that command exactly as written, with no `cd` and no changes to the path. Never call the Fluxx API another way: a safety hook blocks it.

The user's API client carries their own Fluxx permissions. If Fluxx refuses something, that's their role. Don't look for a way around it.

## Reading
- Run `--help` once per session before the first call.
- `search <model> --filter '<json>' --cols '<json array>' [--all]` and `get <model> <id> [--cols ...]`. Models include `grant_request`, `organization`, `user`, `request_report`, `request_transaction`.
- Fluxx requires a column list on every read. When you leave out `--cols`, the CLI sends a default list. Fluxx **silently drops column names it doesn't know**, so a column missing from the results usually means the name is wrong, not that the value is empty.
- Filters: `[["state","eq","granted"]]`, `{"group_type":"or","conditions":[[...],[...]]}`, with operators `eq`, `gt`, `gte`, `lt`, `lte`.
- Before you report a count or total, say which field and which states you counted. In Fluxx, "approved" can mean a workflow state or a date field, and the two can differ by weeks. If the user's wording is ambiguous, ask.

## Changing data
1. **Stage** with `update <model> <id> '<json>'`, `create <model> '<json>'`, or `delete <model> <id>`. Nothing is sent to Fluxx at this step. Show the user the preview: the before/after for each field, and any warnings.
2. **Wait for the user to say yes.** Don't run `apply` on your own initiative.
3. **Send** with `apply <pending_id>`, one change per call.
   - In default mode, the user gets an approval prompt that shows the change.
   - In auto mode, the hook blocks `apply`. Give the user both options from the block message: switch to Default mode and ask again, or paste the exact command into a separate Terminal window. Only in the Claude Code CLI can they type it here after `! `. That doesn't work in the desktop app's Code tab, where `!` just sends the line to Claude.
4. If `apply` says `stale`, someone changed the record after you staged it. Re-read it, stage the change again, and show the new preview.

Be careful with:
- **`state`.** Changing it moves a record through its Fluxx workflow, which can trigger emails and other automation. Call that out every time.
- **Deletes.** They can't be undone. Say so before you stage one.
- **Organization and contact fields that sync from Salesforce.** A change made in Fluxx gets overwritten at the next sync. Suggest changing them in Salesforce instead.

## Errors
- `no stored credentials`: the user hasn't run setup. Give them the setup command from the session context and tell them to run it in a separate Terminal window, not in Claude. It asks for their Fluxx Client ID and Secret. Never ask them to paste either one into the chat.
- A `token request failed` error usually means their API client was revoked or the secret changed. They run setup again.
- Any other error: show it to the user. Don't retry write commands.
