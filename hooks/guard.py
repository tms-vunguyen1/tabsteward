#!/usr/bin/env python3
"""PreToolUse guard for tabsteward. Reads the hook JSON on stdin, prints a decision.

ponytail: string matching on Bash commands stops accidents and page-driven injection,
not a determined author. Hard isolation needs managed settings or Chrome's own toggle.
"""
import json
import os
import re
import sys
import time
from pathlib import Path

CHROME_PY = r"chrome\.py\s+"
RAW_CHROME = [
    (r"osascript\b[\s\S]*chrome|chrome[\s\S]*\bosascript\b", "AppleScript against Chrome"),
    (r"com\.google\.chrome", "Chrome by bundle id"),
    (r"Google\W*Chrome\.app", "the Chrome binary"),
    (r"\bopen\s+(-\w+\s+)*[\"']?(Google\W*)?Chrome", "opening Chrome directly"),
    (r"Application\W*Support/Google/Chrome", "Chrome profile data"),
    (r"remote-debugging", "a Chrome debug port"),
    (r"\bimport\s+chrome\b|\bfrom\s+chrome\s+import\b", "importing chrome.py"),
]
ANTI_GUARD = r"disableAllHooks|TABSTEWARD_DEV|\bplugins?\b[^|;&\n]*\b(disable|uninstall|remove)\b[^|;&\n]*tabsteward|tabsteward@\S*:\s*false"
STATE = r"\.config/tabsteward\b|\bsetup-grant\b|tabsteward/(policy\.json|audit\.jsonl)"
GUARD_FILES = r"hooks/guard\.(py|sh)|tabsteward\S*/hooks/hooks\.json"  # also the cache layout, <name>/<version>/hooks/
WRITE_TO = r"(>|\btee\b|\bsed\b[^|;&\n]*\s-i|\b(cp|mv|rm|ln)\b)[^|;&\n]*(chrome\.py|hooks/hooks\.json)\b"  # generic names: reading or running stays allowed
PROTECTED_MENTION = "|".join((STATE, GUARD_FILES, WRITE_TO, ANTI_GUARD))
PROTECTED_PATH = "|".join((STATE, GUARD_FILES, r"skills/tabsteward/scripts/chrome\.py$"))
MUTATING = CHROME_PY + r"(open|goto|activate|click|fill|js|close)\b"
SET_POLICY = CHROME_PY + r"set-policy\b"
CONFIRM_WINDOW = r"--confirm-window\b"
CONFIRM_DATA = r"--confirm-page-data\b"
POLICY = Path.home() / ".config/tabsteward/policy.json"
GRANT = POLICY.with_name("setup-grant")  # proof the user typed the setup command, consumed by set-policy
GRANT_SECONDS = 900
WIPE = r"\s*rm\s+-(rf?|fr)\s+(~|\$HOME|" + re.escape(str(Path.home())) + r")/\.config/tabsteward/?\s*"  # the whole command
SETUP_COMMAND = "/tabsteward:setup"
DEV = os.environ.get("TABSTEWARD_DEV") == "1"  # set by the user when launching claude


def granted():
    try:
        return time.time() - GRANT.stat().st_mtime < GRANT_SECONDS
    except FileNotFoundError:
        return False


def plain(text):
    """Quotes and backslashes mean nothing to these patterns, but would split the words they look for."""
    return re.sub(r"[\"'\\]", "", text)


def found(pattern, text):
    return re.search(pattern, text, re.IGNORECASE)  # macOS paths ignore case


def decide(event):
    tool, data = event.get("tool_name"), event.get("tool_input") or {}
    if tool in ("Write", "Edit"):
        path = str(Path(data.get("file_path", "")).expanduser().resolve())
        if not DEV and found(PROTECTED_PATH, path):
            return "deny", "tabsteward: this file is yours to edit by hand"
        if found(ANTI_GUARD, plain(str(data.get("content", "")) + str(data.get("new_string", "")))):
            return "deny", "tabsteward: hooks stay on"
        return None
    if tool != "Bash":
        return None
    cmd = data.get("command", "")
    text = plain(cmd)
    if not DEV:
        for pattern, what in RAW_CHROME:
            if found(pattern, text):
                return "deny", f"tabsteward: {what} is blocked, drive Chrome only via chrome.py"
        if re.fullmatch(WIPE, text, re.IGNORECASE) and event.get("permission_mode") != "bypassPermissions":
            return "ask", "tabsteward: this deletes your policy and audit log, and the next set-policy needs no grant"
        if found(PROTECTED_MENTION, text):
            return "deny", "tabsteward: the policy, audit log and guard are off limits"
    setting, confirming, sending = found(SET_POLICY, text), found(CONFIRM_WINDOW, text), found(CONFIRM_DATA, text)
    needs_person = setting or confirming or sending
    if needs_person or found(MUTATING, text):
        if event.get("permission_mode") == "bypassPermissions":
            return "deny", "tabsteward: this needs a human, not bypass mode"
        if not DEV and setting and POLICY.exists() and not granted():  # a dev session can forge a grant anyway
            return "deny", f"tabsteward: changing a policy needs the user to type {SETUP_COMMAND}"
    if needs_person:  # the rest was decided in setup, and chrome.py enforces it
        what = ("change its policy" if setting else "send data it read on one site to another" if sending
                else "use a window whose profile is uncertain")
        return "ask", f"tabsteward wants to {what}: {cmd[:300]}"
    return None


def main():
    if sys.argv[1:] == ["session-start"]:
        if not POLICY.exists():
            print("tabsteward is installed but not set up. When the user asks for something in their "
                  "browser, run the tabsteward:setup skill first, then continue their task.")
        return
    if sys.argv[1:] == ["user-prompt"]:  # only a real user message reaches this hook
        if json.load(sys.stdin).get("prompt", "").strip().startswith(SETUP_COMMAND):
            GRANT.parent.mkdir(parents=True, exist_ok=True)
            GRANT.touch()
        return
    try:
        verdict = decide(json.load(sys.stdin))
    except Exception as e:  # a broken guard must not open the door
        verdict = ("deny", f"tabsteward guard failed: {e}")
    if verdict:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                 "permissionDecision": verdict[0],
                                                 "permissionDecisionReason": verdict[1]}}))


if __name__ == "__main__":
    main()
