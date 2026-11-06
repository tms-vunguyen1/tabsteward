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

CHROME_PY = r"chrome\.py[\"']?\s+"
RAW_CHROME = [
    (r"osascript\b[\s\S]*chrome", "AppleScript against Chrome"),
    (r"Google\W*Chrome\.app", "the Chrome binary"),
    (r"\bopen\s+(-\w+\s+)*[\"']?(Google\W*)?Chrome", "opening Chrome directly"),
    (r"Application\W*Support/Google/Chrome", "Chrome profile data"),
    (r"remote-debugging", "a Chrome debug port"),
    (r"\bimport\s+chrome\b|\bfrom\s+chrome\s+import\b", "importing chrome.py"),
]
ANTI_GUARD = r"disableAllHooks|TABSTEWARD_DEV|plugins?\s+(disable|uninstall)\s+tabsteward"
PROTECTED_MENTION = r"tabsteward/(policy\.json|audit\.jsonl|setup-grant|hooks/(guard\.py|hooks\.json))|" + ANTI_GUARD
PROTECTED_FILES = ("tabsteward/policy.json", "tabsteward/audit.jsonl", "tabsteward/setup-grant",
                   "tabsteward/hooks/guard.py",
                   "tabsteward/hooks/hooks.json", "tabsteward/skills/tabsteward/scripts/chrome.py")
MUTATING = CHROME_PY + r"(open|goto|activate|click|fill|js|close)\b"
SET_POLICY = CHROME_PY + r"set-policy\b"
POLICY = Path.home() / ".config/tabsteward/policy.json"
GRANT = POLICY.with_name("setup-grant")  # proof the user typed the setup command, consumed by set-policy
GRANT_SECONDS = 900
SETUP_COMMAND = "/tabsteward:setup"
DEV = os.environ.get("TABSTEWARD_DEV") == "1"  # set by the user when launching claude


def granted():
    try:
        return time.time() - GRANT.stat().st_mtime < GRANT_SECONDS
    except FileNotFoundError:
        return False


def decide(event):
    tool, data = event.get("tool_name"), event.get("tool_input") or {}
    if tool in ("Write", "Edit"):
        path = str(Path(data.get("file_path", "")).expanduser())
        if not DEV and path.endswith(PROTECTED_FILES):
            return "deny", "tabsteward: this file is yours to edit by hand"
        if re.search(ANTI_GUARD, str(data.get("content", "")) + str(data.get("new_string", ""))):
            return "deny", "tabsteward: hooks stay on"
        return None
    if tool != "Bash":
        return None
    cmd = data.get("command", "")
    if not DEV:
        for pattern, what in RAW_CHROME:
            if re.search(pattern, cmd, re.IGNORECASE):
                return "deny", f"tabsteward: {what} is blocked, drive Chrome only via chrome.py"
        if re.search(PROTECTED_MENTION, cmd):
            return "deny", "tabsteward: the policy, audit log and guard are off limits"
    setting = re.search(SET_POLICY, cmd)
    if setting or re.search(MUTATING, cmd):
        if event.get("permission_mode") == "bypassPermissions":
            return "deny", "tabsteward: this needs a human, not bypass mode"
        if setting and POLICY.exists() and not granted():
            return "deny", f"tabsteward: changing a policy needs the user to type {SETUP_COMMAND}"
        what = "change its policy" if setting else "change your browser"
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
