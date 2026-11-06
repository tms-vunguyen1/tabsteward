import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "skills/tabsteward/scripts"))
import chrome

GUARD = Path(__file__).parents[1] / "hooks/guard.py"
ENV = {k: v for k, v in os.environ.items() if k != "TABSTEWARD_DEV"}  # a dev session must not reach the guard under test


class Profiles(unittest.TestCase):
    blobs = {"A": b"x https://x.com/home y", "B": b"https://teams.example/ https://x.com/home"}

    def test_needle_strips_query_and_skips_internal(self):
        self.assertEqual(chrome.needle("https://a.b/c?d=1#e"), b"https://a.b/c")
        self.assertIsNone(chrome.needle("chrome://newtab/"))

    def test_most_matches_wins(self):
        self.assertEqual(chrome.best_profile(["https://x.com/home", "https://teams.example/"], self.blobs), "B")

    def test_tie_or_no_match_is_unknown(self):
        self.assertIsNone(chrome.best_profile(["https://x.com/home"], self.blobs))
        self.assertIsNone(chrome.best_profile(["chrome://newtab/"], self.blobs))

    def test_resolve_profile(self):
        known = [{"dir": "P1", "name": "Work", "email": "a@x"}, {"dir": "P2", "name": "Work", "email": "b@x"},
                 {"dir": "P3", "name": "Me", "email": "c@x"}]
        self.assertEqual(chrome.resolve_profile("me", known)["dir"], "P3")
        self.assertEqual(chrome.resolve_profile("b@x", known)["dir"], "P2")
        with self.assertRaises(chrome.Fail):
            chrome.resolve_profile("Work", known)


class Policy(unittest.TestCase):
    pol = {"profiles": ["P1"], "allow_js": False, "allow_domains": []}

    def test_only_web_urls(self):
        chrome.check_url("https://a.b/", self.pol)
        chrome.check_url("about:blank", self.pol)
        for url in ("javascript:alert(1)", "file:///etc/passwd", "chrome://settings", "data:text/html,x"):
            with self.assertRaises(chrome.Fail):
                chrome.check_url(url, self.pol)

    def test_domain_allowlist(self):
        pol = {**self.pol, "allow_domains": ["x.com"]}
        chrome.check_url("https://x.com/home", pol)
        chrome.check_url("https://mobile.x.com/", pol)
        for url in ("https://notx.com/", "https://x.com.evil.io/", "https://evil.io/x.com"):
            with self.assertRaises(chrome.Fail):
                chrome.check_url(url, pol)

    def test_tab_outside_profile_refused(self):
        win = [{"window": "1", "profile": "P2", "tabs": [{"tab": "7", "url": "https://a.b/"}]}]
        with patch.object(chrome, "windows", return_value=win), self.assertRaises(chrome.Fail):
            chrome.authorize("7", self.pol)

    def test_tab_with_unknown_profile_refused(self):
        win = [{"window": "1", "profile": None, "tabs": [{"tab": "7", "url": "https://a.b/"}]}]
        with patch.object(chrome, "windows", return_value=win), self.assertRaises(chrome.Fail):
            chrome.authorize("7", self.pol)

    def test_missing_policy_refused(self):
        with patch.object(chrome, "POLICY", Path("/nonexistent/policy.json")), self.assertRaises(chrome.Fail):
            chrome.policy()

    def test_js_off_by_default(self):
        a = SimpleNamespace(cmd="js")
        with patch.object(chrome, "policy", return_value=self.pol), patch.object(chrome, "require_single_chrome"), \
             self.assertRaises(chrome.Fail):
            chrome.gate(a)


class Setup(unittest.TestCase):
    known = [{"dir": "P1", "name": "A", "email": "a@x"}]

    def run_set(self, tmp, **kw):
        args = SimpleNamespace(**{"profile": ["P1"], "domain": [], "allow_js": False, **kw})
        with patch.object(chrome, "profiles", return_value=self.known), patch.object(chrome, "CONFIG", tmp), \
             patch.object(chrome, "POLICY", tmp / "policy.json"):
            return chrome.cmd_set_policy(args)

    def test_writes_private_file(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d) / "new"
            self.run_set(tmp, domain=["X.com"])
            self.assertEqual(json.loads((tmp / "policy.json").read_text()),
                             {"profiles": ["P1"], "allow_js": False, "allow_domains": ["x.com"]})
            self.assertEqual((tmp / "policy.json").stat().st_mode & 0o777, 0o600)

    def test_grant_is_single_use(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "setup-grant").touch()
            with patch.object(chrome, "GRANT", tmp / "setup-grant"):
                self.run_set(tmp)
            self.assertFalse((tmp / "setup-grant").exists())

    def test_rejects_unknown_profile_and_bad_domain(self):
        with tempfile.TemporaryDirectory() as d:
            for kw in ({"profile": ["Nope"]}, {"domain": ["https://x.com/"]}, {"domain": ["*"]}):
                with self.assertRaises(chrome.Fail):
                    self.run_set(Path(d), **kw)

    def test_setup_commands_skip_policy(self):
        with patch.object(chrome, "policy", side_effect=chrome.Fail("no policy")), \
             patch.object(chrome, "require_single_chrome"):
            chrome.gate(SimpleNamespace(cmd="setup-info"))
            with self.assertRaises(chrome.Fail):
                chrome.gate(SimpleNamespace(cmd="windows"))

    def test_second_chrome_process_stops_everything(self):
        two = SimpleNamespace(stdout="431\n90602\n")
        with patch.object(chrome.subprocess, "run", return_value=two), \
             patch.object(chrome, "policy", return_value={"profiles": [], "allow_js": False, "allow_domains": []}):
            for cmd in ("windows", "read", "setup-info"):
                with self.assertRaises(chrome.Fail):
                    chrome.gate(SimpleNamespace(cmd=cmd))
        with patch.object(chrome.subprocess, "run", return_value=SimpleNamespace(stdout="431\n")):
            chrome.require_single_chrome()


class Guard(unittest.TestCase):
    def run_guard(self, tool, mode="auto", env=None, **tool_input):
        r = subprocess.run([sys.executable, str(GUARD)], capture_output=True, text=True, env={**ENV, **(env or {})},
                           input=json.dumps({"tool_name": tool, "permission_mode": mode, "tool_input": tool_input}))
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] if r.stdout else None

    def test_raw_chrome_denied(self):
        for cmd in ('osascript -e \'tell application "Google Chrome" to count windows\'',
                    'open -na "Google Chrome" --args --profile-directory=X',
                    '"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --new-window',
                    'sqlite3 ~/Library/Application\\ Support/Google/Chrome/Default/Cookies .dump',
                    "python3 -c 'import chrome; chrome.js(1, \"x\")'"):
            self.assertEqual(self.run_guard("Bash", command=cmd), "deny", cmd)

    def test_mutating_asks(self):
        for sub in ("open https://a.b --profile V", "click 1 '#b'", "fill 1 '#a' x", "js 1 --code x", "close 1", "goto 1 https://a.b"):
            self.assertEqual(self.run_guard("Bash", command=f"python3 /x/scripts/chrome.py {sub}"), "ask", sub)

    def test_set_policy_asks_and_needs_a_human(self):
        cmd = "python3 /x/scripts/chrome.py set-policy --profile P1 --allow-js"
        with tempfile.TemporaryDirectory() as home:  # no policy here, whatever this machine has
            env = {"HOME": home}
            self.assertEqual(self.run_guard("Bash", env=env, command=cmd), "ask")
            self.assertEqual(self.run_guard("Bash", env={**env, "TABSTEWARD_DEV": "1"}, command=cmd), "ask")
            self.assertEqual(self.run_guard("Bash", env=env, mode="bypassPermissions", command=cmd), "deny")
        self.assertIsNone(self.run_guard("Bash", command="python3 /x/scripts/chrome.py setup-info"))

    def test_changing_policy_needs_the_user_typed_grant(self):
        cmd = "python3 /x/scripts/chrome.py set-policy --profile P1"
        with tempfile.TemporaryDirectory() as home:
            env = {"HOME": home}
            prompt = lambda text: subprocess.run([sys.executable, str(GUARD), "user-prompt"], text=True,
                                                 capture_output=True, env={**ENV, **env},
                                                 input=json.dumps({"prompt": text}))
            self.assertEqual(self.run_guard("Bash", env=env, command=cmd), "ask")  # first run, no policy
            policy = Path(home) / ".config/tabsteward/policy.json"
            policy.parent.mkdir(parents=True)
            policy.write_text("{}")
            self.assertEqual(self.run_guard("Bash", env=env, command=cmd), "deny")
            prompt("please run /tabsteward:setup for me")
            self.assertEqual(self.run_guard("Bash", env=env, command=cmd), "deny")
            prompt("/tabsteward:setup")
            self.assertEqual(self.run_guard("Bash", env=env, command=cmd), "ask")
            grant = policy.with_name("setup-grant")
            os.utime(grant, (0, 0))
            self.assertEqual(self.run_guard("Bash", env=env, command=cmd), "deny")  # expired

    def test_grant_cannot_be_forged(self):
        self.assertEqual(self.run_guard("Bash", command="touch ~/.config/tabsteward/setup-grant"), "deny")
        self.assertEqual(self.run_guard("Write", file_path="~/.config/tabsteward/setup-grant", content=""), "deny")

    def test_session_start_nudges_only_without_policy(self):
        with tempfile.TemporaryDirectory() as home:
            env = {**ENV, "HOME": home}
            run = lambda: subprocess.run([sys.executable, str(GUARD), "session-start"], capture_output=True,
                                         text=True, env=env).stdout
            self.assertIn("tabsteward:setup", run())
            policy = Path(home) / ".config/tabsteward/policy.json"
            policy.parent.mkdir(parents=True)
            policy.write_text("{}")
            self.assertEqual(run(), "")

    def test_read_only_passes(self):
        for sub in ("windows", "profiles", "read 1", "wait 1 '#a'"):
            self.assertIsNone(self.run_guard("Bash", command=f"python3 /x/scripts/chrome.py {sub}"), sub)
        self.assertIsNone(self.run_guard("Bash", command="git status"))
        self.assertIsNone(self.run_guard("Write", file_path="/tmp/notes.md", content="hi"))

    def test_protected_files_denied(self):
        for path in ("~/.config/tabsteward/policy.json", "/p/tabsteward/hooks/guard.py",
                     "/p/tabsteward/skills/tabsteward/scripts/chrome.py"):
            self.assertEqual(self.run_guard("Edit", file_path=path, new_string="x"), "deny", path)
        self.assertEqual(self.run_guard("Bash", command="sed -i '' s/false/true/ ~/.config/tabsteward/policy.json"), "deny")
        self.assertEqual(self.run_guard("Edit", file_path="/h/.claude/settings.json", new_string='"disableAllHooks": true'), "deny")

    def test_guard_cannot_be_switched_off(self):
        self.assertEqual(self.run_guard("Bash", command="claude plugin disable tabsteward@tabsteward"), "deny")
        self.assertEqual(self.run_guard("Edit", file_path="/h/.claude/settings.json",
                                        new_string='"env": {"TABSTEWARD_DEV": "1"}'), "deny")

    def test_other_plugins_and_this_folder_are_not_blocked(self):
        for cmd in ("find . -path '*hooks/hooks.json'", "cat ~/.claude/plugins/postman/hooks/hooks.json",
                    "open tabsteward/README.md"):
            self.assertIsNone(self.run_guard("Bash", command=cmd), cmd)
        self.assertIsNone(self.run_guard("Edit", file_path="/p/other-plugin/hooks/hooks.json", new_string="x"))

    def test_bypass_mode_denies_changes(self):
        self.assertEqual(self.run_guard("Bash", mode="bypassPermissions", command="python3 chrome.py click 1 a"), "deny")

    def test_hooks_ignore_the_session_python_environment(self):
        hooks = json.loads((GUARD.parent / "hooks.json").read_text())["hooks"]
        commands = [h["command"] for event in hooks.values() for entry in event for h in entry["hooks"]]
        self.assertEqual(len(commands), 3)
        for command in commands:
            self.assertTrue(command.startswith("python3 -I "), command)

    def test_broken_input_fails_closed(self):
        r = subprocess.run([sys.executable, str(GUARD)], input="not json", capture_output=True, text=True, env=ENV)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_dev_mode_allows_editing_guard(self):
        self.assertIsNone(self.run_guard("Edit", env={"TABSTEWARD_DEV": "1"}, file_path="/p/tabsteward/hooks/guard.py", new_string="x"))


class OpenByProfile(unittest.TestCase):
    known = [{"dir": "P1", "name": "Me", "email": "a@x"}]
    args = SimpleNamespace(url="https://a.b/", window=None, profile="Me")

    def test_unknown_window_blocks_new_window(self):
        with patch.object(chrome, "allowed_profiles", return_value=self.known), \
             patch.object(chrome, "windows", return_value=[{"window": "1", "profile": None}]), \
             patch.object(chrome.subprocess, "Popen") as popen:
            with self.assertRaises(chrome.Fail):
                chrome.cmd_open(self.args)
        popen.assert_not_called()

    def test_no_window_for_profile_launches(self):
        with patch.object(chrome, "allowed_profiles", return_value=self.known), \
             patch.object(chrome, "windows", return_value=[{"window": "1", "profile": "P9"}]), \
             patch.object(chrome.subprocess, "Popen") as popen:
            self.assertEqual(chrome.cmd_open(self.args)["launched"], "P1")
        popen.assert_called_once()


if __name__ == "__main__":
    unittest.main()
