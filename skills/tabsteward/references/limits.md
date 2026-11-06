# Tested limits

Measured on 2026-11-06 with Chrome 157 on macOS 15, on a local test page unless noted. Re-test before relying on a row after a Chrome upgrade: serve `tests/lab/` on 127.0.0.1 ports 8765 and 8766 (two ports make the iframe cross-origin) and open it in a scratch window.

Prerequisite: **View > Developer > Allow JavaScript from Apple Events**, set per profile (`browser.allow_javascript_apple_events` in each profile's Preferences). Without it, `profiles`, `windows`, `open`, `goto`, `close` still work, and `activate` switches the tab but cannot report visibility; `read`, `click`, `fill`, `js` do not.

## Works

| Case | Notes |
|---|---|
| Plain and React controlled inputs | `fill` reads back the value |
| `contenteditable` | Via `execCommand`. Rich editors can differ, see below |
| Select, checkbox, date value | Set directly or by script click |
| Open shadow DOM, same-origin iframe | |
| File input | Only with a script-built `File` via `DataTransfer` |
| Drag and drop | Only when the page handles the events itself |
| Acting on a background tab | Works while hidden; the cursor overlay is skipped |
| Cursor overlay | Reached its target on a visible tab in real Chrome, and the click ring rendered. The icon also painted on GitHub's strict CSP, measured from canvas pixels. Headless virtual time does not reproduce it |
| `chrome://` pages | Title readable. Interaction untested |

## Does not work

| Case | Result | Way around |
|---|---|---|
| Handler that checks `isTrusted` | Click is ignored. `effect` reads `none_seen` when the page does nothing visible | Ask the user to click |
| Typing by key events | Event fires, no text appears | `fill` |
| CSS `:hover` | Not triggered | None |
| `showPicker()`, file dialog | Needs a real user gesture | Ask the user |
| `window.open` | Popup blocked | `chrome.py open` |
| Closed shadow DOM | Unreachable | None |
| Cross-origin iframe | `contentDocument` is null, `js` only reaches the main frame | Open the frame URL directly in its own tab |
| Page JS variables | Scripts run in an isolated world: DOM shared, globals not | Read the DOM |
| Promises as return value | Nothing returned | Write to the DOM, read in a second call |
| `alert()` | Tab stops answering and cannot be dismissed by script. `click` returns `effect: blocked` after about 3 seconds, other tab commands time out after 10. `windows` and `close` still work | Ask the user, or `close` it if it is your tab |

## Single Chrome only

AppleScript addresses "Google Chrome" by name and cannot pick a process. With a second Chrome running, such as one started by chrome-devtools-mcp or Puppeteer, it answered from that browser instead of the user's. `chrome.py` refuses to run while more than one Chrome process exists.

## Unreliable

- **X post editor:** script typing doubled the text while the Post button stayed enabled. Use the intent URL.
- **Bringing Chrome forward:** `activate` worked sometimes and reported `hidden` other times. Trust the returned `visibility`.
- **Window title and real keyboard or mouse input:** need Accessibility permission for the terminal app. Not used here.

## How far the policy holds

- The hook matches text in Bash commands. It ignores quotes, backslashes and case before matching, and refuses any mention of `~/.config/tabsteward`, except a lone `rm -r` of that whole folder, which asks the user first. It stops accidents and page-driven injection, not obfuscated commands: a path in a variable, a `cd` into Chrome's folder, a script file passed to `osascript`, or Python loading `chrome.py` indirectly all still pass. It is not a sandbox.
- `disableAllHooks`, `plugin disable` and `TABSTEWARD_DEV` can each switch the guard off. It refuses Edit, Write and Bash that mention them, but that list is whack-a-mole. A hard wall needs managed settings.
- Changing an existing policy needs a one-time grant, valid 15 minutes, created only when a user message starts with `/tabsteward:setup`. `chrome.py` checks it as well as the hook, so a command the hook misses still cannot change a policy, unless the grant file is forged in a way the hook misses too. The first run, with no policy yet, has no such check.
- The guard runs on every prompt and every Bash, Write and Edit call in every project. It can misfire on a compound command with `osascript` and any word `chrome` in it, on any `hooks/guard.py` or `setup-grant` in another project, and on writing to any file named `chrome.py` or `hooks/hooks.json`. Claude also cannot read the audit log through Bash, so the user reads it.
- `click` compares page snapshots for up to 2.5 seconds. `none_seen` does not prove the click was ignored: a fetch, a download or a slower page looks the same. `changed` does not prove the click caused it, since pages change on their own. A change in a cross-origin frame is not seen, and a change that reverts between two looks is missed.
- A Bash command that only quotes `chrome.py set-policy`, such as release notes in a heredoc, is still treated as a policy change, and quoting a browser command raises a prompt. No text rule can separate running from quoting. Write the text to a file first and pass the file, such as `--notes-file`. In a dev session the policy case asks instead of refusing.
- A hook deny under `bypassPermissions` is not confirmed by the docs. The guard denies changes there on a best-effort basis.
- A guard that cannot run blocks the call: a crash or a missing `python3` exits 2 on PreToolUse. Tested in a headless session with a crashing guard. The cost is that without a working `python3`, every Bash, Write and Edit call is blocked in every project until the plugin is turned off by hand.
- `windows` reads every profile's session file locally to infer profiles, but prints only what the policy allows.
- Profile inference is a heuristic, so a window could be misattributed. Keep `allow_js` off and limit `allow_domains` where it matters.
- The Chrome menu toggle is the hard off switch: with it off, no script can act on that profile.

## Not tested

Clipboard and downloads.

Screenshots are not part of `chrome.py`. `screencapture -R` worked on the tested machine, but it records whatever is on screen in that region. If the user switches apps, it captures that app instead, so it can expose unrelated content. A `visible` check just before does not prevent this.
