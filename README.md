<p align="center">
  <img src="docs/assets/logo.png" alt="tabsteward logo" width="180">
</p>

<h1 align="center">tabsteward</h1>

<p align="center">
  <strong>Let Claude Code work in your real, logged-in Chrome, inside rules you set.</strong>
</p>

<p align="center">
  <a href="https://github.com/tms-vunguyen1/tabsteward/releases/latest"><img src="https://img.shields.io/github/v/release/tms-vunguyen1/tabsteward?color=f5b301&label=version" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/platform-macOS-5b3a29" alt="Platform: macOS">
  <img src="https://img.shields.io/badge/Claude%20Code-plugin-5b3a29" alt="Claude Code plugin">
  <img src="https://img.shields.io/badge/dependencies-none-f5b301" alt="No dependencies">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-5b3a29" alt="License: MIT"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-you-stay-in-control">How you stay in control</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#limitations">Limitations</a>
</p>

<p align="center">
  <img src="docs/assets/cursor-demo.png" alt="The tabsteward cursor ringing a button and rippling as it clicks" width="640">
</p>

## Why tabsteward

Browser automation usually starts a separate browser that knows nothing about you. tabsteward works in the Chrome you already have open, with your sessions, and needs no extension or debug port.

That access is powerful, so nothing runs until you choose what is allowed. You pick the profiles and sites once in setup. Inside those choices Claude works without interrupting you, and everything outside them is refused.

- **Your real browser.** Open tabs, read pages, click and fill forms in the windows you already use.
- **Default deny.** No policy means no access, and profiles you did not allow stay out of reach.
- **Prompts only when they matter.** You are asked before page data goes to another site, before buttons such as delete, pay, send or post, and before Claude closes a tab it did not open. You can turn off that last group in setup.
- **A visible cursor.** Ask to watch and a labelled cursor shows what is about to be clicked.
- **An audit trail.** Every attempted change is logged locally, without the text you typed.
- **No dependencies.** It only needs Python's standard library and macOS AppleScript.

## Quick start

**Requirements:** macOS, Google Chrome, Python 3 and [Claude Code](https://claude.com/claude-code).

**1. Install the plugin**

```sh
claude plugin marketplace add tms-vunguyen1/tabsteward
claude plugin install tabsteward@tabsteward
```

**2. Choose what Claude may touch**

Claude starts setup the first time you ask for something in your browser, or you can run it yourself:

```text
/tabsteward:setup
```

Setup lists the Chrome profiles on your machine, then asks which ones Claude may use, whether to limit it to specific sites, whether to allow arbitrary JavaScript, and whether to ask before hard-to-undo actions. You approve the result in a prompt.

> [!IMPORTANT]
> Claude clicks and types without asking inside what you allow here. With any site allowed, that covers every site you are logged in to in that profile, so a list of sites and a low-stakes profile are safer.

**3. Allow scripting in Chrome**

In each chosen profile, enable **View > Developer > Allow JavaScript from Apple Events** in the macOS menu bar.

> [!WARNING]
> This setting lets any local script run JavaScript in that profile's tabs, logged-in sites included. Turn it off when you are not using it.

**4. Ask for something**

```text
Open a new tab in my Personal profile and search X for "AI"
```

## How you stay in control

```mermaid
flowchart LR
    A[Claude Code] --> B{Guard hook}
    B -- raw Chrome access --> X[Denied]
    B -- browser command --> D{Policy}
    D -- outside your rules --> X
    D -- allowed --> E[Your Chrome]
    D -- page data to another site, or hard to undo --> C[You approve]
    C --> E
    E --> F[(Audit log)]
```

| Layer | What it does |
|---|---|
| **Policy** | Limits which profiles and domains are reachable, and whether arbitrary JavaScript runs. Only `http(s)` pages are allowed. |
| **Guard hook** | Blocks raw `osascript`, the Chrome binary and Chrome's data folder. Protects the policy, and asks you when a `--confirm-*` flag is used. |
| **Audit log** | Records each attempted change and its outcome in `~/.config/tabsteward/audit.jsonl`. |
| **Credentials rule** | `fill` refuses password fields, and `read` masks their values. |

Claude can start setup only when no policy exists. To change an existing policy, type `/tabsteward:setup` yourself, so Claude cannot widen its own access after a refusal.

### Policy file

Setup writes `~/.config/tabsteward/policy.json`, which stays on your machine. You can also edit it by hand:

```json
{
  "profiles": ["Profile 3"],
  "allow_js": false,
  "allow_domains": ["example.com"],
  "ask_sensitive": true,
  "sensitive_words": []
}
```

| Key | Meaning |
|---|---|
| `profiles` | Profile folders Claude may touch, listed in `chrome://version` under "Profile Path". |
| `allow_js` | Whether arbitrary JavaScript may run. Leave this off unless you need it. |
| `allow_domains` | Allowed sites. `example.com` also covers subdomains. Empty means any web domain. |
| `ask_sensitive` | Whether to ask before buttons that look hard to undo and before closing tabs Claude did not open. Missing means `true`. |
| `sensitive_words` | Extra button words to ask about, added to the built-in English list. Use it for other languages, such as `"löschen"`. |

## Commands

Claude runs these for you through the skill.

| Command | Purpose | Asks first |
|---|---|---|
| `profiles` | List allowed profiles | No |
| `windows [--profile NAME]` | List windows and tabs. Any command on a window with an uncertain profile needs `--confirm-window ID` | No, but that flag asks |
| `read TAB [--selector S]` | Read page text and interactive elements | No |
| `wait TAB SELECTOR` | Wait for an element | No |
| `open URL --profile NAME` | Open a tab in an existing window. Text copied from a page on another site needs `--confirm-page-data`, also for `goto` and `fill` | No, but that flag asks |
| `goto TAB URL` | Navigate a tab | No, but that flag asks |
| `activate TAB` | Bring a tab forward | No |
| `click TAB SELECTOR [--expect T] [--within S] [--cursor]` | Click an element. A button that looks hard to undo needs `--confirm-action` | No, but that flag asks |
| `fill TAB SELECTOR TEXT` | Fill a field and read it back | No, but that flag asks |
| `js TAB --code JS` | Run custom JavaScript, off by default | No |
| `close TAB` | Close one tab. A tab Claude did not open needs `--confirm-action` | No, but that flag asks |

## Limitations

- **The guard is a seatbelt, not a sandbox.** It matches text in Bash commands, so it stops accidents and page-driven injection, not deliberately disguised commands. Turning off the Chrome setting above is the real off switch.
- **Prompt injection is not fully solved.** The skill tells Claude to treat page content as data, and no hook can enforce that. `open`, `goto` and `fill` do refuse text copied verbatim from a page on another site until you approve it, but a paraphrase or a short secret still gets through. `read` also warns Claude about wording aimed at an AI, and after such wording in hidden text, `chrome.py` holds back data going to other sites for 30 minutes. Both match set wording, so they miss a lot. Inside your policy a malicious page could steer a click or a fill that nobody reviews, and the check for hard-to-undo buttons only reads their words.
- **One Chrome at a time.** AppleScript cannot choose between Chrome processes, so tabsteward stops if a second one is running, such as one started by chrome-devtools-mcp.
- **Profile detection is inferred** from session files. Windows it cannot identify stay hidden and refused. A close call between two profiles stays hidden too, until you confirm it.
- **Clicks are scripted.** Sites that require a real user gesture can ignore them, and native dialogs need you. `click` reports whether the page visibly changed and whether a dialog stopped the tab, but Claude still has to check the result.
- **It adds a small cost everywhere.** While enabled, a shell filter runs on every prompt and every Bash, Write and Edit call, in every project, about 18 ms per call on the tested machine. Write, Edit and any Bash command mentioning Chrome or tabsteward also start `python3`, about 50 ms, and so does every call made inside a folder with tabsteward in its path. If `python3` stops working, those calls are blocked until you turn the plugin off yourself. Other Bash commands and prompts keep working.

See [tested limits](skills/tabsteward/references/limits.md) for the full list.

## Development

```sh
python3 tests/test_chrome.py
```

To edit the plugin with Claude, start it with `TABSTEWARD_DEV=1 claude`. That turns off the guard's deny rules for that session.

## Update

Check your version:

```sh
claude plugin list
```

Then update, in this order, and restart Claude Code:

```sh
claude plugin marketplace update tabsteward
claude plugin update tabsteward@tabsteward
```

Run both. Without the first command, the second reports that you are on the latest version even when a newer one exists.

## Uninstall

```sh
claude plugin uninstall tabsteward@tabsteward
claude plugin marketplace remove tabsteward
```

Your policy and audit log remain in `~/.config/tabsteward/`. Delete that folder to remove them, or let Claude do it after you approve the prompt, and turn off the Chrome setting in each profile.

## Credits

The logo and cursor icon (`docs/assets/logo.png`, `skills/tabsteward/assets/cursor*.png`) were AI-generated with ChatGPT.

Not affiliated with Google or Anthropic. Chrome and Claude are trademarks of their respective owners.
