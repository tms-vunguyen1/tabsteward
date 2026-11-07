---
name: setup
description: First-run setup for tabsteward. Choose which Chrome profiles, domains and capabilities it may use. Run this when chrome.py or the session reports it is not set up, then resume the user's task. Do not run it to get around a policy refusal.
---

# Set up tabsteward

Walk the user through their policy. The goal is least privilege they understand, so explain each choice in a line and never pick for them. Use the user's language.

The script is `../tabsteward/scripts/chrome.py`, relative to this skill's base directory.

Claude may start this only when no policy exists. If a policy exists and the user did not type `/tabsteward:setup`, stop: `set-policy` will be denied, and that refusal is deliberate.

1. Run `chrome.py setup-info`. It lists every Chrome profile and the current policy, if any.
2. **Profiles.** Steps 2 to 5 each use their own AskUserQuestion call, one after the other, so the user picks answers instead of typing them. Do not print these questions as text. Use `multiSelect: true`, the profile name as the label, and the email and `dir` as the description, so same-named profiles can be told apart. A question holds 4 options at most, so with more than 4 profiles split them into pages: 3 profiles plus a `None on this page` option, one question per page, 4 pages per call, then another call for the rest. If nothing was picked, ask again. Pass the `dir` to the command. Mention that a work or banking profile exposes everything logged in there, so a separate low-stakes profile is the safest choice.
3. **Domains.** Ask whether to limit Claude to specific sites or allow any site. Say that Claude acts without asking inside what they allow here, and that anything outside is refused. Any site therefore means clicking and typing on every logged-in site with no prompt. A list is safer. If they want a list, ask them to type the domains, such as `x.com`, which also covers subdomains.
4. **JavaScript.** Ask whether to allow the `js` command, with `No (Recommended)` as the first option. It runs arbitrary code in logged-in pages with no prompt and skips the check in step 5, and `read`, `click` and `fill` cover most work without it.
5. **Hard-to-undo actions.** Ask whether Claude should still ask before clicking buttons such as delete, pay, send or post, and before closing tabs it did not open, with `Ask first (Recommended)` as the first option. Say that this matches the words on a button, so it can miss one.
6. Summarize the choices, then run:

   ```
   chrome.py set-policy --profile DIR [--profile DIR ...] [--domain example.com ...] [--allow-js] [--no-ask-sensitive]
   ```

   The user sees an approval prompt with these exact values. If they decline, ask what to change. Do not work around it.
7. Tell them to enable **View > Developer > Allow JavaScript from Apple Events** in the macOS menu bar, once in a window of each chosen profile. It is a per-profile setting, and it stays theirs to turn off.
8. Run `chrome.py windows` and report what is now reachable. An empty list is fine if no chosen profile has a window open.
9. If setup interrupted a browser task, continue it now.
