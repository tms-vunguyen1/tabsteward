---
name: setup
description: First-run setup for tabsteward. Choose which Chrome profiles, domains and capabilities it may use. Run this when chrome.py or the session reports it is not set up, then resume the user's task. Do not run it to get around a policy refusal.
---

# Set up tabsteward

Walk the user through their policy. The goal is least privilege they understand, so explain each choice in a line and never pick for them. Use the user's language.

The script is `../tabsteward/scripts/chrome.py`, relative to this skill's base directory.

Claude may start this only when no policy exists. If a policy exists and the user did not type `/tabsteward:setup`, stop: `set-policy` will be denied, and that refusal is deliberate.

1. Run `chrome.py setup-info`. It lists every Chrome profile and the current policy, if any.
2. **Profiles.** Ask which profiles Claude may use. With up to 4 profiles use AskUserQuestion with `multiSelect: true`. With more, print a numbered list and ask them to reply with the numbers. Show name and email so same-named profiles can be told apart, and pass the `dir` to the command. Mention that a work or banking profile exposes everything logged in there, so a separate low-stakes profile is the safest choice.
3. **Domains.** Ask whether to limit Claude to specific sites, such as `x.com`, which also covers subdomains. Any site is the other option. A list is safer.
4. **JavaScript.** Ask whether to allow the `js` command, recommending no. It runs arbitrary code in logged-in pages, and `read`, `click` and `fill` cover most work without it.
5. Summarize the choices, then run:

   ```
   chrome.py set-policy --profile DIR [--profile DIR ...] [--domain example.com ...] [--allow-js]
   ```

   The user sees an approval prompt with these exact values. If they decline, ask what to change. Do not work around it.
6. Tell them to enable **View > Developer > Allow JavaScript from Apple Events** in the macOS menu bar, once in a window of each chosen profile. It is a per-profile setting, and it stays theirs to turn off.
7. Run `chrome.py windows` and report what is now reachable. An empty list is fine if no chosen profile has a window open.
8. If setup interrupted a browser task, continue it now.
