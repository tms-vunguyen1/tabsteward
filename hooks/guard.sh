#!/bin/sh
# Skips Python for events guard.py could not act on, since it runs on every call in every project.
# Python is skipped only on a definite no. Anything unexpected falls through to it.
# Write and Edit always go to Python: it resolves symlinks, which text cannot show.

# Must stay a superset of what guard.py looks for in a Bash command. The tests run through this file.
WORDS='chrome|tabsteward|setup-grant|hooks/guard|hooks/hooks|disableall|remote-debugging|--confirm-'
SETUP_COMMAND='/tabsteward:setup'

input=$(cat)

run_guard() {
    printf '%s' "$input" | python3 -I "${0%/*}/guard.py" "$@"
    exit $?
}

if [ "$1" = user-prompt ]; then
    case "$input" in
        *"$SETUP_COMMAND"*) run_guard user-prompt ;;
    esac
    exit 0
fi

case "$input" in
    *'"tool_name":"Bash"'* | *'"tool_name": "Bash"'*) ;;
    *) run_guard ;;
esac

plain=$(printf '%s' "$input" | tr -d "\"'\\\\") || run_guard  # as plain() does in guard.py
printf '%s' "$plain" | LC_ALL=C grep -qiaE "$WORDS"
[ $? -eq 1 ] && exit 0
run_guard
