#!/bin/bash
# macOS Cleaner infostealer detect/clean
# usage: ./detect_macclean.sh [--clean]

hit=0
flag() { echo "[!] $1"; hit=1; }

for f in ~/.pass ~/.username ~/.agent ~/.mainhelper /tmp/helper /tmp/out.zip /tmp/starter; do
    [ -e "$f" ] && flag "$f"
done

[ -f /Library/LaunchDaemons/com.finder.helper.plist ] && flag "com.finder.helper plist"
launchctl list 2>/dev/null | grep -q com.finder.helper && flag "com.finder.helper loaded"

for app in "Ledger Live" "Trezor Suite" "Exodus"; do
    [ -d "/Applications/${app}.app" ] && ! codesign -v "/Applications/${app}.app" 2>/dev/null && flag "${app} bad sig"
done

ls -d /tmp/[0-9][0-9][0-9][0-9][0-9] 2>/dev/null | while read d; do flag "staging $d"; done
ls /tmp/chunk_* &>/dev/null && flag "exfil chunks in /tmp"

netstat -an 2>/dev/null | grep -q "92.246.136.14" && flag "connection to 92.246.136.14"

[ "$hit" -eq 0 ] && echo "Clean." && exit 0
[ "$1" != "--clean" ] && echo && echo "Rerun with --clean to remediate." && exit 1

echo
echo "Cleaning..."
rm -f ~/.pass ~/.username ~/.agent ~/.mainhelper /tmp/helper /tmp/starter /tmp/out.zip /tmp/chunk_*
rm -rf /tmp/[0-9][0-9][0-9][0-9][0-9]
sudo launchctl unload /Library/LaunchDaemons/com.finder.helper.plist 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.finder.helper.plist
pkill -f '.mainhelper' 2>/dev/null

echo "Done. Artifacts removed but this stealer exfils everything — passwords, cookies, wallets, keychain, notes, files."
echo "Rotate every credential, enable 2FA everywhere, move crypto to new wallets. Honestly you should wipe this machine."
