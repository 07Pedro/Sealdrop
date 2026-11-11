#!/bin/sh
# Installs or updates the collector on a Linux server with systemd (Debian, Raspberry Pi OS): its own user, Python and
# the packages in requirements.txt in /opt/sealdrop, the `sealdrop` command, and the services with their timers (a run
# every 10 minutes, a check of the store once a month).
# Run it as root from the repository: `sudo collector/install/install.sh`. Safe to run again (that's the update);
# it never changes what's in the data root. Details: ../INSTALL.md.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
DATA=/srv/sealdrop
OPT=/opt/sealdrop
VENV=$OPT/venv
SERVICE=sealdrop-collector.service
TIMER=sealdrop-collector.timer
VERIFY_SERVICE=sealdrop-verify.service
VERIFY_TIMER=sealdrop-verify.timer

say() { printf '%s\n' "$*"; }
fail() { printf 'Not done: %s\n' "$*" >&2; exit 1; }

# --- what's needed --------------------------------------------------------------------------------------------------
[ "$(id -u)" = 0 ] || fail "run it as root: sudo $0"
[ -d /run/systemd/system ] || fail "this needs a system that runs systemd."
[ -s /etc/machine-id ] || fail "/etc/machine-id is missing or empty; the collector needs it (PROTOCOL.md §10)."
command -v python3 >/dev/null || fail "Python 3.11 or newer is needed (python3)."
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || fail "Python 3.11 or newer is needed."
python3 -c 'import struct, sys; sys.exit(struct.calcsize("P") != 8)' ||
    fail "this needs a 64-bit system: the cryptography package has no ready-made files for 32-bit ones."
# The data root's disk: if /etc/fstab names a disk for the data root's place (such as an SSD at /srv) and it isn't
# mounted, the data root would be made on the disk below it (the SD card), and the collector would run there.
disk=$(findmnt --fstab -n -o TARGET 2>/dev/null |
    awk -v data="$DATA/" '$0 != "/" && index(data, $0 "/") == 1 && length($0) > length(best) { best = $0 }
                          END { print best }')
if [ -n "$disk" ] && ! findmnt -n --mountpoint "$disk" >/dev/null; then
    fail "the disk for $disk (in /etc/fstab) isn't mounted. Mount it first (sudo mount $disk), then run this again."
fi
if command -v dpkg >/dev/null; then
    missing=""
    for package in python3-venv ca-certificates; do
        dpkg -s "$package" >/dev/null 2>&1 || missing="$missing $package"
    done
    if [ -n "$missing" ]; then
        say "Installing$missing"
        # shellcheck disable=SC2086 # one word per package
        apt-get update -q && apt-get install -y -q --no-install-recommends $missing
    fi
fi

# --- the collector's own user, without a login --------------------------------------------------------------------
if ! getent passwd sealdrop >/dev/null; then
    useradd --system --user-group --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin sealdrop
    say "Made the user sealdrop."
fi

# --- the data root: the collector's user's only, on a case-sensitive filesystem (§10) ----------------------------
if [ ! -e "$DATA" ]; then
    install -d -m 700 -o sealdrop -g sealdrop "$DATA"
elif [ -z "$(ls -A "$DATA")" ]; then
    chown sealdrop:sealdrop "$DATA" && chmod 700 "$DATA"   # an empty folder or mount point
elif [ "$(stat -c %U "$DATA")" != sealdrop ]; then
    fail "$DATA isn't empty and belongs to $(stat -c %U "$DATA"). If it's the collector's: chown -R sealdrop:sealdrop $DATA"
fi
fstype=$(findmnt -n -o FSTYPE --target "$DATA")
device=$(findmnt -n -o SOURCE --target "$DATA")
case $fstype in
    vfat|msdos|exfat|ntfs|ntfs3|fuseblk)
        fail "$DATA is on a $fstype filesystem; the store needs a case-sensitive one such as ext4." ;;
esac

# --- let a run or a check in progress finish, and none start while the code changes -----------------------------
timer_was_on=no
if systemctl is-active --quiet "$TIMER"; then
    timer_was_on=yes
    systemctl stop "$TIMER"
fi
verify_timer_was_on=no
if systemctl is-active --quiet "$VERIFY_TIMER"; then
    verify_timer_was_on=yes
    systemctl stop "$VERIFY_TIMER"
fi
for unit in "$SERVICE" "$VERIFY_SERVICE"; do
    while [ "$(systemctl show -p ActiveState --value "$unit")" = activating ]; do
        say "Waiting for the run or check in progress to finish …"
        sleep 10
    done
done

# --- Python and the packages, at exactly the versions and checksums in requirements.txt -----------------------
want=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
have=$("$VENV/bin/python" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)
if [ "$have" != "$want" ]; then
    rm -rf "$VENV"   # none yet, or the system's Python changed
    python3 -m venv "$VENV"
fi
# PyPI only (no other index from a pip.conf), only ready-made files, each checked against requirements.txt.
PIP_CONFIG_FILE=/dev/null "$VENV/bin/python" -m pip install -q --disable-pip-version-check --no-cache-dir \
    --index-url https://pypi.org/simple --only-binary :all: --require-hashes -r "$HERE/requirements.txt"

# --- the collector itself: a copy of collector/sealdrop/ that only root can change ---------------------------
site=$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')
rm -rf "$site/sealdrop"
cp -R "$HERE/../sealdrop" "$site/sealdrop"
rm -rf "$site/sealdrop/__pycache__"
"$VENV/bin/python" -m compileall -q "$site/sealdrop"
chown -R root:root "$OPT"
chmod -R u=rwX,go=rX "$OPT"

# --- the command and the units ------------------------------------------------------------------------------------
install -m 755 "$HERE/sealdrop" /usr/local/bin/sealdrop
for unit in "$SERVICE" "$TIMER" "$VERIFY_SERVICE" "$VERIFY_TIMER"; do
    install -m 644 "$HERE/$unit" /etc/systemd/system/
done
systemctl daemon-reload

say "Installed: the collector in $OPT, the data root $DATA ($device, $fstype)."
case $device in
    /dev/mmcblk*) say "Note: $DATA is on an SD card. For lasting use, put it on a USB SSD first (INSTALL.md)." ;;
esac
if [ -f "$DATA/config/collector.json" ]; then
    systemctl enable --now "$TIMER" "$VERIFY_TIMER" >/dev/null 2>&1
    say "The timers are on: a run every 10 minutes, a check of the store once a month."
else
    [ "$timer_was_on" = no ] || systemctl start "$TIMER"
    [ "$verify_timer_was_on" = no ] || systemctl start "$VERIFY_TIMER"
    if [ "$timer_was_on" = no ]; then
        say "Next, in your own terminal (not as root):"
        say "  sealdrop init        the storage locations and the collector's two storage keys"
        say "  sealdrop show-keys   once: the collector's own keys, to keep safe"
        say "  sudo systemctl enable --now $TIMER $VERIFY_TIMER"
        say "  sealdrop pair        pair a phone"
    fi
fi
