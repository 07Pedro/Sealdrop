# Installing the collector on a server

For a small Linux server with systemd that's always on, such as a **Raspberry Pi 3B+ with Raspberry Pi OS** (1 GB
of RAM is plenty). The collector runs every 10 minutes from a systemd timer, as its own user, in a sandbox.

**State:** the packaging is tested in WSL (Python 3.11 and the locked packages; the service's sandbox with a real run
against a test bucket, and all the collector's tests inside it), and in use on a Raspberry Pi 3B+ with 64-bit Raspberry
Pi OS. New in 0.3.0: `sealdrop-verify.service` is checked with `systemd-analyze` (verify, security); its first run on
the Pi is still to come.

## What you need

- **64-bit Raspberry Pi OS** (Lite is enough) or Debian 12 or newer: Python 3.11 or newer and systemd. A 32-bit
  system won't do: there are no ready-made `cryptography` packages for it, and building them needs more than 1 GB.
- **A disk for the data root**, `/srv/sealdrop`, with a case-sensitive filesystem such as ext4. On a Pi, a USB SSD,
  not the SD card (see below).
- **The inbox:** the bucket and the collector's two storage keys (`collector-pickup`, `collector-receipts`) from the
  setup ([README.md](README.md#setting-up-the-inbox-at-backblaze-b2)).
- **Outgoing HTTPS** to the storage, and a synchronized clock (Raspberry Pi OS sets it over the network at start).
  Nothing incoming.

## The data root on the SSD

- **The system starts from the SSD:** nothing to do, `/srv/sealdrop` is on it.
- **The SSD is a separate data disk:** format it as ext4 and mount it at `/srv` before installing, with a line in
  `/etc/fstab` (find the UUID with `lsblk -f`):

  ```
  UUID=…  /srv  ext4  defaults,noatime,nofail  0  2
  ```

  `nofail` lets the Pi start without the disk; the collector then doesn't run, because the service needs the data
  root's disk mounted. It never writes to the SD card in its place.

The install script says which disk the data root is on, and warns if it's an SD card.

## Install

```sh
git clone https://github.com/07Pedro/Sealdrop.git
cd Sealdrop
sudo collector/install/install.sh
```

What it does:
- makes the user `sealdrop` (no login), and the data root `/srv/sealdrop` (that user's only);
- puts Python's venv, the packages and the collector in `/opt/sealdrop` (changeable by root only). The packages are
  exactly those in [install/requirements.txt](install/requirements.txt), each checked against its checksum, from
  PyPI only;
- installs the `sealdrop` command, and two services with their timers: a run every 10 minutes, and `verify` once a
  month.

If `/etc/fstab` names a disk for the data root's place (such as the SSD at `/srv`) and it isn't mounted, the script
stops and says so. Otherwise it would make the data root on the disk below it.

Then set it up, in your own terminal (a plain window without session logging, for the keys and the QR code):

```sh
sealdrop init        # the storage locations and the collector's two storage keys (not shown)
sealdrop show-keys   # once: the collector's own keys, to keep safe
sudo systemctl enable --now sealdrop-collector.timer sealdrop-verify.timer
sealdrop pair        # pair a phone; close the window afterwards
```

`sealdrop` runs the collector's commands as its own user ([README.md](README.md#the-commands)). Don't run them as
root: the files in the data root would then belong to root, and the service couldn't use them.

## Day to day

```sh
sealdrop status                                  # what the last run and the last check found; --json for a dashboard
sealdrop verify                                  # check the store against the notes now
systemctl list-timers 'sealdrop-*'               # when the next run and the next check are
journalctl -u sealdrop-collector                 # the runs, and why one failed
sudo tail /srv/sealdrop/log/collector.log        # the collector's own log
```

- **The result** is in `/srv/sealdrop/store/<app>/<delivery>/` (README, "The store"). A reader such as an importer
  only reads it, as the `sealdrop` user or root.
- **A failed run** (no network, the storage not answering) shows as `failed` until the next run works; nothing is
  lost, the next run carries on.
- **A failed check** (`sealdrop-verify.service` failed): something in the store doesn't match the notes.
  `sealdrop verify` says what: `missing`, `changed`, `unreadable` (the disk may be failing) or `unknown`. Restore the
  affected deliveries from the backup.
- **Update:** `git pull`, then `sudo collector/install/install.sh` again. It waits for a run or a check in progress,
  and never changes what's in the data root. Security fixes in the packages come this way too, not with the system's
  updates.
- **Back up** the whole data root (`config/` and `keys/` hold the keys; keep your own copy of them too). A backup job
  should:
  - **hold the collector's lock for the whole snapshot,** for example `flock /srv/sealdrop/state/lock <backup
    command>`, as the `sealdrop` user or root. Runs skip quietly while it's held and carry on after. Without it, the
    notes (`state/state.db`) and the store can be copied at different moments, and a restored copy may not match;
  - **write `state/last-backup` only after a backup that fully worked:** the time the snapshot started, in
    milliseconds since 1970, as the collector's user. The phone sees it in its receipts (PROTOCOL.md §6), and an app
    may free its own copies on the strength of it;
  - **check a restored copy** with `sealdrop verify --root <the copy>`.
- **Remove:**

  ```sh
  sudo systemctl disable --now sealdrop-collector.timer sealdrop-verify.timer
  sudo rm /etc/systemd/system/sealdrop-collector.* /etc/systemd/system/sealdrop-verify.* /usr/local/bin/sealdrop
  sudo systemctl daemon-reload
  sudo rm -r /opt/sealdrop   # the data root /srv/sealdrop stays
  ```

## The sandbox

The service (`install/sealdrop-collector.service`):
- runs as `sealdrop`, with no privileges and no way to gain any;
- may write only to its data root: the system is read-only, home folders and `/tmp` are hidden, and there are no
  devices;
- has only network sockets and local ones (for the clock check), and a system call filter;
- runs at low priority, with at most 256 MB of memory.

`sealdrop-verify.service` has the same sandbox and no network at all.

`systemd-analyze security sealdrop-collector.service` rates it about 1.2 ("OK", on a scale where 10 is unprotected). The
rest is what the collector needs: the network, and `/proc/cpuinfo` for the board's serial number (PROTOCOL.md §10).
