## vfs495-fprint 0.1.5 — one-package fingerprint login for the Validity VFS495 (`138a:003f`)

**Install (Debian 13 / Ubuntu-derived, amd64):**
```bash
sudo apt install ./vfs495-fprint_0.1.5_amd64.deb
fprintd-enroll          # wait ~2 s after each prompt, then swipe the same finger slowly, full length
sudo -k && sudo true    # swipe -> fingerprint login works (password still works as fallback)
```

**What the package does at install time**
- Downloads HP's Validity Linux driver (SoftPaq sp84530) straight from HP's server, verifies its checksum, extracts it, and applies the 5-byte gate patch. Nothing proprietary is redistributed here.
- Installs the capture service (`vfs495-bridge`), the fprintd socket drop-in, the udev rule, and its own PAM profile (3 tries, 30 s) via `pam-auth-update`.
- Pulls in `fprintd`, `libpam-fprintd`, `gdb`, `python3-dbus`, `python3-gi`, `gir1.2-fprint-2.0`, `7zip` as dependencies.

**Diagnostics built in**
- `sudo journalctl -u fprintd | grep score` shows the matcher score of every swipe (≥ 40 = match).
- `sudo vfs495-match --capture 3` takes three swipes and scores them against your enrolled finger and against each other.
- `sudo vfs495-match --enroll /run/vfs495-fprint/test/swipe-*.pgm` enrolls from exactly those swipes.
- The bridge is event-driven: idle until fprintd needs a finger, cancelled when it stops, and it rejects tiny scans.

**Known limits**
- Capture still drives HP's proprietary userspace binary under `gdb` as root (see README "Limitations").
- The sensor needs ~2 s to arm after a prompt; a swipe made instantly is missed, just swipe again.
- If every swipe comes back as a "tiny scan", the sensor is in its stuck state: shut the laptop down fully and power it on again. A warm reboot does not clear it. Password auth is always a fallback.
- Tested on an HP EliteBook running Debian 13 with fprintd 1.94.

sha256: `390600b67cb718a069ee002c8e0f79597859fc6e39afdbdeba627d9dc1397b03`
