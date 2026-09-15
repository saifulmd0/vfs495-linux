# VFS495 fingerprint login: fprintd + PAM setup

This wires the working VFS495 capture path into `fprintd` (and therefore PAM: login screen,
`sudo`, screen unlock). It uses the stock Debian `fprintd` + `libfprint` (which already ship
the `virtual_image` driver), plus our capture bridge.

**Architecture**
```
you swipe ──▶ validity-sensor (SSL+capture) ──gdb harvest──▶ assembled 200x300 image
                                                                    │
   vfs495-bridge (root, capture loop) ──sends over FP_VIRTUAL_IMAGE socket──▶ fprintd's
   virtual_image device ──▶ NBIS enroll/verify ──▶ PAM (login / sudo)
```
fprintd talks to a *virtual* device fed by the bridge; the bridge is the only thing that
touches the real sensor. **Honesty:** this is a working proof-of-concept, not a polished
driver — the capture runs the proprietary binary under gdb and needs root. It authenticates
correctly (genuine finger score 79 vs impostor 5, threshold 40), but it's not as seamless as
a native driver. A cleaner long-term build would port the assembly into a real libfprint driver.

---

## 1. Install fprintd + PAM module + the virtual driver's python dep
```bash
sudo apt install fprintd libpam-fprintd python3-usb python3-numpy python3-scipy python3-pil
```
(`gdb` and the capture tools are already installed under ~/vfs495-re.)

## 2. Point fprintd at the virtual_image socket
Create a systemd drop-in so fprintd exposes the socket the bridge feeds:
```bash
sudo mkdir -p /etc/systemd/system/fprintd.service.d
sudo tee /etc/systemd/system/fprintd.service.d/virtimg.conf >/dev/null <<'EOF'
[Service]
RuntimeDirectory=fprint
Environment=FP_VIRTUAL_IMAGE=/run/fprint/virtimg_sock
Environment=G_MESSAGES_DEBUG=
EOF
sudo systemctl daemon-reload
sudo systemctl restart fprintd
```
Now `fprintd` sees exactly one device: the virtual image device.

## 3. Run the capture bridge (as root — needs USB + gdb)
Install it as a service:
```bash
sudo tee /etc/systemd/system/vfs495-bridge.service >/dev/null <<'EOF'
[Unit]
Description=VFS495 fingerprint capture bridge
After=fprintd.service

[Service]
Type=simple
User=root
Environment=FP_VIRTUAL_IMAGE=/run/fprint/virtimg_sock
ExecStart=/usr/bin/python3 /ABSOLUTE/PATH/TO/vfs495-linux/tools/vfs495_bridge.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now vfs495-bridge
```
The bridge loops: it runs a capture (which blocks up to ~75 s waiting for a swipe), then sends
the assembled image to the socket. So **whenever you swipe, an image is delivered** — during
enroll or verify that becomes the scan; at any other time it's harmlessly dropped.

## 4. Enroll your finger
```bash
fprintd-enroll        # enrolls the right index by default; -f <finger> for others
```
It asks for several swipes. **Swipe the same finger slowly, full length, each time it prompts.**
Verify enrollment:
```bash
fprintd-verify        # swipe again → should say "verify-match"
```

## 5. Turn on fingerprint for PAM (login / sudo / unlock)
```bash
sudo pam-auth-update          # tick "Fingerprint authentication", confirm
```
That edits `/etc/pam.d/common-auth` to add `pam_fprintd.so` (as `sufficient`, before password).
Test **in a throwaway terminal** (so you can fall back to password):
```bash
sudo -k && sudo true          # should prompt to swipe; password still works as fallback
```

---

## Caveats & troubleshooting
- **Root capture / gdb.** The bridge runs the proprietary binary under gdb as root. That's why
  it's a service. It relies on `~/vfs495-re/runtime/bin/validity-sensor-unlocked` + the harvest
  scripts; keep that tree in place.
- **Timing.** fprintd waits ~30 s for a finger. Swipe promptly when prompted. If a verify times
  out, just retry — the bridge is always ready to capture.
- **Sensor gets stuck** after many rapid captures (returns ~39 lines / empty). A full **power-off**
  clears it (a warm reboot or USB re-enumeration does not). Space out enrollments.
- **Password always works.** `pam_fprintd` is `sufficient`, not `required`, so a failed/absent
  swipe falls through to your password. You are never locked out.
- **Undo everything:** `sudo pam-auth-update` (untick), `sudo systemctl disable --now
  vfs495-bridge`, `sudo rm /etc/systemd/system/fprintd.service.d/virtimg.conf` + the bridge unit,
  `sudo systemctl daemon-reload`.
- **Security note.** Anyone who can write to the `FP_VIRTUAL_IMAGE` socket can present a
  fingerprint image to fprintd. `/run/fprint` is root-owned, so only root (the bridge) can — but
  understand this bridge model trusts whatever connects to that socket.
- **Heavy loop.** The always-on bridge cycles capture attempts (each a gdb+validity-sensor run) even
  when idle, holding the sensor. It's fine for occasional use; for lighter operation, start the bridge
  only around enroll/verify instead of enabling it permanently. A native libfprint driver would remove
  this entirely.
