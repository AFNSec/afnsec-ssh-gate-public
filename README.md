# AFNSec SSH Gate

AFNSec SSH Gate is a PAM based SSH security control that evaluates every SSH authentication attempt using AFNSec Threat Intelligence before authentication succeeds.

It is designed as a **lightweight security appliance**:
- single static binary
- one configuration file
- no database
- no daemon
- safe failure modes
- full audit logging

---

## What it does

- Checks the **source IP** of every SSH login attempt
- Queries AFNSec Threat Intelligence for reputation
- Optionally enforces **geo block** or **geo allowlist** policies
- Caches decisions locally for performance and resilience
- Logs every decision to **AUTHPRIV** (`/var/log/auth.log`)
- Automatically maintains its cache (purge + size limits)

---

## What it does NOT do

- It does not replace SSH authentication methods
- It does not inspect credentials
- It does not require a database or background service
- It does not block the SSH client password prompt (PAM limitation)

---

### ⚙️Installation (one-time)

### Requirements
- Linux with systemd and PAM
- OpenSSH server
- Outbound HTTPS access to AFNSec API
- Root access (for installation only)

### Install

1️⃣ Download and run the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/AFNSec/afnsec-ssh-gate-public/master/install.sh -o install.sh
chmod +x install.sh
sudo ./install.sh
```

🧩 The installer will:

- download and verify the AFNSec SSH Gate binary

- prompt for your AFNSec API key

- optionally prompt for admin bypass IPs

- install the binary globally (/usr/local/bin/afnsec-ssh-gate)

- configure PAM safely

- set up automatic cache maintenance

- setup nft(nftables) afnsec profile for firewall blocking if available.

- start in DRY_RUN mode (log-only)

After installation

Check status
````bash
sudo afnsec-ssh-gate --doctor
````
View decisions
````bash
sudo tail -n 50 /var/log/auth.log | grep afnsec-ssh-gate
````

Enable enforcement

Edit the config:

````bash
sudo nano /etc/afnsec-ssh-gate.conf
````

Set:

````bash
DRY_RUN=0
````

Then restart SSH:

````bash
sudo systemctl restart ssh
````

Maintenance commands

````bash
sudo afnsec-ssh-gate --purge-now     # run cache maintenance now
sudo afnsec-ssh-gate --purge-all     # clear entire cache (destructive)
sudo afnsec-ssh-gate --doctor        # show config stats
sudo afnsec-ssh-gate --check         # Validates config correctness
sudo afnsec-ssh-gate --fw-status     # show counts of blocked ip's
sudo afnsec-ssh-gate --fw-del <ip>   # Removes single IP from nft block set
sudo afnsec-ssh-gate --fw-clear      # Flushes all firewall-blocked IPs
````

Cache maintenance also runs automatically via systemd.

Configuration

All settings are in:

````bash
/etc/afnsec-ssh-gate.conf
````

AFNSec nft profile check

````bash
sudo nft list set inet afnsec ssh_block_v4
sudo nft list set inet afnsec ssh_block_v6
````
Defaults are safe:

- fail-open behavior

- dry-run enabled

- geo policy disabled

- nft firewall enabled (only if package is found, if not it auto disables. Does not apply to Geo)

- nft firewall enabled (only if package is found, if not it auto disables. Does not apply to Geo)

You can later enable geo block or allowlist policies as needed.

📄 Logging

All decisions are logged to:

````bash
/var/log/auth.log
````

Logs include:

source IP

verdict

geo information

cache status

deny reason (intel or geo)

one time nft status (if package not found and disabled)

🧹 Uninstall

````bash
curl -fsSL https://raw.githubusercontent.com/AFNSec/afnsec-ssh-gate/master/uninstall.sh -o uninstall.sh
chmod +x uninstall.sh
sudo ./uninstall.sh
````

The uninstaller safely removes:

- PAM changes

- systemd units

- binary

- optional config, cache, and service user

License

© 2025 AFNSec — All rights reserved.
Enterprise internal use only.
Contact: secops@afnsec.com



