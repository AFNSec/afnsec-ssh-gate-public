#!/usr/bin/env bash
set -euo pipefail

BIN_DST="/usr/local/bin/afnsec-ssh-gate"
CFG_DST="/etc/afnsec-ssh-gate.conf"
CACHE_DIR="/var/lib/afnsec-ssh/cache"

SVC_USER="afnsec-ssh-gate"
PAM_SSHD="/etc/pam.d/sshd"

SYSTEMD_SVC="/etc/systemd/system/afnsec-ssh-gate-purge.service"
SYSTEMD_TIMER="/etc/systemd/system/afnsec-ssh-gate-purge.timer"

die() { echo "ERROR: $*" >&2; exit 1; }
need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (sudo ./uninstall.sh)."; }
timestamp() { date -u +"%Y%m%dT%H%M%SZ"; }

restart_ssh_service() {
  if systemctl list-unit-files | awk '{print $1}' | grep -qx "ssh.service"; then
    systemctl restart ssh
  elif systemctl list-unit-files | awk '{print $1}' | grep -qx "sshd.service"; then
    systemctl restart sshd
  else
    systemctl restart ssh || systemctl restart sshd
  fi
}

prompt_yes_no() {
  local prompt="$1"
  local default="$2" # y or n
  local ans
  read -r -p "${prompt} [${default}/$( [[ "$default" == "y" ]] && echo "n" || echo "y")]: " ans
  ans="${ans:-$default}"
  [[ "$ans" == "y" || "$ans" == "Y" ]]
}

remove_systemd() {
  systemctl disable --now afnsec-ssh-gate-purge.timer >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_TIMER" "$SYSTEMD_SVC"
  systemctl daemon-reload
}

remove_pam_line() {
  [[ -f "$PAM_SSHD" ]] || return 0

  echo "Removing PAM hook from $PAM_SSHD"
  BACKUP="${PAM_SSHD}.afnsec.uninstall.bak.$(timestamp)"
  cp -a "$PAM_SSHD" "$BACKUP"

  grep -v "/usr/local/bin/afnsec-ssh-gate" "$PAM_SSHD" > "${PAM_SSHD}.tmp"
  mv "${PAM_SSHD}.tmp" "$PAM_SSHD"
  chmod 644 "$PAM_SSHD"

  echo "Restarting SSH (with rollback safety)..."
  if restart_ssh_service; then
    echo "SSH restart: OK"
    return 0
  fi

  echo "SSH restart failed. Rolling back PAM file..."
  cp -a "$BACKUP" "$PAM_SSHD"
  restart_ssh_service || die "Rollback failed: SSH still not restarting."
  echo "Rollback complete."
}

remove_files() {
  if prompt_yes_no "Remove binary ($BIN_DST)?" "y"; then
    rm -f "$BIN_DST"
  fi

  if prompt_yes_no "Remove config ($CFG_DST)?" "n"; then
    rm -f "$CFG_DST"
  fi

  if prompt_yes_no "Remove cache directory ($CACHE_DIR)?" "n"; then
    rm -rf "$CACHE_DIR"
  fi
}

remove_user() {
  if id -u "$SVC_USER" >/dev/null 2>&1; then
    if prompt_yes_no "Remove system user ($SVC_USER)?" "n"; then
      userdel "$SVC_USER" >/dev/null 2>&1 || true
    fi
  fi
}

remove_nft_profile() {
  if command -v nft >/dev/null 2>&1; then
    nft list table inet afnsec >/dev/null 2>&1 && nft delete table inet afnsec >/dev/null 2>&1 || true
  fi
}



main() {
  need_root
  remove_systemd
  remove_nft_profile
  remove_pam_line
  remove_files
  remove_user
  echo "Uninstall complete."
}

main "$@"
