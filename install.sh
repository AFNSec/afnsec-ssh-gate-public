#!/usr/bin/env bash
set -euo pipefail

# =========================
# Release
# =========================
RELEASE_TAG="v1"
ASSET_NAME="afnsec-ssh-gate-v1-amd64"
BIN_URL="https://github.com/AFNSec/afnsec-ssh-gate-public/releases/download/${RELEASE_TAG}/${ASSET_NAME}"
SHA_URL="https://github.com/AFNSec/afnsec-ssh-gate-public/releases/download/${RELEASE_TAG}/${ASSET_NAME}.sha256"

# =========================
# Paths / identities
# =========================
BIN_DST="/usr/local/bin/afnsec-ssh-gate"
CFG_DST="/etc/afnsec-ssh-gate.conf"
CACHE_DIR="/var/lib/afnsec-ssh/cache"

SVC_USER="afnsec-ssh-gate"
SVC_GROUP="afnsec-ssh-gate"

PAM_SSHD="/etc/pam.d/sshd"
PAM_LINE='auth requisite pam_exec.so quiet /usr/local/bin/afnsec-ssh-gate'

SYSTEMD_SVC="/etc/systemd/system/afnsec-ssh-gate-purge.service"
SYSTEMD_TIMER="/etc/systemd/system/afnsec-ssh-gate-purge.timer"

# =========================
# Defaults
# =========================
DEFAULT_TIMEOUT_MS="800"
DEFAULT_FAIL_MODE="open"
DEFAULT_DRY_RUN="1"              # install starts in dry-run (log-only)
DEFAULT_DENY_SUSPICIOUS="1"

DEFAULT_CACHE_MAX_ENTRIES="100000"
DEFAULT_CACHE_MAX_MB="200"
DEFAULT_PURGE_INTERVAL_MIN="1440" # 24 hours

die() { echo "ERROR: $*" >&2; exit 1; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
timestamp() { date -u +"%Y%m%dT%H%M%SZ"; }

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (sudo ./install.sh)."
}

restart_ssh_service() {
  # Debian/Ubuntu often "ssh"; others "sshd"
  if systemctl list-unit-files | awk '{print $1}' | grep -qx "ssh.service"; then
    systemctl restart ssh
  elif systemctl list-unit-files | awk '{print $1}' | grep -qx "sshd.service"; then
    systemctl restart sshd
  else
    systemctl restart ssh || systemctl restart sshd
  fi
}

preflight() {
  need_root

  have_cmd systemctl || die "systemd required (systemctl not found)."
  have_cmd sha256sum || die "sha256sum required."
  if ! have_cmd curl && ! have_cmd wget; then
    die "curl or wget required."
  fi
  have_cmd sshd || die "OpenSSH server (sshd) not found."
  [[ -f "$PAM_SSHD" ]] || die "PAM sshd file not found: $PAM_SSHD"

  mkdir -p "$(dirname "$BIN_DST")"
  mkdir -p "$(dirname "$CACHE_DIR")"
}

prompt_inputs() {
  echo "AFNSec SSH Gate Installer"
  echo "Pinned release: ${RELEASE_TAG}/${ASSET_NAME}"
  echo

  # API key prompt (hidden)
  echo -n "Enter AFNSec API key: "
  read -r -s AFN_API_KEY
  echo
  [[ -n "${AFN_API_KEY}" ]] || die "AFN_API_KEY is required."

  # Admin bypass CIDRs (optional)
  read -r -p "Enter admin bypass CIDRs (comma-separated) or leave blank: " BYPASS_CIDRS
  if [[ -z "${BYPASS_CIDRS}" ]]; then
    echo "WARNING: BYPASS_CIDRS is empty. Allowed, but be careful with GEO allowlists."
  else
    IFS=',' read -ra CIDRS <<< "${BYPASS_CIDRS}"
    for c in "${CIDRS[@]}"; do
      c="$(echo "$c" | xargs)"
      [[ "$c" =~ / ]] || die "Invalid CIDR (missing /): $c"
      [[ "${#c}" -ge 5 ]] || die "Invalid CIDR: $c"
    done
  fi
}

download_and_verify() {
  TMPDIR="$(mktemp -d /tmp/afnsec-ssh-gate-install.XXXXXX)"
  trap 'rm -rf "$TMPDIR"' EXIT

  echo
  echo "Downloading binary:"
  echo "  $BIN_URL"
  echo "Downloading sha256:"
  echo "  $SHA_URL"

  if have_cmd curl; then
    curl -fsSL -o "${TMPDIR}/${ASSET_NAME}" "$BIN_URL"
    curl -fsSL -o "${TMPDIR}/${ASSET_NAME}.sha256" "$SHA_URL"
  else
    wget -qO "${TMPDIR}/${ASSET_NAME}" "$BIN_URL"
    wget -qO "${TMPDIR}/${ASSET_NAME}.sha256" "$SHA_URL"
  fi

  echo "Verifying SHA256..."
  (cd "$TMPDIR" && sha256sum -c "${ASSET_NAME}.sha256") || die "SHA256 verification failed."
}

install_binary() {
  echo "Installing binary to $BIN_DST"
  install -m 0755 "${TMPDIR}/${ASSET_NAME}" "$BIN_DST"
}

create_service_user() {
  if id -u "$SVC_USER" >/dev/null 2>&1; then
    echo "Service user exists: $SVC_USER"
    return
  fi
  echo "Creating service user: $SVC_USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
}

setup_cache_dir() {
  echo "Setting up cache directory: $CACHE_DIR"
  mkdir -p "$CACHE_DIR"
  chown -R "${SVC_USER}:${SVC_GROUP}" "$CACHE_DIR"
  chmod 700 "$CACHE_DIR"
}

write_config() {
  echo "Writing config: $CFG_DST"
  umask 077

  cat > "$CFG_DST" <<EOF
ENFORCEMENT=on
FAIL_MODE=${DEFAULT_FAIL_MODE}
DRY_RUN=${DEFAULT_DRY_RUN}
DENY_SUSPICIOUS=${DEFAULT_DENY_SUSPICIOUS}

AFN_API_KEY=${AFN_API_KEY}
BYPASS_CIDRS=${BYPASS_CIDRS}

CACHE_DIR=${CACHE_DIR}
TIMEOUT_MS=${DEFAULT_TIMEOUT_MS}
LOCAL_RPS_CEILING=20
LOG_LEVEL=info

# GEO policy disabled by default
GEO_MODE=off
GEO_SCOPE=continent
GEO_LIST=

# Cache housekeeping
CACHE_MAX_ENTRIES=${DEFAULT_CACHE_MAX_ENTRIES}
CACHE_MAX_MB=${DEFAULT_CACHE_MAX_MB}
PURGE_INTERVAL_MIN=${DEFAULT_PURGE_INTERVAL_MIN}
EOF

  chown root:root "$CFG_DST"
  chmod 600 "$CFG_DST"
}

install_systemd_units() {
  echo "Installing systemd purge service/timer"

  cat > "$SYSTEMD_SVC" <<EOF
[Unit]
Description=AFNSec SSH Gate cache purge
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/afnsec-ssh-gate --purge
User=${SVC_USER}
Group=${SVC_GROUP}

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CACHE_DIR}
EOF

  cat > "$SYSTEMD_TIMER" <<EOF
[Unit]
Description=Run AFNSec SSH Gate cache purge periodically

[Timer]
OnBootSec=10m
OnUnitActiveSec=60m
AccuracySec=5m
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now afnsec-ssh-gate-purge.timer
}

patch_pam_sshd() {
  echo "Patching PAM: $PAM_SSHD"

  BACKUP="${PAM_SSHD}.afnsec.bak.$(timestamp)"
  cp -a "$PAM_SSHD" "$BACKUP"

  if grep -q "/usr/local/bin/afnsec-ssh-gate" "$PAM_SSHD"; then
    echo "PAM already references afnsec-ssh-gate. Skipping insert."
    PAM_BACKUP_FOR_ROLLBACK="$BACKUP"
    return
  fi

  if grep -q "^@include[[:space:]]\+common-auth" "$PAM_SSHD"; then
    awk -v line="$PAM_LINE" '
      BEGIN{inserted=0}
      {
        if(!inserted && $0 ~ /^@include[[:space:]]+common-auth/){
          print line
          inserted=1
        }
        print $0
      }
      END{
        if(!inserted){ print line }
      }
    ' "$PAM_SSHD" > "${PAM_SSHD}.tmp"
    mv "${PAM_SSHD}.tmp" "$PAM_SSHD"
  else
    printf "%s\n%s\n" "$PAM_LINE" "$(cat "$PAM_SSHD")" > "${PAM_SSHD}.tmp"
    mv "${PAM_SSHD}.tmp" "$PAM_SSHD"
  fi

  chmod 644 "$PAM_SSHD"
  PAM_BACKUP_FOR_ROLLBACK="$BACKUP"
}

restart_ssh_with_rollback() {
  echo "Restarting SSH (with rollback safety)..."
  if restart_ssh_service; then
    echo "SSH restart: OK"
    return
  fi

  echo "SSH restart failed. Rolling back PAM changes..."
  if [[ -n "${PAM_BACKUP_FOR_ROLLBACK:-}" && -f "${PAM_BACKUP_FOR_ROLLBACK}" ]]; then
    cp -a "${PAM_BACKUP_FOR_ROLLBACK}" "$PAM_SSHD"
    restart_ssh_service || die "Rollback failed: SSH still not restarting."
    echo "Rollback complete."
  else
    die "No PAM backup found to rollback."
  fi
}

final_summary() {
  echo
  echo "========================================"
  echo "AFNSec SSH Gate installed successfully."
  echo "========================================"
  echo
  echo "Installed from:"
  echo "  $BIN_URL"
  echo
  echo "Binary:"
  echo "  $BIN_DST"
  echo
  echo "Config (root-only):"
  echo "  $CFG_DST"
  echo
  echo "PAM line added:"
  echo "  $PAM_LINE"
  echo
  echo "Cache:"
  echo "  $CACHE_DIR (owned by ${SVC_USER})"
  echo
  echo "Purge timer:"
  echo "  systemctl status afnsec-ssh-gate-purge.timer"
  echo
  echo "Commands:"
  echo "  sudo afnsec-ssh-gate --doctor"
  echo "  sudo afnsec-ssh-gate --check"
  echo "  sudo afnsec-ssh-gate --purge-now"
  echo "  sudo afnsec-ssh-gate --purge-all"
  echo "  sudo afnsec-ssh-gate --fw-status"
  echo "  sudo afnsec-ssh-gate --fw-del <ip>"
  echo "  sudo afnsec-ssh-gate --fw-clear"
  echo
  echo "Logs:"
  echo "  sudo tail -n 50 /var/log/auth.log | grep afnsec-ssh-gate"
  echo
  echo "AFNSec nft profile check"
  echo "  sudo nft list set inet afnsec ssh_block_v4"
  echo "  sudo nft list set inet afnsec ssh_block_v6"
  echo
  echo "Enforcement:"
  echo "  Installer set DRY_RUN=1 (log-only)."
  echo "  To enforce blocking:"
  echo "    1) edit $CFG_DST and set: DRY_RUN=0"
  echo "    2) sudo systemctl restart ssh"
  echo
}

main() {
  preflight
  prompt_inputs
  download_and_verify
  install_binary
  create_service_user
  setup_cache_dir
  write_config
  install_systemd_units
  patch_pam_sshd
  restart_ssh_with_rollback
  final_summary
}

main "$@"
