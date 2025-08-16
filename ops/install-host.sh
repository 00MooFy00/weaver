#!/usr/bin/env bash
set -euo pipefail

# === Настройки ===
APT_LIST="ops/apt-host.txt"

# Определим дистрибутив
if [ -r /etc/os-release ]; then
  . /etc/os-release
  DIST_ID="${ID:-ubuntu}"
  DIST_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
else
  echo "Cannot detect distro via /etc/os-release" >&2
  exit 1
fi

echo "[*] Detected: ${DIST_ID} ${DIST_CODENAME}"

# === Docker репозиторий (официальный), если ещё не добавлен ===
if ! grep -Rq "download.docker.com/linux/${DIST_ID}" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
  echo "[*] Adding Docker APT repo..."
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/${DIST_ID}/gpg \
  | sudo -H gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  # Если нет кодового имени, по умолчанию использовать stable для текущего релиза
  if [ -z "${DIST_CODENAME}" ]; then
    echo "[*] No codename found; will attempt 'stable' channel"
    DIST_CODENAME="stable"
  fi

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${DIST_ID} ${DIST_CODENAME} stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
else
  echo "[*] Docker APT repo already present"
fi

# === Чистим возможные дубли Docker-строки в /etc/apt/sources.list ===
if grep -n "download.docker.com/linux/${DIST_ID}" /etc/apt/sources.list >/dev/null 2>&1; then
  echo "[*] Removing duplicated docker entries from /etc/apt/sources.list (backup will be saved)"
  sudo cp /etc/apt/sources.list /etc/apt/sources.list.backup.$(date +%s)
  # Комментируем все строки с docker в основном списке источников
  sudo sed -i 's|^\(.*download\.docker\.com/linux/'"${DIST_ID}"'.*\)$|# \1|' /etc/apt/sources.list
fi

echo "[*] apt-get update..."
sudo apt-get update -y

# === Устанавливаем пакеты из ops/apt-host.txt ===
if [ ! -f "$APT_LIST" ]; then
  echo "File $APT_LIST not found. Run from repo root." >&2
  exit 1
fi

# Собираем список пакетов (игнорируем пустые и комментарии)
PKGS=$(grep -vE '^\s*(#|$)' "$APT_LIST" | tr '\n' ' ')
echo "[*] Installing packages: $PKGS"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $PKGS

# === Модуль nfnetlink_queue ===
echo "[*] Loading kernel module nfnetlink_queue..."
if ! lsmod | grep -q '^nfnetlink_queue'; then
  sudo modprobe nfnetlink_queue || true
fi
echo "nfnetlink_queue" | sudo tee /etc/modules-load.d/weaver.conf >/dev/null

# === IPv6 включён? ===
V1=$(sysctl -n net.ipv6.conf.all.disable_ipv6 || echo 1)
V2=$(sysctl -n net.ipv6.conf.default.disable_ipv6 || echo 1)
if [ "$V1" != "0" ] || [ "$V2" != "0" ]; then
  echo "[*] Enabling IPv6 via sysctl..."
  sudo tee /etc/sysctl.d/99-weaver-ipv6.conf >/dev/null <<'EOF'
net.ipv6.conf.all.disable_ipv6=0
net.ipv6.conf.default.disable_ipv6=0
EOF
  sudo sysctl --system || true
fi

# === docker post-steps ===
echo "[*] Ensuring user is in docker group..."
if ! id -nG "$USER" | grep -qw docker; then
  sudo usermod -aG docker "$USER"
  echo ">> You were added to 'docker' group. Re-login to use Docker without sudo."
fi

echo "[*] Docker compose version:"
docker compose version || true

echo "[*] Host prerequisites installed. Done."
