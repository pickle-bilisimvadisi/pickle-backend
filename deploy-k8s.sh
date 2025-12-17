#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
K8S_DIR="$ROOT_DIR/k8s"
ENV_FILE="$ROOT_DIR/.env"

if [[ ! -d "$K8S_DIR" ]]; then
  echo "k8s directory not found: $K8S_DIR" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo ".env file missing: $ENV_FILE" >&2
  exit 1
fi

install_docker() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Docker auto-install only supported with apt-get; install manually." >&2
    return 1
  fi
  echo "Installing Docker..."
  sudo apt-get update -y
  if sudo apt-get install -y docker.io; then
    sudo systemctl enable --now docker || true
    if command -v docker >/dev/null 2>&1; then
      return 0
    fi
  fi
  if command -v lsb_release >/dev/null 2>&1; then
    distro_id=$(lsb_release -is 2>/dev/null | tr '[:upper:]' '[:lower:]')
    distro_codename=$(lsb_release -cs 2>/dev/null)
  else
    . /etc/os-release
    distro_id=${ID:-debian}
    distro_codename=${VERSION_CODENAME:-stable}
  fi
  repo_distro=$distro_id
  if [[ "$repo_distro" != "ubuntu" && "$repo_distro" != "debian" ]]; then
    repo_distro="debian"
  fi
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl gnupg lsb-release
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo rm -f /etc/apt/sources.list.d/docker.list
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${repo_distro} ${distro_codename} stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io
  sudo systemctl enable --now docker
}

install_kubectl() {
  echo "Installing kubectl..."
  tmpfile=$(mktemp)
  curl -L -o "$tmpfile" "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  sudo install -m 0755 "$tmpfile" /usr/local/bin/kubectl
  rm -f "$tmpfile"
}

install_minikube() {
  echo "Installing minikube..."
  tmpfile=$(mktemp)
  curl -Lo "$tmpfile" https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
  sudo install -m 0755 "$tmpfile" /usr/local/bin/minikube
  rm -f "$tmpfile"
}

ensure_tool() {
  local name="$1"
  local installer="$2"
  if command -v "$name" >/dev/null 2>&1; then
    return
  fi
  "$installer"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "Missing tool: $name (install failed, please install manually)" >&2
    exit 1
  fi
}

ensure_tool docker install_docker
ensure_tool kubectl install_kubectl
ensure_tool minikube install_minikube

status_host=$(minikube status --format '{{.Host}}' 2>/dev/null || true)
if [[ "$status_host" != "Running" ]]; then
  echo "Starting Minikube..."
  minikube start --driver=docker --force
fi

echo "Building images..."

declare -a images=(
  "pickle-vault:latest|vault"
  "pickle-redis:latest|redis"
  "pickle-postgres:latest|postgres"
  "pickle-backend:latest|."
)

for item in "${images[@]}"; do
  IFS='|' read -r name ctx <<<"$item"
  echo "Building image: $name"
  docker build -t "$name" "$ROOT_DIR/$ctx"
done

echo "Loading images into Minikube..."
for item in "${images[@]}"; do
  IFS='|' read -r name ctx <<<"$item"
  echo "Pushing to Minikube: $name"
  minikube image load "$name"
done

echo "Applying vault-env secret..."
kubectl create secret generic vault-env --from-file="$ENV_FILE" --dry-run=client -o yaml | kubectl apply -f -

apply_order=(pvc.yaml vault.yaml redis.yaml database.yaml backend.yaml)
for file in "${apply_order[@]}"; do
  path="$K8S_DIR/$file"
  echo "kubectl apply -f $path"
  kubectl apply -f "$path"
done

echo "Starting port-forward (vault 8200, backend 8080)..."
nohup kubectl port-forward svc/vault 8200:8200 >/tmp/portf-vault.log 2>&1 &
nohup kubectl port-forward svc/backend 8080:8080 >/tmp/portf-backend.log 2>&1 &
echo "Ready. Backend NodePort: 30080, Vault NodePort: 30820"
