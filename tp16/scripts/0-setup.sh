#!/usr/bin/env bash
# Préparation : K3s (plan B mono-nœud du TP14), /etc/hosts, pré-téléchargement des images, application whoami
set -uo pipefail
source ~/tp16/scripts/lib.sh
V=v1.34.12+k3s1
t "RAM disponible (Keycloak a besoin d'au moins 2 Go libres)"; free -h
if ! command -v k3s >/dev/null; then
  if sudo ss -ltnp | grep -qE ':(80|443) '; then echo "⚠️ ports 80/443 déjà pris"; exit 1; fi
  t "Installation K3s $V"
  curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=$V sh -s - server --write-kubeconfig-mode 600 2>&1 | tail -3
fi
mkdir -p ~/.kube && sudo cat /etc/rancher/k3s/k3s.yaml > ~/.kube/config && chmod 600 ~/.kube/config
echo "attente des composants système..."
until kubectl -n kube-system get deploy traefik >/dev/null 2>&1; do sleep 5; done
kubectl -n kube-system wait --for=condition=Available deploy --all --timeout=600s >/dev/null
NODEIP=$(nodeip)
t "/etc/hosts : $NODEIP whoami.lab.local keycloak.lab.local"
sudo sed -i -E '/[[:space:]](whoami|keycloak)\.lab\.local/d' /etc/hosts
echo "$NODEIP whoami.lab.local keycloak.lab.local" | sudo tee -a /etc/hosts
mkdir -p "$S" && chmod 700 "$S"
t "Pré-téléchargement des images (connexion lente : patience, Keycloak ~ 450 Mo)"
for img in traefik/whoami:v1.10.0 quay.io/oauth2-proxy/oauth2-proxy:v7.9.0 busybox:1.36 quay.io/keycloak/keycloak:26.3; do
  echo "-> $img"; until sudo k3s crictl pull "$img" >/dev/null; do echo "   nouvel essai..."; sleep 10; done
done
kubectl apply -f $M/00-app.yaml
kubectl -n tp16 rollout status deploy/whoami --timeout=300s
clear
t "kubectl get nodes -o wide"; kubectl get nodes -o wide
t "kubectl -n tp16 get all"; kubectl -n tp16 get all
t "free -h"; free -h
