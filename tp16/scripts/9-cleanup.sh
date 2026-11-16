#!/usr/bin/env bash
# Nettoyage du TP16 (garde K3s pour le TP17)
set -uo pipefail
source ~/tp16/scripts/lib.sh
kubectl delete ns tp16 keycloak --ignore-not-found
kubectl -n kube-system delete configmap coredns-custom --ignore-not-found && kubectl -n kube-system rollout restart deploy/coredns
kubectl delete -f $M/10-issuers.yaml --ignore-not-found
helm uninstall cert-manager -n cert-manager; kubectl delete ns cert-manager --ignore-not-found
sudo rm -f /usr/local/share/ca-certificates/lab-ca.crt && sudo update-ca-certificates --fresh | tail -1
rm -rf "$S" $T/lab-ca.crt
echo "TP16 nettoyé."
