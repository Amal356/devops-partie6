#!/usr/bin/env bash
# Partie 1 : cert-manager et CA de lab  -> 📸 clusterissuers.png
set -uo pipefail
source ~/tp16/scripts/lib.sh; cd $T
t "helm install cert-manager $CMV"
helm repo add jetstack https://charts.jetstack.io --force-update >/dev/null
helm repo update jetstack >/dev/null
helm upgrade --install cert-manager jetstack/cert-manager -n cert-manager --create-namespace \
  --version $CMV --set crds.enabled=true --wait --timeout 15m | head -4
t "Émetteurs (nouvel essai tant que le webhook n'est pas prêt)"
until kubectl apply -f $M/10-issuers.yaml; do sleep 5; done
kubectl -n cert-manager wait --for=condition=Ready certificate/lab-ca --timeout=180s
kubectl wait --for=condition=Ready clusterissuer --all --timeout=120s
t "Export du certificat PUBLIC de la CA et confiance système"
kubectl -n cert-manager get secret lab-ca -o jsonpath='{.data.ca\.crt}' | base64 -d > lab-ca.crt
sudo cp lab-ca.crt /usr/local/share/ca-certificates/lab-ca.crt && sudo update-ca-certificates | tail -1
clear
t "kubectl -n cert-manager get pods"; kubectl -n cert-manager get pods
t "kubectl get clusterissuers"; kubectl get clusterissuers -o wide
t "kubectl -n cert-manager get certificate lab-ca"; kubectl -n cert-manager get certificate lab-ca
t "openssl x509 -in lab-ca.crt -noout -subject -issuer -dates"; openssl x509 -in lab-ca.crt -noout -subject -issuer -dates
t "Clés du Secret lab-ca (noms seulement : tls.key ne quitte jamais le cluster)"
kubectl -n cert-manager get secret lab-ca -o jsonpath='{.data}' | jq -c 'keys'
