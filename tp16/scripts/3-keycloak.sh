#!/usr/bin/env bash
# Partie 3 : DNS interne + Keycloak  -> pas de capture, sortie texte à m'envoyer
set -uo pipefail
source ~/tp16/scripts/lib.sh
NODEIP=$(nodeip)
kubectl create namespace keycloak --dry-run=client -o yaml | kubectl apply -f -
# mot de passe admin généré et stocké uniquement dans le Secret (jamais affiché)
kubectl -n keycloak get secret keycloak-admin >/dev/null 2>&1 || \
  kubectl -n keycloak create secret generic keycloak-admin --from-literal=password="$(openssl rand -base64 18)"
t "CoreDNS : *.lab.local -> $NODEIP"
sed "s/10\.0\.2\.15/$NODEIP/" $M/05-coredns-custom.yaml | kubectl apply -f -
kubectl -n kube-system rollout restart deploy/coredns
kubectl -n kube-system rollout status deploy/coredns --timeout=120s
kubectl apply -f $M/30-keycloak.yaml
t "Démarrage de Keycloak (2 à 5 min sur la VM)"
kubectl -n keycloak rollout status deploy/keycloak --timeout=900s
kubectl -n keycloak wait --for=condition=Ready certificate/keycloak-tls --timeout=180s
clear
t "kubectl -n keycloak get pods,svc,ingress,certificate"; kubectl -n keycloak get pods,svc,ingress,certificate
t "Résolution DNS depuis un pod (même nom que le navigateur)"
kubectl -n tp16 run dnstest --rm -i --restart=Never --image=busybox:1.36 -- nslookup keycloak.lab.local 2>/dev/null | grep -A2 'Name:'
t "Découverte OIDC du realm master via HTTPS"
curl -s https://keycloak.lab.local/realms/master/.well-known/openid-configuration | jq '{issuer}'
t "Mémoire"; kubectl top pod -n keycloak 2>/dev/null; free -h | head -2
