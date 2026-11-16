#!/usr/bin/env bash
# Partie 5 : déploiement d'oauth2-proxy devant whoami  -> sortie texte à m'envoyer
set -uo pipefail
source ~/tp16/scripts/lib.sh; cd $T
# secrets créés depuis les fichiers (rien n'est affiché)
kubectl -n tp16 create secret generic oauth2-proxy \
  --from-file=client-secret=$S/client.secret \
  --from-literal=cookie-secret="$(openssl rand -base64 32 | tr -- '+/' '-_' | head -c 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n tp16 create secret generic lab-ca-public --from-file=ca.crt=lab-ca.crt --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f $M/40-oauth2-proxy.yaml
kubectl -n tp16 rollout status deploy/oauth2-proxy --timeout=300s
kubectl apply -f $M/41-ingress-oauth2-proxy.yaml
sleep 5
clear
t "kubectl -n tp16 get pods,svc,ingress"; kubectl -n tp16 get pods,svc,ingress
t "Ingress whoami -> backend"; kubectl -n tp16 get ingress whoami -o jsonpath='{.spec.rules[0].http.paths[0].backend.service.name}{"\n"}'
t "Sans session : / et /oauth2/start"
echo "GET /             -> $(curl -s -o /dev/null -w '%{http_code}' https://whoami.lab.local/)"
curl -s -o /dev/null -w 'GET /oauth2/start -> %{http_code} vers %{redirect_url}\n' "https://whoami.lab.local/oauth2/start?rd=%2F" | sed -E 's/(state|code_challenge)=[^&]*/\1=…/g'
t "Logs oauth2-proxy"; kubectl -n tp16 logs deploy/oauth2-proxy --tail=6 | mask
