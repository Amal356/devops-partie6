#!/usr/bin/env bash
# Partie 2 : Ingress HTTPS  -> 📸 https-curl.png
set -uo pipefail
source ~/tp16/scripts/lib.sh
kubectl apply -f $M/20-ingress-tls.yaml
echo "attente du certificat whoami-tls..."
sleep 5; kubectl -n tp16 wait --for=condition=Ready certificate/whoami-tls --timeout=180s
sleep 5
clear
t "kubectl -n tp16 get certificate,certificaterequest"; kubectl -n tp16 get certificate,certificaterequest
t "curl -v https://whoami.lab.local (certificat vérifié par la CA de lab)"
curl -v https://whoami.lab.local 2>&1 | grep -E 'subject|issuer|SSL certificate verify|HTTP/'
t "SAN et validité (openssl s_client)"
openssl s_client -connect whoami.lab.local:443 -servername whoami.lab.local </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep -E -A1 'Subject Alternative|Not Before' | grep -v '^--'
t "HTTP en clair (entrypoint web) : plus de route"
echo "http://whoami.lab.local -> code $(curl -s -o /dev/null -w '%{http_code}' http://whoami.lab.local)"
