#!/usr/bin/env bash
# Partie 5 : carol (user) authentifiée mais NON autorisée  -> 📸 oauth2-403.png
set -uo pipefail
source ~/tp16/scripts/lib.sh
J=$(mktemp); trap 'rm -f $J' EXIT
CODE=$(login carol $J)
clear
t "Connexion de carol (rôle user)"; echo "code HTTP final après le callback : $CODE"
t "GET https://whoami.lab.local/ avec les cookies de carol"
curl -si -b $J https://whoami.lab.local/ | tr -d '\r' | grep -E '^HTTP/'
t "Logs oauth2-proxy (refus pour carol)"
kubectl -n tp16 logs deploy/oauth2-proxy --tail=30 | mask | grep -iE 'carol|denied|unauthori|403' | tail -4
