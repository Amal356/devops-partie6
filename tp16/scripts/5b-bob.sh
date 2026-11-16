#!/usr/bin/env bash
# Partie 5 : bob (developer) autorisé  -> 📸 oauth2-allowed.png
set -uo pipefail
source ~/tp16/scripts/lib.sh
J=$(mktemp); trap 'rm -f $J' EXIT
CODE=$(login bob $J)
clear
t "Connexion de bob (navigateur simulé : oauth2-proxy -> Keycloak -> /oauth2/callback)"; echo "code HTTP final : $CODE"
t "GET https://whoami.lab.local/ avec la session de bob"
curl -si -b $J https://whoami.lab.local/ | tr -d '\r' | mask | grep -iE '^(HTTP/|X-Auth-Request|Hostname|GET |X-Forwarded-(User|Email|Preferred|Proto))'
t "GET /oauth2/auth : en-têtes X-Auth-Request-* renvoyés par oauth2-proxy"
curl -si -b $J https://whoami.lab.local/oauth2/auth | tr -d '\r' | mask | grep -iE '^(HTTP/|X-Auth-Request)'
t "GET /oauth2/userinfo"; curl -s -b $J https://whoami.lab.local/oauth2/userinfo | jq -c .
