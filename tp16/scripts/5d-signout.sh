#!/usr/bin/env bash
# Partie 5 : alice + déconnexion /oauth2/sign_out et persistance SSO  -> sortie texte à m'envoyer
set -uo pipefail
source ~/tp16/scripts/lib.sh
J=$(mktemp); trap 'rm -f $J' EXIT
CODE=$(login alice $J)
clear
t "alice (admin)"; echo "connexion -> $CODE ; GET / -> $(curl -s -o /dev/null -w '%{http_code}' -b $J https://whoami.lab.local/)"
curl -s -b $J https://whoami.lab.local/oauth2/userinfo | jq -c .
t "Déconnexion oauth2-proxy"
curl -s -o /dev/null -c $J -b $J -w 'GET /oauth2/sign_out -> %{http_code}\n' https://whoami.lab.local/oauth2/sign_out
echo "GET / après sign_out -> $(curl -s -o /dev/null -w '%{http_code}' -b $J https://whoami.lab.local/)"
t "Nouvelle connexion SANS mot de passe : la session Keycloak (SSO) est toujours valide"
echo "GET /oauth2/start -> $(curl -s -c $J -b $J -L -o /dev/null -w '%{http_code}' 'https://whoami.lab.local/oauth2/start?rd=%2F')"
curl -s -b $J https://whoami.lab.local/oauth2/userinfo | jq -c .
echo "cookies Keycloak encore présents : $(grep -cE 'KEYCLOAK_(IDENTITY|SESSION)' $J)"
