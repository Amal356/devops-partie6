#!/usr/bin/env bash
# Partie 4 : realm lab, rôles, utilisateurs, client whoami (kcadm.sh, scripté)  -> 📸 keycloak-realm.png
set -uo pipefail
source ~/tp16/scripts/lib.sh
mkdir -p "$S" && chmod 700 "$S"
# mots de passe des utilisateurs et secret du client : générés une fois, fichiers 600, jamais affichés
for f in alice bob carol; do [ -s "$S/$f.pw" ] || { printf '%s' "$(openssl rand -hex 12)" > "$S/$f.pw"; }; done
[ -s "$S/client.secret" ] || printf '%s' "$(openssl rand -hex 24)" > "$S/client.secret"
chmod 600 "$S"/*
kc_login
kc create realms -s realm=lab -s enabled=true 2>/dev/null || echo "realm lab déjà présent"
for r in user developer admin; do kc create roles -r lab -s name=$r 2>/dev/null || true; done
declare -A ROLE=([alice]=admin [bob]=developer [carol]=user)
for u in alice bob carol; do
  kc create users -r lab -s username=$u -s enabled=true -s email=$u@lab.local -s emailVerified=true \
     -s firstName=${u^} -s lastName=Lab 2>/dev/null || true
  # mot de passe passé par l'entrée standard (n'apparaît ni à l'écran ni dans ps)
  kubectl -n keycloak exec -i deploy/keycloak -- bash -c 'read -r P || true; /opt/keycloak/bin/kcadm.sh set-password --config /tmp/kcadm.config -r lab --username "$1" --new-password "$P"' _ $u < "$S/$u.pw"
  kc add-roles -r lab --uusername $u --rolename ${ROLE[$u]}
done
# client confidentiel whoami : Standard flow uniquement, redirect URI exacte
if [ -z "$(kc get clients -r lab -q clientId=whoami --fields id --format csv --noquotes)" ]; then
  kubectl -n keycloak exec -i deploy/keycloak -- bash -c 'read -r P || true; /opt/keycloak/bin/kcadm.sh create clients --config /tmp/kcadm.config -r lab \
    -s clientId=whoami -s enabled=true -s protocol=openid-connect -s publicClient=false \
    -s clientAuthenticatorType=client-secret -s "secret=$P" \
    -s standardFlowEnabled=true -s directAccessGrantsEnabled=false -s implicitFlowEnabled=false -s serviceAccountsEnabled=false \
    -s "redirectUris=[\"https://whoami.lab.local/oauth2/callback\"]" -s "attributes.\"pkce.code.challenge.method\"=S256"' < "$S/client.secret"
fi
CID=$(kc get clients -r lab -q clientId=whoami --fields id --format csv --noquotes)
# mapper Audience (onglet Client scopes -> whoami-dedicated) : "whoami" dans le claim aud
kc create clients/$CID/protocol-mappers/models -r lab -s name=audience-whoami -s protocol=openid-connect \
  -s protocolMapper=oidc-audience-mapper -s 'config."included.client.audience"=whoami' \
  -s 'config."access.token.claim"=true' -s 'config."id.token.claim"=false' 2>/dev/null || true
clear
t "Realm"; kc get realms/lab --fields realm,enabled --format csv --noquotes
t "Rôles de realm"; kc get roles -r lab --fields name,description --format csv --noquotes
t "Utilisateurs et rôles"
printf '%-8s %-18s %s\n' USER EMAIL ROLES
for u in alice bob carol; do
  printf '%-8s %-18s %s\n' $u "$u@lab.local" "$(kc get-roles -r lab --uusername $u | jq -r '[.[].name | select(test("^default-roles")|not)] | join(", ")')"
done
t "Client whoami"
kc get clients/$CID -r lab | jq '{clientId, publicClient, clientAuthenticatorType, standardFlowEnabled, directAccessGrantsEnabled, implicitFlowEnabled, redirectUris, pkce: .attributes["pkce.code.challenge.method"]}'
t "Mapper du scope whoami-dedicated"
kc get clients/$CID/protocol-mappers/models -r lab | jq -c '.[] | {name, protocolMapper, audience: .config["included.client.audience"]}'
