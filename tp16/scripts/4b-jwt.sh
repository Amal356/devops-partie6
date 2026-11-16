#!/usr/bin/env bash
# Partie 4 : jeton de bob décodé + découverte OIDC  -> 📸 jwt-decoded.png
set -uo pipefail
source ~/tp16/scripts/lib.sh
kc_login
CID=$(kc get clients -r lab -q clientId=whoami --fields id --format csv --noquotes)
kc update clients/$CID -r lab -s directAccessGrantsEnabled=true      # activé TEMPORAIREMENT
TOKEN=$(curl -s https://keycloak.lab.local/realms/lab/protocol/openid-connect/token \
  -d grant_type=password -d client_id=whoami --data-urlencode "client_secret@$S/client.secret" \
  -d username=bob --data-urlencode "password@$S/bob.pw" | jq -r .access_token)
kc update clients/$CID -r lab -s directAccessGrantsEnabled=false     # désactivé aussitôt
P=$(cut -d. -f2 <<<"$TOKEN" | tr '_-' '/+'); while [ $(( ${#P} % 4 )) -ne 0 ]; do P="$P="; done
clear
t "Jeton d'accès de bob : 3 parties (en-tête.charge.signature), longueur ${#TOKEN} caractères (non affiché)"
t "En-tête"; cut -d. -f1 <<<"$TOKEN" | tr '_-' '/+' | base64 -d 2>/dev/null | jq -c '{alg, typ, kid}'
t "Charge utile décodée"
base64 -d <<<"$P" | jq '{iss, aud, azp, exp, exp_lisible: (.exp|todate), iat: (.iat|todate), preferred_username, email, realm_access}'
t "Direct access grants désactivé à nouveau"
kc get clients/$CID -r lab | jq '{clientId, directAccessGrantsEnabled}'
t "Découverte OIDC (extrait)"
curl -s https://keycloak.lab.local/realms/lab/.well-known/openid-configuration \
  | jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri, end_session_endpoint, code_challenge_methods_supported}'
unset TOKEN P
