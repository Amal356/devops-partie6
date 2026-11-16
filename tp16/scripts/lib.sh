# Fonctions communes du TP16 (sourcé par les scripts, ne pas lancer seul)
export KUBECONFIG=$HOME/.kube/config
T=~/tp16; M=$T/manifests; S=$T/.secrets      # .secrets : mots de passe générés, jamais copiés ni commités
CMV=v1.19.1                                  # version figée de cert-manager
t(){ echo; echo "========== $* =========="; }
nodeip(){ kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}'; }
# kcadm.sh exécuté DANS le pod Keycloak (aucun secret ne sort du pod)
kc(){ local c=$1; shift; kubectl -n keycloak exec -i deploy/keycloak -- /opt/keycloak/bin/kcadm.sh "$c" --config /tmp/kcadm.config "$@"; }
kc_login(){ kubectl -n keycloak exec deploy/keycloak -- bash -c '/opt/keycloak/bin/kcadm.sh config credentials --config /tmp/kcadm.config --server http://localhost:8080 --realm master --user admin --password "$KC_BOOTSTRAP_ADMIN_PASSWORD"' >/dev/null; }
# masque les jetons et cookies dans les sorties (captures propres)
mask(){ sed -E 's/^((X-Forwarded-Access-Token|X-Auth-Request-Access-Token|Authorization|Cookie|Set-Cookie):).*/\1 ***masqué***/I'; }
# login <utilisateur> <cookie-jar> : simule le navigateur (oauth2-proxy -> Keycloak -> callback) ; affiche le code HTTP final
login(){ local u=$1 jar=$2 page action; rm -f "$jar"
  page=$(curl -s -c "$jar" -b "$jar" -L "https://whoami.lab.local/oauth2/start?rd=%2F")
  action=$(grep -oE 'action="[^"]*login-actions/authenticate[^"]*"' <<<"$page" | head -1 | sed -e 's/^action="//' -e 's/"$//' -e 's/&amp;/\&/g')
  [ -z "$action" ] && { echo "ERREUR : formulaire Keycloak introuvable"; return 1; }
  curl -s -c "$jar" -b "$jar" -L -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=$u" --data-urlencode "password@$S/$u.pw" -d credentialId= "$action"
}
