#!/usr/bin/env bash
# Partie 2 (question) : suppression du Secret whoami-tls, renewBefore  -> sortie texte à m'envoyer
set -uo pipefail
source ~/tp16/scripts/lib.sh
clear
t "Avant : Secret whoami-tls"; kubectl -n tp16 get secret whoami-tls -o custom-columns=NOM:.metadata.name,UID:.metadata.uid,CREE:.metadata.creationTimestamp
t "kubectl -n tp16 delete secret whoami-tls"; kubectl -n tp16 delete secret whoami-tls
for i in $(seq 1 30); do kubectl -n tp16 get secret whoami-tls >/dev/null 2>&1 && break; sleep 2; done
t "Après quelques secondes : cert-manager l'a recréé (nouvel UID)"
kubectl -n tp16 get secret whoami-tls -o custom-columns=NOM:.metadata.name,UID:.metadata.uid,CREE:.metadata.creationTimestamp
kubectl -n tp16 wait --for=condition=Ready certificate/whoami-tls --timeout=120s
t "Durée et renouvellement du Certificate"
kubectl -n tp16 get certificate whoami-tls -o jsonpath='duration={.spec.duration}  renewBefore={.spec.renewBefore}{"\n"}notBefore={.status.notBefore}  notAfter={.status.notAfter}{"\n"}renewalTime={.status.renewalTime}  revision={.status.revision}{"\n"}'
t "Événements"; kubectl -n tp16 get events --field-selector involvedObject.name=whoami-tls --sort-by=.lastTimestamp | tail -6
