# DevOps & Cloud – Partie 6 : Sécurité de la plateforme

> **Étudiante** : Amal Jemli, Master DevOps
> **Cours** : [Teknolabs – DevOps & Cloud, M. Wahid](https://docs.teknolabs.net/courses/devops-cloud/partie-6-securite-plateforme/)
> Suite de [devops-partie4](https://github.com/Amal356/devops-partie4) et [devops-partie5](https://github.com/Amal356/devops-partie5).

Objectif de la partie : chiffrer les échanges, gérer les identités, durcir le cluster et sortir les secrets des manifests.

| TP | Sujet | Dossier | État |
|---|---|---|---|
| TP16 | HTTPS avec cert-manager (CA de lab) et IAM avec Keycloak (OIDC, rôles, oauth2-proxy) | [tp16/](tp16/README.md) | ✅ 6/6 captures (+3 complémentaires) |
| TP17 | Sécurité Kubernetes : RBAC, PSS, NetworkPolicy, Kyverno, Falco | tp17/ | ⏳ |
| TP18 | Secrets et Vault : Vault, External Secrets, Sealed Secrets, rotation | tp18/ | ⏳ |

## Fil rouge sécurité
- Aucun secret affiché ni commité : clé privée de la CA, secret du client OIDC, mots de passe Keycloak, kubeconfig (voir `.gitignore`).
- Mots de passe générés (`openssl rand`), stockés dans `~/tp16/.secrets` (droits 600) sur la VM, passés par l'entrée standard.
- Versions figées (cert-manager v1.19.1, Keycloak 26.3, oauth2-proxy v7.9.0, K3s v1.34.12+k3s1).
