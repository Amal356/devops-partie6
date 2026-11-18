# DevOps & Cloud – Partie 6 : Sécurité de la plateforme

> **Étudiante** : Amal Jemli, Master DevOps
> **Cours** : [Teknolabs – DevOps & Cloud, M. Wahid](https://docs.teknolabs.net/courses/devops-cloud/partie-6-securite-plateforme/)
> Suite de [devops-partie4](https://github.com/Amal356/devops-partie4) et [devops-partie5](https://github.com/Amal356/devops-partie5).

Objectif de la partie : chiffrer les échanges, gérer les identités, durcir le cluster et sortir les secrets des manifests.

| TP | Sujet | Dossier | État |
|---|---|---|---|
| TP16 | HTTPS avec cert-manager (CA de lab) et IAM avec Keycloak (OIDC, rôles, oauth2-proxy) | [tp16/](tp16/README.md) | ✅ 6/6 captures (+3 complémentaires) |
| TP17 | Sécurité Kubernetes : RBAC, PSS, NetworkPolicy, Kyverno, Falco | [tp17/](tp17/README.md) | ✅ 7/7 captures |
| TP18 | Secrets et Vault : Vault, External Secrets, Sealed Secrets, rotation | [tp18/](tp18/README.md) | ✅ 6/6 captures |

## Fil rouge sécurité
- Aucun secret affiché ni commité : clé privée de la CA, secret du client OIDC, mots de passe Keycloak, kubeconfig (voir `.gitignore`).
- Mots de passe générés (`openssl rand`), stockés dans `~/tp16/.secrets` (droits 600) sur la VM, passés par l'entrée standard.
- Versions figées (cert-manager v1.19.1, Keycloak 26.3, oauth2-proxy v7.9.0, K3s v1.34.12+k3s1, Kyverno 1.19.2, Trivy Operator 0.36.1, Falco 0.45.2, Vault chart 0.34.1, ESO 2.15.0, Sealed Secrets 0.41.2) ; binaires vérifiés par checksum (Kubescape, kubeseal).
- Défense en profondeur (TP17) : RBAC, PSS `restricted`, NetworkPolicies, Kyverno, Trivy Operator, Kubescape, Falco.
- Secrets (TP18) : Vault (source de vérité) + ESO, Sealed Secrets pour GitOps ; aucun secret en clair dans Git.
