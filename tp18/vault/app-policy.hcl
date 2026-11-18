# TP18 partie 2 : policy Vault de l'application (moindre privilège).
# Avec KV v2, les données sont lues sous secret/data/<chemin>.

# COMPLÉTÉ : uniquement la capacité "read" sur secret/data/tp18/*
# (pas de list, pas d'écriture, pas d'accès aux autres chemins ni à secret/metadata/)
path "secret/data/tp18/*" {
  capabilities = ["read"]
}
