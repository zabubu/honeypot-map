# Déploiement sur un VPS

Ce guide met le honeypot en ligne : Cowrie sur le port 22, le vrai SSH d'administration sur le port **22022**, et le dashboard accessible par tunnel SSH (ou en HTTPS avec mot de passe).

## Avant de commencer

- Un VPS **dédié et jetable** (Debian 12 ou Ubuntu 22.04/24.04, 1 vCPU, 1 Go de RAM), sans aucune donnée personnelle ni lien avec tes autres serveurs.
- Des conditions d'utilisation de l'hébergeur qui **autorisent les honeypots** (à vérifier avant de payer).
- Une clé SSH. Si tu n'en as pas, depuis PowerShell : `ssh-keygen -t ed25519`, puis donne le contenu de `~/.ssh/id_ed25519.pub` à l'hébergeur à la création du serveur.
- Tes bases GeoLite2 (`GeoLite2-City.mmdb` et `GeoLite2-ASN.mmdb`) dans `data\` sur ton PC.

Remplace dans les commandes : `IP_DU_VPS` par l'adresse du serveur et `sabri` par le nom d'utilisateur que tu choisis.

## 1. Sécuriser le serveur

Depuis ton PC (dossier du projet) :

```powershell
scp .\deploy\harden.sh root@IP_DU_VPS:/root/
ssh root@IP_DU_VPS
```

Sur le serveur :

```bash
bash /root/harden.sh sabri
```

**Ne ferme pas cette session.** Ouvre un deuxième terminal sur ton PC et teste :

```powershell
ssh -p 22022 sabri@IP_DU_VPS
```

Si la connexion marche, tu peux fermer la session root. À partir de maintenant, **administre toujours avec `-p 22022`** : le port 22 est celui du honeypot. Si tu es bloqué, utilise la console web de ton hébergeur.

## 2. Installer Docker

Connecté en `sabri` :

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
exit
```

Reconnecte-toi (`ssh -p 22022 sabri@IP_DU_VPS`) pour que le groupe `docker` soit pris en compte, puis vérifie : `docker --version`.

## 3. Récupérer le projet

Avant de déployer, règle sur ton PC la position de ton serveur dans `web/index.html` (constante `HOME`), puis commit et push. Sur le serveur :

```bash
git clone https://github.com/zabubu/honeypot-map.git
cd honeypot-map
mkdir geoip
```

Depuis ton PC, envoie les bases GeoLite2 (elles ne sont pas sur GitHub) :

```powershell
scp -P 22022 data\GeoLite2-City.mmdb data\GeoLite2-ASN.mmdb sabri@IP_DU_VPS:~/honeypot-map/geoip/
```

## 4. Lancer

```bash
docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml ps
```

Tous les services doivent être « running ». Pour voir ce qui se passe :

```bash
docker compose -f docker-compose.prod.yml logs -f cowrie
docker compose -f docker-compose.prod.yml logs ingester enrich api
```

## 5. Vérifier que ça marche

1. Depuis ton PC, attaque ton propre honeypot : `ssh root@IP_DU_VPS` (port 22), tape un mot de passe quelconque, puis quelques commandes.
2. Ouvre un tunnel vers le dashboard :

```powershell
ssh -p 22022 -L 8000:localhost:8000 sabri@IP_DU_VPS
```

3. Va sur http://localhost:8000. Ta tentative apparaît dans le flux. Les premiers bots arrivent en général en quelques heures.

## 6. Accès public en HTTPS (optionnel)

À ne faire qu'après avoir vérifié ce que le dashboard affiche : les mots de passe et commandes viennent d'attaquants.

```bash
cp deploy/Caddyfile.example deploy/Caddyfile
docker run --rm caddy caddy hash-password       # génère le hash de ton mot de passe
nano deploy/Caddyfile                           # domaine + hash
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
docker compose -f docker-compose.prod.yml --profile public up -d
```

Le domaine doit déjà pointer vers l'IP du VPS pour que le certificat soit émis.

## Maintenance

| Besoin | Commande |
|---|---|
| Mettre à jour le code | `git pull && docker compose -f docker-compose.prod.yml up -d --build` |
| Arrêter | `docker compose -f docker-compose.prod.yml down` |
| Sauvegarder la base | `docker run --rm -v honeypot-map_data:/data -v "$PWD":/backup alpine tar czf /backup/data.tgz /data` |
| Surveiller l'espace disque | `docker system df` et `df -h` |

## Sécurité : à retenir

- **Ne lance jamais** un fichier téléchargé par un bot, et ne l'ouvre pas sur ton PC. Cowrie conserve ces fichiers pour analyse : ne garde que leur hash dans ton rapport.
- Cowrie émule un shell mais **télécharge réellement** les URL demandées par les bots. Le serveur doit rester isolé et sans secret.
- Les IP sont **masquées** dans l'API par défaut. Garde-les masquées dans tout ce que tu publies (README, captures, rapport).
- Docker publie ses ports en contournant `ufw` : c'est pourquoi l'API n'est exposée que sur `127.0.0.1`.
- Pense à **supprimer le serveur** (ou à l'éteindre) à la fin de ta collecte.
- Fige l'image `cowrie/cowrie` sur un tag précis une fois que tout fonctionne.
