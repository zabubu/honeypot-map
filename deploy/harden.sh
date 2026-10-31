#!/usr/bin/env bash
# Durcissement initial d'un VPS Debian 12 / Ubuntu 22.04+ dédié au honeypot.
#
# Usage (en root, une seule fois) :
#     bash harden.sh NOM_UTILISATEUR
#
# Ce que fait le script :
#   - crée un utilisateur d'administration (connexion par clé SSH uniquement)
#   - déplace le vrai SSH sur le port 22022 (le port 22 est réservé à Cowrie)
#   - interdit la connexion root et les mots de passe SSH
#   - active le pare-feu (ufw), fail2ban sur le SSH d'administration
#     et les mises à jour de sécurité automatiques
#
# SÉCURITÉ : ne ferme PAS ta session actuelle avant d'avoir testé, dans un autre
# terminal :  ssh -p 22022 NOM_UTILISATEUR@IP_DU_VPS
# (en cas de blocage, la console web de ton hébergeur permet de réparer).
set -euo pipefail

SSH_PORT=22022
NEWUSER="${1:-}"

[ "$(id -u)" -eq 0 ] || { echo "Lance ce script en root."; exit 1; }
[ -n "$NEWUSER" ] || { echo "Usage : bash harden.sh NOM_UTILISATEUR"; exit 1; }
[ -s /root/.ssh/authorized_keys ] || {
  echo "Aucune clé SSH dans /root/.ssh/authorized_keys."
  echo "Ajoute ta clé publique avant de continuer, sinon tu serais verrouillé dehors."
  exit 1
}

echo "==> Installation des paquets"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban unattended-upgrades ca-certificates curl

echo "==> Utilisateur $NEWUSER"
if ! id "$NEWUSER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$NEWUSER"
fi
usermod -aG sudo "$NEWUSER"
install -d -m 700 -o "$NEWUSER" -g "$NEWUSER" "/home/$NEWUSER/.ssh"
install -m 600 -o "$NEWUSER" -g "$NEWUSER" /root/.ssh/authorized_keys "/home/$NEWUSER/.ssh/authorized_keys"
# Pas de mot de passe sur ce compte (clé uniquement) : sudo sans mot de passe.
# Acceptable sur un serveur jetable et dédié, à ne pas copier ailleurs.
echo "$NEWUSER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-$NEWUSER"
chmod 440 "/etc/sudoers.d/90-$NEWUSER"

echo "==> Configuration SSH (port $SSH_PORT)"
# Le préfixe 00- fait lire ce fichier en premier : pour SSH, la première valeur gagne
# (certains fichiers cloud-init réactivent sinon les mots de passe).
cat > /etc/ssh/sshd_config.d/00-honeypot.conf <<EOF
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
EOF
sshd -t

echo "==> Pare-feu"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp" comment 'SSH administration'
ufw allow 22/tcp comment 'Honeypot Cowrie'
ufw --force enable

echo "==> fail2ban (SSH d'administration)"
cat > /etc/fail2ban/jail.d/sshd-honeypot.local <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
backend = systemd
maxretry = 3
bantime = 1h
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

echo "==> Mises à jour de sécurité automatiques"
dpkg-reconfigure -f noninteractive unattended-upgrades

echo "==> Redémarrage du service SSH"
# Ubuntu 24.04 : l'activation par socket ignore le Port du fichier de configuration.
if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
  systemctl disable --now ssh.socket
  systemctl enable ssh.service
fi
systemctl restart ssh

echo
echo "Ports en écoute pour sshd :"
ss -tlnp | grep sshd || true
echo
echo "TERMINÉ. Étape obligatoire avant de fermer cette session :"
echo "  ouvre un NOUVEAU terminal et teste :  ssh -p ${SSH_PORT} ${NEWUSER}@IP_DU_VPS"
echo "  N'utilise plus 'root' ni le port 22 pour administrer : le port 22 est pour Cowrie."
