#  OWASP UnCrackable Level 3 – Analyse, Bypass et Extraction du Secret

> **Objectif :** Contourner les protections Java et natives d'une application Android obfusquée, puis extraire et décrypter la clé secrète cachée.

---

##  Table des Matières

1. [Introduction](#-introduction)
2. [Objectifs](#-objectifs)
3. [Environnement et Outils](#-environnement-et-outils)
4. [Analyse Statique avec JADX](#-analyse-statique-avec-jadx)
5. [Bypass Java via Smali](#️-bypass-java-via-smali)
6. [Rebuild et Signature de l'APK](#-rebuild-et-signature-de-lapk)
7. [Analyse Native avec Ghidra](#-analyse-native-avec-ghidra)
8. [Bypass Natif – Patch Binaire](#-bypass-natif--patch-binaire)
9. [Extraction du Secret depuis la Mémoire](#-extraction-du-secret-depuis-la-mémoire)
10. [Conversion Little Endian](#️-conversion-little-endian-important)
11. [Décryptage XOR](#-décryptage-xor)
12. [Validation Finale](#-validation-finale)
13. [Analyse et Leçons Apprises](#-analyse-et-leçons-apprises)
14. [Conclusion](#-conclusion)

---

##  Introduction

### Contexte

Le **Reverse Engineering Android** est une discipline fondamentale en cybersécurité mobile. Elle consiste à analyser une application compilée — sans accès au code source — afin d'en comprendre le comportement interne, d'identifier les vulnérabilités et de contourner les mécanismes de protection.

Le projet [**OWASP Mobile Security Testing Guide (MSTG)**](https://github.com/OWASP/owasp-mastg) met à disposition une série de challenges graduels appelés **UnCrackable Apps**. Ces applications sont conçues comme des terrains d'entraînement pour les professionnels de la sécurité mobile.

### L'application : UnCrackable Level 3

**UnCrackable Level 3** représente le niveau de difficulté le plus élevé de la série. Elle implémente un empilement de protections opérant à deux niveaux distincts :

| Niveau | Protection | Mécanisme |
|--------|-----------|-----------|
| Java (Dalvik) | Root Detection | Vérifie la présence de binaires suspects (`su`, `busybox`, etc.) |
| Java (Dalvik) | Integrity Check | Calcule le CRC32 de `libfoo.so` et `classes.dex` |
| Natif (ARM) | Anti-Debug | Parcourt `/proc/self/maps` pour détecter `frida-agent` |
| Natif (ARM) | Anti-Frida/Xposed | Détecte les hooks dynamiques via des patterns mémoire |
| Natif (ARM) | Secret Validation | Valide le secret en mémoire native, hors portée Java |

### Objectif Final

Contourner **toutes** ces couches de protection afin d'extraire la chaîne secrète encodée dans la bibliothèque native `libfoo.so`, la décoder via une opération XOR, puis la saisir dans l'application pour obtenir un message de succès.

---

##  Objectifs

- [ ] Comprendre l'architecture et les mécanismes de protection de l'application
- [ ] **Contourner les protections Java** (Root Detection, Integrity Check) via modification Smali
- [ ] **Contourner les protections natives** (Anti-Debug, Anti-Frida) via patch binaire dans Ghidra
- [ ] **Extraire le secret encodé** depuis la mémoire de la bibliothèque native
- [ ] **Décrypter le secret** via opération XOR avec la clé identifiée dans le code Java

---

##  Environnement et Outils

### Configuration Technique

| Composant | Détail |
|-----------|--------|
| Système hôte | Windows 10/11 |
| Émulateur Android | AVD (Android Virtual Device) via Android Studio |
| Architecture cible | x86_64 |
| APK cible | `UnCrackable-Level3.apk` |

### Outils Utilisés

| Outil | Rôle | Version recommandée |
|-------|------|---------------------|
| **adb** (Android Debug Bridge) | Communication avec l'appareil/émulateur | SDK Platform Tools ≥ 34 |
| **apktool** | Décompilation et recompilation d'APK | ≥ 2.9.0 |
| **JADX** | Décompilation Java du bytecode Dalvik | ≥ 1.5.0 |
| **Ghidra** | Analyse statique du code natif ARM/ELF | ≥ 11.0 |
| **Frida** | Instrumentation dynamique *(bloqué par l'app)* | ≥ 16.x |
| **Python 3** | Décryptage XOR de la clé secrète | ≥ 3.9 |
| **apksigner** | Signature de l'APK recompilé | Inclus dans Build-Tools |
| **keytool** | Génération du keystore de signature | Inclus dans JDK |

### Connexion à l'Émulateur

La première étape consiste à vérifier que l'émulateur Android est correctement détecté par `adb` :

```bash
adb devices
```

<p align="center"> <img src="images/0.1.png" width="600"> </p>

L'émulateur `emulator-5556` est actif et accessible. On installe ensuite l'APK :

```bash
adb install UnCrackable-Level3.apk
```

### Comportement Initial de l'Application

Au premier lancement de l'application sur un émulateur rooté, un dialogue s'affiche immédiatement :


<p align="center"> <img src="images/0.png" width="400"> </p>

Ce comportement confirme que l'application est protégée par une détection de root active. L'application se ferme dès que l'utilisateur clique sur **OK**. Notre premier objectif est de neutraliser ce mécanisme.

---

##  Analyse Statique avec JADX

### Décompilation de l'APK

JADX (Java Decompiler for Android) nous permet de transformer le bytecode Dalvik (`.dex`) en code Java lisible. On ouvre l'APK directement dans l'interface graphique de JADX :

```bash
jadx-gui UnCrackable-Level3.apk
```

### Exploration de MainActivity

La classe principale `MainActivity` révèle plusieurs éléments critiques dès l'ouverture :


<p align="center"> <img src="images/2.png" width="600"> </p>
<p align="center"> <img src="images/29.1.png" width="600"> </p>

**Observations clés :**
- La clé XOR `"pizzapizzapizzapizzapizza"` est **directement visible** dans le code décompilé
- La méthode `init(byte[] bArr)` délègue l'initialisation au code natif
- La méthode native `baz()` retourne une valeur CRC attendue pour `classes.dex`

### Identification de la Root Detection

En explorant les imports et les méthodes de `MainActivity`, on trouve les appels aux classes de protection :

```java
import sg.vantagepoint.util.IntegrityCheck;
import sg.vantagepoint.util.RootDetection;
```

La méthode `onCreate()` enchaîne plusieurs vérifications :

<p align="center"> <img src="images/4.png" width="600"> </p>

### La Méthode showDialog() : Point de Blocage Principal

<p align="center"> <img src="images/32.png" width="600"> </p>
```

**Analyse :** La méthode `showDialog()` est le **point de sortie forcée** de l'application. Toute détection (root, debug, tamper) aboutit à cet appel. Notre stratégie sera de **neutraliser cette méthode directement dans le bytecode Smali**.

### La vérification d'intégrité : verifyLibs()

<p align="center"> <img src="images/3.png" width="600"> </p>

**Implication critique :** Si on modifie `classes.dex` (via patch Smali), la valeur CRC32 changera, ce qui positionnera `tampered = 31337`. Or, `tampered` est vérifié dans `onCreate()`. C'est un **anti-tamper double layer** : la modification Smali sera détectée via le CRC natif.

> **Notre stratégie :** Patcher `showDialog()` **et** forcer `tampered` à rester à `0`, OU patcher la condition de comparaison CRC dans `verifyLibs()`.

### Chargement de la Bibliothèque Native

<p align="center"> <img src="images/6.png" width="600"> </p>

La bibliothèque `libfoo.so` contient toute la logique de protection native que nous devrons analyser dans Ghidra.

---

##  Bypass Java via Smali

### Qu'est-ce que le Smali ?

Le **Smali** est le langage d'assemblage du bytecode Dalvik. Quand `apktool` décompile un APK, il convertit le fichier `.dex` en fichiers `.smali` lisibles et modifiables. On peut ensuite modifier ces fichiers et recompiler l'APK pour obtenir un binaire modifié.

### Étape 1 – Décompiler l'APK avec apktool

```bash
apktool d UnCrackable-Level3.apk -o UnCrackable3_decompiled
```
<p align="center"> <img src="images/7.png" width="600"> </p>

Cette commande génère la structure suivante :
<p align="center"> <img src="images/8.png" width="600"> </p>
<p align="center"> <img src="images/9.png" width="600"> </p>

```
UnCrackable3_decompiled/
├── AndroidManifest.xml
├── smali/
│   └── sg/vantagepoint/uncrackable3/
│       ├── MainActivity.smali       ← Notre cible principale
│       └── CodeCheck.smali
├── res/
└── original/
```

### Étape 2 – Localiser MainActivity.smali

```bash
cd UnCrackable3_decompiled/smali/sg/vantagepoint/uncrackable3/
```

On ouvre `MainActivity.smali` dans un éditeur de texte (VS Code, Notepad++, etc.).

### Étape 3 – Identifier la méthode showDialog()

On recherche la signature de la méthode :
<p align="center"> <img src="images/10.png" width="600"> </p>
<p align="center"> <img src="images/11.png" width="600"> </p>
<p align="center"> <img src="images/12.png" width="600"> </p>

```smali
.method private showDialog(Ljava/lang/String;)V
```

**Code Smali AVANT le patch :**

<p align="center"> <img src="images/14.png" width="600"> </p>


### Étape 4 – Appliquer le Patch

On remplace **tout le corps** de la méthode par un simple `return-void` :

**Code Smali APRÈS le patch :**

<p align="center"> <img src="images/15.png" width="600"> </p>


**Pourquoi ce patch fonctionne-t-il ?**

En remplaçant tout le corps de `showDialog()` par `return-void`, on fait en sorte que chaque appel à cette méthode **retourne immédiatement sans effet**. L'AlertDialog ne sera jamais créé, et `System.exit(0)` ne sera jamais appelé. L'application continue son exécution normalement.

> **Note :** On patchera également la vérification CRC dans `verifyLibs()` pour neutraliser le flag `tampered`, ou on s'assurera que la condition `tampered != 0` dans `onCreate()` appelle toujours `showDialog()` — que l'on vient de neutraliser.

---

##  Rebuild et Signature de l'APK

### Étape 1 – Recompiler avec apktool

```bash
apktool b UnCrackable3_decompiled -o UnCrackable3_patched.apk
```

<p align="center"> <img src="images/16.png" width="600"> </p>

### Étape 2 – Générer un Keystore de Signature

Android exige que tout APK soit signé pour pouvoir être installé :

<p align="center"> <img src="images/17.png" width="600"> </p>


### Étape 4 – Installer et Lancer l'APK Signé

<p align="center"> <img src="images/18.png" width="600"> </p>

> ** – Application lancée sans popup de root detection**
> 
<p align="center"> <img src="images/18.png" width="400"> </p>

L'application se lance désormais sans afficher le dialogue de détection de root. Le bypass Java est **opérationnel**.

---

##  Analyse Native avec Ghidra

### Contexte

Malgré le bypass Java, l'application dispose d'une seconde ligne de défense implémentée en code natif (C/C++) dans la bibliothèque partagée `libfoo.so`. Ce code est compilé en bytecode ARM et ne peut pas être lu directement — il nécessite l'utilisation d'un désassembleur/décompilateur natif comme **Ghidra**.

### Extraction de libfoo.so

On extrait la bibliothèque depuis l'APK (qui est en réalité une archive ZIP) :

### Ouverture dans Ghidra

1. Lancer Ghidra
2. Créer un nouveau projet : `File > New Project`
3. Importer le fichier : `File > Import File > libfoo.so`
4. Sélectionner le format **ELF** et l'architecture **x86** (ou ARM selon l'APK)
5. Lancer l'auto-analyse : `Analysis > Auto Analyze`
6. Attendre la fin de l'analyse (processus pouvant durer plusieurs minutes)

<p align="center"> <img src="images/21.png" width="600"> </p>

### Identification des Fonctions Critiques

Dans le **Symbol Tree** de Ghidra, on identifie les fonctions exportées (JNI) et les fonctions internes. Parmi les fonctions non exportées, deux retiennent notre attention :

| Adresse | Nom (auto-généré) | Rôle suspecté |
|---------|-------------------|---------------|
| `0x001037c0` | `FUN_001037c0` | Détection Anti-Frida/Debug |
| `0x001012c0` | `FUN_001012c0` | Validation du secret / XOR |

### Analyse de FUN_001037c0 – La Fonction Anti-Debug

<p align="center"> <img src="images/23.png" width="600"> </p>


**Analyse du mécanisme :**

Le fichier `/proc/self/maps` est un fichier virtuel Linux exposant la **carte mémoire virtuelle** du processus courant. Frida injecte ses agents sous forme de bibliothèques partagées (`frida-agent-64.so`, etc.) qui apparaissent dans ce fichier. En scannant régulièrement ce fichier, l'application peut détecter toute tentative d'instrumentation dynamique.

<p align="center"> <img src="images/24.png" width="600"> </p>
La fonction tourne dans un **thread en arrière-plan** (lancé depuis la fonction `init()`), ce qui signifie qu'elle surveille en permanence la mémoire, même après le démarrage de l'activité principale.


---

##  Bypass Natif – Patch Binaire

### Objectif

Neutraliser la fonction `FUN_001037c0` pour qu'elle se termine immédiatement sans effectuer ses vérifications anti-debug/anti-Frida.

### Stratégie de Patch

La méthode la plus propre consiste à **remplacer les premiers octets de la fonction** par une instruction de retour immédiat (`RET` sur x86, ou `BX LR` sur ARM).

<p align="center"> <img src="images/25.png" width="600"> </p>


| Instruction | Opcode |
|-------------|--------|
| `RET` (retour immédiat) | `C3` |
| `NOP` (no-operation) | `90` |

### Procédure dans Ghidra

#### 1. Localiser la fonction

Dans le **Listing View**, naviguer vers l'adresse `001037c0`. On voit le début de la fonction :

```asm
001037c0  PUSH  EBP
001037c1  MOV   EBP, ESP
001037c3  PUSH  EBX
001037c4  PUSH  EDI
001037c5  PUSH  ESI
001037c6  SUB   ESP, 0x21c
...
```
 via l'interface Ghidra :
- Clic droit sur l'instruction > `Patch Instruction`
- Remplacer par `RET`
- 
**Résultat après patch :**

```c
void FUN_001037c0(void)
{
    return;  // ← La fonction retourne immédiatement
}
```

```asm
001037c0  RET   ; ← Seule instruction restante
```

#### 2. Exporter le binaire patché

<p align="center"> <img src="images/26.png" width="600"> </p>




### Réintégration du Binaire Patché dans l'APK
<p align="center"> <img src="images/26.1.png" width="600"> </p>
<p align="center"> <img src="images/27.png" width="600"> </p>

```bash
# Copier le libfoo.so patché dans le dossier décompilé
cp libfoo_patched.so UnCrackable3_decompiled/lib/x86/libfoo.so

# Rebuilder et signer l'APK
apktool b UnCrackable3_decompiled -o UnCrackable3_patched_v2.apk
apksigner sign --ks my-release-key.jks --out UnCrackable3_final.apk UnCrackable3_patched_v2.apk

# Réinstaller
adb uninstall owasp.mstg.uncrackable3
adb install UnCrackable3_final.apk
```

> **Note importante :** Remplacer `libfoo.so` invalidera le CRC calculé par `verifyLibs()`. Ce CRC est vérifié dans la couche Java. Puisqu'on a déjà patché `showDialog()`, cette vérification ne produira plus d'effet visible.

---

##  Extraction du Secret depuis la Mémoire

### Analyse de FUN_001012c0 – La Fonction de Validation
<p align="center"> <img src="images/22.png" width="600"> </p>

<p align="center"> <img src="images/29.png" width="600"> </p>

En continuant l'analyse de `libfoo.so` dans Ghidra, on examine la fonction `FUN_001012c0`. Cette fonction est appelée lors de la validation de la chaîne saisie par l'utilisateur. Son décompilé révèle un tableau de valeurs encodées :

```c
void FUN_001012c0(long *param_1)
{
    param_1[0] = 0x1549170f1311081d;
    param_1[1] = 0x15131d5a1903000d;
    param_1[2] = 0x14130817005a0e08;
    
    // ... 
}
```


### Interprétation des Données

Ces trois valeurs 64-bit représentent le **secret chiffré par XOR**, stocké directement dans le binaire natif. Il s'agit d'un classique exemple de **hardcoded secret** obfusqué au niveau natif.

La valeur brute extraite est :

```
Bloc 0 : 0x1549170f1311081d
Bloc 1 : 0x15131d5a1903000d
Bloc 2 : 0x14130817005a0e08
```

Pour décoder ces valeurs, il faut comprendre comment elles sont stockées en mémoire.

---

##  Conversion Little Endian (IMPORTANT)

### Qu'est-ce que le Little Endian ?

Les processeurs x86 et la majorité des ARM modernes utilisent la convention **Little Endian** pour stocker les entiers multi-octets en mémoire. Cela signifie que **l'octet de poids faible est stocké à l'adresse la plus basse**.

Autrement dit, quand Ghidra affiche une valeur 64-bit comme `0x1549170f1311081d`, les octets sont stockés en mémoire dans l'ordre **inversé**.

### Procédure de Conversion

#### Bloc 0 : `0x1549170f1311081d`

**Étape 1 – Découpage en octets (lecture gauche → droite) :**

```
15  49  17  0f  13  11  08  1d
```

**Étape 2 – Inversion pour obtenir l'ordre mémoire réel (little endian) :**

```
1d  08  11  13  0f  17  49  15
```

Représentation hexadécimale : `1d0811130f174915`

---

#### Bloc 1 : `0x15131d5a1903000d`

**Découpage :**
```
15  13  1d  5a  19  03  00  0d
```

**Inversion :**
```
0d  00  03  19  5a  1d  13  15
```

Représentation hexadécimale : `0d0003195a1d1315`

---

#### Bloc 2 : `0x14130817005a0e08`

**Découpage :**
```
14  13  08  17  00  5a  0e  08
```

**Inversion :**
```
08  0e  5a  00  17  08  13  14
```

Représentation hexadécimale : `080e5a0017081314`

---

### Résumé de la Conversion

| Bloc | Valeur Ghidra | Octets en mémoire (little endian) |
|------|---------------|-----------------------------------|
| 0 | `0x1549170f1311081d` | `1d 08 11 13 0f 17 49 15` |
| 1 | `0x15131d5a1903000d` | `0d 00 03 19 5a 1d 13 15` |
| 2 | `0x14130817005a0e08` | `08 0e 5a 00 17 08 13 14` |

### Concaténation Finale

En concaténant les trois blocs convertis dans l'ordre :

```
1d0811130f174915 | 0d0003195a1d1315 | 080e5a0017081314
```

**Séquence d'octets complète :**

```
1d0811130f1749150d0003195a1d1315080e5a0017081314
```

Cette séquence de **24 octets** représente le secret XOR-encodé que nous allons maintenant décrypter.

---

##  Décryptage XOR

### La Clé XOR

Lors de l'analyse de `MainActivity` dans JADX, nous avons identifié une constante Java particulièrement intéressante :

```java
private static final String xorkey = "pizzapizzapizzapizzapizza";
```
<p align="center"> <img src="images/29.1.png" width="600"> </p>

Cette clé est passée à la fonction native `init()` :

```java
init(xorkey.getBytes());
```

La fonction native utilise cette clé pour encoder/décoder le secret via une opération XOR symétrique. Puisque XOR est une opération réversible (`a XOR b XOR b = a`), nous pouvons retrouver le plaintext en appliquant le même XOR.

**Vérification de la cohérence :**
- Secret encodé : `24 octets`
- Clé XOR : `"pizzapizzapizzapizzapizza"` → `25 caractères ASCII` → on utilisera les 24 premiers

### Script de Décryptage Python

<p align="center"> <img src="images/30.png" width="600"> </p>

```python
encoded_hex = "1d0811130f1749150d0003195a1d1315080e5a0017081314"
encoded = bytes.fromhex(encoded_hex)

xor_key = b"pizzapizzapizzapizzapizza"

secret = bytes(a ^ b for a, b in zip(encoded, xor_key))

print(f"[*] Octets encodés  : {encoded.hex()}")
print(f"[*] Clé XOR         : {xor_key.decode()}")
print(f"[*] Secret décodé   : {secret.decode('utf-8')}")
```

### Exécution et Résultat
```
[*] Octets encodés  : 1d0811130f1749150d0003195a1d1315080e5a0017081314
[*] Clé XOR         : pizzapizzapizzapizzapizza
[*] Secret décodé   : making owasp great again
```

### Vérification Manuelle (Exemple)

Pour illustrer le mécanisme XOR sur les deux premiers octets :

| Position | Encodé (hex) | Encodé (dec) | Clé (char) | Clé (dec) | XOR (dec) | Résultat |
|----------|-------------|--------------|------------|-----------|-----------|---------|
| 0 | `0x1d` | 29 | `'p'` | 112 | 29 ⊕ 112 = 109 | `'m'` |
| 1 | `0x08` | 8 | `'i'` | 105 | 8 ⊕ 105 = 97 | `'a'` |
| 2 | `0x11` | 17 | `'z'` | 122 | 17 ⊕ 122 = 107 | `'k'` |
| 3 | `0x13` | 19 | `'z'` | 122 | 19 ⊕ 122 = 105 | `'i'` |
| ... | ... | ... | ... | ... | ... | ... |

Le résultat final est :

> ** Secret : `making owasp great again`**

---

##  Validation Finale

### Saisie du Secret dans l'Application

On lance l'application patchée sur l'émulateur et on saisit le secret découvert dans le champ de texte :

<p align="center"> <img src="images/31.png" width="600"> </p>

### Message de Succès

L'application affiche un message de confirmation, prouvant que le secret est correct 

---

##  Analyse et Leçons Apprises

### 1. La Faiblesse de la Validation Client-Side

L'ensemble des protections de cette application opère **côté client** (sur l'appareil Android). Cette architecture présente une faiblesse fondamentale : un attaquant ayant un accès physique ou un émulateur rooté peut toujours inspecter et modifier le code. La règle d'or en cybersécurité est :

> *"Never trust the client."*

Toute validation de valeur sensible (mot de passe, clé de licence, token d'authentification) doit être effectuée **côté serveur**, hors de portée de l'utilisateur.

### 2. Le Danger des Clés Hardcodées

La clé XOR `"pizzapizzapizzapizzapizza"` est directement visible dans le code Java décompilé. Même déplacée dans le code natif, une clé hardcodée reste vulnérable à l'extraction par reverse engineering. Les bonnes pratiques recommandent :

- Utiliser des mécanismes de **dérivation de clés** (PBKDF2, Argon2)
- Stocker les secrets sensibles dans des **enclaves sécurisées** (Android Keystore)
- Ne jamais stocker de secrets en clair dans un binaire distribué

### 3. Les Limites de l'Obfuscation Native

Déplacer la logique de sécurité du code Java vers le code natif C/C++ augmente la complexité de l'analyse, mais ne constitue pas une protection absolue. Ghidra est capable de décompiler du code ARM/x86 en pseudo-C lisible. L'obfuscation native est une **barrière supplémentaire**, pas une solution définitive.

### 4. L'Intérêt de la Détection d'Intégrité

Le mécanisme CRC32 sur `libfoo.so` et `classes.dex` est une approche pertinente : il complique la tâche de l'attaquant qui doit patcher à la fois le code Java **et** le binaire natif. En pratique, cette protection est contournable, mais elle augmente significativement le travail nécessaire.

### 5. La Valeur Pédagogique du Reverse Engineering

Le reverse engineering est une compétence à double tranchant. Du côté offensif, il permet de découvrir des vulnérabilités et d'extraire des secrets. Du côté défensif, comprendre comment les attaquants analysent les applications permet de concevoir des protections plus robustes. Les certifications comme **OSCP**, **OSCE** ou **EMAPT** incluent ces techniques dans leur curriculum.

---

##  Conclusion

Ce projet a permis de mener une analyse complète d'une application Android fortement protégée, en combinant des techniques de reverse engineering statique et d'analyse binaire. Voici le bilan des étapes accomplies :

| Étape | Technique | Outil | Résultat |
|-------|-----------|-------|---------|
|  Analyse Java | Décompilation | JADX | Identification du XOR key et de showDialog() |
|  Bypass Java | Patch Smali | apktool | Neutralisation de la root detection |
|  Signature | Re-signing | apksigner | APK réinstallable et fonctionnel |
|  Analyse native | Décompilation ARM | Ghidra | Identification de la détection anti-Frida |
|  Bypass natif | Patch binaire | Ghidra | Neutralisation de FUN_001037c0 |
|  Extraction | Analyse statique | Ghidra | Buffer encodé de 24 octets extrait |
|  Conversion | Little Endian | Manuel/Python | Octets correctement réordonnés |
|  Décryptage | XOR | Python | Secret `making owasp great again` obtenu |
|  Validation | Test app | adb | Message de succès affiché |

### Points Clés à Retenir

1. **Le bypass Java** consiste à modifier le bytecode Smali pour court-circuiter les vérifications
2. **Le bypass natif** nécessite un patch binaire direct dans le code ARM compilé
3. **La convention Little Endian** est cruciale pour interpréter correctement les données extraites
4. **Le XOR est symétrique** : connaître la clé suffit à décrypter (et à chiffrer)
5. **Aucune protection client-side n'est inviolable** face à un attaquant motivé disposant des bons outils




---


