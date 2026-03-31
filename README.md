#  OWASP UnCrackable Level 3 – Analyse, Bypass et Extraction du Secret

> **Domaine :** Sécurité Mobile · Reverse Engineering Android  
> **Niveau :** Avancé  
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
| Architecture cible | x86 / ARM (selon l'émulateur) |
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

> **Figure 1 – Détection de l'émulateur via `adb devices`**

![Figure 1 - adb devices](screenshots/adb_devices.png)

L'émulateur `emulator-5556` est actif et accessible. On installe ensuite l'APK :

```bash
adb install UnCrackable-Level3.apk
```

### Comportement Initial de l'Application

Au premier lancement de l'application sur un émulateur rooté, un dialogue s'affiche immédiatement :

> **Figure 2 – Erreur "Rooting or tampering detected" au lancement**

![Figure 2 - Root detected](screenshots/root_detected.png)

Ce comportement confirme que l'application est protégée par une détection de root active. L'application se ferme dès que l'utilisateur clique sur **OK**. Notre premier objectif est de neutraliser ce mécanisme.

---

## 🔍 Analyse Statique avec JADX

### Décompilation de l'APK

JADX (Java Decompiler for Android) nous permet de transformer le bytecode Dalvik (`.dex`) en code Java lisible. On ouvre l'APK directement dans l'interface graphique de JADX :

```bash
jadx-gui UnCrackable-Level3.apk
```

### Exploration de MainActivity

La classe principale `MainActivity` révèle plusieurs éléments critiques dès l'ouverture :

> **Figure 3 – Vue d'ensemble de MainActivity dans JADX**

![Figure 3 - JADX MainActivity](screenshots/jadx_mainactivity.png)

On identifie immédiatement :

```java
public class MainActivity extends AppCompatActivity {
    private static final String TAG = "UnCrackable3";
    static int tampered = 0;
    private static final String xorkey = "pizzapizzapizzapizzapizza";  // ← Clé XOR visible !
    private CodeCheck check;
    Map<String, Long> crc;

    private native long baz();
    private native void init(byte[] bArr);  // ← Initialisation native
```

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

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    init(xorkey.getBytes());  // Passage de la clé XOR au code natif
    
    if (RootDetection.checkRoot1() || RootDetection.checkRoot2() || RootDetection.checkRoot3()
        || IntegrityCheck.isDebuggable(getApplicationContext())
        || tampered != 0) {
        showDialog("Rooting or tampering detected.");  // ← Déclencheur
    }
    verifyLibs();
    // ...
}
```

### La Méthode showDialog() : Point de Blocage Principal

```java
private void showDialog(String str) {
    AlertDialog.Builder alertDialogCreate = new AlertDialog.Builder(this);
    alertDialogCreate.setTitle(str);
    alertDialogCreate.setMessage("This is unacceptable. The app is now going to exit.");
    alertDialogCreate.setButton(-3, "OK", new DialogInterface.OnClickListener() {
        @Override
        public void onClick(DialogInterface dialogInterface, int i) {
            System.exit(0);  // ← Fermeture forcée de l'application
        }
    });
    alertDialogCreate.setCancelable(false);
    alertDialogCreate.show();
}
```

**Analyse :** La méthode `showDialog()` est le **point de sortie forcée** de l'application. Toute détection (root, debug, tamper) aboutit à cet appel. Notre stratégie sera de **neutraliser cette méthode directement dans le bytecode Smali**.

### La vérification d'intégrité : verifyLibs()

> **Figure 4 – Code de verifyLibs() dans JADX**

![Figure 4 - verifyLibs](screenshots/jadx_verifylibs.png)

```java
private void verifyLibs() {
    this.crc = new HashMap<>();
    this.crc.put("armeabi-v7a", Long.valueOf(Long.parseLong(getResources().getString(R.string.armeabi_v7a))));
    this.crc.put("arm64-v8a",   Long.valueOf(Long.parseLong(getResources().getString(R.string.arm64_v8a))));
    this.crc.put("x86",         Long.valueOf(Long.parseLong(getResources().getString(R.string.x86))));
    this.crc.put("x86_64",      Long.valueOf(Long.parseLong(getResources().getString(R.string.x86_64))));
    
    try {
        ZipFile zipFile = new ZipFile(getPackageCodePath());
        for (Map.Entry<String, Long> entry : this.crc.entrySet()) {
            String str = "lib/" + entry.getKey() + "/libfoo.so";
            ZipEntry entry2 = zipFile.getEntry(str);
            if (entry2.getCrc() != entry.getValue().longValue()) {
                tampered = 31337;  // ← Marqueur de tamper si CRC invalide
            }
        }
        ZipEntry entry3 = zipFile.getEntry("classes.dex");
        if (entry3.getCrc() != baz()) {  // ← baz() est une méthode native retournant le CRC attendu
            tampered = 31337;
        }
    } catch (IOException unused) {
        System.exit(0);
    }
}
```

**Implication critique :** Si on modifie `classes.dex` (via patch Smali), la valeur CRC32 changera, ce qui positionnera `tampered = 31337`. Or, `tampered` est vérifié dans `onCreate()`. C'est un **anti-tamper double layer** : la modification Smali sera détectée via le CRC natif.

> **Notre stratégie :** Patcher `showDialog()` **et** forcer `tampered` à rester à `0`, OU patcher la condition de comparaison CRC dans `verifyLibs()`.

### Chargement de la Bibliothèque Native

```java
static {
    System.loadLibrary("foo");  // ← Chargement de libfoo.so
}
```

La bibliothèque `libfoo.so` contient toute la logique de protection native que nous devrons analyser dans Ghidra.

---

## 🛠️ Bypass Java via Smali

### Qu'est-ce que le Smali ?

Le **Smali** est le langage d'assemblage du bytecode Dalvik. Quand `apktool` décompile un APK, il convertit le fichier `.dex` en fichiers `.smali` lisibles et modifiables. On peut ensuite modifier ces fichiers et recompiler l'APK pour obtenir un binaire modifié.

### Étape 1 – Décompiler l'APK avec apktool

```bash
apktool d UnCrackable-Level3.apk -o UnCrackable3_decompiled
```

Cette commande génère la structure suivante :

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

```smali
.method private showDialog(Ljava/lang/String;)V
```

**Code Smali AVANT le patch :**

```smali
.method private showDialog(Ljava/lang/String;)V
    .locals 3
    .param p1, "str"    # Ljava/lang/String;

    .line 34
    new-instance v0, Landroid/app/AlertDialog$Builder;

    invoke-direct {v0, p0}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;)V

    .line 35
    invoke-virtual {v0, p1}, Landroid/app/AlertDialog$Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    .line 36
    const-string v1, "This is unacceptable. The app is now going to exit."

    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setMessage(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    .line 37
    const/4 v1, -0x3

    new-instance v2, Lsg/vantagepoint/uncrackable3/MainActivity$2;

    invoke-direct {v2, p0}, Lsg/vantagepoint/uncrackable3/MainActivity$2;-><init>(Lsg/vantagepoint/uncrackable3/MainActivity;)V

    invoke-virtual {v0, v1, v2}, Landroid/app/AlertDialog$Builder;->setButton(ILjava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)V

    .line 44
    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/app/AlertDialog$Builder;->setCancelable(Z)V

    .line 45
    invoke-virtual {v0}, Landroid/app/AlertDialog$Builder;->show()Landroid/app/AlertDialog;

    .line 46
    return-void
.end method
```

> **Figure 5 – Code Smali de showDialog() AVANT patch**

![Figure 5 - Smali avant patch](screenshots/smali_before.png)

### Étape 4 – Appliquer le Patch

On remplace **tout le corps** de la méthode par un simple `return-void` :

**Code Smali APRÈS le patch :**

```smali
.method private showDialog(Ljava/lang/String;)V
    .locals 0

    return-void
.end method
```

> **Figure 6 – Code Smali de showDialog() APRÈS patch**

![Figure 6 - Smali après patch](screenshots/smali_after.png)

**Pourquoi ce patch fonctionne-t-il ?**

En remplaçant tout le corps de `showDialog()` par `return-void`, on fait en sorte que chaque appel à cette méthode **retourne immédiatement sans effet**. L'AlertDialog ne sera jamais créé, et `System.exit(0)` ne sera jamais appelé. L'application continue son exécution normalement.

> **Note :** On patchera également la vérification CRC dans `verifyLibs()` pour neutraliser le flag `tampered`, ou on s'assurera que la condition `tampered != 0` dans `onCreate()` appelle toujours `showDialog()` — que l'on vient de neutraliser.

---

##  Rebuild et Signature de l'APK

### Étape 1 – Recompiler avec apktool

```bash
apktool b UnCrackable3_decompiled -o UnCrackable3_patched.apk
```

En cas de succès :

```
I: Using Apktool 2.9.x
I: Checking whether sources has changed...
I: Smaling smali folder into classes.dex...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk into: UnCrackable3_patched.apk
```

> **Figure 7 – Build réussi de l'APK patché**

![Figure 7 - Build APK](screenshots/apktool_build.png)

### Étape 2 – Générer un Keystore de Signature

Android exige que tout APK soit signé pour pouvoir être installé :

```bash
keytool -genkey -v -keystore my-release-key.jks \
        -alias alias_name \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000
```

On peut utiliser des valeurs arbitraires pour les informations du certificat (CN, O, L, etc.).

### Étape 3 – Signer l'APK

```bash
apksigner sign --ks my-release-key.jks \
               --ks-key-alias alias_name \
               --out UnCrackable3_signed.apk \
               UnCrackable3_patched.apk
```

### Étape 4 – Installer et Lancer l'APK Signé

```bash
# Désinstaller l'ancienne version
adb uninstall owasp.mstg.uncrackable3

# Installer la version patchée
adb install UnCrackable3_signed.apk

# Lancer l'application
adb shell am start -n owasp.mstg.uncrackable3/.MainActivity
```

> **Figure 8 – Application lancée sans popup de root detection**

![Figure 8 - App lancée](screenshots/app_launched.png)

L'application se lance désormais sans afficher le dialogue de détection de root. Le bypass Java est **opérationnel**.

---

##  Analyse Native avec Ghidra

### Contexte

Malgré le bypass Java, l'application dispose d'une seconde ligne de défense implémentée en code natif (C/C++) dans la bibliothèque partagée `libfoo.so`. Ce code est compilé en bytecode ARM et ne peut pas être lu directement — il nécessite l'utilisation d'un désassembleur/décompilateur natif comme **Ghidra**.

### Extraction de libfoo.so

On extrait la bibliothèque depuis l'APK (qui est en réalité une archive ZIP) :

```bash
# Méthode 1 : via adb après installation
adb pull /data/app/owasp.mstg.uncrackable3-1/lib/x86/libfoo.so .

# Méthode 2 : dézipper l'APK
unzip UnCrackable-Level3.apk lib/x86/libfoo.so
```

### Ouverture dans Ghidra

1. Lancer Ghidra
2. Créer un nouveau projet : `File > New Project`
3. Importer le fichier : `File > Import File > libfoo.so`
4. Sélectionner le format **ELF** et l'architecture **x86** (ou ARM selon l'APK)
5. Lancer l'auto-analyse : `Analysis > Auto Analyze`
6. Attendre la fin de l'analyse (processus pouvant durer plusieurs minutes)

### Identification des Fonctions Critiques

Dans le **Symbol Tree** de Ghidra, on identifie les fonctions exportées (JNI) et les fonctions internes. Parmi les fonctions non exportées, deux retiennent notre attention :

| Adresse | Nom (auto-généré) | Rôle suspecté |
|---------|-------------------|---------------|
| `0x001037c0` | `FUN_001037c0` | Détection Anti-Frida/Debug |
| `0x001012c0` | `FUN_001012c0` | Validation du secret / XOR |

### Analyse de FUN_001037c0 – La Fonction Anti-Debug

En décompilant `FUN_001037c0`, Ghidra révèle le code pseudo-C suivant :

```c
void FUN_001037c0(void)
{
    FILE *fp;
    char line[512];
    char *result;
    
    while (1) {  // ← Boucle infinie : elle tourne dans un thread séparé
        sleep(5);
        
        fp = fopen("/proc/self/maps", "r");  // ← Lecture des mappings mémoire du processus
        
        if (fp != NULL) {
            while (fgets(line, 512, fp) != NULL) {
                // Cherche les signatures de Frida dans les bibliothèques chargées
                result = strstr(line, "frida");
                if (result != NULL) {
                    goodbye();   // ← Fermeture immédiate si Frida détecté
                }
                result = strstr(line, "xposed");
                if (result != NULL) {
                    goodbye();
                }
            }
            fclose(fp);
        }
    }
    return;
}
```

**Analyse du mécanisme :**

Le fichier `/proc/self/maps` est un fichier virtuel Linux exposant la **carte mémoire virtuelle** du processus courant. Frida injecte ses agents sous forme de bibliothèques partagées (`frida-agent-64.so`, etc.) qui apparaissent dans ce fichier. En scannant régulièrement ce fichier, l'application peut détecter toute tentative d'instrumentation dynamique.

La fonction tourne dans un **thread en arrière-plan** (lancé depuis la fonction `init()`), ce qui signifie qu'elle surveille en permanence la mémoire, même après le démarrage de l'activité principale.

**Voilà pourquoi Frida est bloqué sur cette application.**

> **Figure 9 – Code de FUN_001037c0 dans Ghidra (avant patch)**

![Figure 9 - Ghidra anti-debug avant](screenshots/ghidra_antidebug_before.png)

---

##  Bypass Natif – Patch Binaire

### Objectif

Neutraliser la fonction `FUN_001037c0` pour qu'elle se termine immédiatement sans effectuer ses vérifications anti-debug/anti-Frida.

### Stratégie de Patch

La méthode la plus propre consiste à **remplacer les premiers octets de la fonction** par une instruction de retour immédiat (`RET` sur x86, ou `BX LR` sur ARM).

**Architecture cible x86 :**

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

#### 2. Patcher via l'éditeur d'octets

Dans Ghidra :
1. `Window > Bytes` pour ouvrir la vue hexadécimale
2. Naviguer vers l'offset de `FUN_001037c0`
3. Activer le mode édition : `Edit > Enable Disassembler`
4. Remplacer l'octet `0x55` (PUSH EBP) par `0xC3` (RET)

Alternatively, via l'interface Ghidra :
- Clic droit sur l'instruction > `Patch Instruction`
- Remplacer par `RET`

#### 3. Exporter le binaire patché

```
File > Export Program > ELF
```

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

> **Figure 10 – Code de FUN_001037c0 dans Ghidra APRÈS patch**

![Figure 10 - Ghidra après patch](screenshots/ghidra_antidebug_after.png)

### Réintégration du Binaire Patché dans l'APK

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

En continuant l'analyse de `libfoo.so` dans Ghidra, on examine la fonction `FUN_001012c0`. Cette fonction est appelée lors de la validation de la chaîne saisie par l'utilisateur. Son décompilé révèle un tableau de valeurs encodées :

```c
void FUN_001012c0(long *param_1)
{
    // Initialisation d'un buffer caché avec des données encodées
    param_1[0] = 0x1549170f1311081d;
    param_1[1] = 0x15131d5a1903000d;
    param_1[2] = 0x14130817005a0e08;
    
    // ... (logique de comparaison / XOR)
}
```

> **Figure 11 – Fonction FUN_001012c0 dans Ghidra avec le buffer encodé**

![Figure 11 - Buffer secret Ghidra](screenshots/ghidra_secret_buffer.png)

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

Cette clé est passée à la fonction native `init()` :

```java
init(xorkey.getBytes());
```

La fonction native utilise cette clé pour encoder/décoder le secret via une opération XOR symétrique. Puisque XOR est une opération réversible (`a XOR b XOR b = a`), nous pouvons retrouver le plaintext en appliquant le même XOR.

**Vérification de la cohérence :**
- Secret encodé : `24 octets`
- Clé XOR : `"pizzapizzapizzapizzapizza"` → `25 caractères ASCII` → on utilisera les 24 premiers

### Script de Décryptage Python

```python
#!/usr/bin/env python3
"""
OWASP UnCrackable Level 3 – Décryptage XOR
Auteur : [Votre nom]
"""

# Secret encodé extrait de libfoo.so (après conversion little endian)
encoded_hex = "1d0811130f1749150d0003195a1d1315080e5a0017081314"
encoded = bytes.fromhex(encoded_hex)

# Clé XOR identifiée dans MainActivity.java
xor_key = b"pizzapizzapizzapizzapizza"

# Opération XOR byte par byte
secret = bytes(a ^ b for a, b in zip(encoded, xor_key))

print(f"[*] Octets encodés  : {encoded.hex()}")
print(f"[*] Clé XOR         : {xor_key.decode()}")
print(f"[*] Secret décodé   : {secret.decode('utf-8')}")
```

### Exécution et Résultat

```bash
python3 decrypt_xor.py
```

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

```
making owasp great again
```

On appuie sur le bouton **VERIFY**.

> **Figure 12 – Saisie du secret dans l'application**

![Figure 12 - Saisie secret](screenshots/app_input_secret.png)

### Message de Succès

L'application affiche un message de confirmation, prouvant que le secret est correct :

> **Figure 13 – Message de succès affiché par l'application**

![Figure 13 - Succès](screenshots/app_success.png)

Le challenge est **résolu avec succès** ✅

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
| ✅ Analyse Java | Décompilation | JADX | Identification du XOR key et de showDialog() |
| ✅ Bypass Java | Patch Smali | apktool | Neutralisation de la root detection |
| ✅ Signature | Re-signing | apksigner | APK réinstallable et fonctionnel |
| ✅ Analyse native | Décompilation ARM | Ghidra | Identification de la détection anti-Frida |
| ✅ Bypass natif | Patch binaire | Ghidra | Neutralisation de FUN_001037c0 |
| ✅ Extraction | Analyse statique | Ghidra | Buffer encodé de 24 octets extrait |
| ✅ Conversion | Little Endian | Manuel/Python | Octets correctement réordonnés |
| ✅ Décryptage | XOR | Python | Secret `making owasp great again` obtenu |
| ✅ Validation | Test app | adb | Message de succès affiché |

### Points Clés à Retenir

1. **Le bypass Java** consiste à modifier le bytecode Smali pour court-circuiter les vérifications
2. **Le bypass natif** nécessite un patch binaire direct dans le code ARM compilé
3. **La convention Little Endian** est cruciale pour interpréter correctement les données extraites
4. **Le XOR est symétrique** : connaître la clé suffit à décrypter (et à chiffrer)
5. **Aucune protection client-side n'est inviolable** face à un attaquant motivé disposant des bons outils

### Perspectives

Pour aller plus loin dans la sécurisation des applications Android, les équipes de développement devraient considérer :
- L'intégration de **SafetyNet / Play Integrity API** pour une détection de root côté serveur
- L'utilisation de **R8/ProGuard** avec des règles d'obfuscation agressives
- L'implémentation de **certificate pinning** pour sécuriser les communications réseau
- Le recours à des solutions de **RASP** (Runtime Application Self-Protection) commerciales

---

## 📎 Ressources

- [OWASP MASTG – Mobile Application Security Testing Guide](https://mas.owasp.org/)
- [OWASP UnCrackable Apps Repository](https://github.com/OWASP/owasp-mastg/tree/master/Crackmes)
- [Ghidra – NSA Reverse Engineering Tool](https://ghidra-sre.org/)
- [JADX – Dex to Java Decompiler](https://github.com/skylot/jadx)
- [apktool – Android APK Tool](https://apktool.org/)
- [Frida – Dynamic Instrumentation Toolkit](https://frida.re/)

---

<div align="center">

**Réalisé dans le cadre d'un projet académique de cybersécurité mobile**  
*OWASP UnCrackable App Level 3 – Reverse Engineering Challenge*

</div>
