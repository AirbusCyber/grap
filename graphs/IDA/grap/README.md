README
------


# Ajout d'un module

Le plug-in IDAgrap permet d'étendre les algorithmes détectés.

## Hiérarchie

La hiérarchie des modules est la suivante:

- Dans le dossier `patterns`, il y a deux grands groupes qui sont la
**cryptographie** et la **compression**.

- Dans ces groupes (ex. cryptographie), il est possible de trouver les
différents types de cette catégorie. Par exemple, pour le groupe
**cryptographie**, il y aura les types suivants **block** (pour *block cipher*),
**hash**, **mode** (pour *mode of operation*) et **stream** (pour *stream
cipher*). L'implémentation dans le plug-in fait qu'il est possible de rajouter
d'autres types.
   
- Dans chaque type, il y a des dossiers qui représentent les modules
(algorithmes). Par exemple, dans le cas des *stream cipher*, il y a le module
**RC4**.

- Chaque module peut posséder un ou plusieurs *patterns* situés dans des
  dossiers qui représentent des fonctions. Par exemple, pour le chiffrement par
  flot **RC4**, il pourrait y avoir un *patterns* `RC4_set_key` qui détecterait
  la fonction d'initialisation de la clé. Puis, il serait possible d'ajouter un
  deuxième *patterns* qui permettrait de détecter la fonction de chiffrement
  (ex. `RC4_encrypt`).

- Chaque *patterns* possède une liste de *pattern*. Ces motifs sont les motifs
  au format *DOT* qui peuvent être détectés dans le binaire à l'aide de la
  librairie **grap**. 

Ci-dessous l'arborescence du dossier `patterns`:

```
.
├── compression
│   ├── __init__.py
│   └── ModulesCompression.py
├── cryptography
│   ├── block
│   │   ├── __init__.py
│   │   └── ModulesCryptoBlock.py
│   ├── hash
│   │   ├── __init__.py
│   │   └── ModulesCryptoHash.py
│   ├── __init__.py
│   ├── mode
│   │   ├── __init__.py
│   │   └── ModulesCryptoMode.py
│   ├── ModulesCrypto.py
│   └── stream
│       ├── __init__.py
│       ├── ModulesCryptoStream.py
│       └── rc4
│           ├── __init__.py
│           ├── RC4.py
│           └── set_key
│               ├── __init__.py
│               ├── loop1.dot
│               ├── loop2.dot
│               └── RC4SetKey.py
├── __init__.py
└── Modules.py


```

## Intégration d'algorithmes

### Questions

Maintenant que la hiérarchie a été présentée, il va être possible d'attaquer
l'intégration d'un algorithme. Pour créer un bon module de détection, il faut
répondre aux questions suivantes:

- Dans quel groupe/type se trouve mon algorithme ? Par exemple pour **RC4**
  ce sera le groupe de cryptographie (**cryptography**) et son type est un
  chiffrement par flot (**stream**). Une fois que le groupe et le type ont été
  identifiés, il faut se rendre dans le dossier correspondant, c-à-d
  `./cryptography/stream`.

- Quel est le nom de mon algorithme ? Pour notre chiffrement par flot c'est
  **RC4**. Dans ce cas, il faut créer un dossier au nom du chiffrement
  (ex. `rc4`) et s'y rendre.

- Puis, il faut déterminer les fonctions que l'on veut détecter. Par exemple,
  pour **RC4** ça peut-être la fonction d'initialisation et de
  chiffrement/déchiffrement. Dans ce cas, il faudra créer des dossiers
  représentant la fonction (ex. `rc4_set_key` ou `set_key`, `RC4_encrypt`, ...).
  
Une fois la hiérarchie du module créée à l'aide des questions précédentes, il
est possible de passer à l'intégration.

### Intégration

Les modules de IDAgrap sont très simples et reposent sur un système de
listes/dictionnaires et d'objets à renseigner. La liste principale porte le nom de
`MODULES` et elle est déclarée dans le fichier `patterns/Modules.py`. Son objectif
est de déclarer tous les groupes, voir ci-dessous:

```python
from .compression.ModulesCompression import COMPRESSION
from .cryptography.ModulesCrypto import CRYPTO

MODULES = {
    "Crypto": CRYPTO,
    "Compression": COMPRESSION,
}
```

Dans ce dictionnaire les clés sont les noms des groupes et les valeurs les
dictionnaires vers les types. Les noms des clés sont déclarés dans le fichier
`idagrap/modules/Module.py`. Les dictionnaires `CRYPTO` et `COMPRESSION` son
déclarés dans le leur dossier respectif. Par exemple, pour la cryptographie le
dictionnaire `CRYPTO` est déclaré dans `patterns/cryptography/ModulesCrypto.py`,
voir ci-après.

```python
from .block.ModulesCryptoBlock import CRYPTO_BLOCK
from .hash.ModulesCryptoHash import CRYPTO_HASH
from .mode.ModulesCryptoMode import CRYPTO_MODE
from .stream.ModulesCryptoStream import CRYPTO_STREAM

CRYPTO = {
    "Stream": CRYPTO_STREAM,
    "Block": CRYPTO_BLOCK,
    "Mode": CRYPTO_MODE,
    "Hash": CRYPTO_HASH,
}
```

Comme pour les groupes, le dictionnaire des types est représenté par des clés
qui sont les noms des types (déclarés dans `idagrap/modules/Module.py`) et les
valeurs qui sont des *tuples* contenant la liste des différents algorithmes. Ces
listes sont déclarées dans les sous-dossiers dédiés au type de chiffrement. Dans
le cas des chiffrements par flot, `CRYPTO_STREAM` se trouve dans
`patterns/cryptography/stream/ModulesCryptoStream.py`. Ci-dessous le contenu de
ce fichier.

```python
from .rc4.RC4 import CRYPTO_STREAM_RC4

# Tuple of stream ciphers
CRYPTO_STREAM = (
    CRYPTO_STREAM_RC4,
)
```

Les fichiers des types sont extrêmement importants, car c'est dans ces documents
qu'il faudra ajouter le nouvel algorithme. Comme il est possible de le constater
plus haut, l'algorithme *RC4* a été ajouté à la liste des chiffrements par
flot. Si vous décidez d'ajouter votre algorithme de chiffrement par flot c'est
dans le *tuple* `CRYPTO_STREAM` qu'il faudra l'ajouter. Le types des objets ajoutés dans
les listes de types dépendent de ceux-ci. Par exemple, pour le type **stream** la
classe utilisée sera `ModuleCryptoStream`, pour les **block** ce sera
`ModuleCryptoBlock`, etc. Tous les modules descendent de la même classe
`Module`. 

Par convention les algorithmes sont mis dans des dossiers portant leur nom en
minuscule. Donc, pour **RC4** ce sera `patterns/cryptography/stream/rc4`. Ce
dossier contient le coeur de l'algorithme, comme le montre le code de `RC4.py`.

```python
from idagrap.modules.Module import ModuleCryptoStream

from .set_key.RC4SetKey import RC4_SET_KEY

CRYPTO_STREAM_RC4 = ModuleCryptoStream(
    patterns=[RC4_SET_KEY],
    name="RC4",
    author=["Jonathan Thieuleux"],
    description="RC4 Stream Cipher."
)
```

Tous les modules possèdent les mêmes arguments qui sont les suivants:

- **pattern**: Cette liste contient tous les `Patterns`(fonctions) de
  l'algorithme.
- **name**: Le nom de l'algorithme.
- **author**: Une liste des auteurs.
- **description**: Une description du module.

Une fois l'objet créé avec tous ces champs de remplis, il faut déclarer les
motifs. Là aussi, par convention les *patterns* sont mis dans des dossiers à
leur nom. Par exemple, si les motifs vont chercher l'initialisation de la clé de
l'algorithme **RC4**, alors il serait judicieux de créer un dossier ayant un nom
tel que `rc4_set_key` ou `set_key`. Dans la mesure du possible, il est conseillé
de mettre un nom de fonction connu. Pour l'algorithme **RC4** le nom de
l'initialisation de la clé a été inspirée de la librairie cryptographique
**libressl**.


Enfin, la dernière étape est d'initialiser ces `Patterns`. Ci-dessous la
déclaration des motifs de `RC4_set_key` (voir
`idagrap/patterns/cryptography/stream/rc4/set_key/RC4SetKey.py`).

```python

from os.path import abspath, dirname

from idagrap.modules.Pattern import Pattern, Patterns

# Definitions---------------------------------------------------------------
ROOT = dirname(abspath(__file__))

#
# Pattern
#

# RC4 set key first loop
loop1 = Pattern(f=ROOT + "/loop1.dot",
                name="First Loop",
                description="First Initialization loop of RC4 set_key.",
                min_pattern=1,
                max_pattern=1)

# RC4 set key second loop
loop2 = Pattern(f=ROOT + "/loop2.dot",
                name="Second Loop",
                description="Second Initialization loop of RC4 set_key.",
                min_pattern=1,
                max_pattern=1)


RC4_SET_KEY = Patterns(
    patterns=[
        loop1,
        loop2
    ],
    threshold=1.0,
    name="RC4 Set_Key()",
    description="Initialization function of the RC4 algorithm."
)

```

Ce fichier renseigne plusieurs choses. Tout d'abord, il y a l'objet `Patterns`. 
Cet élément permet d'apporter des informations sur les motifs à rechercher. Tous
les `Patterns` possèdent les arguments suivants:

- **patterns**: Liste de `Pattern` à détecter dans la fonction.
- **threshold**: Seuil limite au-dessus duquel la fonction est considérée comme
  détectée. Par exemple, si une fonction possède 4 motifs et qu'elle a mis un
  seuil de 0.75 alors si le plug-in détecte 3 motifs sur 4 elle considérera
  que ces trois motifs sont suffisants pour considérer la fonction comme
  détectée. Ce seuil varie entre 0.0 et 1.0.
- **name**: Nom de la fonction.
- **description**: Description de cette fonction.

Ensuite, il y a les deux objets de type `Pattern`, qui sont utilisés par
**RC4_SET_KEY**. Cette classe contient les informations sur le motif voulant
être détecté. Les arguments de cette classe sont les suivants:

- **f**: Lien absolu vers le motif *DOT* qui va être analysé par **grap**. 
- **name**: Nom du motif.
- **description**: Une description de ce motif.
- **min_pattern** (optionnel): Le minimum de motifs autorisés à être détectés
  dans la même fonction (valeur par défaut: 1).
- **max_pattern** (optionnel): Le maximum de motifs autorisés à être détectés
  dans la même fonction (valeur par défaut: 1).

Donc, dans le cas de l'ajout d'un nouvel algorithme, il sera nécessaire de
renseigner tous ces champs.
