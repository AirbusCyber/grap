Deux composants sont nécessaires : le désassembleur et l'analyse de graphes

Désassembleur:
cf PandaPE

Compiler la partie graphes sous Linux:
cd graphes/
cmake -DCMAKE_BUILD_TYPE=Release .
make

Sous Windows (avec Visual Studio installé):
Il est nécessaire de générer les fichiers du parseur (Lexer.cpp, Lexer.h, Parser.cpp et Parser.h) avec flex et bison (sous Linux par exemple), puis, dans le dossier graphes/:
cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release .
nmake


Utilisation du script grap:
./grap motif.dot prg.exe
./grap motif.dot prg.exe -v
./grap motif.dot prg.exe -q

Utilisation de graphes/GTSI-grap directement:
./GTSI-grap --help
./GTSI-grap motif.dot prg.dot
./GTSI-grap motif.dot prg.dot -ncl
./GTSI-grap motif.dot prg.dot -q


# Binding

Pour créer le binding python il est nécessaire d'ajouter l'option suivante dans `cmake`.

```
cmake -DPYTHON_BINDING=1
```

Pour installer celui-ci, il suffit d'exécuter la commande ci-après.

```
make install
```

# Tools

Pour créer les outils il faut ajouter l'option ci-après à `cmake`.

```
cmake -DTOOLS=1
```


# Compilation Windows

## MinGW

Pour compiler le projet `grap` et son binding python, il faut suivre les
instructions suivantes.  Tout d'abord, il est nécessaire d'installer Mingw
(https://sourceforge.net/projects/mingw/files/latest/download?source=files). Une
fois installé, il faut ouvrir le gestionnaire de paquets (`guimain.exe`) qui se
situe dans `C:\MinGW\libexec\mingw-get\` et installer les outils suivants.

```
mingw-developer-toolkit
mingw32-base
mingw32-gcc-g++
msys-base
msys-system-builder
```

Puis, il faudra supprimer le paquet `msys-gcc` qui est obsolète. Pour permettre
l'accès aux binaires de MinGW, il faut ajouter le lien `C:\MinGW\bin` dans le
`Path`. Les variables d'environnements sous Windows 7 se situent dans
`Start> (click droit sur computer) Properties> Advanced system settings> (onglet
Advanced) Environment Variables`. Il ne reste plus qu'à créer une variable
utilisateur du nom de `Path` avec comme valeur `C:\MinGW\bin`.


## Flex + Bison

MinGW possède une version de flex et bison. Cependant, ces outils sont
obsolètes. Pour remédier à ceci, il faut récupérer une version plus récente sur
le site https://sourceforge.net/projects/winflexbison/. Une fois le document
décompressé, il est nécessaire de renommer les deux fichiers `win_bison` et
`win_flex` en `bison` et `flex`. Enfin il faudra copier les deux binaires avec
le dossier `data` dans `C:\MinGW\msys\1.0\bin`.

## SWIG

L'installation de SWIG se passe en deux étapes qui sont les suivantes:
- compilation
- installation

Pour télécharger le code source de SWIG il faut se rendre à l'adresse suivante
https://sourceforge.net/projects/swig/files/swigwin/swigwin-3.0.8/swigwin-3.0.8.zip/download?use_mirror=tenet. Puis,
il faut décompresser l'archive dans le dossier `C:\MinGW\msys\1.0\home\[USER]\`
et exécuter le script `bat` qui se situe dans le dossier msys
(`C:\MinGW\msys\1.0\msys.bat`). Enfin, il faudra exécuter les commandes ci-après.

```
cd swigwin-x.x.x
./autogen.sh
./configure --without-pcre
make
make install
```
## Boost

Pour compiler le projet `grap` il est nécessaire d'avoir les librairies
Boost. Pour les obtenir, il faut télécharger les binaires 32-bit à l'adresse
suivante
https://sourceforge.net/projects/boost/files/boost-binaries/1.61.0/boost_1_61_0-msvc-14.0-32.exe/download
. Une fois installé, il faut se rendre dans `C:\Program Files\boost_x_xx_x` et
renommer le dossier `lib32-xxxxx` en `lib`.

## Grap

Maintenant que toutes les dépendances sont installées, il ne reste plus qu'à
installer `grap`. Pour cela il faut ouvrir une console msys, se mettre dans le
dossier `grap` et exécuter les commandes suivantes.

```
cmake . -G "MSYS Makefiles" -DPYTHON_BINDING=1
make
make install
```