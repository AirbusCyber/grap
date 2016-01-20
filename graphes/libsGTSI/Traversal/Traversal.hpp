#ifndef TRAVERSAL_HPP
#define TRAVERSAL_HPP


#include <tuple>
#include <unordered_set>
#include <set>
#include <map>
#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <forward_list>
#include <queue>
#include "utils-gtsi.h"
#include <fstream>
#include <assert.h>
#include <regex>
using namespace std;

extern "C" {
#include "symbol.h"
#include "graph.h"
#include "nodeIO.h"
} extern char *labCharToString(vsize_t label);

enum TypeMotParcours {
  TYPE_M1,
  TYPE_M2
};

class MotParcours {
public:
  int version;                  // 1: original; 2: enhanced
  char type;
  bool has_symbol;
  symb_t symbol;
  int i;
  bool alpha_is_R;
  int k;
  MotParcours();
  string toString();
  bool matchesSymbol(node_t * n, bool);
  bool matchesCF(node_t * n);
  bool equals(MotParcours * m, bool checkLabels);
  bool sameSymbol(MotParcours * m, bool);
  bool sameRepeatAndCF(MotParcours * m);
  void addV2Info(node_t * n);

  // for version 2:
  label_t csymbtype;
  string csymb;
//   repeat_t repeat;
  uint8_t minChildrenNumber;
  bool hasMaxChildrenNumber;
  uint8_t maxChildrenNumber;
  uint8_t minFathersNumber;
  bool hasMaxFathersNumber;
  uint8_t maxFathersNumber;
  vsize_t minRepeat;
  bool hasMaxRepeat;
  vsize_t maxRepeat;

  bool get;
  string getid;
};

class Parcours {
public:
  bool complete;
  int version;                  // 1: original; 2: enhanced
  int size;
  MotParcours **mots;
  Parcours();
  string toString();
  void addMot(MotParcours * m);
  typedef std::pair < bool, std::map < string, std::list < node_t * >*>*>RetourParcoursDepuisSommet;
  RetourParcoursDepuisSommet parcourirDepuisSommet(graph_t *, vsize_t root, vsize_t W, bool checkLabels, bool printFound);
  typedef std::pair < vsize_t, std::unordered_set < std::map < string, std::list < node_t * >*>*>>RetourParcours;
  RetourParcours parcourir(graph_t * gr, vsize_t W, bool checkLabels, bool countAllMatches, bool printFound);
  bool equals(Parcours *, bool checkLabels);
};

void freeRetourParcoursDepuisSommet(Parcours::RetourParcoursDepuisSommet rt);

typedef std::tuple < node_t *, uint8_t, node_t * >TupleQueue;
Parcours *parcoursLargeur(graph_t * graph, vsize_t root, vsize_t W);
Parcours *newParcours();
std::unordered_set < Parcours * >parcoursFromGraph(graph_t *, vsize_t, bool);

class ParcoursNode {
public:
  uint64_t id;
  bool feuille;
  MotParcours *mot;
  std::list < ParcoursNode * >fils;
  ParcoursNode();
  ParcoursNode(std::list < ParcoursNode * >fils, MotParcours * mot, uint64_t id);
  bool addGraphFromNode(graph_t *, node_t *, vsize_t W, bool checkLabels);
  vsize_t addGraph(graph_t *, vsize_t W, vsize_t maxLearn, bool checkLabels);
  bool addParcours(Parcours * p, int index, bool checkLabels);
  void saveParcoursNodeToDot(string path);
  string toDotPartiel();
  string toDot();
  string toString();
  vsize_t parcourir(graph_t * gr, vsize_t W, bool checkLabels, bool countAllMatches);
  typedef std::tuple < bool, vsize_t > RetourParcourir;
  list < vsize_t > parcourirDepuisSommetRec(bool racine, graph_t * gr, node_t * r, vsize_t W, std::pair < node_t *, node_t * >*numeros, vsize_t max_numeros, std::unordered_set < node_t * >numerotes, bool checkLabels);
  list < vsize_t > parcourirDepuisSommet(graph_t *, vsize_t r, vsize_t W, bool checkLabels);
  typedef std::tuple < bool, node_t *, std::pair < node_t *, node_t * >*, vsize_t, unordered_set < node_t * >>RetourEtape;
  RetourEtape etape(MotParcours * m, node_t *, graph_t *, std::pair < node_t *, node_t * >*, vsize_t, unordered_set < node_t * >, bool);
  vsize_t countLeaves();
  vsize_t countFinal();
};


#endif
