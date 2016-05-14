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
#include "utils-gtsi.hpp"
#include <fstream>
#include <assert.h>
#include <regex>
using namespace std;

#include "graph.hpp"
#include "nodeIO.hpp"
#include "node_info.hpp"


extern char *labCharToString(vsize_t label);

enum TypeMotParcours {
  TYPE_M1,
  TYPE_M2
};

class MotParcours {
public:
  TypeMotParcours type;
  bool has_symbol;
  vsize_t i;
  bool alpha_is_R;
  uint8_t k;
  MotParcours();
  string toString();
  bool matchesSymbol(node_t * n, bool);
  bool matchesCF(node_t * n);
  bool equals(MotParcours * m, bool checkLabels);
  bool sameSymbol(MotParcours * m, bool);
  bool sameRepeatAndCF(MotParcours * m);
  
  NodeInfo* info;
  CondNode* condition;
};

CondNode* computeCond(node_t* n);

class Parcours {
public:
  bool complete;
  vsize_t size;
  MotParcours **mots;
  Parcours();
  string toString();
  void addMot(MotParcours * m);
  typedef std::pair < bool, std::map < string, std::list < node_t * >*>*>RetourParcoursDepuisSommet;
  RetourParcoursDepuisSommet parcourirDepuisSommet(graph_t *, vsize_t root, vsize_t W, bool checkLabels, bool printFound);
  typedef std::pair < vsize_t, std::unordered_set < std::map < string, std::list < node_t * >*>*>*>RetourParcours;
  RetourParcours parcourir(graph_t * gr, vsize_t W, bool checkLabels, bool countAllMatches, bool getId);
  bool equals(Parcours *, bool checkLabels);
};

void freeMapGotten(std::map < string, std::list < node_t * >*>*);
void freeRetourParcoursDepuisSommet(Parcours::RetourParcoursDepuisSommet rt);

typedef std::tuple < node_t *, uint8_t, node_t * >TupleQueue;
Parcours *parcoursLargeur(graph_t * graph, vsize_t root, vsize_t W);
std::unordered_set < Parcours * >parcoursFromGraph(graph_t *, vsize_t, bool);

// TODO: implémenter la remontée des id (getid) des solutions
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
  bool addParcours(Parcours * p, vsize_t index, bool checkLabels);
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
