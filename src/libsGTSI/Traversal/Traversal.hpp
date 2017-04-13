#ifndef TRAVERSAL_HPP
#define TRAVERSAL_HPP

#include <tuple>
#include <set>
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


enum TypeMotParcours {
  TYPE_M1,
  TYPE_M2
};

class MotParcours {
public:
  MotParcours* duplicate();
  
  TypeMotParcours type;
  bool has_symbol;
  vsize_t i;
  bool alpha_is_R;
  bool children_are_wildcards;
  uint8_t k;
  MotParcours();
  string toString();
  bool matchesSymbol(node_t * n, bool);
  bool matchesCF(node_t * n);
  bool matchesC(node_t * n);
  bool matchesF(node_t * n);
  bool equals(MotParcours * m, bool checkLabels);
  bool sameSymbol(MotParcours * m, bool);
  bool sameRepeatAndCF(MotParcours * m);
  
  NodeInfo* info;
  CondNode* condition;
};

CondNode* computeCond(node_t* n);

typedef std::map < string, std::list < node_t * >*> Match;
typedef std::list <Match*> MatchList;
typedef std::map < std::string, MatchList*> PatternsMatches;


Match* clone_match(Match* m);

class Parcours {
public:
  bool complete;
  vsize_t size;
  MotParcours **mots;
  string name;
  bool need_postprocessing;
  
  Parcours();
  string toString();
  void addMot(MotParcours * m);
//   std::list<Parcours *> postprocessParcours();
  typedef std::pair < bool, Match*> RetourParcoursDepuisSommet;
  RetourParcoursDepuisSommet parcourirDepuisSommet(graph_t *, vsize_t root, vsize_t W, bool checkLabels, bool printFound, bool printAllMatches);
  std::pair <bool, node_t*> parcoursUnmatchedNode(bool checkLabels, bool returnFound, MotParcours* m, node_t* node, node_t* current_node, set < node_t * >* matched_nodes, std::pair < node_t *, node_t * >*numbers, vsize_t max_numbered, Match* found_nodes, bool printAllMatches);
  typedef std::pair < vsize_t, MatchList*> RetourParcours;
  RetourParcours parcourir(graph_t * gr, vsize_t W, bool checkLabels, bool countAllMatches, bool getId, bool printAllMatches);
  bool equals(Parcours *, bool checkLabels);
  void freeParcours(bool free_mots);
};

void freeMatch(std::map < string, std::list < node_t * >*>*);
void freeRetourParcoursDepuisSommet(Parcours::RetourParcoursDepuisSommet rt, bool getid);
void freePatternsMatches(PatternsMatches* patterns_matches, bool freeMatches);

typedef std::tuple < node_t *, uint8_t, node_t * >TupleQueue;

vsize_t parcoursProfondeurRec(Parcours *p, bool has_father, vsize_t father_number, node_t * s, bool i_wildcard, vsize_t i, set < node_t * >* explored, std::map <node_t*, vsize_t>* node_ids, vsize_t W);
Parcours* parcoursProfondeur(graph_t * graph, vsize_t vroot, vsize_t W);
Parcours *parcoursLargeur(graph_t * graph, vsize_t root, vsize_t W);
Parcours* parcoursGen(graph_t * graph, vsize_t root, vsize_t W);

std::set < Parcours * >parcoursFromGraph(graph_t *, vsize_t, bool);

class ParcoursNode {
public:
  vsize_t id;
  bool feuille;
  MotParcours *mot;
  std::list < ParcoursNode * >fils;
  string name;
  
  ParcoursNode();
  ParcoursNode(std::list < ParcoursNode * >fils, MotParcours * mot, uint64_t id);
  bool addGraphFromNode(graph_t* gr, node_t* r, vsize_t W, bool checkLabels);
  bool addParcours(Parcours * p, vsize_t index, bool checkLabels);
  void saveParcoursNodeToDot(string path);
  string toDotPartiel();
  string toDot();
  string toString();

  typedef std::pair < vsize_t, PatternsMatches*> RetourParcourir;
  RetourParcourir parcourir(graph_t * gr, vsize_t W, bool checkLabels, bool returnFound, bool printAllMatches);
  PatternsMatches* parcourirDepuisSommetRec(bool racine, graph_t * gr, node_t * r, std::pair < node_t *, node_t * >*numeros, vsize_t max_numeros, std::set < node_t * > matched_nodes, bool checkLabels, Match* current_match, bool returnFound, bool printAllMatches);
  PatternsMatches* parcourirDepuisSommet(graph_t *, vsize_t r, vsize_t W, bool checkLabels, bool printFound, bool printAllMatches);
  typedef std::tuple < bool, node_t *, std::pair < node_t *, node_t * >*, vsize_t, set < node_t * >>RetourEtape;
  std::tuple <bool, node_t*, set < node_t * >> etapeUnmatchedNode(bool checkLabels, bool returnFound, MotParcours* m, node_t* node, node_t* current_node, set < node_t * > matched_nodes, std::pair < node_t *, node_t * >*numbers, vsize_t max_numbered, Match*, bool printAllMatches);
  RetourEtape etape(MotParcours* m, node_t* s, graph_t* gr, std::pair< node_t*, node_t* >* numbers, vsize_t max_numbered, std::set< node_t* > matched_nodes, bool checkLabels, Match* current_match, bool returnFound, bool printAllMatches);
  vsize_t countLeaves();
  vsize_t countFinal();
  void freeParcoursNode();
  void merge_patternsmatches(PatternsMatches* leaves_to_matches, PatternsMatches* leaves_to_matches_rec);
};


#endif
