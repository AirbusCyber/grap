#ifndef TRAVERSAL_CPP
#define TRAVERSAL_CPP

#include "Traversal.hpp"

MotParcours::MotParcours() {

}

string MotParcours::toString() {
  string s = "";

  if (this->type == TYPE_M1) {
    if (this->version == 2) {
      s += "(";
    }

    s += "1: ";
    if (this->version == 2) {
      if (this->csymbtype != LABEL_STAR) {
        s += this->csymb;
        s += "(";
        s += string(csymbtypeToString(this->csymbtype));
        s += ")";
      }
      else {
        s += string(csymbtypeToString(this->csymbtype));
      }

    }
    else {
      char *desc = labCharToString(this->symbol);
      s += string(desc);
    }
  }
  else if (this->type == TYPE_M2) {
    s += "-";
    if (this->alpha_is_R) {
      s += "R> ";
    }
    else {
      s += i2s(this->k);
      s += "> ";
    }

    if (this->version == 2) {
      s += "(";
    }
    s += i2s(this->i);
    if (this->has_symbol) {
      if (this->version == 2) {
        s += ": ";
        if (this->csymbtype != LABEL_STAR) {
          s += this->csymb;
          s += "(";
          s += string(csymbtypeToString(this->csymbtype));
          s += ")";
        }
        else {
          s += string(csymbtypeToString(this->csymbtype));
        }
      }
      else {
        s += ": ";
        char *desc = labCharToString(this->symbol);
        s += string(desc);
      }
    }
  }
  else {
    s += "ERR";
    printf("ERROR in MotParcours::toString.\n");
  }

  if (this->version == 2) {
    s += ")";
    if (this->minRepeat == 1 and not this->hasMaxRepeat) {
      s += "+";
    }
    else if (this->minRepeat == 0 and not this->hasMaxRepeat) {
      s += "*";
    }
    else {
      s += "{" + i2s(this->minRepeat) + ",";
      if (this->hasMaxRepeat) {
        s += i2s(this->maxRepeat);
      }
      s += "}";
    }
    if (this->hasMaxChildrenNumber or this->hasMaxFathersNumber or this->minChildrenNumber != 0 or this->minFathersNumber != 0) {
      s += "_";
      bool one = false;
      if (this->minChildrenNumber > 0) {
        s += "mc=" + i2s(this->minChildrenNumber);
        one = true;
      }
      if (this->hasMaxChildrenNumber) {
        if (one)
          s += ",";
        s += "mc=" + i2s(this->maxChildrenNumber);
        one = true;
      }
      if (this->minFathersNumber > 0) {
        if (one)
          s += ",";
        s += "mf=" + i2s(this->minFathersNumber);
        one = true;
      }
      if (this->hasMaxFathersNumber) {
        if (one)
          s += ",";
        s += "mc=" + i2s(this->hasMaxFathersNumber);
        one = true;
      }
    }
  }

  return s;
}

void MotParcours::addV2Info(node_t * n) {
  if (n != NULL and n->version == 2) {
    this->version = 2;
    this->csymbtype = n->csymbType;
    this->csymb = n->csymb;
    this->minChildrenNumber = n->minChildrenNumber;
    this->minFathersNumber = n->minFathersNumber;
    this->minRepeat = n->minRepeat;

    if (n->hasMaxChildrenNumber) {
      this->hasMaxChildrenNumber = true;
      this->maxChildrenNumber = n->maxChildrenNumber;
    }
    else {
      this->hasMaxChildrenNumber = false;
    }

    if (n->hasMaxFathersNumber) {
      this->hasMaxFathersNumber = true;
      this->maxFathersNumber = n->maxFathersNumber;
    }
    else {
      this->hasMaxFathersNumber = false;
    }

    if (n->hasMaxRepeat) {
      this->hasMaxRepeat = true;
      this->maxRepeat = n->maxRepeat;
    }
    else {
      this->hasMaxRepeat = false;
    }

    if (n->get) {
      this->get = true;
      this->getid = std::string(n->getid);
    }
    else {
      this->get = false;
    }
  }
  else {
    this->version = 1;
    this->get = false;
  }
}

bool MotParcours::sameSymbol(MotParcours * m, bool checkLabels) {
  if (not checkLabels)
    return true;

  if (this->version != m->version)
    return false;

  if (this->version == 2) {
    return (this->csymbtype == m->csymbtype)
      and(this->csymb == m->csymb);
  }
  else {
    return this->symbol == m->symbol;
  }
}

bool MotParcours::sameRepeatAndCF(MotParcours * m) {
  if (this->version != m->version)
    return false;

  bool r = (this->minRepeat == m->minRepeat)
    and(this->hasMaxRepeat == m->hasMaxRepeat)
    and((not this->hasMaxRepeat) or this->maxRepeat == m->maxRepeat)
    and(this->minChildrenNumber == m->minChildrenNumber)
    and(this->hasMaxChildrenNumber == m->hasMaxChildrenNumber)
    and((not this->hasMaxChildrenNumber) or this->maxChildrenNumber == m->maxChildrenNumber)
    and(this->hasMaxFathersNumber == m->hasMaxFathersNumber)
    and((not this->hasMaxFathersNumber) or this->maxFathersNumber == m->maxFathersNumber);

  return r;
}

bool MotParcours::equals(MotParcours * m, bool checkLabels) {
  if (this->version != m->version)
    return false;

//   printf("type: %d %d\n", this->type, m->type);
  if (this->type == m->type) {
//     printf("type passed\n");
    if (this->type == TYPE_M1) {
      return this->symbol == m->symbol and(this->version != 2 or this->sameRepeatAndCF(m));
    }
    else {
      if (this->alpha_is_R == m->alpha_is_R) {
        if (this->alpha_is_R) {
          return (this->i == m->i)
            and(this->has_symbol == m->has_symbol)
            and((not this->has_symbol) or this->sameSymbol(m, checkLabels))
            and(this->version != 2 or this->sameRepeatAndCF(m));
        }
        else {
          return (this->k == m->k)
            and(this->i == m->i)
            and(this->has_symbol == m->has_symbol)
            and((not this->has_symbol) or this->sameSymbol(m, checkLabels))
            and(this->version != 2 or this->sameRepeatAndCF(m));
        }
      }
      else {
        return false;
      }
    }
  }
  printf("type not passed\n");
  return false;
}

Parcours::Parcours() {
  this->mots = NULL;
  this->size = 0;
}

bool Parcours::equals(Parcours * p, bool checkLabels) {
  if (this->size != p->size) return false;

  vsize_t n;
  for (n = 0; n < this->size; n++) {
    if (not this->mots[n]->equals(p->mots[n], checkLabels)) return false;
  }

  return true;
}


string Parcours::toString() {
  int i;
  string s = "";
  for (i = 0; i < this->size; i++) {
    s += this->mots[i]->toString();
    s += " ";
  }
  return s;
}


void Parcours::addMot(MotParcours * m) {
  this->mots = (MotParcours **) realloc(this->mots, (this->size + 1) * sizeof(MotParcours *));
  this->mots[this->size] = m;
  this->size++;
  assert(m->type == TYPE_M1 or m->type == TYPE_M2);
}

Parcours *parcoursLargeur(graph_t * graph, vsize_t vroot, vsize_t W) {
  //WARNING : after calling this function, the ->list_id fields for nodes in inputGraph are changed
  //TODO: change that !!!
  Parcours *p = new Parcours();

  //all inputgraph nodes to unexplored(0):
  node_list_t *listI = &(graph->nodes);

  node_t *nI;

  bool p_is_epsilon = true;
  vsize_t s = 0;
  nI = node_list_item(listI, vroot);
  node_t* original_root = nI;

  assert(nI != NULL);

  nI->list_id = (vsize_t) 1;

  std::queue < TupleQueue > queue3;
  queue3.push(std::make_tuple((node_t *) NULL, (vsize_t) 0, nI));
  s++;
  int a = 0;
  node_t *child;
  TupleQueue tq;
  node_t *pere;
  node_t *ss;
  uint8_t k;
  node_t *sc = 0;
  MotParcours *m;
  size_t i = 1;
  size_t k2;
  node_t *f;

  unordered_set < node_t * >explored;

  while (not queue3.empty()) {
    tq = queue3.front();
    pere = std::get < 0 > (tq);
    k = std::get < 1 > (tq);
    ss = std::get < 2 > (tq);

    unordered_set < node_t * >::iterator it = explored.find(ss);
    if ((it != explored.end()or i < W + 1) and sc != pere and not p_is_epsilon) {
      m = new MotParcours();
      m->type = TYPE_M2;
      m->alpha_is_R = true;
      m->has_symbol = false;
      m->i = pere->list_id;
      m->addV2Info(ss);
      p->addMot(m);

      sc = pere;
    }

    if (it == explored.end()and i < W + 1) {
      if (p_is_epsilon) {
        m = new MotParcours();
        m->type = TYPE_M1;
        m->has_symbol = true;
        m->symbol = ss->symb;
        m->addV2Info(ss);
        p->addMot(m);
        p_is_epsilon = false;
      }
      else {
        m = new MotParcours();
        m->type = TYPE_M2;
        m->alpha_is_R = false;
        m->i = i;
        m->k = k;
        m->has_symbol = true;
        m->symbol = ss->symb;
        m->addV2Info(ss);
        p->addMot(m);
      }

      ss->list_id = i;
      i++;
      sc = ss;

      assert(ss->children_nb <= 2);
      for (k2 = 0; k2 < ss->children_nb; k2++) {
        f = ss->children[k2];
        queue3.push(std::make_tuple(ss, k2, f));
      }

      explored.insert(ss);
    }
    else if (it != explored.end()) {
      m = new MotParcours();
      m->type = TYPE_M2;
      m->alpha_is_R = false;
      m->i = ss->list_id;
      m->k = k;
      m->has_symbol = false;
      m->addV2Info(ss);
      p->addMot(m);
      sc = ss;
    }
    queue3.pop();
  }

  if (i == W + 1) {
    p->complete = true;
  }
  else {
    p->complete = false;
  }
  
  original_root->list_id = vroot;
  return p;
}

bool MotParcours::matchesSymbol(node_t * n, bool checkLabels) {
  if (not checkLabels)
    return true;

  if (this->version == 2) {
    if (this->csymbtype == LABEL_STAR)
      return true;

    string n_symb_str;
    if (n->version == 2) {
      n_symb_str = string(n->csymb);
    }
    else {
      n_symb_str = string(symbToString(n->symb));
    }

    if (this->csymbtype == LABEL_EXACT_STRING) {
      return n_symb_str == this->csymb;
    }
    else if (this->csymbtype == LABEL_REGEX or this->csymbtype == LABEL_SUBSTRING or this->csymbtype == LABEL_EXACT_OPCODE or this->csymbtype == LABEL_GENERIC_OPCODE) {
      std::regex e(".*" + this->csymb + ".*");
//       std::cmatch cm;           // same as std::match_results<const char*> cm;
      bool ret = std::regex_match(n_symb_str, e, std::regex_constants::match_default);
//       std::cout << "string literal with " << cm.size() << " matches\n";
//       std::cout << string(this->csymb) << " / " << n_symb_str << ": " << ret << "\n";
      return ret;
    }
  }
  else {
    return this->symbol == n->symb;
  }
}

bool MotParcours::matchesCF(node_t * n) {
  if (this->version != 2)
    return false;

  return this->minChildrenNumber <= n->children_nb and this->minFathersNumber <= n->fathers_nb and((not this->hasMaxChildrenNumber) or n->children_nb <= this->maxChildrenNumber)
    and((not this->hasMaxFathersNumber) or n->fathers_nb <= this->maxFathersNumber);
}

Parcours::RetourParcoursDepuisSommet Parcours::parcourirDepuisSommet(graph_t * graph, vsize_t vroot, vsize_t W, bool checkLabels, bool printFound) {
//   cout << this->toString() << "\n";

  node_t *sc;
  node_list_t *listI = &(graph->nodes);
  node_t *nI;
  nI = node_list_item(listI, vroot);
  sc = nI;
  unordered_set < node_t * >numerotes;
  std::map < string, std::list < node_t * >*>*found_nodes = new std::map < string, std::list < node_t * >*>();

//   node_t **numeros = (node_t **) calloc(W, sizeof(node_t *));
  std::pair < node_t *, node_t * >*numeros = (std::pair < node_t *, node_t * >*)calloc(W, sizeof(std::pair < node_t *, node_t * >));
  vsize_t max_numeros = 0;

  if (this->size >= 1 and this->mots[0]->type == TYPE_M1 and this->mots[0]->matchesSymbol(nI, checkLabels) and(this->mots[0]->version != 2 or this->mots[0]->matchesCF(nI))) {
    numeros[max_numeros] = std::pair < node_t *, node_t * >(sc, NULL);
    max_numeros++;
    numerotes.insert(sc);

    if (printFound and this->mots[0]->get) {
      std::list < node_t * >*list_nodes_1 = new std::list < node_t * >();
      list_nodes_1->push_back(sc);
      found_nodes->insert(std::pair < string, std::list < node_t * >*>(this->mots[0]->getid, list_nodes_1));
    }
  }
  else {
    free(numeros);
    return RetourParcoursDepuisSommet(false, found_nodes);
  }
//   cout << "sc_begin: " << sc->csymb << "\n";

  size_t i;
  for (i = 1; i < this->size; i++) {
//     cout << "sc_in: " << sc->csymb << "\n";
    
    MotParcours *m = this->mots[i];
    if (m->alpha_is_R) {
      if (max_numeros >= m->i) {
        std::pair < node_t *, node_t * >p = numeros[m->i - 1];
        if (p.second == NULL)
          sc = p.first;
        else
          sc = p.second;
        
//         printf("R: %x\n", sc->node_id);
      }
      else {
        free(numeros);
        return RetourParcoursDepuisSommet(false, found_nodes);
      }
    }
    else {
      if (m->k < sc->children_nb) {
//         cout << m->toString() << "\n";
        node_t *f = sc->children[m->k];
        unordered_set < node_t * >::iterator it = numerotes.find(f);
        if (it == numerotes.end()) {
          // f n'est pas numéroté
          if (m->matchesSymbol(f, checkLabels) and(m->version != 2 or m->matchesCF(f)) and max_numeros < m->i) {
//             printf("%x: not numbered, found\n", f->address);
            vsize_t r = 1;
            numeros[max_numeros] = std::pair < node_t *, node_t * >(f, NULL);
            max_numeros++;
            numerotes.insert(f);
            sc = f;

            std::list < node_t * >*list_nodes = new std::list < node_t * >();
            if (printFound and m->get) {
              list_nodes->push_back((node_t *) sc);
            }

            if (m->version == 2 and(not m->hasMaxRepeat or m->maxRepeat > 1)) {
              while (true) {
                if ((not m->hasMaxRepeat or r < m->maxRepeat) and sc->children_nb == 1 and sc->children[0]->fathers_nb == 1 and m->matchesSymbol(sc->children[0], checkLabels) and m->matchesCF(sc->children[0])) {
//                   printf("%x !r\n", sc->address);
                  
                  unordered_set < node_t * >::iterator it = numerotes.find(sc->children[0]);
                  if (it != numerotes.end()) break;
                  
                  // le fils trouvé n'est pas numéroté
                  // s'il l'était déjà, on n'aurait pas itéré pas dessus
                  sc = sc->children[0];
                  r++;

                  if (printFound and m->get) list_nodes->push_back((node_t *) sc);
                }
                else {
//                   printf("%x not repeat\n", sc->address);
                  break;
                }
              }
              
              numeros[max_numeros - 1].second = sc;
            }

            if (printFound and m->get) found_nodes->insert(std::pair < string, std::list < node_t * >*>(m->getid, list_nodes));
            else delete list_nodes;
            
            // TODO: attention, on peut renvoyer false alors qu'on a "simplement" tenté de boucler dans la mauvaise branche
            // FIX: il faut nécessairement tenter les autres branches
            if (m->version == 2 and r < m->minRepeat) {
//               printf("%d < %d -> ret\n", r, m->minRepeat);
              free(numeros);
              return RetourParcoursDepuisSommet(false, found_nodes);
            }
          }
          else {
//             printf("%x: not numbered, not found\n", f->address);
            free(numeros);
            return RetourParcoursDepuisSommet(false, found_nodes);
          }
        }
        else if (not m->has_symbol) {
          // Verify that f is numbered m->i:
          if (max_numeros >= m->i) {
            std::pair < node_t *, node_t * >p = numeros[m->i - 1];
            
            if (p.first != f){
              free(numeros);
              return RetourParcoursDepuisSommet(false, found_nodes);
            }
            
            if (p.second == NULL) sc = p.first;
            else sc = p.second;
          }
          else{
              free(numeros);
              return RetourParcoursDepuisSommet(false, found_nodes);
          }
     
          
//           cout << "sc: " << sc->csymb << "\n" ;
        }
        else {
//           printf("has symbol ; sc: %x\n", sc->address);
          free(numeros);
          return RetourParcoursDepuisSommet(false, found_nodes);
        }
      }
      else {
//         printf("no child with this number\n");
        free(numeros);
        return RetourParcoursDepuisSommet(false, found_nodes);
      }
    }
    
//     cout << "sc_out: " << sc->csymb << "\n";
  }

  free(numeros);
  return RetourParcoursDepuisSommet(true, found_nodes);
}

void freeRetourParcoursDepuisSommet(Parcours::RetourParcoursDepuisSommet rt){
    // freeing found nodes
    std::map < string, std::list < node_t * >*>* found_nodes = rt.second;
    if (not found_nodes->empty()) {
      std::map < string, std::list < node_t * >*>::iterator it;

      for (it = found_nodes->begin(); it != found_nodes->end(); it++) {
        std::list < node_t * >* p_found_nodes = (*it).second;
        delete p_found_nodes;
      }
    }
    
    delete rt.second;
}

Parcours::RetourParcours Parcours::parcourir(graph_t * gr, vsize_t W, bool checkLabels, bool countAllMatches, bool printFound) {
  vsize_t n;
  vsize_t count = 0;
  std::unordered_set < std::map < string, std::list < node_t * >*>*>set_gotten;
  for (n = 0; n < gr->nodes.size; n++) {
    RetourParcoursDepuisSommet rt = this->parcourirDepuisSommet(gr, n, W, checkLabels, printFound);
    if (rt.first) {
      if (printFound and not rt.second->empty())
        set_gotten.insert(rt.second);
      if (not countAllMatches)
        return RetourParcours(1, set_gotten);
      else
        count++;
    }
    else{
      freeRetourParcoursDepuisSommet(rt);
    }    
  }
  return RetourParcours(count, set_gotten);
}

unordered_set < Parcours * >parcoursFromGraph(graph_t * gr, vsize_t W, bool checkLabels) {
  unordered_set < Parcours * >parcours;
  Parcours *p;
  vsize_t n;

  for (n = 0; n < gr->nodes.size; n++) {
    p = parcoursLargeur(gr, n, W);

    if (p->complete) {
      // check if duplicate:
      unordered_set < Parcours * >::iterator it;
      bool new_p = true;
      for (it = parcours.begin(); it != parcours.end(); it++) {
        Parcours *p2 = *it;
        if (p->equals(p2, checkLabels)) {
          new_p = false;
          break;
        }
      }
      if (new_p)
        parcours.insert(p);
    }
  }

  return parcours;
}

ParcoursNode::ParcoursNode() {
  this->id = 0;
  this->feuille = false;
}

ParcoursNode::ParcoursNode(std::list < ParcoursNode * >fils, MotParcours * mot, uint64_t id) {
  this->fils = fils;
  this->mot = mot;
  this->id = id;
}

bool ParcoursNode::addGraphFromNode(graph_t * gr, node_t * r, vsize_t W, bool checkLabels) {
  Parcours *p = parcoursLargeur(gr, r->list_id, W);
  return this->addParcours(p, 0, checkLabels);
}

vsize_t ParcoursNode::addGraph(graph_t * gr, vsize_t W, vsize_t maxLearn, bool checkLabels) {
  Parcours *p;
  vsize_t n;
  vsize_t added = 0;

  for (n = 0; n < gr->nodes.size; n++) {
    if (maxLearn == 0 || added < maxLearn) {
      p = parcoursLargeur(gr, n, W);

//       if (p->size > 1){
//       std::cout << p->toString() + "\n";
//       }

      if (p->complete) {
        if (this->addParcours(p, 0, checkLabels)) {
          std::cout << p->toString() + "\n";
          added++;
        }
      }
    }
    else {
      break;
    }
  }
  
  delete p;
  return added;
}

string ParcoursNode::toString() {
  string s;
  s += this->mot->toString();
  list < ParcoursNode * >::iterator it;
  for (it = this->fils.begin(); it != this->fils.end(); it++) {
    s += "fils:";
    s += (*it)->toString();
  }
  return s;
}

string ParcoursNode::toDotPartiel() {
  string s;
  s += "\"";
  s += i2s(this->id);
  if (not this->feuille)
    s += "\" [label=\"";
  else
    s += "\" [label=\"F ";
  s += h2s(this->id);
  s += "\"]\n";
  list < ParcoursNode * >::iterator it;
  for (it = this->fils.begin(); it != this->fils.end(); it++) {
    ParcoursNode *f = (*it);
    s += "\"";
    s += i2s(this->id);
    s += "\" -> \"";
    s += i2s(f->id);
    s += "\" [label=\"";
    s += f->mot->toString();
    s += "\"]\n";
    s += f->toDotPartiel();
  }
  return s;
}

string ParcoursNode::toDot() {
  string s = "digraph G {\n";
  s += this->toDotPartiel();
  s += "\n}";
  return s;
}

void ParcoursNode::saveParcoursNodeToDot(string path) {
  ofstream ofs(path);
  string str = this->toDot();
  ofs << str;
  ofs.close();
}

bool ParcoursNode::addParcours(Parcours * p, int index, bool checkLabels) {
  if (index >= p->size) {
    bool b = this->feuille;
    this->feuille = true;
    return not b;
  }
  MotParcours *m = p->mots[index];
  list < ParcoursNode * >::iterator it;
  for (it = this->fils.begin(); it != this->fils.end(); it++) {
    ParcoursNode *f = (*it);
    if (f->mot->equals(m, checkLabels)) {
      return f->addParcours(p, index + 1, checkLabels);
    }
  }

  ParcoursNode *pn = new ParcoursNode();
  pn->mot = m;
  pn->id = (uint64_t) pn;

  this->fils.push_back(pn);
  return pn->addParcours(p, index + 1, checkLabels);
}

vsize_t ParcoursNode::parcourir(graph_t * gr, vsize_t W, bool checkLabels, bool countAllMatches) {
  vsize_t count = 0;
  vsize_t n;
  std::set < vsize_t > leaves;
  for (n = 0; n < gr->nodes.size; n++) {
    list < vsize_t > ret = this->parcourirDepuisSommet(gr, n, W, checkLabels);
    list < vsize_t >::iterator it = ret.begin();

    for (it = ret.begin(); it != ret.end(); it++) {
      vsize_t id = *it;
      if (get < 1 > (leaves.insert(id)) or countAllMatches) {
//         printf("possible from node: %d ; leave: %d\n", n, id);
        count++;
      }
    }
  }
  return count;
}

list < vsize_t > ParcoursNode::parcourirDepuisSommet(graph_t * gr, vsize_t v, vsize_t W, bool checkLabels) {
  unordered_set < node_t * >numerotes;
  node_t *r = node_list_item(&gr->nodes, v);

//   node_t **numeros = (node_t **) calloc(W, sizeof(node_t *));
  std::pair < node_t *, node_t * >*numeros = (std::pair < node_t *, node_t * >*)calloc(W, sizeof(std::pair < node_t *, node_t * >));
  vsize_t max_numeros = 0;
  list < vsize_t > l = this->parcourirDepuisSommetRec(true, gr, r, W, numeros, max_numeros, numerotes, checkLabels);
  free(numeros);
  return l;
}


list < vsize_t > ParcoursNode::parcourirDepuisSommetRec(bool racine, graph_t * gr, node_t * r, vsize_t W, std::pair < node_t *, node_t * >*numeros, vsize_t max_numeros, unordered_set < node_t * >numerotes, bool checkLabels) {
  list < vsize_t > l;

  if (this->feuille) {
    l.push_back(this->id);
  }

  assert(this->feuille or racine or not this->fils.empty());

  list < ParcoursNode * >::iterator it;
  for (it = this->fils.begin(); it != this->fils.end(); it++) {
    ParcoursNode *f = (*it);
//     printf("trying to match %s\n", f->mot->toString().c_str());
    RetourEtape ret = etape(f->mot, r, gr, numeros, max_numeros, numerotes, checkLabels);
    bool possible = get < 0 > (ret);
//     printf("%d\n", possible);
    node_t *node = get < 1 > (ret);
    numeros = get < 2 > (ret);
    vsize_t max_numeros_r = get < 3 > (ret);
    unordered_set < node_t * >numerotes_r = get < 4 > (ret);

    if (possible) {
      list < vsize_t > l2 = f->parcourirDepuisSommetRec(false, gr, node, W, numeros, max_numeros_r, numerotes_r, checkLabels);
      l.splice(l.begin(), l2);
    }
  }
  return l;
}

ParcoursNode::RetourEtape ParcoursNode::etape(MotParcours * m, node_t * s, graph_t * gr, std::pair < node_t *, node_t * >*numeros, vsize_t max_numeros, unordered_set < node_t * >numerotes, bool checkLabels) {
  if (m->type == TYPE_M1) {
    if (m->matchesSymbol(s, checkLabels) and(m->version != 2 or m->matchesCF(s))) {

      assert(max_numeros == 0);

      numeros[max_numeros] = std::pair < node_t *, node_t * >(s, NULL);
      max_numeros++;
      numerotes.insert(s);
      return std::make_tuple(true, s, numeros, max_numeros, numerotes);
    }
    else {
      return std::make_tuple(false, s, numeros, max_numeros, numerotes);
    }
  }
  else if (m->type == TYPE_M2) {
    if (m->alpha_is_R) {
      if (max_numeros >= m->i) {
        std::pair < node_t *, node_t * >p = numeros[m->i - 1];
        if (p.second == NULL)
          s = p.first;
        else
          s = p.second;

        return std::make_tuple(true, s, numeros, max_numeros, numerotes);
      }
      else {
        return std::make_tuple(false, s, numeros, max_numeros, numerotes);
      }
    }
    else {
      if (m->k < s->children_nb) {
        node_t *f = s->children[m->k];
        unordered_set < node_t * >::iterator it = numerotes.find(f);
        if (it == numerotes.end()) {
          // f n'est pas numéroté
          if ((m->matchesSymbol(f, checkLabels) and(m->version != 2 or m->matchesCF(f)) and max_numeros < m->i)) {

            assert(max_numeros == m->i - 1);

            node_t *last_s = s;
            vsize_t last_max_numeros = max_numeros;
            vsize_t r = 1;
            numeros[max_numeros] = std::pair < node_t *, node_t * >(f, NULL);
            max_numeros++;
            s = f;

            if (m->version == 2 and(not m->hasMaxRepeat or m->maxRepeat > 1)) {
              while (true) {
                if ((not m->hasMaxRepeat or r < m->maxRepeat) and s->children_nb == 1 and s->children[0]->fathers_nb == 1 and m->matchesSymbol(s->children[0], checkLabels) and m->matchesCF(s->children[0])) {
                  s = s->children[0];
                  r++;
                }
                else {
                  break;
                }
              }

              numeros[max_numeros - 1].second = s;
            

              if (r < m->minRepeat) {
                // pas trouvé, TODO: attention au branchement
                return std::make_tuple(false, last_s, numeros, last_max_numeros, numerotes);
              }
            }
            
            numerotes.insert(f);
            return std::make_tuple(true, f, numeros, max_numeros, numerotes);
          }
          else {
            return std::make_tuple(false, s, numeros, max_numeros, numerotes);
          }
        }
        else if (not m->has_symbol) {
          return std::make_tuple(true, f, numeros, max_numeros, numerotes);
        }
        else {
          return std::make_tuple(false, s, numeros, max_numeros, numerotes);
        }
      }
      else {
        return std::make_tuple(false, s, numeros, max_numeros, numerotes);
      }
    }
  }
  else {
    printf("ERR: UNKNOWN TYPE.\n");
    return std::make_tuple(false, s, numeros, max_numeros, numerotes);
  }
}


vsize_t ParcoursNode::countLeaves() {
  if (this->fils.empty()) {
    return 1;
  }
  else {
    vsize_t somme = 0;
    list < ParcoursNode * >::iterator it;
    for (it = this->fils.begin(); it != this->fils.end(); it++) {
      ParcoursNode *f = (*it);
      somme += f->countLeaves();
    }
    return somme;
  }
}

vsize_t ParcoursNode::countFinal() {
  vsize_t count = 0;
  if (this->feuille) {
    count++;
  }

  list < ParcoursNode * >::iterator it;
  for (it = this->fils.begin(); it != this->fils.end(); it++) {
    ParcoursNode *f = (*it);
    count += f->countFinal();
  }
  return count;
}

#endif
