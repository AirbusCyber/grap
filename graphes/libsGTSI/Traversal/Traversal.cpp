#ifndef TRAVERSAL_CPP
#define TRAVERSAL_CPP

#include "Traversal.hpp"

MotParcours::MotParcours() {

}

string MotParcours::toString() {
  string s = "";

  if (this->type == TYPE_M1) {
      s += "(";

    s += "1: ";
    s += this->info->inst_str;
  }
  else if (this->type == TYPE_M2) {
    s += "-";
    if (this->alpha_is_R) {
      s += "R> ";
      s += std::to_string(this->i);
    }
    else {
      s += i2s(this->k);
      s += "> ";
    }

    if (this->has_symbol){
      s += "(";
      s += i2s(this->i);
      s += ": ";
      s += this->info->inst_str;
      s += ")";
    }
  }
  else {
    printf("ERROR in MotParcours::toString.\n");
    return "ERR";
  }
  
  if (this->has_symbol){
    if (this->info->minRepeat == 1 and not this->info->has_maxRepeat) {
      s += "+";
    }
    else if (this->info->minRepeat == 0 and not this->info->has_maxRepeat) {
      s += "*";
    }
    else {
      s += "{" + i2s(this->info->minRepeat) + ",";
      if (this->info->has_maxRepeat) {
        s += i2s(this->info->maxRepeat);
      }
      s += "}";
    }
    
    if (this->info->has_maxChildrenNumber or this->info->has_maxFathersNumber or this->info->minChildrenNumber != 0 or this->info->minFathersNumber != 0) {
      s += "_";
      bool one = false;
      if (this->info->minChildrenNumber > 0) {
        s += "mc=" + i2s(this->info->minChildrenNumber);
        one = true;
      }
      if (this->info->has_maxChildrenNumber) {
        if (one)
          s += ",";
        s += "mc=" + i2s(this->info->maxChildrenNumber);
        one = true;
      }
      if (this->info->minFathersNumber > 0) {
        if (one)
          s += ",";
        s += "mf=" + i2s(this->info->minFathersNumber);
        one = true;
      }
      if (this->info->has_maxFathersNumber) {
        if (one)
          s += ",";
        s += "mc=" + i2s(this->info->has_maxFathersNumber);
        one = true;
      }
    }

    s += "?(" + this->condition->toString() + ")";
  }
  
  return s;
}

bool MotParcours::sameSymbol(MotParcours * m, bool checkLabels) {
//   std::cout << this->info->toString() << " VS \n" << m->info->toString() << " : " << (this->info->equals(m->info)) << "\n";
  
  // TODO: etre plus malin avec les comparaisons (ne prendre que les champs de condition en compte dans la comparaison des infos ?)
  return (not checkLabels) or (this->info->equals(m->info) and this->condition->equals(m->condition));
}

bool MotParcours::sameRepeatAndCF(MotParcours * m) {
  bool r = (this->info->minRepeat == m->info->minRepeat)
    and(this->info->has_maxRepeat == m->info->has_maxRepeat)
    and((not this->info->has_maxRepeat) or this->info->maxRepeat == m->info->maxRepeat)
    and(this->info->minChildrenNumber == m->info->minChildrenNumber)
    and(this->info->has_maxChildrenNumber == m->info->has_maxChildrenNumber)
    and((not this->info->has_maxChildrenNumber) or this->info->maxChildrenNumber == m->info->maxChildrenNumber)
    and(this->info->has_maxFathersNumber == m->info->has_maxFathersNumber)
    and((not this->info->has_maxFathersNumber) or this->info->maxFathersNumber == m->info->maxFathersNumber);

  return r;
}

bool MotParcours::equals(MotParcours * m, bool checkLabels) {
  if (this->type == m->type) {
    if (this->type == TYPE_M1) {
      return this->sameSymbol(m, checkLabels) and this->sameRepeatAndCF(m);
    }
    else {
      if (this->alpha_is_R == m->alpha_is_R) {
        if (this->alpha_is_R) {
          return this->i == m->i and this->sameSymbol(m, checkLabels) and this->sameRepeatAndCF(m);
        }
        else {
          return this->k == m->k and this->i == m->i and this->sameSymbol(m, checkLabels) and this->sameRepeatAndCF(m);
        }
      }
      else {
        return false;
      }
    }
  }
  
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
  size_t i;
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
      m->info = ss->info;
      m->condition = ss->condition;
      p->addMot(m);

      sc = pere;
    }

    if (it == explored.end()and i < W + 1) {
      if (p_is_epsilon) {
        m = new MotParcours();
        m->type = TYPE_M1;
        m->has_symbol = true;
        m->info = ss->info;
        m->condition = ss->condition;
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
        m->info = ss->info;
        m->condition = ss->condition;
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
      m->info = ss->info;
      m->condition = ss->condition;
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
  
  return this->condition->evaluate(this->info, n->info);
}

bool MotParcours::matchesCF(node_t * n) {
  // TODO: use n->children_nb or n->info->childrenNumber ? Same with father ?
  return this->info->minChildrenNumber <= n->children_nb and this->info->minFathersNumber <= n->fathers_nb and((not this->info->has_maxChildrenNumber) or n->children_nb <= this->info->maxChildrenNumber)
    and((not this->info->has_maxFathersNumber) or n->fathers_nb <= this->info->maxFathersNumber);
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

  if (this->size >= 1 and this->mots[0]->type == TYPE_M1 and this->mots[0]->matchesSymbol(nI, checkLabels) and(this->mots[0]->matchesCF(nI))) {
//     cout << this->mots[0]->toString() << "\n";
    numeros[max_numeros] = std::pair < node_t *, node_t * >(sc, NULL);
    max_numeros++;
    numerotes.insert(sc);

    if (printFound and this->mots[0]->info->get) {
      std::list < node_t * >*list_nodes_1 = new std::list < node_t * >();
      list_nodes_1->push_back(sc);
      found_nodes->insert(std::pair < string, std::list < node_t * >*>(this->mots[0]->info->getid, list_nodes_1));
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
//     cout << m->toString() << "\n";
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
          if (m->matchesSymbol(f, checkLabels) and m->matchesCF(f) and max_numeros < m->i) {
//             printf("%x: not numbered, found\n", f->address);
            vsize_t r = 1;
            numeros[max_numeros] = std::pair < node_t *, node_t * >(f, NULL);
            max_numeros++;
            numerotes.insert(f);
            sc = f;

            std::list < node_t * >*list_nodes = new std::list < node_t * >();
            if (printFound and m->info->get) {
              list_nodes->push_back((node_t *) sc);
            }

            if (not m->info->has_maxRepeat or m->info->maxRepeat > 1) {
              while (true) {
                if ((not m->info->has_maxRepeat or r < m->info->maxRepeat) and sc->children_nb == 1 and sc->children[0]->fathers_nb == 1 and m->matchesSymbol(sc->children[0], checkLabels) and m->matchesCF(sc->children[0])) {
//                   printf("%x !r\n", sc->address);
                  
                  unordered_set < node_t * >::iterator it_find = numerotes.find(sc->children[0]);
                  if (it_find != numerotes.end()) break;
                  
                  // le fils trouvé n'est pas numéroté
                  // s'il l'était déjà, on n'aurait pas itéré pas dessus
                  sc = sc->children[0];
                  r++;

                  if (printFound and m->info->get) list_nodes->push_back((node_t *) sc);
                }
                else {
//                   printf("%x not repeat\n", sc->address);
                  break;
                }
              }
              
              numeros[max_numeros - 1].second = sc;
            }

            if (printFound and m->info->get) {
              found_nodes->insert(std::pair < string, std::list < node_t * >*>(m->info->getid, list_nodes));
            }
            else{
              delete list_nodes;
            }
            
            // TODO: attention, on peut renvoyer false alors qu'on a "simplement" tenté de boucler dans la mauvaise branche
            // FIX: il faut nécessairement tenter les autres branches
            if (r < m->info->minRepeat) {
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

ParcoursNode::ParcoursNode(std::list < ParcoursNode * >_fils, MotParcours * _mot, uint64_t _id) {
  this->fils = _fils;
  this->mot = _mot;
  this->id = _id;
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

bool ParcoursNode::addParcours(Parcours * p, vsize_t index, bool checkLabels) {
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
//       std::cout << "equals " << f->mot->toString() << "\n";
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
      vsize_t _id = *it;
      if (get < 1 > (leaves.insert(_id)) or countAllMatches) {
        node_t *r = node_list_item(&gr->nodes, n);
//         printf("possible from node: %s ; leaf: 0x%x\n", r->info->inst_str.c_str(), (int) _id);
        count++;
      }
    }
  }
  return count;
}

list < vsize_t > ParcoursNode::parcourirDepuisSommet(graph_t * gr, vsize_t v, vsize_t W, bool checkLabels) {
  unordered_set < node_t * >numerotes;
  node_t *r = node_list_item(&gr->nodes, v);

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

  // TODO: implement release_assert ?
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
    if (m->matchesSymbol(s, checkLabels) and m->matchesCF(s)) {

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
          if ((m->matchesSymbol(f, checkLabels) and m->matchesCF(f) and max_numeros < m->i)) {

            assert(max_numeros == m->i - 1);

            node_t *last_s = s;
            vsize_t last_max_numeros = max_numeros;
            vsize_t r = 1;
            numeros[max_numeros] = std::pair < node_t *, node_t * >(f, NULL);
            max_numeros++;
            s = f;

            if (not m->info->has_maxRepeat or m->info->maxRepeat > 1) {
              while (true) {
                if ((not m->info->has_maxRepeat or r < m->info->maxRepeat) and s->children_nb == 1 and s->children[0]->fathers_nb == 1 and m->matchesSymbol(s->children[0], checkLabels) and m->matchesCF(s->children[0])) {
                  unordered_set < node_t * >::iterator it_find = numerotes.find(s->children[0]);
                  if (it_find != numerotes.end()) break;
                  
                  s = s->children[0];
                  r++;
                }
                else {
                  break;
                }
              }

              numeros[max_numeros - 1].second = s;
            
              if (r < m->info->minRepeat) {
                // pas trouvé, TODO: attention au branchement
                return std::make_tuple(false, last_s, numeros, last_max_numeros, numerotes);
              }
            }
            
            numerotes.insert(f);
            return std::make_tuple(true, s, numeros, max_numeros, numerotes);
          }
          else {
            return std::make_tuple(false, s, numeros, max_numeros, numerotes);
          }
        }
        else if (not m->has_symbol) {
          // Verify that f is numbered m->i:
                      
          if (max_numeros >= m->i) {
            std::pair < node_t *, node_t * >p = numeros[m->i - 1];
            
            if (p.first != f){
              return std::make_tuple(false, f, numeros, max_numeros, numerotes);
            }
            
            if (p.second == NULL){
              s = p.first;
            }
            else{
              s = p.second;
            }
          }
          else{
              return std::make_tuple(false, f, numeros, max_numeros, numerotes);
          }
          
          return std::make_tuple(true, s, numeros, max_numeros, numerotes);
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
