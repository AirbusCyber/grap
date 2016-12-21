#ifndef TRAVERSAL_CPP
#define TRAVERSAL_CPP

#include "Traversal.hpp"

MotParcours::MotParcours() {

}

string MotParcours::toString() {
  string s = "";

  if (this->type == TYPE_M1) {
    s += "1:";
  }
  else if (this->type == TYPE_M2) {
    s += "-";
    if (this->alpha_is_R) {
      s += "R> ";
    }
    else {
      s += std::to_string((int) this->k);
      s += "> ";
    }
    
    s += std::to_string((int) this->i);
    if (this->has_symbol){
      s += ":";
    }
  }
  else {
    std::cerr << "ERROR in MotParcours::toString.\n";
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
      if (this->info->has_maxRepeat and this->info->minRepeat == this->info->maxRepeat){
        if (this->info->minRepeat != 1){
          s += "{" + std::to_string(this->info->minRepeat);
          s += "}";
        }
      }
      else{
        s += "{" + std::to_string(this->info->minRepeat) + ",";
        if (this->info->has_maxRepeat) {
          s += std::to_string(this->info->maxRepeat);
        }
        s += "}";
      }
    }
    
    if (this->info->has_maxChildrenNumber or this->info->has_maxFathersNumber or this->info->minChildrenNumber != 0 or this->info->minFathersNumber != 0) {
      s += "_";
      bool one = false;
      if (this->info->minChildrenNumber > 0) {
        s += "minc=" + std::to_string((int) this->info->minChildrenNumber);
        one = true;
      }
      if (this->info->has_maxChildrenNumber) {
        if (one)
          s += ",";
        s += "maxc=" + std::to_string((int) this->info->maxChildrenNumber);
        one = true;
      }
      if (this->info->minFathersNumber > 0) {
        if (one)
          s += ",";
        s += "minf=" + std::to_string((int) this->info->minFathersNumber);
        one = true;
      }
      if (this->info->has_maxFathersNumber) {
        if (one)
          s += ",";
        s += "maxf=" + std::to_string((int) this->info->maxFathersNumber);
        one = true;
      }
    }

    if (this->condition != NULL){
      s += "?" + this->condition->toString(this->info);
    }
  }
  
  return s;
}

bool MotParcours::sameSymbol(MotParcours *m, bool checkLabels)
{
  // TODO: etre plus malin avec les comparaisons (ne prendre que les champs de
  // condition en compte dans la comparaison des infos ?)
  return (not checkLabels) or (this->info->equals(m->info)
                              and this->condition->equals(m->condition));
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
          return this->i == m->i;
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
  this->mots = (MotParcours **) realloc_or_quit(this->mots, (this->size + 1) * sizeof(MotParcours *));
  this->mots[this->size] = m;
  this->size++;
  assert(m->type == TYPE_M1 or m->type == TYPE_M2);
}

CondNode* computeCond(node_t* n){
  if (not n->info->lazyRepeat or n->children_nb == 0){
    n->condition->add_pointer_usage();
    return n->condition;
  }
  else {
    // If lazy repeat, the condition of the first child should be excluded
    // TODO: there is no way to properly delete those "derived" conditions
    node_t* child;
    if (n->has_child1){
      child = n->child1;
    }
    else{
      RELEASE_ASSERT(n->has_child2);
      child = n->child2;
    }

    std::list<CondNode*>* not_child = new std::list<CondNode*>();
    not_child->push_front(child->condition);
    child->condition->add_pointer_usage();
    CondNode *cn_not = new CondNode(not_child, UnOpEnum::logic_not);
    cn_not->has_fixed_pattern_info = true;
    cn_not->fixed_pattern_info = child->info;

    if (n->condition->children->size() == 0
        and n->condition->comparison == bool_true) {
      // Case: The original condition is only "true"
      // Then the new one is "not(child->condition)"
      return cn_not;
    }
    else {
      // Otherwise the new condition is "n->condition and not
      // (child->condition)"
      std::list<CondNode *>* and_children = new std::list<CondNode *>();
      and_children->push_front(n->condition);
      n->condition->add_pointer_usage();
      and_children->push_front(cn_not);
      CondNode *cn = new CondNode(and_children, BinOpEnum::logic_and);
      return cn;
    }
  }
}

vsize_t parcoursProfondeurRec(Parcours *p, bool has_father, vsize_t father_number, node_t * s, vsize_t i, set < node_t * >* explored, std::map <node_t*, vsize_t>* node_ids) {
  set < node_t * >::iterator explored_search;
  std::map<node_t*, vsize_t>::iterator node_ids_search;
  vsize_t new_i;
  
  explored_search = explored->find(s);
  if (explored_search == explored->end()){
    // Case: s not yet explored
    // TODO: add mot parcours M1 or M2
    MotParcours* m;
    
    if (not has_father) {
        m = new MotParcours();
        m->type = TYPE_M1;
        m->alpha_is_R = false;
        m->has_symbol = true;
//         m->i = i;
        m->info = s->info;
        m->condition = computeCond(s);
        p->addMot(m);
      }
      else {
        m = new MotParcours();
        m->type = TYPE_M2;
        m->alpha_is_R = false;
        m->i = i;
        m->k = father_number;
        m->has_symbol = true;
        m->info = s->info;
        m->condition = computeCond(s);
        p->addMot(m);
      }
    
    explored->insert(s);
    node_ids->insert(std::pair<node_t *, vsize_t>(s, i));
    
    new_i = i + 1;
    
    if (s->has_child1){
      new_i = parcoursProfondeurRec(p, true, 0, s->child1, new_i, explored, node_ids);
    }
    
    if (s->has_child2){
      if (s->has_child1){
        // Make return mot
        m = new MotParcours();
        m->type = TYPE_M2;
        m->alpha_is_R = true;
        m->has_symbol = false;
        m->i = i;
        m->info = NULL;
        m->condition = NULL;
        p->addMot(m);
      }
      
      new_i = parcoursProfondeurRec(p, true, 1, s->child2, new_i, explored, node_ids);
    }
    
    return new_i;
  }
  else {
    // Case: node already explored
      MotParcours* m = new MotParcours();
      m->type = TYPE_M2;
      m->alpha_is_R = false;
      
      node_ids_search = node_ids->find(s);
      RELEASE_ASSERT(node_ids_search != node_ids->end());
      m->i = node_ids_search->second;
      
      m->k = father_number;
      m->has_symbol = false;
      m->info = s->info;
      m->condition = nullptr;
      p->addMot(m);
      
      return i;
  }
}

Parcours* parcoursGen(graph_t * graph, vsize_t vroot, vsize_t W){
  return parcoursProfondeur(graph, vroot, W);
}

Parcours* parcoursProfondeur(graph_t * graph, vsize_t vroot, vsize_t W){
  //TODO: limit size to W and fill complete accordingly
  
  Parcours *p = new Parcours();
  p->name = graph->name;
  set < node_t * >* explored = new std::set<node_t*>();
  std::map <node_t*, vsize_t>* node_ids = new std::map <node_t*, vsize_t>();
  
  parcoursProfondeurRec(p, false, 0, node_list_item(&(graph->nodes), vroot), 1, explored, node_ids);
  p->complete = true;
  
  delete explored;
  delete node_ids;
  return p;
}

Parcours *parcoursLargeur(graph_t * graph, vsize_t vroot, vsize_t W) {
  Parcours *p = new Parcours();
  p->name = graph->name;

  node_list_t *listI = &(graph->nodes);

  node_t *nI;

  bool p_is_epsilon = true;
  vsize_t s = 0;
  nI = node_list_item(listI, vroot);
  node_t* original_root = nI;
  
  std::map <node_t*, vsize_t> node_ids = std::map <node_t*, vsize_t>();
  std::map<node_t*, vsize_t>::iterator node_ids_search;
  node_ids.insert(std::pair<node_t*, vsize_t>(nI, 1));

  std::queue < TupleQueue > queue3;
  queue3.push(std::make_tuple((node_t *) NULL, (vsize_t) 0, nI));
  s++;
  int a = 0;
  TupleQueue tq;
  node_t *pere;
  node_t *ss;
  uint8_t k;
  node_t *sc = 0;
  MotParcours *m;
  size_t i = 1;
  size_t k2;
  node_t *f;

  set < node_t * >explored;

  while (not queue3.empty()) {
    tq = queue3.front();
    pere = std::get < 0 > (tq);
    k = std::get < 1 > (tq);
    ss = std::get < 2 > (tq);

    set < node_t * >::iterator it = explored.find(ss);
    if ((it != explored.end()or i < W + 1) and sc != pere and not p_is_epsilon) {
      m = new MotParcours();
      m->type = TYPE_M2;
      m->alpha_is_R = true;
      m->has_symbol = false;
      
      node_ids_search = node_ids.find(pere);
      RELEASE_ASSERT(node_ids_search != node_ids.end());
      m->i = node_ids_search->second;
      
      m->info = NULL;
      m->condition = NULL;
      p->addMot(m);

      sc = pere;
    }

    if (it == explored.end() and i < W + 1) {
      if (p_is_epsilon) {
        m = new MotParcours();
        m->type = TYPE_M1;
        m->has_symbol = true;
        m->info = ss->info;
        m->condition = computeCond(ss);
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
        m->condition = computeCond(ss);
        p->addMot(m);
      }

      node_ids.insert(std::pair<node_t *, vsize_t>(ss, i));
      i++;
      sc = ss;

      if (ss->has_child1){
        queue3.push(std::make_tuple(ss, 0, ss->child1));
      }
      if (ss->has_child2){
        queue3.push(std::make_tuple(ss, 1, ss->child2));
      }

      explored.insert(ss);
    }
    else if (it != explored.end()) {
      m = new MotParcours();
      m->type = TYPE_M2;
      m->alpha_is_R = false;
      
      node_ids_search = node_ids.find(ss);
      RELEASE_ASSERT(node_ids_search != node_ids.end());
      m->i = node_ids_search->second;
      
      m->k = k;
      m->has_symbol = false;
      m->info = ss->info;
      m->condition = nullptr;
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

  return p;
}

bool MotParcours::matchesSymbol(node_t * n, bool checkLabels) {
  if (not checkLabels)
    return true;
  
  return this->condition->evaluate(this->info, n->info);
}

bool MotParcours::matchesCF(node_t *n)
{
  // TODO: use n->children_nb or n->info->childrenNumber ? Same with father ?
  return this->info->minChildrenNumber <= n->children_nb and this->info->minFathersNumber <= n->fathers_nb and((not this->info->has_maxChildrenNumber) or n->children_nb <= this->info->maxChildrenNumber)
    and((not this->info->has_maxFathersNumber) or n->fathers_nb <= this->info->maxFathersNumber);
}

bool MotParcours::matchesC(node_t *n)
{
  // TODO: use n->children_nb or n->info->childrenNumber ? Same with father ?
  return this->info->minChildrenNumber <= n->children_nb and((not this->info->has_maxChildrenNumber) or n->children_nb <= this->info->maxChildrenNumber);
}

bool MotParcours::matchesF(node_t *n)
{
  // TODO: use n->children_nb or n->info->childrenNumber ? Same with father ?
  return this->info->minFathersNumber <= n->fathers_nb and((not this->info->has_maxFathersNumber) or n->fathers_nb <= this->info->maxFathersNumber);
}

std::pair <bool, node_t*> Parcours::parcoursUnmatchedNode(bool checkLabels, bool returnFound, MotParcours* m, node_t* node, node_t* current_node, set < node_t * >* matched_nodes, std::pair < node_t *, node_t * >*numbers, vsize_t max_numbered, Match* found_nodes, bool printAllMatches){    
    // cond_m: conditions match and there is no node already numbered m->i
  bool cond_m = m->matchesSymbol(node, checkLabels)
                and m->matchesF(node) and (m->type == TYPE_M1 or max_numbered < m->i);

  // cond_lazy: lazyrepeat is on, minrepeat is 0 and we don't check
  // labels ; this is a corner case where 0 nodes should always be
  // matched
  bool cond_lazy = m->info->minRepeat == 0 and m->info->lazyRepeat
                    and not checkLabels;

  if (cond_m and not cond_lazy) {
    // Case: child_node matches with m: number child_node and try to
    // repeat if necessary
    // The entrypoint for this matched block numbered max_numbered is
    // child_node
    numbers[max_numbered] = std::pair<node_t *, node_t *>(node, NULL);

    max_numbered++;
    matched_nodes->insert(node);
    current_node = node;
    vsize_t n_matched = 1;

    std::list < node_t * >*list_nodes;
    if (returnFound and (m->info->get or printAllMatches)) {
      list_nodes = new std::list < node_t * >();
      list_nodes->push_back((node_t *) current_node);
    }

    if (not m->info->has_maxRepeat or m->info->maxRepeat > 1) {
      // Repeat is done on basic blocks (no incoming edge within, but no
      // check is done on addresses)
      while (
          (not m->info->has_maxRepeat or n_matched < m->info->maxRepeat)
          and current_node->children_nb == 1
          and current_node->has_child1
          and current_node->child1->fathers_nb == 1
          and m->matchesSymbol(current_node->child1, checkLabels)
          and m->matchesCF(current_node->child1)) {
        if (n_matched >= m->info->minRepeat and m->info->lazyRepeat
            and not checkLabels) {
          // Case: lazyrepeat and labels are not checked ; this is a
          // corner case
          // We take the least number of nodes accepted by repeat
          // options
          break;
        }
        
        set < node_t * >::iterator it_find = matched_nodes->find(current_node->child1);
        if (it_find != matched_nodes->end()) {
          // Case: the reached node is already matched
          // We won't add it to a block since it has already been defined elsewhere
          break;
        }
        
        current_node = current_node->child1;
        n_matched++;

        if (returnFound and m->info->get){
          list_nodes->push_back((node_t *) current_node);
        }
      }
      
      // The exitpoint for this matched block numbered max_numbered is the last node reached with repeat
      numbers[max_numbered - 1].second = current_node;
    }

    if (returnFound and (m->info->get or printAllMatches)) {
      string str_gotten;
      
      if (m->info->get){
        str_gotten = m->info->getid;
      }
      else {
        str_gotten = m->info->inst_str; 
      }
      
      found_nodes->insert(std::pair < string, std::list < node_t * >*>(str_gotten, list_nodes));
    }
    
    if (n_matched < m->info->minRepeat or not m->matchesC(current_node)) {
      // Case: not enough match or children number on last node does not match word
      return std::pair<bool, node_t*>(false, NULL);
    }
  }
  else if (m->info->minRepeat == 0){
    // Case: there was no match but it is allowed (minrepeat=0)
    // It is a ghost node: you can do a back reference (-R> max_numeros)
    // but it is not really matched
    // Thus it can still be numbered and referenced by another
    // MotParcours

    numbers[max_numbered] = std::pair<node_t *, node_t *>(node, NULL);
    max_numbered++;
  }
  else{      
    // Case: there was no match and minrepeat > 0
    return std::pair<bool, node_t*>(false, NULL);
  }
  
  // max_numbered is not returned but it was incremented by 1 if and only if
  // the function returns true
  return std::pair<bool, node_t*>(true, current_node);
}

Parcours::RetourParcoursDepuisSommet Parcours::parcourirDepuisSommet(graph_t * graph, vsize_t vroot, vsize_t W, bool checkLabels, bool returnFound, bool printAllMatches) {
// TODO: Should we try to match as regular expressions (by trying all repeat numbers for instance) ?
  
  node_t *current_node;
  current_node = node_list_item(&(graph->nodes), vroot);
  
  // set of all nodes already matched
  set < node_t * >* matched_nodes = new set < node_t * >(); 
  
  // map associating a string (getid value) to a list of matched nodes 
  Match* found_nodes = new std::map < string, std::list < node_t * >*>();
  
  // array of pairs: each numbered node has a first matching node and may have (when repeat) a (different) last matching node
  RELEASE_ASSERT(W != 0);
  std::pair < node_t *, node_t * >*numbers = (std::pair < node_t *, node_t * >*)calloc_or_quit(W, sizeof(std::pair < node_t *, node_t * >));
  // nodes will be numbered 1, 2, 3.. ; max_numbered keeps track of the latest numbered given
  vsize_t max_numbered = 0;

//   Match first word (mot): it has to number a matching first node
  if (this->size >= 1 and this->mots[0]->type == TYPE_M1) { 
    std::pair <bool, node_t*> added = this->parcoursUnmatchedNode(checkLabels, returnFound, this->mots[0], current_node, current_node, matched_nodes, numbers, max_numbered, found_nodes, printAllMatches);
    
    if (added.first){
      max_numbered++; 
      current_node = added.second;
    }
    else{
      free(numbers);
      delete matched_nodes;
      return RetourParcoursDepuisSommet(false, found_nodes);
    }
  }
  else {
    free(numbers);
    delete matched_nodes;
    return RetourParcoursDepuisSommet(false, found_nodes);
  }

  for (size_t w = 1; w < this->size; w++) {
    MotParcours *m = this->mots[w];
    
    if (m->alpha_is_R) {
      if (m->i <= max_numbered) {
        std::pair < node_t *, node_t * >p = numbers[m->i - 1];
        if (p.second == NULL) {
          current_node = p.first;
        }
        else {
          current_node = p.second;
        }
      }
      else {
        // Case: m is of return type (R) to a node number (m->i) that was not attributed to a node yet
        free(numbers);
        delete matched_nodes;
        return RetourParcoursDepuisSommet(false, found_nodes);
      }
    }
    else {
      // Case: m is not of return type but defines an edge to a child number (m->k)
      if (matched_nodes->size() == 0 or ((m->k == 0 and current_node->has_child1) or (m->k == 1 and current_node->has_child2))){
        node_t *child_node;
        
        if (matched_nodes->size() == 0){
          // Case: first word (TYPE_M1) did not match a node because of repeat option (minrepeat == 0)
          child_node = current_node; 
        }
        else{
          // Case: first word matched and m defines an edge to a child
          if (m->k == 0 and current_node->has_child1){
            child_node = current_node->child1;
          }
          else if (m->k == 1 and current_node->has_child2){
            child_node = current_node->child2;
          }
        }
        
        set < node_t * >::iterator it = matched_nodes->find(child_node);
        if (it == matched_nodes->end()) {
          // Case: child_node is not yet matched
          
          if (m->i <= max_numbered){
            // Case: child_node should be numbered
            free(numbers);
            delete matched_nodes;
            return RetourParcoursDepuisSommet(false, found_nodes);
          }
          
          std::pair <bool, node_t*> added = this->parcoursUnmatchedNode(checkLabels, returnFound, m, child_node, current_node, matched_nodes, numbers, max_numbered, found_nodes, printAllMatches);
          
          if (added.first){
            max_numbered++; 
            current_node = added.second;
          }
          else{
            free(numbers);
            delete matched_nodes;
            return RetourParcoursDepuisSommet(false, found_nodes);
          }
        }
        else if (not m->has_symbol) {
          // Case: child_node is numbered and m does not define a new node
          // We verify that child_node (gotten from current_node) is numbered m->i
          if (max_numbered >= m->i) {
            std::pair < node_t *, node_t * >p = numbers[m->i - 1];
            
            if (p.first != child_node){
              // Case: child_node and current_node's number m->i child are different
              free(numbers);
              delete matched_nodes;
              return RetourParcoursDepuisSommet(false, found_nodes);
            }
            
            if (p.second == NULL){
              current_node = p.first;
            }
            else{
              current_node = p.second;
            }
          }
          else{
            // Case: there is no node numbered m->i
            free(numbers);
            delete matched_nodes;
            return RetourParcoursDepuisSommet(false, found_nodes);
          }
        }
        else {
          // Case: child_node is numbered and m does define a new node ; this should not happen
          free(numbers);
          delete matched_nodes;
          return RetourParcoursDepuisSommet(false, found_nodes);
        }
      }
      else {
        // Case: current_node has no child with this number (m->k)
        free(numbers);
        delete matched_nodes;
        return RetourParcoursDepuisSommet(false, found_nodes);
      }
    }
  }

  // The whole Parcours has successfully been traversed within the test graph
  numbers[0].first = graph->root;        
  free(numbers);
  delete matched_nodes;
  
  return RetourParcoursDepuisSommet(true, found_nodes);
}

void freeMatch(Match* match){
  // Match: associates a string with a list of nodes
  // Frees each list associated with a string, then free the map ; does not free the nodes
  
  Match::iterator it;
  for (it = match->begin(); it != match->end(); it++) {
    std::list < node_t * >*node_list = (*it).second;    
    delete(node_list);
  }

  delete(match);
}

void freeRetourParcoursDepuisSommet(Parcours::RetourParcoursDepuisSommet rt, bool getids){
    Match* match = rt.second;
    freeMatch(match);
}

Parcours::RetourParcours Parcours::parcourir(graph_t * gr, vsize_t W, bool checkLabels, bool countAllMatches, bool getId, bool printAllMatches) {
  vsize_t n;
  vsize_t count = 0;
  MatchList* list_gotten = new MatchList();
  for (n = 0; n < gr->nodes.size; n++) {
    RetourParcoursDepuisSommet rt = this->parcourirDepuisSommet(gr, n, W, checkLabels, getId, printAllMatches);
    if (rt.first) {
      if (getId and not rt.second->empty()){
        list_gotten->push_back(rt.second);
      }
      else {
        freeMatch(rt.second);
      }
      
      if (not countAllMatches){
        return RetourParcours(1, list_gotten);
      }
      else{
        count++;
      }
    }
    else{
      freeRetourParcoursDepuisSommet(rt, getId);
    }    
  }
  return RetourParcours(count, list_gotten);
}

void Parcours::freeParcours(bool free_mots)
{ 
  if (free_mots){
    vsize_t i;
    for (i = 0; i < this->size; i++){
      if (this->mots[i] != NULL){
        CondNode::freeCondition(this->mots[i]->condition, true, true);
        delete this->mots[i];
      }
    }
  }
  
  free(this->mots);
  delete(this);
}


set < Parcours * >parcoursFromGraph(graph_t * gr, vsize_t W, bool checkLabels) {
  set < Parcours * >parcours;
  Parcours *p;
  vsize_t n;

  for (n = 0; n < gr->nodes.size; n++) {
    p = parcoursGen(gr, n, W);

    if (p->complete) {
      // check if duplicate:
      set < Parcours * >::iterator it;
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
  this->mot = NULL;
}

ParcoursNode::ParcoursNode(std::list < ParcoursNode * >_fils, MotParcours * _mot, uint64_t _id) {
  this->fils = _fils;
  this->mot = _mot;
  this->id = _id;
}

bool ParcoursNode::addGraphFromNode(graph_t * gr, node_t * r, vsize_t W, bool checkLabels) {
  Parcours *p = parcoursGen(gr, r->list_id, W);
  bool ret = this->addParcours(p, 0, checkLabels);
  p->freeParcours(false);
  return ret;
}

vsize_t ParcoursNode::addGraph(graph_t * gr, vsize_t W, vsize_t maxLearn, bool checkLabels) {
  Parcours *p = NULL;
  vsize_t n;
  vsize_t added = 0;

  for (n = 0; n < gr->nodes.size; n++) {
    if (maxLearn == 0 || added < maxLearn) {
      p = parcoursGen(gr, n, W);

      if (p->complete) {
        if (this->addParcours(p, 0, checkLabels)) {
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
  s += std::to_string(this->id);
  if (not this->feuille)
    s += "\" [label=\"";
  else
    s += "\" [label=\"F ";
  s += h2s(this->id);
  if (this->mot != NULL and this->mot->condition != NULL){
    CondNode* cn = this->mot->condition;
    s += " ";
    s += h2s((vsize_t) cn);
  }
  s += "\"]\n";
  list < ParcoursNode * >::iterator it;
  for (it = this->fils.begin(); it != this->fils.end(); it++) {
    ParcoursNode *f = (*it);
    s += "\"";
    s += std::to_string(this->id);
    s += "\" -> \"";
    s += std::to_string(f->id);
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
    this->name = p->name;
    return not b;
  }
  MotParcours *m = p->mots[index];
  list < ParcoursNode * >::iterator it;
  for (it = this->fils.begin(); it != this->fils.end(); it++) {
    ParcoursNode *f = (*it);
    
    if (f->mot->equals(m, checkLabels)) {
      CondNode::freeCondition(m->condition, true, true);
      delete(m);
      return f->addParcours(p, index + 1, checkLabels);
    }
  }

  ParcoursNode *pn = new ParcoursNode();
  pn->mot = m;
  pn->id = (uint64_t) pn;

  this->fils.push_back(pn);
  return pn->addParcours(p, index + 1, checkLabels);
}

ParcoursNode::RetourParcourir ParcoursNode::parcourir(graph_t* gr, vsize_t W, bool checkLabels, bool returnFound, bool printAllMatches) {
  vsize_t count = 0;
  vsize_t n;
  std::set < vsize_t > leaves;
  PatternsMatches* patterns_matches = new PatternsMatches();
  for (n = 0; n < gr->nodes.size; n++) {    
    PatternsMatches* ret = this->parcourirDepuisSommet(gr, n, W, checkLabels, returnFound, printAllMatches);
    merge_patternsmatches(patterns_matches, ret);
  }
  
  PatternsMatches::iterator it_pattersmatches;
  for (it_pattersmatches = patterns_matches->begin(); it_pattersmatches != patterns_matches->end(); it_pattersmatches++){
    MatchList* match_list = it_pattersmatches->second;
    
    count += match_list->size();
  }
  
  return RetourParcourir(count, patterns_matches);
}

void ParcoursNode::merge_patternsmatches(PatternsMatches* leaves_to_matches, PatternsMatches* leaves_to_matches_rec){
  PatternsMatches::iterator it_pattersmatches_rec;
  
  for (it_pattersmatches_rec = leaves_to_matches_rec->begin(); it_pattersmatches_rec != leaves_to_matches_rec->end(); it_pattersmatches_rec++){
    std::string leaf_name = it_pattersmatches_rec->first;
    MatchList* match_list_rec = it_pattersmatches_rec->second;
    PatternsMatches::iterator pattern_match = leaves_to_matches->find(leaf_name);
    
    if (pattern_match != leaves_to_matches->end()){
      // Case: merge MatchLists 
      MatchList* match_list = pattern_match->second;
      
      match_list->insert(match_list->end(), match_list_rec->begin(), match_list_rec->end());
      delete match_list_rec;
    }
    else {
      // Case: add MatchList
      leaves_to_matches->insert(std::pair<std::string, MatchList*>(leaf_name, match_list_rec));
    }
  }
  
  freePatternsMatches(leaves_to_matches_rec, false);
  return;
}

PatternsMatches* ParcoursNode::parcourirDepuisSommet(graph_t* gr, vsize_t v, vsize_t W, bool checkLabels, bool returnFound, bool printAllMatches) {
  set < node_t * > matched_nodes;
  node_t *r = node_list_item(&gr->nodes, v);
  std::pair < node_t *, node_t * >*numeros = (std::pair < node_t *, node_t * >*)calloc_or_quit(W, sizeof(std::pair < node_t *, node_t * >));
  vsize_t max_numeros = 0;
  Match* empty_match = new Match();
  PatternsMatches* found_leaves = this->parcourirDepuisSommetRec(true, gr, r, numeros, max_numeros, matched_nodes, checkLabels, empty_match, returnFound, printAllMatches);
  free(numeros);
  return found_leaves;
}

Match* clone_match(Match* m){
  Match* new_match =  new Match();
  
  Match::iterator it;
  for (it = m->begin(); it != m->end(); it++){   
    std::string s = (*it).first;
    std::list < node_t * >* list_nodes = (*it).second;
    
    std::list < node_t * >* new_list_nodes = new std::list < node_t * >();
    new_list_nodes->insert(new_list_nodes->end(), list_nodes->begin(), list_nodes->end());
    new_match->insert(std::pair<string, std::list < node_t * >*>(s, new_list_nodes));
  }
  
  return new_match;
}

void freePatternsMatches(PatternsMatches* pattern_matches, bool freeMatches){
  PatternsMatches::iterator it_patternsmatches;

  if (freeMatches){
    for (it_patternsmatches = pattern_matches->begin(); it_patternsmatches != pattern_matches->end(); it_patternsmatches++){
      MatchList* match_list = it_patternsmatches->second;
      MatchList::iterator it_match_list;
      
        for (it_match_list = match_list->begin(); it_match_list != match_list->end(); it_match_list++) {
          Match* match = *it_match_list;    
          freeMatch(match);
        }
      delete match_list;
    }
  }   
  delete pattern_matches;
}

PatternsMatches* ParcoursNode::parcourirDepuisSommetRec(bool racine, graph_t * gr, node_t * r, std::pair < node_t *, node_t * >*numeros, vsize_t max_numeros, set < node_t * > matched_nodes, bool checkLabels, Match* current_match, bool returnFound, bool printAllMatches) {
  PatternsMatches* leaves_to_matches = new PatternsMatches();

  if (this->feuille) {
    PatternsMatches::iterator pattern_match_list = leaves_to_matches->find(this->name);
    if (pattern_match_list == leaves_to_matches->end()){
      // Need to add a match list for this pattern
      Match* cloned_match = clone_match(current_match);
        MatchList* ml = new MatchList();
        ml->push_front(cloned_match);
        leaves_to_matches->insert(std::pair<std::string, MatchList*>(this->name, ml));
    }
    else{
      pattern_match_list->second->push_front(clone_match(current_match));
    }
  }

  assert(this->feuille or racine or not this->fils.empty());
  
  list < ParcoursNode * >::iterator it;
  for (it = this->fils.begin(); it != this->fils.end(); it++) {       
    ParcoursNode *f = (*it);
    
    Match* current_match_copy;
    current_match_copy = clone_match(current_match);
    
    RetourEtape ret = etape(f->mot, r, gr, numeros, max_numeros, matched_nodes, checkLabels, current_match_copy, returnFound, printAllMatches);
    bool possible = get<0>(ret);
    node_t *node = get<1>(ret);
    numeros = get<2>(ret);
    vsize_t max_numeros_r = get<3>(ret);
    set<node_t *> matched_nodes_r = get<4>(ret);

    if (possible) {    
      PatternsMatches* leaves_to_matches_rec = f->parcourirDepuisSommetRec(false, gr, node, numeros, max_numeros_r, matched_nodes_r, checkLabels, current_match_copy, returnFound, printAllMatches);
      merge_patternsmatches(leaves_to_matches, leaves_to_matches_rec);
    }
    else {
      freeMatch(current_match_copy);
    }
  }
  
  freeMatch(current_match);
  return leaves_to_matches;
}

std::tuple <bool, node_t*, set < node_t * >> ParcoursNode::etapeUnmatchedNode(bool checkLabels, bool returnFound, MotParcours* m, node_t* node, node_t* current_node, set < node_t * > matched_nodes, std::pair < node_t *, node_t * >*numbers, vsize_t max_numbered, Match* current_match, bool printAllMatches){  
  // node n'est pas numéroté
  bool cond_symbol = (m->matchesSymbol(node, checkLabels) and m->matchesF(node) and (m->type == TYPE_M1 or max_numbered < m->i));
  bool cond_lazy = m->info->minRepeat == 0 and m->info->lazyRepeat and not checkLabels;
  
  if (cond_symbol and not cond_lazy) {
    vsize_t last_max_numeros = max_numbered;
    vsize_t r = 1;
    numbers[max_numbered] = std::pair < node_t *, node_t * >(node, NULL);
    max_numbered++;
    current_node = node;
    
    bool keep_list_nodes = returnFound and (m->info->get or printAllMatches);
    std::list < node_t * >*list_nodes;
    if (keep_list_nodes) {
      list_nodes = new std::list < node_t * >();
      list_nodes->push_back((node_t *) current_node);
    }

    if (not m->info->has_maxRepeat or m->info->maxRepeat > 1) {
      while (true) {
        // If lazy repeat and labels are not checked... this is a corner
        // case: take the least repeat as possible
        if (r >= m->info->minRepeat and m->info->lazyRepeat
            and not checkLabels)
          break;

        if ((not m->info->has_maxRepeat or r < m->info->maxRepeat)
            and current_node->children_nb == 1 and current_node->has_child1 and current_node->child1->fathers_nb == 1
            and m->matchesSymbol(current_node->child1, checkLabels)
            and m->matchesCF(current_node->child1)) {
          set<node_t *>::iterator it_find = matched_nodes.find(current_node->child1);

          if (it_find != matched_nodes.end()) break;
          
          current_node = current_node->child1;
          r++;
        
          if (keep_list_nodes){
            list_nodes->push_back((node_t *) current_node);
          }
        }
        else {
          break;
        }
      }

      numbers[max_numbered - 1].second = current_node;
    
      if (r < m->info->minRepeat or not m->matchesC(current_node)) {
        // pas trouvé, TODO: attention au branchement
        if (keep_list_nodes){
          delete(list_nodes);
        }
        return std::tuple <bool, node_t*, set < node_t * >> (false, current_node, matched_nodes);
      }
    }
    
    matched_nodes.insert(node);
    
    if (returnFound and (m->info->get or printAllMatches)) {
      string str_gotten;
      
      if (m->info->get){
        str_gotten = m->info->getid;
      }
      else {
        str_gotten = m->info->inst_str; 
      }
      
      current_match->insert(std::pair < string, std::list < node_t * >*>(str_gotten, list_nodes));
    }
    
    return std::tuple <bool, node_t*, set < node_t * >> (true, current_node, matched_nodes);
  }
  else {
    if (m->info->minRepeat == 0){
      // It is a ghost node: you can do a back reference (-R> max_numeros) but it is not really matched
      // Thus it can still be "numerote" and referenced by another MotParcours
      node_t* child = NULL;
      
      numbers[max_numbered] = std::pair < node_t *, node_t * >(node, NULL);
      max_numbered++;
      
      return std::tuple <bool, node_t*, set < node_t * >> (true, current_node, matched_nodes);
    }
    
    return std::tuple <bool, node_t*, set < node_t * >> (false, current_node, matched_nodes);
  }
}

ParcoursNode::RetourEtape ParcoursNode::etape(MotParcours * m, node_t * s, graph_t * gr, std::pair < node_t *, node_t * >*numbers, vsize_t max_numbered, set < node_t * > matched_nodes, bool checkLabels, Match* current_match, bool returnFound, bool printAllMatches) {
  if (m->type == TYPE_M1) {
    std::tuple <bool, node_t*, set < node_t * >> added = this->etapeUnmatchedNode(checkLabels, returnFound, m, s, s, matched_nodes, numbers, max_numbered, current_match, printAllMatches);
    if (std::get<0>(added)){
      s = std::get<1>(added);
      matched_nodes = std::get<2>(added);
      max_numbered++;
    }
    else {
      return std::make_tuple(false, s, numbers, max_numbered, matched_nodes);
    }
          
    return std::make_tuple(true, s, numbers, max_numbered, matched_nodes);
  }
  else if (m->type == TYPE_M2) {
    if (m->alpha_is_R) {
      if (max_numbered >= m->i) {
        std::pair < node_t *, node_t * >p = numbers[m->i - 1];
        if (p.second == NULL)
          s = p.first;
        else
          s = p.second;

        return std::make_tuple(true, s, numbers, max_numbered, matched_nodes);
      }
      else {
        return std::make_tuple(false, s, numbers, max_numbered, matched_nodes);
      }
    }
    else {
      // Case: m is not of return type but defines an edge to a child number (m->k)
      if (matched_nodes.size() == 0 or ((m->k == 0 and s->has_child1) or (m->k == 1 and s->has_child2))) {
        node_t *f;
        
        if (matched_nodes.size() == 0){
          // Case: first word (TYPE_M1) did not match a node because of repeat option (minrepeat == 0)
          f = s; 
        }
        else{
          // Case: first word matched and m defines an edge to a child
          if (m->k == 0 and s->has_child1){
            f = s->child1;
          }
          
          if (m->k == 1 and s->has_child2){
            f = s->child2;
          }
        }
        
        set < node_t * >::iterator it = matched_nodes.find(f);
        if (it == matched_nodes.end()) {
          // Case: child_node is not yet matched
          
          if (m->i <= max_numbered){
            // Case: child_node should be numbered
            return std::make_tuple(false, s, numbers, max_numbered, matched_nodes);
          }
          
          std::tuple <bool, node_t*, set < node_t * >> added = this->etapeUnmatchedNode(checkLabels, returnFound, m, f, s, matched_nodes, numbers, max_numbered, current_match, printAllMatches);
          if (std::get<0>(added)){
            s = std::get<1>(added);
            matched_nodes = std::get<2>(added);
            max_numbered++;
          }
          else {
            return std::make_tuple(false, s, numbers, max_numbered, matched_nodes);
          }
          
          return std::make_tuple(true, s, numbers, max_numbered, matched_nodes);
        }
        else if (not m->has_symbol) {
          // Case: child_node is numbered and m does not define a new node
          // We verify that child_node (gotten from current_node) is numbered m->i
          if (max_numbered >= m->i) {
            std::pair < node_t *, node_t * >p = numbers[m->i - 1];
            
            if (p.first != f){
              // Case: child_node and current_node's number m->i child are different
              return std::make_tuple(false, f, numbers, max_numbered, matched_nodes);
            }
            
            if (p.second == NULL){
              s = p.first;
            }
            else{
              s = p.second;
            }
            return std::make_tuple(true, s, numbers, max_numbered, matched_nodes);
          }
          else{
              // Case: there is no node numbered m->i
              return std::make_tuple(false, f, numbers, max_numbered, matched_nodes);
          }
        }
        else {
          // Case: child_node is numbered and m does define a new node ; this should not happen
          return std::make_tuple(false, s, numbers, max_numbered, matched_nodes);
        }
      }
      else {
        // Case: current_node has no child with this number (m->k)
        return std::make_tuple(false, s, numbers, max_numbered, matched_nodes);
      }
    }
  }
  else {
    std::cerr << "ERR: unknown type." << std::endl;
    return std::make_tuple(false, s, numbers, max_numbered, matched_nodes);
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

void ParcoursNode::freeParcoursNode()
{
  list < ParcoursNode * >::iterator it;
  for (it = this->fils.begin(); it != this->fils.end(); it++) {
    ParcoursNode *f = (*it);
    f->freeParcoursNode();
  }
  
  if (this->mot != NULL){
    CondNode::freeCondition(this->mot->condition, true, true);
    delete this->mot;
  }
  
  delete this;
}


#endif
