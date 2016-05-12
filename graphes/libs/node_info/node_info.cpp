#include "node_info.hpp"

NodeInfo::NodeInfo(){
  this->inst_str = "";
  this->is_root = false;
  this->has_address = false;
  this->address = 0;
  this->childrenNumber = 0;
  this->fathersNumber = 0;
  this->minChildrenNumber = 0;
  this->has_maxChildrenNumber = false;
  this->maxChildrenNumber = 0;
  this->minFathersNumber = 0;
  this->has_maxFathersNumber = false;
  this->maxFathersNumber = 0;
  this->minRepeat = 1;
  this->has_maxRepeat = true;
  this->maxRepeat = 1;
  this->get = false;
  this->getid = "";
}

std::string NodeInfo::toString()
{
  std::string s = "";
  s += this->inst_str;
  s += "(";
  
  if (this->is_root){
    s += "root";
  }
  else {
    s += "noroot"; 
  }
  s += ", ";
  
  if (this->has_address){
    s += "address=";
//     s += h2s(this->address);
  }
  else {
    s += "noaddress"; 
  }
  s += ", ";
  
  s += "cn=" + std::to_string((uint) this->childrenNumber);
  s += ", fn=" + std::to_string((uint) this->fathersNumber);
  
  if (this->has_maxChildrenNumber){
   s += ", maxcn=" + std::to_string((uint) this->maxChildrenNumber); 
  }
  else {
   s += ", nomaxcn"; 
  }
  s += ", mincn=" + std::to_string((uint) this->minChildrenNumber); 
  
  if (this->has_maxFathersNumber){
   s += ", maxfn=" + std::to_string((uint) this->maxFathersNumber); 
  }
  else {
   s += ", nomaxfn"; 
  }
  s += ", minfn=" + std::to_string((uint) this->minFathersNumber); 
  
  s += ", minrepeat=" + std::to_string((uint) this->minRepeat);
  
  if (this->has_maxRepeat){
    s += ", maxrepeat=" + std::to_string((uint) this->maxRepeat);
  }
  else {
    s += ", nomaxrepeat"; 
  }
  
  if (this->get){
    s += ", get=" + this->getid;
  }
  else {
    s += ", noget"; 
  }
  
  return s;
}


bool NodeInfo::equals(NodeInfo* ni){
  return this->inst_str == ni->inst_str
         and this-> is_root == ni->is_root
         and this->has_address == ni->has_address
         and (not this->has_address or (this->address == ni->address))
         and this->childrenNumber == ni->childrenNumber
         and this->fathersNumber == ni->fathersNumber
         and this->minChildrenNumber == ni->minChildrenNumber
         and this->has_maxChildrenNumber == ni->has_maxChildrenNumber
         and (not this->has_maxChildrenNumber or (this->maxChildrenNumber == ni->maxChildrenNumber))
         and this->minFathersNumber == ni->minFathersNumber
         and this->has_maxFathersNumber == ni->has_maxFathersNumber
         and (not this->has_maxFathersNumber or (this->maxFathersNumber == ni->maxFathersNumber))
         and this->minRepeat == ni->minRepeat
         and this->has_maxRepeat == ni->has_maxRepeat
         and (not this->has_maxRepeat or (this->maxRepeat == ni->maxRepeat))
         and this->get == ni->get
         and (not this->get or (this->getid == ni->getid));
}


CondNode::CondNode(){
  std::list<CondNode*>* cn = new std::list<CondNode*>();
  this->children = cn;
  this->comparison = ComparisonFunEnum::bool_false;
  this->has_fixed_pattern_info = false;
}

CondNode::CondNode(std::list<CondNode*>* cn, UnOpEnum un_op){
  assert(cn->size() == 1);
  
  this->children = cn;
  this->unary_operator = un_op;
  this->has_fixed_pattern_info = false;
}

CondNode::CondNode(std::list<CondNode*>* cn, BinOpEnum bin_op){
  assert(cn->size() >= 2);
  
  this->children = cn;
  this->binary_operator = bin_op;
  this->has_fixed_pattern_info = false;
}

bool ComparisonFunctions::bool_equals(void* a1, void* a2)
{
  bool* b1 = static_cast<bool*>(a1);
  bool* b2 = static_cast<bool*>(a2);
  
  return *b1 == *b2;
}

bool ComparisonFunctions::bool_true(void* a1, void* a2)
{  
  return true;
}

bool ComparisonFunctions::bool_false(void* a1, void* a2)
{  
  return false;
}

bool ComparisonFunctions::bool_test_true(void* a1, void* a2)
{
  bool* b2 = static_cast<bool*>(a2);
  
  return *b2 == true;
}

bool ComparisonFunctions::str_contains(void* a1, void* a2)
{
  std::string* s1 = static_cast<std::string *>(a1);
  std::string* s2 = static_cast<std::string *>(a2);
  
  std::size_t found = s2->find(*s1);
  
//   std::cout << "is " << *s1 << " in " << *s2 << " ?\n";
  
  if (found!=std::string::npos){
    return true;
  }
  else{
    return false;
  }
}

bool ComparisonFunctions::str_equals(void* a1, void* a2)
{
  std::string* s1 = static_cast<std::string *>(a1);
  std::string* s2 = static_cast<std::string *>(a2);
  
//   std::cout << "cmp " << *s1 << " VS " << *s2 << "\n";
  
  return *s1 == *s2;
}

bool ComparisonFunctions::uint8t_equals(void* a1, void* a2)
{
  uint8_t* u1 = static_cast<uint8_t*>(a1);
  uint8_t* u2 = static_cast<uint8_t*>(a2);
  
  return *u1 == *u2;
}

bool ComparisonFunctions::uint8t_gt(void* a1, void* a2)
{
  uint8_t* u1 = static_cast<uint8_t*>(a1);
  uint8_t* u2 = static_cast<uint8_t*>(a2);
  
  return *u1 >= *u2;
}

bool ComparisonFunctions::vsizet_equals(void* a1, void* a2)
{
  vsize_t* v1 = static_cast<vsize_t*>(a1);
  vsize_t* v2 = static_cast<vsize_t*>(a2);
  
  return *v1 == *v2;
}

bool CondNode::comparison_fun(void* a1, void* a2)
{
  switch (this->comparison){
    case bool_equals:
      return ComparisonFunctions::bool_equals(a1, a2);
      
    case bool_false:
      return ComparisonFunctions::bool_false(a1, a2);
      
    case bool_true:
      return ComparisonFunctions::bool_true(a1, a2);
      
    case bool_test_true:
      return ComparisonFunctions::bool_test_true(a1, a2);
      
    case vsizet_equals:
      return ComparisonFunctions::vsizet_equals(a1, a2);
      
    case str_contains:
      return ComparisonFunctions::str_contains(a1, a2);
      
    case str_equals:
      return ComparisonFunctions::str_equals(a1, a2);
      
    case uint8t_equals:
      return ComparisonFunctions::uint8t_equals(a1, a2);
      
    case uint8t_gt:
      return ComparisonFunctions::uint8t_gt(a1, a2);
      
    default:
      std::cerr << "ERR in node_info.cpp : unknown comparison_fun\n";
      return false;
  }
}

bool CondNode::unary_fun(bool b){
  switch (this->unary_operator){
    case logical_not:
      return not b;
      
    default:
      std::cerr << "ERR in node_info.cpp : unknown unary_fun\n";
      return false;
  }
}

bool CondNode::binary_fun(bool b1, bool b2){
  switch (this->binary_operator){
    case logical_and:
      return b1 and b2;
      
    case logical_or:
      return b1 or b2;
      
    default:
      std::cerr << "ERR in node_info.cpp : unknown binary_fun\n";
      return false;
  }
}

bool CondNode::evaluate(NodeInfo* pattern, NodeInfo* test)
{
  if (this->has_fixed_pattern_info){
    pattern = this->fixed_pattern_info; 
  }
  
  vsize_t nc = this->children->size();
  
  if (nc == 0){
   return this->comparison_fun(&((*pattern).*(this->pattern_field)), &((*test).*(this->test_field)));
  }
  else if (nc == 1){
   return this->unary_fun(this->children->front()->evaluate(pattern, test)); 
  }
  else{
    // 2 or more children
    bool r = this->children->front()->evaluate(pattern, test);
    
    std::list<CondNode*>::iterator it = this->children->begin();
    it++;
    
    while(it != this->children->end()){
      r = this->binary_fun(r, (*it)->evaluate(pattern, test));
      
     it++; 
    }
    return r;
  }
}

bool CondNode::equals(CondNode* cn){
  vsize_t nc = this->children->size();
  if (nc != cn->children->size()) return false;
  if (this->has_fixed_pattern_info != cn->has_fixed_pattern_info or (this->has_fixed_pattern_info and (this->fixed_pattern_info != cn->fixed_pattern_info))) return false;
  
  if (nc == 0){
    bool r = (this->pattern_field == cn->pattern_field)
              and (this->test_field == cn->test_field)
              and (this->comparison == cn->comparison);
    return r;
  }
  else if(nc == 1){
    bool r = (this->unary_operator == cn->unary_operator);
    
    if (r){
      r = this->children->front()->equals(cn->children->front());
    }
    
    return r;
  }
  else {
    bool r = true;
    
    if (r){
      std::list<CondNode*>::iterator it = this->children->begin();
      std::list<CondNode*>::iterator it2 = cn->children->begin();
      
      while(r and it != this->children->end() and it2 != cn->children->end()){
        r = r and ((*it)->equals(*it2));

        it++; 
        it2++;
      }
    }
    
    return r;
  }
}

// CondNode* CondNode::AddLazyCond(node_t* n)
// {
//   return this;
// }


std::string CondNode::toString(){
  std::string s;
  
  switch (this->children->size()){
    case 0:
      return desc_ComparisonFunEnum[this->comparison];
    
    case 1:
      s = desc_UnOpEnum[this->unary_operator];
      s += "(";
      s += this->children->front()->toString();
      s += ")";
      return s;
      
    default:
      s = desc_BinOpEnum[this->binary_operator];
      s += "(";
      s += this->children->front()->toString();
      
      std::list<CondNode*>::iterator it = this->children->begin();
      it++;

      while(it != this->children->end()){
        s += ", " + (*it)->toString();

        it++;
      }
      s += ")";
      
      return s;
  }
}

void CondNode::freeCondition(){
  std::list<CondNode*>::iterator it = this->children->begin();

  while(it != this->children->end()){
    (*it)->freeCondition();
    
    it++;
  }
  
  delete this;
}


