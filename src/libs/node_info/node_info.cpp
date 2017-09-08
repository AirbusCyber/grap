#include "node_info.hpp"
#include "node.hpp"

NodeInfo::NodeInfo(){
  this->inst_str = "";
  this->opcode = "";
  this->nargs = 0;
  this->arg1 = "";
  this->arg2 = "";
  this->arg3 = "";
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
  this->lazyRepeat = false;
  this->get = false;
  this->getid = "";
  this->color = "";
}
 

NodeInfo* NodeInfo::duplicate(){
  NodeInfo* ni = new NodeInfo();
  
  ni->inst_str = this->inst_str;
  ni->opcode = this->opcode;
  ni->nargs = this->nargs;
  ni->arg1 = this->arg1;
  ni->arg2 = this->arg2;
  ni->arg3 = this->arg3;
  ni->is_root = this->is_root;
  ni->has_address = this->has_address;
  ni->address = this->address;
  ni->childrenNumber = this->childrenNumber;
  ni->fathersNumber = this->fathersNumber;
  ni->minChildrenNumber = this->minChildrenNumber;
  ni->has_maxChildrenNumber= this->has_maxChildrenNumber;
  ni->maxChildrenNumber = this->maxChildrenNumber;
  ni->minFathersNumber  = this->minFathersNumber;
  ni->has_maxFathersNumber = this->has_maxFathersNumber;
  ni->maxFathersNumber = this->maxFathersNumber;
  ni->minRepeat = this->minRepeat;
  ni->has_maxRepeat = this->has_maxRepeat;
  ni->maxRepeat = this->maxRepeat;
  ni->lazyRepeat = this->lazyRepeat;
  ni->get = this->get;
  ni->getid = this->getid;
  ni->color = this->color;
  
  return ni;
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
    s += std::to_string(this->address);
  }
  else {
    s += "noaddress"; 
  }
  s += ", ";
  
  s += "cn=" + std::to_string((vsize_t) this->childrenNumber);
  s += ", fn=" + std::to_string((vsize_t) this->fathersNumber);
  
  if (this->has_maxChildrenNumber){
   s += ", maxcn=" + std::to_string((vsize_t) this->maxChildrenNumber); 
  }
  else {
   s += ", nomaxcn"; 
  }
  s += ", mincn=" + std::to_string((vsize_t) this->minChildrenNumber); 
  
  if (this->has_maxFathersNumber){
   s += ", maxfn=" + std::to_string((vsize_t) this->maxFathersNumber); 
  }
  else {
   s += ", nomaxfn"; 
  }
  s += ", minfn=" + std::to_string((vsize_t) this->minFathersNumber); 
  
  s += ", minrepeat=" + std::to_string((vsize_t) this->minRepeat);
  
  if (this->has_maxRepeat){
    s += ", maxrepeat=" + std::to_string((vsize_t) this->maxRepeat);
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
  
  if (this->color != ""){
    s += ", color=" + this->color;
  }
  else {
    s += ", nocolor"; 
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
  this->children = new std::list<CondNode*>();
  this->comparison = ComparisonFunEnum::bool_false;
  this->pattern_field = NULL;
  this->test_field = NULL;
  this->is_end_basic_block = false;
  this->has_fixed_pattern_info = false;
  this->has_fixed_field = false;
  this->fixed_field_is_new = false;
  this->apply_pattern_condition_to_test = false;
  this->n_pointer_usage = 1;
}

CondNode::CondNode(std::list<CondNode*>* cn){
  this->children = cn;
  this->comparison = ComparisonFunEnum::bool_false;
  this->pattern_field = NULL;
  this->test_field = NULL;
  this->is_end_basic_block = false;
  this->has_fixed_pattern_info = false;
  this->has_fixed_field = false;
  this->fixed_field_is_new = false;
  this->apply_pattern_condition_to_test = false;
  this->n_pointer_usage = 1;
}

CondNode::CondNode(std::list<CondNode*>* cn, UnOpEnum un_op){
  assert(cn->size() == 1);
  
  this->children = cn;
  this->unary_operator = un_op;
  this->pattern_field = NULL;
  this->test_field = NULL;
  this->is_end_basic_block = false;
  this->has_fixed_pattern_info = false;
  this->has_fixed_field = false;
  this->fixed_field_is_new = false;
  this->apply_pattern_condition_to_test = false;
  this->n_pointer_usage = 1;
}

CondNode::CondNode(BinOpEnum bin_op, std::list<CondNode*>* cn){
  assert(cn->size() >= 2);
  
  this->children = cn;
  this->pattern_field = NULL;
  this->test_field = NULL;
  this->binary_operator = bin_op;
  this->is_end_basic_block = false;
  this->has_fixed_pattern_info = false;
  this->has_fixed_field = false;
  this->fixed_field_is_new = false;
  this->apply_pattern_condition_to_test = false;
  this->n_pointer_usage = 1;
}

CondNode::CondNode(std::string key, std::string op, std::string value){ 
  std::list<CondNode*>* cn = new std::list<CondNode*>();
  this->children = cn;
  this->pattern_field = NULL;
  this->test_field = NULL;
  this->is_end_basic_block = false;
  this->fixed_field_is_new = false;
  this->has_fixed_pattern_info = false;
  this->apply_pattern_condition_to_test = false;
  this->n_pointer_usage = 1;
  
  if (key == "inst" or key == "instruction" or key == "op" or key == "opcode"
    or key == "arg1" or key == "arg2" or key == "arg3"){
    if (key == "op" or key == "opcode"){
      this->test_field = (void* NodeInfo::*) &NodeInfo::opcode;
    }
    else if (key == "arg1"){
      this->test_field = (void* NodeInfo::*) &NodeInfo::arg1;
    }
    else if (key == "arg2"){
      this->test_field = (void* NodeInfo::*) &NodeInfo::arg2;
    }
    else if (key == "arg3"){
      this->test_field = (void* NodeInfo::*) &NodeInfo::arg3;
    }
    else{
      // Case: inst or instruction
      this->test_field = (void* NodeInfo::*) &NodeInfo::inst_str;
    }
    
    if (value.length() >= 1 and value.at(0) == '_'){
      this->has_fixed_field = false;
      this->apply_pattern_condition_to_test = true;
      std::string field = value.substr(1);
      
      if (field == "arg1"){
        this->pattern_field = (void* NodeInfo::*) &NodeInfo::arg1;
      }
      else if (field == "arg2"){
        this->pattern_field = (void* NodeInfo::*) &NodeInfo::arg2;
      }
      else if (field == "arg3"){
        this->pattern_field = (void* NodeInfo::*) &NodeInfo::arg3;
      }
      else {
        std::cerr << "WARNING: Unknown field " << field << ". Defaulting condition to 'not true'." << std::endl;
        new (this) CondNode();
      }
    }
    else{
      this->has_fixed_field = true;
      this->fixed_field_is_new = true;
      std::string* str_ptr = new std::string();
      *str_ptr = value;
      this->fixed_field = (void*) str_ptr;
    }
    
    if (op == "is"){
      this->comparison = ComparisonFunEnum::str_equals; 
    }
    else if (op == "contains"){
      this->comparison = ComparisonFunEnum::str_contains;
    }
    else if (op == "beginswith"){
      this->comparison = ComparisonFunEnum::str_beginswith;
    }
    else if (op == "regex"){
      this->comparison = ComparisonFunEnum::str_regex;
    }
    else {
      std::cerr << "WARNING: Unknown string operator " << op << ". Defaulting condition to 'not true'." << std::endl;
      new (this) CondNode();
    }
  }
  else if (key == "addr" or key == "address" 
    or key == "nf" or key == "nfathers" 
    or key == "nc" or key == "nchildren"){
      this->has_fixed_field = true;
      if (key == "addr" or key == "address"){
        this->test_field = (void* NodeInfo::*) &NodeInfo::address;
      }
      else if (key == "nf" or key == "nfathers"){
        this->test_field = (void* NodeInfo::*) &NodeInfo::fathersNumber;
      }
      else{
        // Case: key == "nc" or key == "nchildren"
        this->test_field = (void* NodeInfo::*) &NodeInfo::childrenNumber;
      }
      
      vsize_t* addr_ptr = new vsize_t();
      *addr_ptr = (vsize_t) strtol(value.c_str(), NULL, 16);
      this->fixed_field = (void*) addr_ptr;
      this->fixed_field_is_new = true;
      
      if (op == "=="){
        this->comparison = ComparisonFunEnum::vsizet_equals; 
      }
      else if (op == ">"){
        // addr > 12 means test > pattern, so we have to use less than operator
        this->comparison = ComparisonFunEnum::vsizet_lt;
      }
      else if (op == ">="){
        this->comparison = ComparisonFunEnum::vsizet_leq;
      }    
      else if (op == "<"){
        this->comparison = ComparisonFunEnum::vsizet_gt;
      }
      else if (op == "<="){
        this->comparison = ComparisonFunEnum::vsizet_geq;
      }
      else {
        std::cerr << "WARNING: Unknown integer operator " << op << " Defaulting condition to 'not true'." << std::endl;
        new (this) CondNode();
      }
  }  
  else if (key == "nargs"){
      this->has_fixed_field = true;
      this->test_field = (void* NodeInfo::*) &NodeInfo::nargs;

      uint8_t* addr_ptr = (uint8_t*) malloc_or_quit(sizeof(uint8_t));
      *addr_ptr = (uint8_t) strtol(value.c_str(), NULL, 10);
      this->fixed_field = (void*) addr_ptr;
      
      if (op == "=="){
        this->comparison = ComparisonFunEnum::uint8t_equals; 
      }
      else if (op == ">"){
        this->comparison = ComparisonFunEnum::uint8t_lt;
      }
      else if (op == ">="){
        this->comparison = ComparisonFunEnum::uint8t_leq;
      }    
      else if (op == "<"){
        this->comparison = ComparisonFunEnum::uint8t_gt;
      }
      else if (op == "<="){
        this->comparison = ComparisonFunEnum::uint8t_geq;
      }
      else {
        std::cerr << "WARNING: Unknown integer operator " << op << " Defaulting condition to 'not true'." << std::endl;
        new (this) CondNode();
      }
  }
  else {
    std::cerr << "WARNING: Unknown key " << key << ". Defaulting condition to 'not true'." << std::endl;
    new (this) CondNode();
  }
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
  
  // Does s2 contain s1 ?
  std::size_t found = s2->find(*s1);
  
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
  
  return *s1 == *s2;
}

bool ComparisonFunctions::str_beginswith(void* a1, void* a2)
{
  std::string* s1 = static_cast<std::string *>(a1);
  std::string* s2 = static_cast<std::string *>(a2);
  
  // Does s2 begin with s1 ?
  vsize_t ls1 = (*s1).length();
  if (ls1 > (*s1).length()){
    return false;
  }
  return ((*s2).substr(0, ls1) == *s1);
}

bool ComparisonFunctions::str_regex(void* a1, void* a2)
{
  std::string* s1 = static_cast<std::string *>(a1);
  std::string* s2 = static_cast<std::string *>(a2);
  
  // Does s2 matches regex s1 ?  
  try {
    boost::regex txt_regex(*s1);
    return boost::regex_match(*s2, txt_regex);
  }
  catch (...) {
    std::cerr << "ERROR: Regex creation failed." << std::endl;
    return false; 
  }
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
  
  return *u1 > *u2;
}

bool ComparisonFunctions::uint8t_geq(void* a1, void* a2)
{
  uint8_t* u1 = static_cast<uint8_t*>(a1);
  uint8_t* u2 = static_cast<uint8_t*>(a2);
  
  return *u1 >= *u2;
}

bool ComparisonFunctions::uint8t_lt(void* a1, void* a2)
{
  uint8_t* u1 = static_cast<uint8_t*>(a1);
  uint8_t* u2 = static_cast<uint8_t*>(a2);
  
  return *u1 < *u2;
}

bool ComparisonFunctions::uint8t_leq(void* a1, void* a2)
{
  uint8_t* u1 = static_cast<uint8_t*>(a1);
  uint8_t* u2 = static_cast<uint8_t*>(a2);
  
  return *u1 <= *u2;
}

bool ComparisonFunctions::vsizet_equals(void* a1, void* a2)
{
  vsize_t* v1 = static_cast<vsize_t*>(a1);
  vsize_t* v2 = static_cast<vsize_t*>(a2);
  
  return *v1 == *v2;
}

bool ComparisonFunctions::vsizet_gt(void* a1, void* a2)
{
  vsize_t* v1 = static_cast<vsize_t*>(a1);
  vsize_t* v2 = static_cast<vsize_t*>(a2);
  
  return *v1 > *v2;
}

bool ComparisonFunctions::vsizet_geq(void* a1, void* a2)
{
  vsize_t* v1 = static_cast<vsize_t*>(a1);
  vsize_t* v2 = static_cast<vsize_t*>(a2);
  
  return *v1 >= *v2;
}

bool ComparisonFunctions::vsizet_lt(void* a1, void* a2)
{
  vsize_t* v1 = static_cast<vsize_t*>(a1);
  vsize_t* v2 = static_cast<vsize_t*>(a2);
  
  return *v1 < *v2;
}

bool ComparisonFunctions::vsizet_leq(void* a1, void* a2)
{
  vsize_t* v1 = static_cast<vsize_t*>(a1);
  vsize_t* v2 = static_cast<vsize_t*>(a2);
  
  return *v1 <= *v2;
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
          
    case vsizet_gt:
      return ComparisonFunctions::vsizet_gt(a1, a2);
            
    case vsizet_geq:
      return ComparisonFunctions::vsizet_geq(a1, a2);
            
    case vsizet_lt:
      return ComparisonFunctions::vsizet_lt(a1, a2);
            
    case vsizet_leq:
      return ComparisonFunctions::vsizet_leq(a1, a2);
      
    case str_contains:
      return ComparisonFunctions::str_contains(a1, a2);
      
    case str_equals:
      return ComparisonFunctions::str_equals(a1, a2);
      
    case str_beginswith:
      return ComparisonFunctions::str_beginswith(a1, a2);    
      
    case str_regex:
      return ComparisonFunctions::str_regex(a1, a2);
      
    case uint8t_equals:
      return ComparisonFunctions::uint8t_equals(a1, a2);
      
    case uint8t_gt:
      return ComparisonFunctions::uint8t_gt(a1, a2);
      
    case uint8t_geq:
      return ComparisonFunctions::uint8t_geq(a1, a2);
      
    case uint8t_lt:
      return ComparisonFunctions::uint8t_lt(a1, a2);
      
    case uint8t_leq:
      return ComparisonFunctions::uint8t_leq(a1, a2);
      
    default:
      std::cerr << "ERROR in node_info.cpp: unknown comparison_fun." << std::endl;
      return false;
  }
}

bool CondNode::unary_fun(bool b){
  switch (this->unary_operator){
    case logic_not:
      return not b;
      
    default:
      std::cerr << "ERROR in node_info.cpp: unknown unary_fun " << this << "." << std::endl;
      return false;
  }
}

bool CondNode::binary_fun(bool b1, bool b2){
  switch (this->binary_operator){
    case logic_and:
      return b1 and b2;
      
    case logic_or:
      return b1 or b2;
      
    default:
      std::cerr << "ERROR in node_info.cpp: unknown binary_fun." << std::endl;
      return false;
  }
}

bool CondNode::endblockcheck_fun(node_t *testNode) {
  /*
   * Check if the node is the end of a basic block
   *
   * This is the case when:
   *   1. it is a jump
   *   2. the current instruction does not have exactly one children (e.g. “ret”)
   *   3. the following instruction has more than one parent
   */

  // TODO: use something else than opcode string to check if it is a jump
  std::string jumpStr("j");
  if(testNode->children_nb != 1 or ComparisonFunctions::str_beginswith((void*) &jumpStr, &testNode->info->opcode)){
    return true;
  }
  else{
    node_t *child = testNode->has_child1 ? testNode->child1 : testNode->child2;

    return child->fathers_nb > 1;
  }
}

bool CondNode::evaluate(NodeInfo* patternInfo, NodeInfo* testInfo, node_t* testNode)
{
  if (this->has_fixed_pattern_info){
    patternInfo = this->fixed_pattern_info;
  }
  else if (this->apply_pattern_condition_to_test){
    patternInfo = testInfo;
  }
  
  vsize_t nc = this->children->size();
  
  if (nc == 0){
   void* pattern_comparison_field;

   if (this->is_end_basic_block)
   {
     if(testNode == nullptr)
       return false;
     else
       return this->endblockcheck_fun(testNode);
   }

   if (this->has_fixed_field){
     pattern_comparison_field = this->fixed_field;
   }
   else{
     pattern_comparison_field = &((*patternInfo).*(this->pattern_field));
   }

   return this->comparison_fun(pattern_comparison_field, &((*testInfo).*(this->test_field)));
  }
  else if (nc == 1){
   return this->unary_fun(this->children->front()->evaluate(patternInfo, testInfo, testNode));
  }
  else{
    // 2 or more children
    bool r = this->children->front()->evaluate(patternInfo, testInfo, testNode);

    std::list<CondNode*>::iterator it = this->children->begin();
    it++;
    
    while(it != this->children->end()){
      CondNode* cn = *it;
      r = this->binary_fun(r, cn->evaluate(patternInfo, testInfo, testNode));

     it++;
    }
    return r;
  }
}

bool CondNode::equals(CondNode* cn){
  vsize_t nc = this->children->size();
  if (nc != cn->children->size()) return false;
  if (this->has_fixed_pattern_info != cn->has_fixed_pattern_info or (this->has_fixed_pattern_info and (this->fixed_pattern_info != cn->fixed_pattern_info))) return false;
  
  // TODO: compare actual values within fixed_field (not only pointer addresses)
  if (this->has_fixed_field != cn->has_fixed_field or (this->has_fixed_field and (this->fixed_field != cn->fixed_field))) return false;
  
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
        CondNode* cn_tmp = *it;
        r = r and (cn_tmp->equals(*it2));

        it++; 
        it2++;
      }
    }
    
    return r;
  }
}

std::string CondNode::field_toString(void* field)
{
  std::string* s;
  bool* b;
  vsize_t* n;
  uint8_t* i;
  
  switch (this->comparison){
    case bool_equals:
      b = static_cast<bool*>(field);
      return *b ? "true" : "false";
      
    case bool_false:      
    case bool_true:      
    case bool_test_true:
      return "";
      
    case vsizet_equals:
    case vsizet_gt:
    case vsizet_geq:
    case vsizet_lt:
    case vsizet_leq:
      n = static_cast<vsize_t*>(field);
      return std::to_string(*n);
      
    case str_contains:      
    case str_equals:
    case str_beginswith:
    case str_regex:
      s = static_cast<std::string*>(field);
      return *s;
      
    case uint8t_equals:      
    case uint8t_gt:
    case uint8t_geq:
    case uint8t_lt:
    case uint8t_leq:
      i = static_cast<std::uint8_t*>(field);
      return std::to_string((int) *i);
      
    default:
      std::cerr << "ERROR in node_info.cpp: unknown comparison_fun." << std::endl;
      return "";
  }
}

std::string CondNode::toString(NodeInfo* ni){
  std::string s;
  std::string r;
  
  if (this->children->size() == 0 and ni == NULL and not this->has_fixed_pattern_info and not this->has_fixed_field){
    std::cerr << "ERROR: Missing leaf node info." << std::endl;
    return "";
  }
  
  if (this->has_fixed_pattern_info){
    ni = this->fixed_pattern_info; 
  }
  
  switch (this->children->size()){
    case 0:
      s = desc_ComparisonFunEnum[this->comparison];
      if (not this->has_fixed_field and ni != NULL){
        r = this->field_toString(&((*ni).*(this->pattern_field)));
      }
      else {
        // Case: this->has_fixed_field is true
        r = this->field_toString(fixed_field);
      }
      
      if (r.length() != 0){
        s += ":" + r; 
      }
      return s;
    
    case 1:
      s = desc_UnOpEnum[this->unary_operator];
      s += "(";
      s += this->children->front()->toString(ni);
      s += ")";
      return s;
      
    default:
      s = desc_BinOpEnum[this->binary_operator];
      s += "(";
      s += this->children->front()->toString(ni);
      
      std::list<CondNode*>::iterator it = this->children->begin();
      it++;

      while(it != this->children->end()){
        CondNode* cn_tmp = *it;
        s += ", " + cn_tmp->toString(ni);

        it++;
      }
      s += ")";
      
      return s;
  }
}

void CondNode::add_pointer_usage(){
  this->n_pointer_usage++;
  std::list<CondNode*>::iterator it;

  for (it = this->children->begin(); it != this->children->end(); it++){
    (*it)->add_pointer_usage();
  }
}

bool CondNode::freeCondition(CondNode* cn, bool b1, bool b2){
  if (cn == NULL){
    return false;
  }
    
  bool to_free = false;
  cn->n_pointer_usage--;
  if (cn->n_pointer_usage == 0){
    to_free = true;
  }
  
  std::list< CondNode* >* children = cn->children;
  std::list<CondNode*>::iterator it = children->begin();

  while(it != cn->children->end()){
    CondNode::freeCondition(*it, b1, b2);
    it++;
  }

  if (to_free){
    delete cn->children;  
    
    // TODO: find a better way to malloc/new and free/delete fixed field
    if (cn->has_fixed_field){
      if (cn->fixed_field_is_new){
        switch (cn->comparison){
          case bool_equals:
            delete(static_cast<bool*>(cn->fixed_field));
            break;
            
          case bool_false:      
          case bool_true:      
          case bool_test_true:
            break;
            
          case vsizet_equals:
          case vsizet_gt:
          case vsizet_geq:
          case vsizet_lt:
          case vsizet_leq:
            delete(static_cast<vsize_t*>(cn->fixed_field));
            break;
            
          case str_contains:      
          case str_equals:
          case str_beginswith:
          case str_regex:
            delete(static_cast<std::string*>(cn->fixed_field));
            break;
            
          case uint8t_equals:      
          case uint8t_gt:
          case uint8t_geq:
          case uint8t_lt:
          case uint8t_leq:
            delete(static_cast<std::uint8_t*>(cn->fixed_field));
            break;
            
          default:
            std::cerr << "ERROR in node_info.cpp: unknown comparison_fun." << std::endl;
            break;
        }
      }
      else{
        free(cn->fixed_field); 
      }
    }
    delete(cn);
  }

  return to_free;
}

CondNodeToken::CondNodeToken(){

}

CondNodeToken::CondNodeToken(std::string str){
  vsize_t size = str.length();
  
  if (str == "("){
    this->type = "LP";
    this->value = "";
  }
  else if (str == ")"){
    this->type = "RP";
    this->value = "";
  }
  else if (str == "or"){
    this->type = "OR";
    this->value = "";
  }
  else if (str == "and"){
    this->type = "AND";
    this->value = "";
  }
  else if (str == "not"){
    this->type = "NOT";
    this->value = "";
  }
  else if (str == "==" or str == "!=" or str == ">=" or str == "<=" 
    or str == "<" or str == ">" or str == "is" or str == "contains"
    or str == "beginswith" or str == "regex"){
    this->type = "OP";
    this->value = str;
  }
  else if (str == "false" or str == "true" or str == "*" or str == "endbasicblock"  or str == "basicblockend"){
    this->type = "BOOL";
    this->value = str;
  }
  else {
    this->type = "W";
    this->value = str;
  }
}

bool CondNodeToken::is_operator_char(char c){
  switch (c){
    case '(':
    case ')':
    case '=':
    case '!':
    case '<':
    case '>':
      return true;
    default:
      return false;
  }
}


CondNodeParser::CondNodeParser(){
  this->has_next_token = false;
}


CondNode* CondNodeParser::parseCondNode(std::string str){
  CondNodeParser cnp = CondNodeParser();
  cnp.tokenize(str);
  cnp.advance();
  return cnp.expression();
}


void CondNodeParser::tokenize(std::string str){
  vsize_t i = 0;
  vsize_t size = str.length();
  vsize_t begin = 0;
  char token_delimiter = '\'';
  bool delimiter_used = false;
  
  /* States:
   * 0: no word began
   * 1: operator began
   * 2: word began
   */
  uint8_t state = 0;
  
  /* Types:
   * 0: blank
   * 1: operator char
   * 2: word char
   */
  uint8_t char_type;
  
  while (i < size){
    char c = str.at(i);
    if (c == ' '){
      char_type = 0; 
    }
    else if (CondNodeToken::is_operator_char(c)){
      char_type = 1; 
    }
    else {
      char_type = 2; 
    }
    
    if (state == 0){
      if (char_type == 1){
        begin = i;
        state = 1;
      }
      else if (char_type == 2){
        begin = i;
        state = 2;
        
        if (c == token_delimiter){
          delimiter_used = true; 
        }
      }
    }
    else if (state == 1){
      if (char_type == 0){
        CondNodeToken t = CondNodeToken(str.substr(begin, i-begin));
        this->tokens.push_back(t);
        state = 0;
      }
      else if (not delimiter_used and (c == ')' or c == '(')){
        // Parenthesis always end a token
        // It forces to tokenize then separately
        
        std::string s = "";
        s += c;
        CondNodeToken t = CondNodeToken(s);
        this->tokens.push_back(t);
        
        begin = i;
        state = 2;
      }
      else if (char_type == 2){
        CondNodeToken t = CondNodeToken(str.substr(begin, i-begin));
        this->tokens.push_back(t);

        begin = i;
        state = 2;
      }
    }
    else if (state == 2){
      if (not delimiter_used and char_type == 0){
        CondNodeToken t = CondNodeToken(str.substr(begin, i-begin));
        this->tokens.push_back(t);
        state = 0;
      }
      else if (delimiter_used and c == token_delimiter){
        CondNodeToken t = CondNodeToken();
        t.type = "W";
        t.value = str.substr(begin+1, i-begin-1);
        this->tokens.push_back(t);
        state = 0;
        delimiter_used = false;
      }
      else if (not delimiter_used and char_type == 1){
        CondNodeToken t = CondNodeToken(str.substr(begin, i-begin));
        this->tokens.push_back(t);
        begin = i;
        state = 1;
      }
    }
    
    if (i == size - 1 and (state == 1 or state == 2)){
      // Case: last character, end token
      CondNodeToken t = CondNodeToken(str.substr(begin, i-begin+1));
      this->tokens.push_back(t);
    }
    
    i++;
  }
}

std::string CondNodeParser::tokens_to_string(){
  std::string r = "";
  std::list<CondNodeToken>::iterator it = this->tokens.begin();
  while (it != this->tokens.end()){
    CondNodeToken t = *it;
    r += t.type + " - " + t.value + "\n";
    it++;
  }
  
  return r;
}



void CondNodeParser::advance(){
  if (this->tokens.size() != 0){
    this->current_token = next_token;
    this->next_token = this->tokens.front();
    this->tokens.pop_front();
    this->has_next_token = true;
  }
  else {
    this->current_token = next_token;
    this->has_next_token = false;
  }
}

bool CondNodeParser::accept(std::string expected_type){
  if (this->has_next_token and this->next_token.type == expected_type){    
    this->advance();
    return true;
  }
  else {
    return false;
  }
}

bool CondNodeParser::expect(std::string expected_type){
  bool r = this->accept(expected_type);
  
  if (not r){
    if (this->has_next_token){
      std::cerr << "WARNING: Expected " << expected_type << ", found " << this->next_token.type << " (" << this->next_token.value << ")." << std::endl;
    }
    else {
      std::cerr << "WARNING: End of expression reached." << std::endl;
    }
  }
  
  return r;
}

CondNode* CondNodeParser::expression(){
  CondNode* cn = this->term();
  bool children = false;
  
  while(this->accept("OR")){
    if (not children){
      std::list<CondNode*>* or_children = new std::list<CondNode*>();
      or_children->push_front(cn);
      cn = new CondNode(or_children);
      cn->binary_operator = BinOpEnum::logic_or;
    }
    
    cn->children->push_back(this->term());
  }
  
  return cn;
}

CondNode* CondNodeParser::term(){
  CondNode* cn = this->factor();
  bool children = false;
  
  while (this->accept("AND")){
    if (not children){
      std::list<CondNode*>* and_children = new std::list<CondNode*>();
      and_children->push_front(cn);
      cn = new CondNode(and_children);
      cn->binary_operator = BinOpEnum::logic_and;
    }
    
    cn->children->push_back(this->factor());
  }
  
  return cn;
}

CondNode* CondNodeParser::factor(){
  CondNode* cn;
  
  if (this->accept("LP")){
    cn = this->expression();
    bool r = this->expect("RP");
    
    if (not r){
      std::cerr << "WARNING: Could not parse condition (expected closing parenthesis). Defaulting condition to 'not true'." << std::endl;
      return new CondNode();
    }
  }
  else if (this->accept("BOOL")){
    cn = new CondNode();

    if (this->current_token.value == "endbasicblock" or this->current_token.value == "basicblockend"){
      cn->is_end_basic_block = true;
    }
    else if (this->current_token.value == "true" or this->current_token.value == "*"){
      cn->comparison = ComparisonFunEnum::bool_true;
    }
  }
  else if (this->accept("NOT")){
    std::list<CondNode*>* not_child = new std::list<CondNode*>();
    if (this->accept("LP")){
      not_child->push_front(this->expression());
      this->expect("RP");
    }
    else {
      not_child->push_front(this->factor());
    }
    cn = new CondNode(not_child, UnOpEnum::logic_not);
  }
  else if (this->accept("W")){
    std::string key = this->current_token.value; 
    
    bool r = this->expect("OP");
    if (not r){
      std::cerr << "WARNING: Could not parse condition (expected operand). Defaulting condition to 'not true'." << std::endl;
      return new CondNode();
    }
    std::string op = this->current_token.value;
    
    this->accept("W");
    std::string value = this->current_token.value;
    
    cn = new CondNode(key, op, value);
  }
  else {
    std::cerr << "WARNING: Could not parse condition. Defaulting condition to 'not true'." << std::endl;
    return new CondNode();
  }
  
  return cn;
}
