#include "node_info.hpp"

bool ComparisonFunctions::bool_equals(void* a1, void* a2)
{
  bool* b1 = static_cast<bool*>(a1);
  bool* b2 = static_cast<bool*>(a2);
  
  return *b1 == *b2;
}

bool ComparisonFunctions::bool_test_true(void* a1, void* a2)
{
  bool* b2 = static_cast<bool*>(a2);
  
  return *b2 == true;
}

bool ComparisonFunctions::str_equals(void* a1, void* a2)
{
  std::string* s1 = static_cast<std::string *>(a1);
  std::string* s2 = static_cast<std::string *>(a2);
  
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


bool CondNode::evaluate(NodeInfo* pattern, NodeInfo* test)
{
  vsize_t nc = this->children->size();
  
  if (nc == 0){ 
   return this->comparison(&((*pattern).*(this->pattern_field)), &((*test).*(this->test_field)));
  }
  else if (nc == 1){
   return this->unary_operator(this->children->front()->evaluate(pattern, test)); 
  }
  else{
    // 2 or more children
    bool r = this->children->front()->evaluate(pattern, test);
    
    std::list<CondNode*>::iterator it = this->children->begin();
    it++;
    
    while(it != this->children->end()){
      r = this->binary_operator(r, (*it)->evaluate(pattern, test));
      
     it++; 
    }
    return r;
  }
}
