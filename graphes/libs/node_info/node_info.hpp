#include <list>
#include <string>
#include <functional>
#include <iostream>

extern "C" {
#include "ga_types.h"
}

class NodeInfo {
public:
  std::string toString();
  
  bool matches(NodeInfo* test);
  bool equals(NodeInfo* ni);

  // Node information (pattern and test)
  std::string inst_str;
  
  bool is_root;
  
  bool has_address;
  vsize_t address;
  
  
  // Only for test
  uint8_t childrenNumber;
  uint8_t fathersNumber;
  
  // Only for pattern
  uint8_t minChildrenNumber;
  bool has_maxChildrenNumber;
  uint8_t maxChildrenNumber;
  
  uint8_t minFathersNumber;
  bool has_maxFathersNumber;
  uint8_t maxFathersNumber;
  
  vsize_t minRepeat;
  bool has_maxRepeat;
  vsize_t maxRepeat;
  
  bool get;
  std::string getid;
};

class ComparisonFunctions{
public:
  static bool str_equals(void*, void*);
//   static bool str_contains(void*, void*);
//   static bool str_begins_with(void*, void*);
  
  static bool bool_test_true(void*, void*);
  static bool bool_equals(void*, void*);
  
  static bool vsizet_equals(void*, void*);
  static bool uint8t_equals(void*, void*);
  static bool uint8t_gt(void*, void*); // pattern >= test ?
};

class CondNode{
public:
  // Evaluate:
  // Two children: returns binary_operator(c1, c2)
  // One child: returns unary_operator(c)
  // No children: returns comparison(pattern_field, pattern, test_field, test)
  
  std::list<CondNode*>* children;
  std::function<bool(bool, bool)> binary_operator;
  std::function<bool(bool)> unary_operator;
  
  void* NodeInfo::* pattern_field;
  void* NodeInfo::* test_field;
  std::function<bool(void*, void*)> comparison;
  
  bool evaluate(NodeInfo* pattern, NodeInfo* test);
};