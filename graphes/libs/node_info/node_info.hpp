#ifndef NODEINFO_HPP
#define NODEINFO_HPP

#include <list>
#include <string>
#include <functional>
#include <iostream>
#include <assert.h>

extern "C" {
#include "ga_types.h"
}

class NodeInfo {
public:
  NodeInfo();
  
  std::string toString();
  
  bool matches(NodeInfo* test);
  bool equals(NodeInfo* ni);

  // Node information (pattern and test)
  std::string inst_str;
  
  bool is_root;
  
  bool has_address;
  vsize_t address;
  
  
  // Only for test
  // TODO: it should be updated with node, do not use for now
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

enum ComparisonFunEnum {
  str_equals,
  str_contains,
  bool_true,
  bool_false,
  bool_test_true,
  bool_equals,
  vsizet_equals,
  uint8t_equals,
  uint8t_gt
};

static const char * desc_ComparisonFunEnum[] = {
  "str_equals",
  "str_contains",
  "bool_true",
  "bool_false",
  "bool_test_true",
  "bool_equals",
  "vsizet_equals",
  "uint8t_equals",
  "uint8t_gt"
};

enum UnOpEnum {
  logical_not
};

static const char * desc_UnOpEnum[] = {
  "logical_not"
};

enum BinOpEnum {
  logical_or,
  logical_and
};

static const char * desc_BinOpEnum[] = {
  "logical_or",
  "logical_and"
};

class ComparisonFunctions{
public:
  static bool str_equals(void*, void*);
  static bool str_contains(void*, void*);
//   static bool str_begins_with(void*, void*);
  
  static bool bool_true(void*, void*);
  static bool bool_false(void*, void*);
  static bool bool_test_true(void*, void*);
  static bool bool_equals(void*, void*);
  
  static bool vsizet_equals(void*, void*);
  static bool uint8t_equals(void*, void*);
  static bool uint8t_gt(void*, void*); // pattern >= test ?
};

class CondNode{
public:
  // Evaluate:
  // Many (2+) children: returns binary_operator(binary_operator(c1, c2), c3) ...
  // One child: returns unary_operator(c)
  // No children: returns comparison(pattern_field, pattern, test_field, test)
  
  CondNode();
  CondNode(std::list<CondNode*>*, UnOpEnum);
  CondNode(std::list<CondNode*>*, BinOpEnum);
  
  std::list<CondNode*>* children;
  UnOpEnum unary_operator;
  BinOpEnum binary_operator;
  
  bool unary_fun(bool);
  bool binary_fun(bool, bool);
  
  void* NodeInfo::* pattern_field;
  void* NodeInfo::* test_field;
  
  bool comparison_fun(void*, void*);
  ComparisonFunEnum comparison;
  
  bool evaluate(NodeInfo* pattern, NodeInfo* test);
  
  bool equals(CondNode* cn);
  
  std::string toString();
};

#endif