#ifndef NODEINFO_HPP
#define NODEINFO_HPP

#include <list>
#include <string>
#include <functional>
#include <iostream>
#include <assert.h>
#include "ga_types.hpp"
#include <iso646.h> // defines "or", "and" as alternatives to ||, && ; alternative: don't use them !

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
  // TODO: it should be updated with node (or be pointers ?), do not use for now
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
  bool lazyRepeat;
  
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

static const std::string desc_ComparisonFunEnum[] = {
// str_equals:
  "str_equals",
// str_contains:
  "str_contains",
// bool_true:
  "true",
// bool_false:
  "false",
// bool_test_true:
  "bool_test_true",
// bool_equals:
  "bool_equals",
// vsizet_equals:
  "vsizet_equals",
// uint8t_equals:
  "uint8t_equals",
// uint8t_gt:
  "uint8t_gt"
};

enum UnOpEnum {
  logic_not
};

static const std::string desc_UnOpEnum[] = {
// logical_not:
  "not"
};

enum BinOpEnum {
  logic_or,
  logic_and
};

static const std::string desc_BinOpEnum[] = {
// logical_or:
  "or",
// logical_and:
  "and"
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
  CondNode(std::list<CondNode**>* cn);
  CondNode(std::list<CondNode**>*, UnOpEnum);
  CondNode(std::list<CondNode**>*, BinOpEnum);
  
  std::list<CondNode**>* children;
  UnOpEnum unary_operator;
  BinOpEnum binary_operator;
  
  bool unary_fun(bool);
  bool binary_fun(bool, bool);
  
  void* NodeInfo::* pattern_field;
  void* NodeInfo::* test_field;
  
  bool has_fixed_pattern_info;
  NodeInfo* fixed_pattern_info;
  
  bool comparison_fun(void*, void*);
  ComparisonFunEnum comparison;
  
  bool evaluate(NodeInfo* pattern, NodeInfo* test);
  
  bool equals(CondNode** cn);
  
  std::string toString(NodeInfo*);
  std::string field_toString(NodeInfo*);
  
  static void freeCondition(CondNode** cn, bool delete_condition, bool free_pointer);
};

#endif
