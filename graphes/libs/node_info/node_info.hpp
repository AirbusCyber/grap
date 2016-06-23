#ifndef NODEINFO_HPP
#define NODEINFO_HPP

#include <list>
#include <string>
#include <functional>
#include <iostream>
#include <assert.h>
#include <boost/concept_check.hpp>
#include "ga_types.hpp"
#include <iso646.h> // defines "or", "and" as alternatives to ||, &&
#include <boost/regex.hpp>

class NodeInfo {
public:
  NodeInfo();
  
  std::string toString();
  
  bool equals(NodeInfo* ni);
  
  // Node information (pattern and test)
  std::string inst_str;
  std::string opcode;
  
  bool is_root;
  
  bool has_address;
  vsize_t address;
  
  
  // Those fields are written at the end of the .dot parsing
  // They should be updated if the graph is modified later
  vsize_t childrenNumber;
  vsize_t fathersNumber;
  
  // Only for pattern
  vsize_t minChildrenNumber;
  bool has_maxChildrenNumber;
  vsize_t maxChildrenNumber;
  
  vsize_t minFathersNumber;
  bool has_maxFathersNumber;
  vsize_t maxFathersNumber;
  
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
  str_beginswith,
  str_regex,
  bool_true,
  bool_false,
  bool_test_true,
  bool_equals,
  vsizet_equals,
  vsizet_gt,
  vsizet_geq,
  vsizet_lt,
  vsizet_leq,
  uint8t_equals,
  uint8t_gt,
  uint8t_geq,
  uint8t_lt,
  uint8t_leq
};

static const std::string desc_ComparisonFunEnum[] = {
// str_equals:
  "str_equals",
// str_contains:
  "str_contains",
// str_beginswith:
  "str_beginswith",
// str_regex:
  "str_regex",
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
// vsizet_gt:
  "vsizet_gt",
// vsizet_geq:
  "vsizet_geq",
// vsizet_lt:
  "vsizet_lt",
// vsizet_leq:
  "vsizet_leq",
// uint8t_equals:
  "uint8t_equals",
// uint8t_gt:
  "uint8t_gt",
// uint8t_geq:
  "uint8t_geq",
// uint8t_lt:
  "uint8t_lt",
// uint8t_leq:
  "uint8t_leq"
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
  static bool str_beginswith(void*, void*);
  static bool str_regex(void*, void*);
  
  static bool bool_true(void*, void*);
  static bool bool_false(void*, void*);
  static bool bool_test_true(void*, void*);
  static bool bool_equals(void*, void*);
  
  static bool vsizet_equals(void*, void*);
  static bool vsizet_gt(void*, void*); // pattern >= test ?
  static bool vsizet_geq(void*, void*);
  static bool vsizet_lt(void*, void*);
  static bool vsizet_leq(void*, void*);
  static bool uint8t_equals(void*, void*);
  static bool uint8t_gt(void*, void*);
  static bool uint8t_geq(void*, void*);
  static bool uint8t_lt(void*, void*);
  static bool uint8t_leq(void*, void*);
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
  CondNode(std::string key, std::string op, std::string value);
  
  std::list<CondNode**>* children;
  UnOpEnum unary_operator;
  BinOpEnum binary_operator;
  
  bool unary_fun(bool);
  bool binary_fun(bool, bool);
  
  void* NodeInfo::* pattern_field;
  void* NodeInfo::* test_field;
  
  bool has_fixed_pattern_info;
  NodeInfo* fixed_pattern_info;
  
  bool has_fixed_field;
  void* fixed_field;
  
  bool comparison_fun(void*, void*);
  ComparisonFunEnum comparison;
  
  bool evaluate(NodeInfo* pattern, NodeInfo* test);
  
  bool equals(CondNode** cn);
  
  std::string toString(NodeInfo*);
  std::string field_toString(void*);
  
  static void freeCondition(CondNode** cn, bool delete_condition, bool free_pointer);
};

class CondNodeToken{
public:
  std::string type;
  std::string value;
  
  CondNodeToken();
  CondNodeToken(std::string);
  static bool is_operator_char(char);
};

class CondNodeParser{
public:
  static CondNode** parseCondNode(std::string);
  CondNodeParser();
  
private:
  std::list<CondNodeToken> tokens;
  bool has_next_token;
  CondNodeToken current_token;
  CondNodeToken next_token;
  
  void advance();
  bool accept(std::string expected_type);
  void expect(std::string expected_type);
  
  CondNode** expression();
  CondNode** term();
  CondNode** factor();
  
  void tokenize(std::string); 
  
  std::string tokens_to_string();
};

#endif
