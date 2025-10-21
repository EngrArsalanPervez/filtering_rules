#ifndef _NODE_H
#define _NODE_H

#include "headers.h"
#include "enums.h"

#define NODE_SIZE 104
struct __attribute__((__packed__)) Node {
  uint16_t rule_id;
  uint8_t type;
  uint8_t action;
  uint8_t field;
  uint8_t function_pointer;
  uint8_t total_vargs;
  uint16_t varg_offset;
  uint16_t left_child_offset;
  uint16_t right_child_offset;
};

struct vargs_offset {
  uint8_t len;
  uint8_t* varg;
};

void print_node(struct Node* node);
void clear_file(void);
const char* node_type_to_string(NodeType type);
void append_vargs(struct vargs_offset* vargs, uint16_t total_vargs);
void create_node(uint16_t rule_id,
  uint8_t type,
  uint8_t action,
  uint8_t field,
  uint8_t function_pointer,
  uint8_t total_vargs,
  uint16_t varg_offset,
  uint16_t left_child_offset,
  uint16_t right_child_offset);
void print_nodes(void);
const char* node_field_to_string(NodeField type);

#endif  // _NODE_H
