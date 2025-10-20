#include "policy.h"
#include "bits.h"
#include "enums.h"
// #include "node.h"
#include "cond.h"
#include "rules.h"

extern uint16_t total_nodes;

void create_policy(void) {
  clear_file();
  create_rule1();
  create_rule2();
  create_rule3();
  create_vargs();
}

typedef int (*condition_fn)(uint8_t* value1, uint8_t* value2);
condition_fn condition_table[] = {
    [ip_subnet] = match_ip_subnet,
    [port_equal] = match_port_equal,
    [port_range] = match_port_range,
    [application_equal] = match_application_equal,
    [sub_protocol_equal] = match_sub_protocol_equal,
};

uint8_t* get_field_value(NodeField field, metadata* meta) {
  switch (field) {
    case src_ip: {
      return (uint8_t*)&meta->src_ip;
    }
    case dst_ip: {
      return (uint8_t*)&meta->dst_ip;
    }
    case src_port: {
      return (uint8_t*)&meta->src_port;
    }
    case dst_port: {
      return (uint8_t*)&meta->dst_port;
    }
    case application: {
      return (uint8_t*)&meta->application;
    }
    case sub_protocol: {
      return (uint8_t*)&meta->sub_protocol;
    }
    default:
      return NULL;
  }
}

int check_condition(struct Node* node, metadata* meta) {
  uint8_t* value1 = get_field_value(node->field, meta);

  uint16_t offset = node->varg_offset;
  uint8_t* varg_len = g_bitstream + (offset / 8);
  uint8_t* varg_value = g_bitstream + ((offset + 8) / 8);

  uint8_t value8;
  uint16_t value16;
  uint32_t value32;
  uint8_t* value2 = NULL;

  switch (*varg_len) {
    case 8:
      memcpy(&value8, varg_value, sizeof(uint8_t));
      value2 = (uint8_t*)&value8;
      break;
    case 16:
      memcpy(&value16, varg_value, sizeof(uint16_t));
      value16 = ntohs(value16);
      value2 = (uint8_t*)&value16;
      break;
    case 32:
      memcpy(&value32, varg_value, sizeof(uint32_t));
      value32 = ntohl(value32);
      value2 = (uint8_t*)&value32;
      break;
    default:
      printf("Unknown varg_len = %u\n", *varg_len);
      return 0;
  }

  return condition_table[node->function_pointer](value1, value2);
}

int dfs_preorder(uint8_t node_type,
                 uint16_t offset,
                 size_t* index,
                 metadata* meta) {
  if (offset == 0 && node_type == CHILD_NODE)
    return 0;

  struct Node* node = (struct Node*)(g_bitstream + (offset / 8));
  node->rule_id = __builtin_bswap16(node->rule_id);
  node->varg_offset = __builtin_bswap16(node->varg_offset);
  node->left_child_offset = __builtin_bswap16(node->left_child_offset);
  node->right_child_offset = __builtin_bswap16(node->right_child_offset);

  *index += NODE_SIZE;

  // print_node(node);

  switch (node->type) {
    case COND: {
      int result = check_condition(node, meta);
      printf("  -> COND check: field=%u result=%s\n", node->field,
             result ? "TRUE" : "FALSE");
      return result;
    }
    case NOT: {
      int left = dfs_preorder(CHILD_NODE, node->left_child_offset, index, meta);
      return !left;
    }
    case AND: {
      int left = dfs_preorder(CHILD_NODE, node->left_child_offset, index, meta);
      int right =
          dfs_preorder(CHILD_NODE, node->right_child_offset, index, meta);
      return left && right;
    }
    case OR: {
      int left = dfs_preorder(CHILD_NODE, node->left_child_offset, index, meta);
      int right =
          dfs_preorder(CHILD_NODE, node->right_child_offset, index, meta);
      return left || right;
    }
    default:
      printf("Unknown node type: %u\n", node->type);
      return 0;
  }
}

void evaluate_rules(metadata* meta) {
  size_t index = 0;
  uint16_t rule_id = 0;

  for (uint16_t i = 0; i < MAX_RULES; i++) {
    rule_id = g_bitstream[index / 8];
    rule_id = rule_id << 8;
    rule_id += g_bitstream[(index / 8) + 1];

    printf("\n=== Evaluating Rule %u (offset=%lu/%lu) ===\n", rule_id, index,
           g_bitstream_size);

    int matched = dfs_preorder(ROOT_NODE, index, &index, meta);

    if (matched) {
      printf("✅ Rule %d matched. Stopping traversal.\n", rule_id);
      return;
    } else {
      printf("❌ No rules matched after evaluating last rule: %u.\n", rule_id);
    }
  }
}