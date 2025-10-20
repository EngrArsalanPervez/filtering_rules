#include "node.h"
#include "bits.h"
// #include "enums.h"
#include "policy.h"
#include "rules.h"
#include "cond.h"

uint16_t total_nodes = 0;

const char* node_type_to_string(NodeType type) {
  switch (type) {
    case NOT:
      return "NOT";
    case AND:
      return "AND";
    case OR:
      return "OR";
    case COND:
      return "COND";
    default:
      return "-";
  }
}

const char* node_action_to_string(NodeAction type) {
  switch (type) {
    case ALLOW:
      return "ALLOW";
    case BLOCK:
      return "BLOCK";
    default:
      return "-";
  }
}

const char* node_field_to_string(NodeField type) {
  switch (type) {
    case src_ip:
      return "src_ip";
    case dst_ip:
      return "dst_ip";
    case src_port:
      return "src_port";
    case dst_port:
      return "dst_port";
    case application:
      return "application";
    case sub_protocol:
      return "sub_protocol";
    default:
      return "-";
  }
}

const char* node_function_pointer_to_string(NodeFunctionPointers type) {
  switch (type) {
    case ip_subnet:
      return "ip_subnet";
    case port_equal:
      return "port_equal";
    case port_range:
      return "port_range";
    case port_one_of:
      return "port_one_of";
    case application_equal:
      return "application_equal";
    case application_one_of:
      return "application_one_of";
    case sub_protocol_equal:
      return "sub_protocol_equal";
    case sub_protocol_one_of:
      return "sub_protocol_one_of";
    default:
      return "-\t";
  }
}

void print_node(struct Node* node) {
  printf(
      "Attribute=============Value====================ENUM====================="
      "===Binary\n");
  printf("id:\t\t\t%u\t\t\t-\t\t\t", node->rule_id);
  PRINT_BITS("", (uint16_t)node->rule_id, 16);

  printf("type\t\t\t%u\t\t\t%s\t\t\t", node->type,
         node_type_to_string(node->type));
  PRINT_BITS("", (uint8_t)node->type, 8);

  printf("action\t\t\t%u\t\t\t%s\t\t\t", node->action,
         node_action_to_string(node->action));
  PRINT_BITS("", (uint8_t)node->action, 8);

  printf("field\t\t\t%u\t\t\t%s\t\t\t", node->field,
         node_field_to_string(node->field));
  PRINT_BITS("", (uint8_t)node->field, 8);

  printf("function_pointer\t%u\t\t\t%s\t\t", node->function_pointer,
         node_function_pointer_to_string(node->function_pointer));
  PRINT_BITS("", (uint8_t)node->function_pointer, 8);

  printf("total_vargs:\t\t%u\t\t\t-\t\t\t", node->total_vargs);
  PRINT_BITS("", (uint16_t)node->total_vargs, 8);

  printf("varg_offset:\t\t%u\t\t\t-\t\t\t", node->varg_offset);
  PRINT_BITS("", (uint16_t)node->varg_offset, 16);

  printf("left_child_offset:\t%u\t\t\t-\t\t\t", node->left_child_offset);
  PRINT_BITS("", (uint16_t)node->left_child_offset, 16);

  printf("right_child_offset:\t%u\t\t\t-\t\t\t", node->right_child_offset);
  PRINT_BITS("", (uint16_t)node->right_child_offset, 16);

  uint16_t offset = node->varg_offset;
  for (uint8_t i = 0; i < node->total_vargs; i++) {
    uint8_t* varg_len = (uint8_t*)(g_bitstream + (offset / 8));

    printf("varg_%u_len:\t\t%u\t\t\t-\t\t\t", i, *varg_len);
    PRINT_BITS("", (uint8_t)(*varg_len), 8);

    uint8_t* varg_value = (uint8_t*)(g_bitstream + ((offset + 8) / 8));

    if (*varg_len == 8) {
      printf("varg_%u_value:\t\t%u\t\t\t-\t\t\t ", i, varg_value[0]);
    } else if (*varg_len == 16) {
      uint16_t value = varg_value[0];
      value = value << 8;
      value += varg_value[1];
      printf("varg_%u_value:\t\t%u\t\t\t-\t\t\t ", i, value);
    } else if (*varg_len == 32) {
      printf("varg_%u_value:\t\t%u.%u.%u.%u\t\t-\t\t\t ", i, varg_value[0],
             varg_value[1], varg_value[2], varg_value[3]);
    } else {
      printf("varg_%u_value:\t\t", i);
      char string[128] = {0};
      memcpy(string, varg_value, (*varg_len / 8));
      printf("%9s\t\t-\t\t\t ", string);
    }

    size_t len = (uint8_t)*varg_len;
    print_bitstream(varg_value, &len);
    offset += 8 + (*varg_len);
  }
}

void append_bits(char* bitstream, uint64_t value, int bits) {
  int len = strlen(bitstream);
  for (int i = bits - 1; i >= 0; i--) {
    bitstream[len++] = (value & (1ULL << i)) ? '1' : '0';
  }
  bitstream[len] = '\0';
}

void append_bytes(char* bitstream, uint8_t value) {
  for (int i = 7; i >= 0; i--) {
    strcat(bitstream, (value & (1 << i)) ? "1" : "0");
  }
}

void string_to_bitstream(const char* input, char* bitstream) {
  int pos = 0;
  for (size_t i = 0; i < strlen(input); i++) {
    unsigned char c = input[i];
    for (int bit = 7; bit >= 0; bit--) {
      bitstream[pos++] = (c & (1 << bit)) ? '1' : '0';
    }
  }
  bitstream[pos] = '\0';  // null terminate
}

void clear_file(void) {
  char query[512] = {0};
  sprintf(query, "echo -n '' > %s", BITSTREAM_FILE);
  int UNUSED ret = system(query);
}

void dump_stream(char* bitstream) {
  FILE* fp = fopen(BITSTREAM_FILE, "a");
  if (!fp) {
    printf("Error opening stream.bin");
    exit(1);
  }

  size_t len = strlen(bitstream);

  size_t UNUSED written = fwrite(bitstream, sizeof(char), len, fp);

  // printf("Written elements: %zu\n", written);

  fclose(fp);
}

void create_node(uint16_t rule_id,
                 uint8_t type,
                 uint8_t action,
                 uint8_t field,
                 uint8_t function_pointer,
                 uint8_t total_vargs,
                 uint16_t varg_offset,
                 uint16_t left_child_offset,
                 uint16_t right_child_offset) {
  char bitstream[512] = {0};

  // Apply endian swaps where necessary (16-bit fields)
  append_bits(bitstream, rule_id, 16);
  append_bits(bitstream, type, 8);
  append_bits(bitstream, action, 8);
  append_bits(bitstream, field, 8);
  append_bits(bitstream, function_pointer, 8);
  append_bits(bitstream, total_vargs, 8);
  append_bits(bitstream, varg_offset, 16);
  append_bits(bitstream, left_child_offset, 16);
  append_bits(bitstream, right_child_offset, 16);

  // printf("Final Bitstream:\n%s\n", bitstream);
  // printf("Total bits: %zu\n", strlen(bitstream));

  dump_stream(bitstream);
  total_nodes++;
}

// Convert vargs array into real bit representation
void vargs_to_bitstream(char* bitstream,
                        struct vargs_offset* vargs,
                        size_t count) {
  bitstream[0] = '\0';  // clear buffer

  for (size_t i = 0; i < count; i++) {
    // Add len (1 byte)
    append_bytes(bitstream, vargs[i].len);

    // Add each character byte
    for (size_t j = 0; j < (vargs[i].len / 8); j++) {
      append_bytes(bitstream, vargs[i].varg[j]);
    }
  }
}

void append_vargs(struct vargs_offset* vargs, uint16_t total_vargs) {
  char bitstream[2048] = {0};
  vargs_to_bitstream(bitstream, vargs, total_vargs);

  // printf("vargs_bitsteam:\n%s\n", bitstream);

  dump_stream(bitstream);
}

void print_nodes(void) {
  struct Node* node = NULL;
  for (uint16_t i = 0; i < total_nodes; i++) {
    node = (struct Node*)(g_bitstream + ((NODE_SIZE * i) / 8));
    node->rule_id = __builtin_bswap16(node->rule_id);
    node->varg_offset = __builtin_bswap16(node->varg_offset);
    node->left_child_offset = __builtin_bswap16(node->left_child_offset);
    node->right_child_offset = __builtin_bswap16(node->right_child_offset);
    print_node(node);
  }
}