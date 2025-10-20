#include "rules.h"
#include "bits.h"
#include "enums.h"
#include "node.h"
#include "policy.h"
#include "cond.h"

// #define NODE_SIZE 104
// struct __attribute__((__packed__)) Node {
//   uint16_t rule_id;
//   uint8_t type;
//   uint8_t action;
//   uint8_t field;
//   uint8_t function_pointer;
//   uint8_t total_vargs;
//   uint16_t varg_offset;
//   uint16_t left_child_offset;
//   uint16_t right_child_offset;
// };

void create_vargs(void) {
  struct vargs_offset vargs[] = {
      {32, (uint8_t[]){192, 168, 0, 1}},
      {32, (uint8_t[]){172, 16, 0, 1}},
      {16, (uint8_t[]){0, 0}},
      {32, (uint8_t[]){12, 12, 12, 12}},
      {16, (uint8_t[]){(8080 >> 8) & 0xFF, 8080 & 0xFF}},
      {32, (uint8_t[]){11, 11, 11, 11}},
      {16, (uint8_t[]){0, 1}},
      {16, (uint8_t[]){0, 0}},
      {16, (uint8_t[]){0, 1}},
      {8, (uint8_t[]){0}},
      {32, (uint8_t[]){5, 5, 5, 5}},

  };
  uint16_t total_vargs = sizeof(vargs) / sizeof(vargs[0]);
  append_vargs(vargs, total_vargs);
}

void create_rule1(void) {
  uint16_t rule_id = 1;
  /*

  Tree
  ===================================================================
                            [AND]
                            /  \
                        [OR]   [application==facebook]
                        /  \
  [src_ip==192.168.0.1/24]     [dst_ip==172.16.0.1/24]

  Sequence
  ===================================================================
  [AND, OR, srcIP==192.168.0.1, dst_ip==172.16.0.1, application==facebook]

  */

  create_node(rule_id, AND, ALLOW, DASH, DASH, 0, 0, (NODE_SIZE * 1),
              (NODE_SIZE * 4));
  create_node(rule_id, OR, DASH, DASH, DASH, 0, 0, (NODE_SIZE * 2),
              (NODE_SIZE * 3));
  create_node(rule_id, COND, DASH, src_ip, ip_subnet, 1, ((NODE_SIZE * 21) + 0),
              0, 0);
  create_node(rule_id, COND, DASH, dst_ip, ip_subnet, 1,
              ((NODE_SIZE * 21) + 40), 0, 0);
  create_node(rule_id, COND, DASH, application, application_equal, 1,
              ((NODE_SIZE * 21) + 80), 0, 0);
}

void create_rule2(void) {
  uint16_t rule_id = 2;
  /*

  Tree
  ===================================================================
                           [AND]
                          /     \
                    [AND]       [NOT]
                    /    \           ─────────────────────────┐
                [AND]   [src_ip=11.11.11.0/16]  [application==YouTube]
                /    \
[dst_ip==12.12.12.12] [dst_port==8080]


  Sequence
  ===================================================================
[AND, AND, AND, dst_ip==12.12.12.12, dst_port==8080, src_ip=11.11.11.0/16, NOT,
application==YouTube]


  */

  create_node(rule_id, AND, ALLOW, DASH, DASH, 0, 0, (NODE_SIZE * 6),
              (NODE_SIZE * 11));
  create_node(rule_id, AND, DASH, DASH, DASH, 0, 0, (NODE_SIZE * 7),
              (NODE_SIZE * 10));
  create_node(rule_id, AND, DASH, DASH, DASH, 0, 0, (NODE_SIZE * 8),
              (NODE_SIZE * 9));
  create_node(rule_id, COND, DASH, dst_ip, ip_subnet, 1,
              ((NODE_SIZE * 21) + 104), 0, 0);
  create_node(rule_id, COND, DASH, dst_port, port_equal, 1,
              ((NODE_SIZE * 21) + 144), 0, 0);
  create_node(rule_id, COND, DASH, src_ip, ip_subnet, 1,
              ((NODE_SIZE * 21) + 168), 0, 0);
  create_node(rule_id, NOT, DASH, DASH, DASH, 0, 0, (NODE_SIZE * 12), 0);
  create_node(rule_id, COND, DASH, application, application_equal, 1,
              ((NODE_SIZE * 21) + 208), 0, 0);
}

void create_rule3(void) {
  uint16_t rule_id = 3;
  /*

  Tree
  ===================================================================
                      [AND]
                     /     \
                 [OR]       [NOT]
                /    \ \ \      \
[application==facebook]   \    [src_ip=5.5.5.5/8]
                           \
                          [AND]
                          /    \
              [application==Youtube] [sub_proto==QUIC]



  Sequence
  ===================================================================
[AND, OR, application==facebook, AND, application==Youtube, sub_proto==QUIC,
NOT, src_ip=10.0.0.0/8]



  */

  create_node(rule_id, AND, ALLOW, DASH, DASH, 0, 0, (NODE_SIZE * 14),
              (NODE_SIZE * 19));
  create_node(rule_id, OR, DASH, DASH, DASH, 0, 0, (NODE_SIZE * 15),
              (NODE_SIZE * 16));
  create_node(rule_id, COND, DASH, application, application_equal, 1,
              ((NODE_SIZE * 21) + 232), 0, 0);
  create_node(rule_id, AND, DASH, DASH, DASH, 0, 0, (NODE_SIZE * 17),
              (NODE_SIZE * 18));
  create_node(rule_id, COND, DASH, application, application_equal, 1,
              ((NODE_SIZE * 21) + 256), 0, 0);
  create_node(rule_id, COND, DASH, sub_protocol, sub_protocol_equal, 1,
              ((NODE_SIZE * 21) + 280), 0, 0);
  create_node(rule_id, NOT, DASH, DASH, DASH, 0, 0, (NODE_SIZE * 20), 0);
  create_node(rule_id, COND, DASH, src_ip, ip_subnet, 1, ((NODE_SIZE * 21) + 296),
              0, 0);
}