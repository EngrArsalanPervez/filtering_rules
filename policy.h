#ifndef _POLICY_H
#define _POLICY_H

#include "headers.h"
#include "node.h"

typedef struct {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t application;
  uint16_t sub_protocol;
} metadata;

void create_policy(void);
void evaluate_rules(metadata* meta);
#endif