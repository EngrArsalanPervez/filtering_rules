#include "cond.h"
#include "bits.h"
#include "enums.h"
#include "node.h"
#include "policy.h"
#include "rules.h"

int match_ip_subnet(uint8_t* value1, uint8_t* value2) {
  for (uint8_t i = 0; i < 4; i++)
    if (value1[i] != value2[i])
      return 0;
  return 1;
}
int match_port_equal(uint8_t* value1, uint8_t* value2) {
  for (uint8_t i = 0; i < 2; i++)
    if (value1[i] != value2[i])
      return 0;
  return 1;
}
int match_port_range(uint8_t* value1, uint8_t* value2) {
  if (value1 && value2)
    return 0;
  return 0;
}
int match_port_one_of(uint8_t* value1, uint8_t* value2) {
  if (value1 && value2)
    return 0;
  return 0;
}
int match_application_equal(uint8_t* value1, uint8_t* value2) {
  for (uint8_t i = 0; i < 2; i++)
    if (value1[i] != value2[i])
      return 0;
  return 1;
}
int match_application_one_of(uint8_t* value1, uint8_t* value2) {
  if (value1 && value2)
    return 0;
  return 0;
}
int match_sub_protocol_equal(uint8_t* value1, uint8_t* value2) {
  if (value1[0] != value2[0])
    return 0;
  return 1;
}
int match_sub_protocol_one_of(uint8_t* value1, uint8_t* value2) {
  if (value1 && value2)
    return 0;
  return 0;
}