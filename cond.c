#include "cond.h"
#include "bits.h"
#include "enums.h"
#include "node.h"
#include "policy.h"
#include "rules.h"

int match_ip_subnet(uint8_t* value1, uint8_t* value2, uint8_t* bytes) {
  for (uint8_t i = 0; i < (*bytes); i++) {
    if (value1[(*bytes) - i - 1] != value2[i])
      return FALSE;
  }
  return TRUE;
}
int match_port_equal(uint8_t* value1, uint8_t* value2, uint8_t* bytes) {
  for (uint8_t i = 0; i < (*bytes); i++) {
    if (value1[(*bytes) - i - 1] != value2[i])
      return FALSE;
  }
  return TRUE;
}
int match_port_range(uint8_t* value1, uint8_t* value2, UNUSED uint8_t* bytes) {
  if (value1 && value2)
    return FALSE;
  return FALSE;
}
int match_port_one_of(uint8_t* value1, uint8_t* value2, uint8_t* bytes) {
  for (uint8_t i = 0; i < (*bytes); i += 2) {
    if (value1[1] == value2[i] && value1[0] == value2[i + 1]) {
      return TRUE;
    }
  }
  return FALSE;
}
int match_application_equal(uint8_t* value1,
                            uint8_t* value2,
                            UNUSED uint8_t* bytes) {
  if (value1[1] == value2[0] && value1[0] == value2[1])
    return TRUE;
  return FALSE;
}
int match_application_one_of(uint8_t* value1, uint8_t* value2, uint8_t* bytes) {
  for (uint8_t i = 0; i < (*bytes); i = i + 2) {
    if (value1[1] == value2[i] && value1[0] == value2[i + 1])
      return TRUE;
  }
  return FALSE;
}
int match_sub_protocol_equal(uint8_t* value1,
                             uint8_t* value2,
                             UNUSED uint8_t* bytes) {
  if (value1[0] == value2[0])
    return TRUE;
  return FALSE;
}
int match_sub_protocol_one_of(uint8_t* value1,
                              uint8_t* value2,
                              uint8_t* bytes) {
  for (uint8_t i = 0; i < (*bytes); i++) {
    if (value1[0] == value2[i])
      return TRUE;
  }
  return FALSE;
}