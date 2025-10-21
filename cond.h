#ifndef _COND_H
#define _COND_H

#include "headers.h"

int match_ip_subnet(uint8_t* value1, uint8_t* value2, uint8_t* bytes);
int match_port_equal(uint8_t* value1, uint8_t* value2, uint8_t* bytes);
int match_port_range(uint8_t* value1, uint8_t* value2, uint8_t* bytes);
int match_port_one_of(uint8_t* value1, uint8_t* value2, uint8_t* bytes);
int match_application_equal(uint8_t* value1, uint8_t* value2, uint8_t* bytes);
int match_application_one_of(uint8_t* value1, uint8_t* value2, uint8_t* bytes);
int match_sub_protocol_equal(uint8_t* value1, uint8_t* value2, uint8_t* bytes);
int match_sub_protocol_one_of(uint8_t* value1, uint8_t* value2, uint8_t* bytes);

#endif