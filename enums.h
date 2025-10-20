#ifndef _ENUMS_H
#define _ENUMS_H

#include "headers.h"

#define ROOT_NODE 0
#define CHILD_NODE 1

typedef enum { NOT = 0, AND = 1, OR = 2, COND = 3 } NodeType;
typedef enum { BLOCK = 0, ALLOW = 1 } NodeAction;

typedef enum { DASH = 99 } NodeDash;

typedef enum {
  src_ip = 0,
  dst_ip = 1,
  src_port = 2,
  dst_port = 3,
  application = 4,
  sub_protocol = 5,
} NodeField;

typedef enum {
  ip_subnet = 0,
  port_equal = 1,
  port_range = 2,
  port_one_of = 3,
  application_equal = 4,
  application_one_of = 5,
  sub_protocol_equal = 6,
  sub_protocol_one_of = 7,
} NodeFunctionPointers;

typedef enum {
  DPI_APP_FACEBOOK = 0,
  DPI_APP_YOUTUBE = 1,
  /* ... */
} NodeApplication;
typedef enum { DPI_PROTO_QUIC = 0, /* ... */ } NodeSubProto;

#define NODE_TYPE(n) ((enum NodeType)((n)->type))
#define NODE_ACTION(n) ((enum NodeAction)((n)->action))
#define NODE_FIELD(n) ((enum NodeField)((n)->field))
#define NODE_FUNCTION_POINTER(n) \
  ((enum NodeFunctionPointers)((n)->function_pointer))

#endif