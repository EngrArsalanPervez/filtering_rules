#ifndef _BITS_H
#define _BITS_H

#include "headers.h"

// Global variables
extern uint8_t* g_bytestream;
extern size_t g_bytestream_size;

extern uint8_t* g_bitstream;
extern size_t g_bitstream_size;  // Number of bits stored

#define BITSTREAM_FILE "bitstream.bin"

#define PRINT_BITS(tag, value, bits)        \
  do {                                      \
    printf("%s (0b ", tag);                 \
    for (int i = (bits) - 1; i >= 0; i--) { \
      printf("%d", ((value) >> i) & 1);     \
    }                                       \
    printf(")\n");                          \
  } while (0)

int fetch_bitstream(void);
void free_streams(void);
void print_bitstream(const uint8_t* data, size_t* bit_len);
void print_bytestream(const uint8_t* data, size_t* bit_len);

#endif