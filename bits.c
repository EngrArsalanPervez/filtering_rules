#include "bits.h"
#include "enums.h"
#include "node.h"
#include "policy.h"
#include "rules.h"
#include "cond.h"

// Global variables
uint8_t* g_bytestream = NULL;
size_t g_bytestream_size = 0;

// Global bitstream
uint8_t* g_bitstream = NULL;
size_t g_bitstream_size = 0;  // Number of bits stored

// Function to read a binary file into global buffer
int read_bytestream(const char* filename) {
  FILE* file = fopen(filename, "rb");
  if (!file) {
    perror("Failed to open file");
    return -1;
  }

  // Get file size
  fseek(file, 0, SEEK_END);
  g_bytestream_size = ftell(file);
  rewind(file);

  // Allocate memory
  g_bytestream = (uint8_t*)malloc(g_bytestream_size);
  if (!g_bytestream) {
    perror("Memory allocation failed");
    fclose(file);
    return -1;
  }

  // Read file into buffer
  size_t read_bytes = fread(g_bytestream, 1, g_bytestream_size, file);
  fclose(file);

  if (read_bytes != g_bytestream_size) {
    perror("Failed to read complete file");
    free(g_bytestream);
    g_bytestream = NULL;
    g_bytestream_size = 0;
    return -1;
  }

  return 0;  // Success
}

// Convert g_bytestream into g_bitstream
void convert_bytestream_to_bitstream(void) {
  if (!g_bytestream || g_bytestream_size == 0) {
    printf("Bytestream is empty.\n");
    return;
  }

  // First count how many 0 or 1 values there are
  size_t bit_count = 0;
  for (size_t i = 0; i < g_bytestream_size; i++) {
    if (g_bytestream[i] == 0x30 || g_bytestream[i] == 0x31) {
      bit_count++;
    }
  }

  if (bit_count == 0)
    return;

  g_bitstream_size = bit_count + 0;
  size_t byte_count = (bit_count + 7) / 8;        // Number of bytes needed
  g_bitstream = (uint8_t*)calloc(byte_count, 1);  // Initialize to 0

  if (!g_bitstream) {
    perror("Failed to allocate bitstream");
    g_bitstream_size = 0;
    return;
  }

  size_t bit_index = 0;
  for (size_t i = 0; i < g_bytestream_size; i++) {
    uint8_t val = g_bytestream[i];
    if (val != 0x30 && val != 0x31)
      continue;

    uint8_t bit = val - 0x30;  // Convert ASCII to 0/1
    size_t byte_pos = bit_index / 8;
    size_t bit_pos = 7 - (bit_index % 8);  // MSB first
    g_bitstream[byte_pos] |= (bit << bit_pos);
    bit_index++;
  }
}

void print_bytestream(const uint8_t* data, size_t* bit_len) {
  if (!data || (*bit_len) == 0) {
    printf("bytestream is empty.\n");
    return;
  }

  printf("(0B ");
  for (size_t i = 0; i < (*bit_len); i++) {
    printf("%02X ", data[i]);  // Hexadecimal (use %u for decimal)
    if ((i + 1) % 16 == 0) {
      printf("\n");  // Newline every 16 bytes
    }
  }
  printf("\n");
}

void print_bitstream(const uint8_t* data, size_t* bit_len) {
  if (!data || (*bit_len) == 0) {
    printf("Bitstream is empty.\n");
    return;
  }
  printf("(0b ");
  for (size_t i = 0; i < (*bit_len); i++) {
    size_t byte_index = i / 8;
    size_t bit_index = 7 - (i % 8);  // MSB first
    uint8_t bit = (data[byte_index] >> bit_index) & 1;
    printf("%d", bit);
  }
  printf(")\n");
}

int fetch_bitstream(void) {
  if (read_bytestream(BITSTREAM_FILE) != 0) {
    return 1;
  }

  // print_bytestream(g_bytestream, &g_bytestream_size);

  convert_bytestream_to_bitstream();

  // print_bitstream(g_bitstream, &g_bitstream_size);

  return 0;
}

void free_bytestream() {
  // Free the global buffer when done
  free(g_bytestream);
  g_bytestream = NULL;
  g_bytestream_size = 0;
}

void free_bitstream() {
  // Free the global buffer when done
  free(g_bitstream);
  g_bitstream = NULL;
  g_bitstream_size = 0;
}

void free_streams(void) {
  free_bytestream();
  free_bitstream();
}