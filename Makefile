# Simple Makefile with clean output and build directory

CC = gcc
CFLAGS = -Wall -Wextra -O2 -MMD -MP
TARGET = build/main
SRC = main.c node.c bits.c policy.c rules.c cond.c
OBJ = $(SRC:%.c=build/%.o)
DEP = $(OBJ:.o=.d)

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(OBJ)
	@$(CC) $(CFLAGS) $(OBJ) -o $(TARGET)

# Compile each .c file into build directory
build/%.o: %.c | build
	@$(CC) $(CFLAGS) -c $< -o $@

# Create build directory if not exists
build:
	@mkdir -p build

# Clean build files
clean:
	@rm -rf build

# Run executable
run: $(TARGET)
	@./$(TARGET)

# Include dependency files if they exist
-include $(DEP)

# Optional: debug and rebuild shortcuts
debug: CFLAGS += -g -O0
debug: clean all

rebuild: clean all
