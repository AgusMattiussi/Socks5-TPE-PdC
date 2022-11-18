CC=gcc
CCFLAGS_FINAL=-g -Wall -Wextra -Wno-unused-parameter -Wno-implicit-fallthrough -pedantic -pedantic-errors -O3 -std=c11 -D_POSIX_C_SOURCE=200112L
CCFLAGS=-Wall -g -pthread
AS= -fsanitize=address
SOURCES=$(wildcard src/*.c) $(wildcard src/parsers/*.c) $(wildcard src/socks5/*.c) $(wildcard src/users/*.c) $(wildcard src/controlProtocol/*.c) $(wildcard src/controlProtocol/parsers/*.c) $(wildcard src/mng/*.c) 
BIN_DIR=./bin
BIN_FILE=./bin/main

all:
	mkdir -p $(BIN_DIR)
	$(CC) $(CCFLAGS) $(SOURCES) -o $(BIN_FILE)
chill:
	mkdir -p $(BIN_DIR)
	$(CC) $(SOURCES) -o $(BIN_FILE)
allsan:
	mkdir -p $(BIN_DIR)
	$(CC) $(CCFLAGS) $(SOURCES) $(AS) -o $(BIN_FILE)
clean:
	rm -rf $(BIN_DIR)

PHONY: clean all