CC=gcc
CCFLAGS_FINAL=-g -Wall -Wextra -Wno-unused-parameter -Wno-unused-parameter -Wno-implicit-fallthrough -pedantic -pedantic-errors -std=c11 -D_POSIX_C_SOURCE=200112L -pthread
# -fsanitize=address
CCFLAGS=-Wall -g -pthread
AS= -fsanitize=address
SOURCES=$(wildcard src/*.c) $(wildcard src/parsers/*.c) $(wildcard src/socks5/*.c) $(wildcard src/users/*.c) $(wildcard src/controlProtocol/*.c) $(wildcard src/controlProtocol/parsers/*.c) $(wildcard src/mng/*.c)  $(wildcard src/logger/*.c) $(wildcard src/sniffer/*.c)
SOURCES_CLI=$(wildcard src/client/*.c)
BIN_DIR=./bin
BIN_FILE=./bin/socks5d
BIN_FILE_CLI=./bin/client

all:
	mkdir -p $(BIN_DIR)
	$(CC) $(CCFLAGS_FINAL) $(SOURCES) -o $(BIN_FILE)
	$(CC) $(CCFLAGS_FINAL) $(SOURCES_CLI) -o $(BIN_FILE_CLI)
chill:
	mkdir -p $(BIN_DIR)
	$(CC) $(SOURCES) -o $(BIN_FILE)
allsan:
	mkdir -p $(BIN_DIR)
	$(CC) $(CCFLAGS) $(SOURCES) $(AS) -o $(BIN_FILE)
clean:
	rm -rf $(BIN_DIR)

PHONY: clean all
