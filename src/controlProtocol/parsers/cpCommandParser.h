#ifndef CP_COMMAND_PARSER_H
#define CP_COMMAND_PARSER_H

#include <stdint.h>
#include <stdio.h>

#define MAX_DATA_SIZE 255

typedef enum cpCommandCode {
    CP_NO_COMMAND,
    CP_ADD_USER = '1',      // HAS_DATA = 1
    CP_REM_USER,            // HAS_DATA = 1
    CP_CHANGE_PASS,         // HAS_DATA = 1
    CP_LIST_USERS,          // HAS_DATA = 0
    CP_GET_METRICS,         // HAS_DATA = 0
    CP_DISSECTOR_ON,        // HAS_DATA = 0
    CP_DISSECTOR_OFF,       // HAS_DATA = 0
} cpCommandCode;

typedef enum cpCommandParserState {
    CPCP_COMMAND_CODE,
    CPCP_HAS_DATA,
    CPCP_READ_DATA,
    CPCP_DONE,
    CPCP_ERROR
} cpCommandParserState;

typedef struct cpCommandParser {
    cpCommandParserState currentState;
    cpCommandCode code;
    uint8_t hasData;
    char data[MAX_DATA_SIZE + 1];   // Cerramos el string con '\0'
    int dataSize;
} cpCommandParser;


void initCpCommandParser(cpCommandParser * parser);
cpCommandParserState cpcpParseByte(cpCommandParser * parser, uint8_t byte);

#endif