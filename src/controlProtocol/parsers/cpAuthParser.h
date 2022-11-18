#ifndef CP_AUTH_PARSER_H
#define CP_AUTH_PARSER_H

#include <stdint.h>
#include <stdio.h>

#define AUTH_COMMAND 1
#define MAX_PASS_LEN 256  // El '\n' seria el byte numero 256

typedef enum cpAuthParserState{
    CPAP_CHECK_AUTH_COMMAND,
    CPAP_HAS_DATA,
    CPAP_READ_PASSWORD,
    CPAP_DONE,
    CPAP_ERROR
} cpAuthParserState;


typedef struct cpAuthParser {
    cpAuthParserState currentState;
    char inputPassword[MAX_PASS_LEN];
    int passLen;
} cpAuthParser;

void initCpAuthParser(cpAuthParser * parser);
void cpapParseByte(cpAuthParser * parser, uint8_t byte);


#endif