#include "cpAuthParser.h"

void initCpAuthParser(cpAuthParser * parser){
    parser->currentState = CPAP_CHECK_AUTH_COMMAND;
    parser->passLen = 0;
}

void cpapParseByte(cpAuthParser * parser, uint8_t byte) {
    switch (parser->currentState){
        case CPAP_CHECK_AUTH_COMMAND:
            printf("[CPAP_CHECK_AUTH_COMMAND] - %hhx (%c)\n", byte, byte);
            if(byte == 'x'/* AUTH_COMMAND */)
                parser->currentState = CPAP_HAS_DATA;               
            else
                parser->currentState = CPAP_ERROR;
            break;
        case CPAP_HAS_DATA:
            printf("[CPAP_HAS_DATA] - %hhx (%c)\n", byte, byte);
            if(byte == 'd'/* 1 */)  // Deberia haber una sola linea (<password>\n)
                parser->currentState = CPAP_READ_PASSWORD;
            else 
                parser->currentState = CPAP_ERROR;
            break;
        case CPAP_READ_PASSWORD:
            printf("[CPAP_READ_PASSWORD] - %hhx (%c)\n", byte, byte);
            if(byte == '\n'){           // Termine de leer la password
                parser->inputPassword[parser->passLen++] = '\0';
                parser->currentState = CPAP_DONE;
            } else if (parser->passLen == MAX_PASS_LEN){
                parser->currentState = CPAP_ERROR;
            }
            parser->inputPassword[parser->passLen++] = byte;
            break;
        default:
            parser->currentState = CPAP_ERROR;
    }
}