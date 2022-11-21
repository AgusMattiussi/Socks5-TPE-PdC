#include "cpAuthParser.h"

void initCpAuthParser(cpAuthParser * parser){
    parser->currentState = CPAP_CHECK_AUTH_COMMAND;
    parser->passLen = 0;
}

cpAuthParserState cpapParseByte(cpAuthParser * parser, uint8_t byte) {
    switch (parser->currentState){
        case CPAP_CHECK_AUTH_COMMAND:
            printf("[CPAP_CHECK_AUTH_COMMAND] - %hhx (%c)\n", byte, byte);
            if(byte == CP_AUTHENTICATION)
                return CPAP_HAS_DATA;               
            break;
        case CPAP_HAS_DATA:
            printf("[CPAP_HAS_DATA] - %hhx (%c)\n", byte, byte);
            if(byte == /* 0x1 */'1')    // Deberia haber una sola linea (<password>\n)
                return CPAP_READ_PASSWORD;
            break;
        case CPAP_READ_PASSWORD:
            printf("[CPAP_READ_PASSWORD] - %hhx (%c)\n", byte, byte);
            if(byte == '\n'){           // Termine de leer la password, la cierro con '\0'
                parser->inputPassword[parser->passLen++] = '\0';
                return CPAP_DONE;
            } else if (parser->passLen == MAX_PASS_LEN){
                return CPAP_ERROR;
            }
            parser->inputPassword[parser->passLen++] = byte;
            return CPAP_READ_PASSWORD;
            break;
        default:
            break;
    }

    return CPAP_ERROR;
}
