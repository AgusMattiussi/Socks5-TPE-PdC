#include "cpCommandParser.h"

void initCpCommandParser(cpCommandParser * parser){
    parser->currentState = CPCP_COMMAND_CODE;
    parser->dataSize = 0;
    parser->code = CP_NO_COMMAND;
    parser->hasData = 0;
}


cpCommandParserState cpcpParseByte(cpCommandParser * parser, uint8_t byte){
    switch (parser->currentState){
        case CPCP_COMMAND_CODE:
            printf("[CPCP_COMMAND_CODE] - %hhx (%c)\n", byte, byte);
            if(byte < CP_ADD_USER || byte > CP_DISSECTOR_OFF)
                return CPCP_ERROR;
            parser->code = byte;
            return CPCP_HAS_DATA;
        case CPCP_HAS_DATA:         // En la version actual del protocolo, HAS_DATA = 0|1 para el cliente
            printf("[CPAP_HAS_DATA] - %hhx (%c)\n", byte, byte); //TODO: Cambiar char
            if(byte == 0x0/* '0' */)
                return CPCP_DONE;   // Por default, hasData = 0
            if(byte == 0x1/* '1' */){
                parser->hasData = 1;
                return CPCP_READ_DATA;
            }
            return CPCP_ERROR;
        case CPCP_READ_DATA:       // En la version actual, la data es una linea terminada en '\n'
            printf("[CPAP_READ_DATA] - %hhx (%c)\n", byte, byte);
            if(parser->dataSize == MAX_DATA_SIZE)
                return CPCP_ERROR;
            parser->data[parser->dataSize++] = byte;
            return byte == '\n' ? CPCP_DONE : CPCP_READ_DATA;
        default:
            break;
    }

    return CPCP_ERROR;
}