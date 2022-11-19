#include "include/cpCommands.h"

static void noDataStatusSuccessAnswer(char * answer);
static void statusFailedAnswer(char * answer, controlProtErrorCode errorCode);

static void noDataStatusSuccessAnswer(char * answer){
    answer = calloc(3, sizeof(char)); 
    sprintf(answer, "%c%c\n", STATUS_SUCCESS, 0);
}

static void statusFailedAnswer(char * answer, controlProtErrorCode errorCode){
    answer = calloc(4, sizeof(char)); 
    sprintf(answer, "%c%c%c\n", STATUS_ERROR, 1, (char) errorCode);
}

void addProxyUser(cpCommandParser * parser, char * answer){
    char * user, * password;

    if(parser->hasData == 0){
        statusFailedAnswer(answer, CPERROR_COMMAND_NEEDS_DATA);
        return;
    }

    user = strtok(parser->data, TOKEN_DELIMITER);
    password = strtok(NULL, LINE_DELIMITER);

    if(user == NULL || password == NULL){
        statusFailedAnswer(answer, CPERROR_INVALID_FORMAT);
        return;
    }

    /* TODO: Agregar usuario y contrasenia */

    noDataStatusSuccessAnswer(answer);
    return;
}

void removeProxyUser(cpCommandParser * parser, char * answer){
    char * user;

    if(parser->hasData == 0){
        statusFailedAnswer(answer, CPERROR_COMMAND_NEEDS_DATA);
        return;
    }

    //TODO: Capaz no hace falta hacer una copia aca
    parser->data[parser->dataSize] = '\0';

    user = malloc(parser->dataSize);
    memcpy(user, parser->data, parser->dataSize);

    /* TODO: Eliminar usuario */
    // TODO: Si no existia, devolver 0

    free(user);
    noDataStatusSuccessAnswer(answer);
    return;    
}