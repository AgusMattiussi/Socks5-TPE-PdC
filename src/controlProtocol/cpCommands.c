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

int addProxyUser(cpCommandParser * parser, char * answer){
    char * user, * password;

    if(parser->hasData == 0){
        statusFailedAnswer(answer, CPERROR_COMMAND_NEEDS_DATA);
        return 0;
    }

    user = strtok(parser->data, TOKEN_DELIMITER);
    password = strtok(NULL, TOKEN_DELIMITER);

    if(user == NULL || password == NULL){
        statusFailedAnswer(answer, CPERROR_INVALID_FORMAT);
        return 0;
    }

    /* TODO: Agregar usuario y contrasenia */

    noDataStatusSuccessAnswer(answer);
    return 1;
}