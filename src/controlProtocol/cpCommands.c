#include "include/cpCommands.h"

static void noDataStatusSuccessAnswer(char * answer);
static void statusFailedAnswer(char * answer, controlProtErrorCode errorCode);
static void switchPassDissectors(cpCommandParser * parser, char * answer, bool value);

static void noDataStatusSuccessAnswer(char * answer){
    answer = calloc(3, sizeof(char)); 
    sprintf(answer, "%c%c\n", STATUS_SUCCESS, 0);
}

static void statusFailedAnswer(char * answer, controlProtErrorCode errorCode){
    answer = calloc(4, sizeof(char)); 
    sprintf(answer, "%c%c%c\n", STATUS_ERROR, 1, errorCode);
}

void addProxyUser(cpCommandParser * parser, char * answer){
    char * user, * password;

    if(parser->hasData == 0) {
        statusFailedAnswer(answer, CPERROR_COMMAND_NEEDS_DATA);
        return;
    }

    user = strtok(parser->data, TOKEN_DELIMITER);
    password = strtok(NULL, LINE_DELIMITER);

    if(user == NULL || password == NULL){
        statusFailedAnswer(answer, CPERROR_INVALID_FORMAT);
        return;
    }

    user_t new = {
        .name = user,
        .pass = password
    }; 

    uint8_t result = add_user(&new);

    switch(result){
        case ADD_MAX_USERS:
            statusFailedAnswer(answer, CPERROR_USER_LIMIT);
            break;
        case ADD_USER_EXISTS:
            statusFailedAnswer(answer, CPERROR_ALREADY_EXISTS);
            break;
        case ADD_OK:
            noDataStatusSuccessAnswer(answer);
            break;
        default:
            statusFailedAnswer(answer, CPERROR_GENERAL_ERROR);
    }

    return;
}

void removeProxyUser(cpCommandParser * parser, char * answer){
    // char * user;

    if(parser->hasData == 0){
        statusFailedAnswer(answer, CPERROR_COMMAND_NEEDS_DATA);
        return;
    }

    // Cambiamos el '\n' por '\0'
    parser->data[parser->dataSize] = '\0';

    /* user = malloc(parser->dataSize);
    memcpy(user, parser->data, parser->dataSize); */

    if(remove_user(parser->data) < 0) {
        statusFailedAnswer(answer, CPERROR_INEXISTING_USER);
    } else {
        noDataStatusSuccessAnswer(answer);
    }

    // free(user);
    noDataStatusSuccessAnswer(answer);
    return;    
}

void changePassword(cpCommandParser * parser, char * answer){
    char * user, * newPass;

    if(parser->hasData == 0){
        statusFailedAnswer(answer, CPERROR_COMMAND_NEEDS_DATA);
        return;
    }

    user = strtok(parser->data, TOKEN_DELIMITER);
    newPass = strtok(NULL, LINE_DELIMITER);

    if(user == NULL || newPass == NULL){
        statusFailedAnswer(answer, CPERROR_INVALID_FORMAT);
        return;
    }

    if(change_password(user, newPass) < 0) {
        statusFailedAnswer(answer, CPERROR_INEXISTING_USER);
    } else {
        noDataStatusSuccessAnswer(answer);
    }
    return;
}

static void switchPassDissectors(cpCommandParser * parser, char * answer, bool value){
    if(parser->hasData == 1){
        statusFailedAnswer(answer, CPERROR_NO_DATA_COMMAND);
        return;
    }

    set_sniffer_state(value);   

    noDataStatusSuccessAnswer(answer);
    return;
}

void turnOnPassDissectors(cpCommandParser * parser, char * answer){
    switchPassDissectors(parser, answer, true);
}

void turnOffPassDissectors(cpCommandParser * parser, char * answer){
    switchPassDissectors(parser, answer, false);
}

void getSniffedUsersList(cpCommandParser * parser, char * answer){
    if(parser->hasData == 1){
        statusFailedAnswer(answer, CPERROR_NO_DATA_COMMAND);
        return;
    }

    answer = calloc(3, 1 /* x Tamanio Usuario+Password */);

    /* TODO: Cargar en answer los usuarios y sus contrasenias 
       uno por uno, en formato CSV    
    */

   answer[0] = STATUS_SUCCESS;
   answer[1] = 1;   // HAS_DATA = 1
   return;
}

void getMetrics(cpCommandParser * parser, char * answer){
    if(parser->hasData == 1){
        statusFailedAnswer(answer, CPERROR_NO_DATA_COMMAND);
        return;
    }


    answer = calloc(3, 1 /* x Tamanio Metricas */);

    /* TODO: Cargar en answer las metricas. Deberian ser siempre 
       dos lineas, en formato CSV    
    */

   answer[0] = STATUS_SUCCESS;
   answer[1] = 1;   // HAS_DATA = 1
   return;
}

