#include "include/cpCommands.h"
#include "../include/args.h"
#include "../logger/logger.h"

#define INITIAL_SOCKS_U_SIZE 512
#define SOCKS_U_HEADER "Socks users: \n"

static char * noDataStatusSuccessAnswer();
static char * statusFailedAnswer(controlProtErrorCode errorCode);
static char * switchPassDissectors(cpCommandParser * parser, bool value);

static char * noDataStatusSuccessAnswer(){
    char * ret = calloc(3, sizeof(char));
    if(ret != NULL){
        ret[0] = STATUS_SUCCESS;
        ret[1] = 0;
        ret[2] = '\n';
    }

    return ret;
}

static char * statusFailedAnswer(controlProtErrorCode errorCode){
    char * ret = calloc(3, sizeof(char)); 

    if(ret != NULL){
        ret[0] = STATUS_ERROR;
        ret[1] = 1;
        ret[2] = (char) errorCode;
        ret[3] = '\n';
    }
    return ret;
}

char * addProxyUser(cpCommandParser * parser){
    char * user, * password;
    char * ret;

    if(parser->hasData == 0) {
        ret = statusFailedAnswer(CPERROR_COMMAND_NEEDS_DATA);
        return ret;
    }

    user = strtok(parser->data, TOKEN_DELIMITER);
    password = strtok(NULL, LINE_DELIMITER);

    if(user == NULL || password == NULL){
        ret = statusFailedAnswer(CPERROR_INVALID_FORMAT);
        return ret;
    }

    user_t new = {
        .name = user,
        .pass = password
    }; 
    LogInfo("user: %s(%ld), pass: %s(%ld)", user, strlen(user), password, strlen(password));

    uint8_t result = add_user(&new);

    switch(result){
        case ADD_MAX_USERS:
            ret = statusFailedAnswer(CPERROR_USER_LIMIT);
            break;
        case ADD_USER_EXISTS:
            ret = statusFailedAnswer(CPERROR_ALREADY_EXISTS);
            break;
        case ADD_OK:
            ret = noDataStatusSuccessAnswer();
            break;
        default:
            ret = statusFailedAnswer(CPERROR_GENERAL_ERROR);
    }

    return ret;
}

char * removeProxyUser(cpCommandParser * parser){
    // char * user;
    char * ret;

    if(parser->hasData == 0){
        ret = statusFailedAnswer(CPERROR_COMMAND_NEEDS_DATA);
        LogError("RemoveProxyUser: no data!\n");
        return ret;
    }

    // Cambiamos el '\n' por '\0'
    parser->data[parser->dataSize - 1] = '\0';

    /* user = malloc(parser->dataSize);
    memcpy(user, parser->data, parser->dataSize); */
    LogError("Remove user: %s\n", parser->data);
    if(remove_user(parser->data) < 0) {
        ret = statusFailedAnswer(CPERROR_INEXISTING_USER);
    } else {
        ret = noDataStatusSuccessAnswer();
    }

    return ret;    
}

char * changePassword(cpCommandParser * parser){
    char * user, * newPass;
    char * ret;

    if(parser->hasData == 0){
        ret = statusFailedAnswer(CPERROR_COMMAND_NEEDS_DATA);
        return ret;
    }

    user = strtok(parser->data, TOKEN_DELIMITER);
    newPass = strtok(NULL, LINE_DELIMITER);

    if(user == NULL || newPass == NULL){
        ret = statusFailedAnswer(CPERROR_INVALID_FORMAT);
        return ret;
    }
    if(change_password(user, newPass) < 0) {
        ret = statusFailedAnswer(CPERROR_INEXISTING_USER);
    } else {
        ret = noDataStatusSuccessAnswer();
    }
    return ret;
}

static char * switchPassDissectors(cpCommandParser * parser, bool value){
    char * ret;
    if(parser->hasData == 1){
        ret = statusFailedAnswer(CPERROR_NO_DATA_COMMAND);
        return ret;
    }

    set_sniffer_state(value);

    ret = noDataStatusSuccessAnswer();
    return ret;
}

char * turnOnPassDissectors(cpCommandParser * parser){
    return switchPassDissectors(parser, true);
}

char * turnOffPassDissectors(cpCommandParser * parser){
    return switchPassDissectors(parser, false);
}

char * getSniffedUsersList(cpCommandParser * parser){
    char * ret;

    if(parser->hasData == 1){
        ret = statusFailedAnswer(CPERROR_NO_DATA_COMMAND);
        return ret;
    }
    /* Obtenemos la lista de usuario sniffeados */
    users_list * userList = get_sniffed_users();
    
    int reallocCount = 0;
    ret = calloc(INITIAL_SIZE, sizeof(char));
    if(ret == NULL)
        return NULL;
    int ansSize = strlen(POP3_CSV_TITLE) + 2;
    /* Copiamos el titulo del CSV */
    sprintf(ret, "%c%c%s", STATUS_SUCCESS, userList == NULL ? 1 : userList->size + 1, POP3_CSV_TITLE);
    if(userList == NULL || userList->size == 0){
        return ret;
    }

    node * current = userList->first;
    for (int i = 0; i < userList->size && current != NULL; i++){
        int userLen = strlen(current->username)+1;
        int passLen = strlen(current->password)+1;
        int lineLen =  userLen + passLen + 2;

        /* Si falta espacio, reservamos mas memoria */
        if(INITIAL_SIZE + reallocCount * MEM_BLOCK - ansSize < lineLen){
            reallocCount++;
            ret = realloc(ret, INITIAL_SIZE + reallocCount * MEM_BLOCK);
            if(ret == NULL){
                LogError("Not enough memory for getSniffedUsersList\n");
                return NULL;
            }
        }

        memcpy(&ret[ansSize], current->username, userLen);
        ansSize += userLen;

        ret[ansSize++] = ';';
        memcpy(&ret[ansSize], current->password, passLen);
        ansSize += passLen;
        ret[ansSize++] = '\n';

        //snprintf(ret, "%s%s;%s\n", ret, current->username, current->password);

        current = current->next;
    }
    return ret;
}



char * getMetrics(cpCommandParser * parser){
    char * ret;

    if(parser->hasData == 1){
        ret = statusFailedAnswer(CPERROR_NO_DATA_COMMAND);
        return ret;
    }

    int titleLen = strlen(METRICS_CSV_TITLE);
    ret = calloc(2*titleLen, sizeof(char));
    if(ret == NULL)
        return NULL;

    sprintf(ret, "%c%c%s%lu;%lu;%lu;%lu;%lu;%lu;%lu\n", STATUS_SUCCESS, 2,
        METRICS_CSV_TITLE, get_current_socks(), get_historic_socks(), 
        get_current_mgmt(), get_historic_mgmt(), get_current_total(),
        get_historic_total(), get_bytes_transferred()
    );

    //*answer[strlen(*answer)] = '\n';

   return ret;
}

char * 
getSocksUsers(cpCommandParser * parser){
    user_t ** users = get_all_users();
    uint8_t n_users = get_total_curr_users();
    char * ret_str = malloc(INITIAL_SOCKS_U_SIZE);
    memset(ret_str, 0x00, INITIAL_SOCKS_U_SIZE);

    ret_str[0] = '1'; //TODO: Change for parametrized version
    ret_str[1] = (char)n_users + 1;
    // ret[1] = userList == NULL ? 1 : userList->size + 1;
    //trcat(ret_str, aux);
    strcat(ret_str, SOCKS_U_HEADER);
    //strcat(ret_str, "\n\n");

    for(int i = 0; i < n_users; i++){
        strcat(ret_str, users[i]->name);
        //strcat(ret_str, ";");
        //strcat(ret_str, users[i]->pass);
        strcat(ret_str, "\n");
    }
    return ret_str;
}



