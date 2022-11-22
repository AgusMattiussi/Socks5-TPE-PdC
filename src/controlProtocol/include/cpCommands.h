#ifndef CP_COMMANDS_H
#define CP_COMMANDS_H

#include <stdbool.h>

#include "controlProtocol.h"
#include "../../sniffer/pop3_sniffer.h"
#include "../../users/user_mgmt.h"
#include "../../include/metrics.h"

#define INITIAL_SIZE 256
#define MEM_BLOCK 256

#define POP3_CSV_TITLE "user;password\n"
#define METRICS_CSV_TITLE "curr_socks;hist_socks;curr_control;hist_control;curr_total;hist_total;bytes_trnf\n"

char * addProxyUser(cpCommandParser * parser);
char * removeProxyUser(cpCommandParser * parser);
char * turnOnPassDissectors(cpCommandParser * parser);
char * turnOffPassDissectors(cpCommandParser * parser);
char * getSniffedUsersList(cpCommandParser * parser);
char * changePassword(cpCommandParser * parser);
char * getMetrics(cpCommandParser * parser);
char * getSocksUsers(cpCommandParser * parser);

#endif