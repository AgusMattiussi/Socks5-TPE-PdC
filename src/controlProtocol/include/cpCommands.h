#ifndef CP_COMMANDS_H
#define CP_COMMANDS_H

#include <stdbool.h>

#include "controlProtocol.h"
#include "../../sniffer/pop3_sniffer.h"
#include "../../users/user_mgmt.h"
#include "../../include/metrics.h"

#define METRICS_CSV_TITLE "curr_socks;hist_socks;curr_control;hist_control;curr_total;hist_total;bytes_trnf\n"


void addProxyUser(cpCommandParser * parser, char * answer);
void removeProxyUser(cpCommandParser * parser, char * answer);
void turnOnPassDissectors(cpCommandParser * parser, char * answer);
void turnOffPassDissectors(cpCommandParser * parser, char * answer);
void getSniffedUsersList(cpCommandParser * parser, char * answer);
void changePassword(cpCommandParser * parser, char * answer);
void getMetrics(cpCommandParser * parser, char * answer);

#endif