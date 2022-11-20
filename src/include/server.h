#ifndef SERVER_H
#define SERVER_H

#include <sys/signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>  
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "buffer.h"
#include "netutils.h"
#include "parser_utils.h"
#include "parser.h"
#include "selector.h"
#include "stm.h"
#include "../socks5/socks5.h"
#include "../mng/mng.h"
#include "conn_handler.h"
#include "../controlProtocol/include/controlProtocol.h"

const struct fd_handler * get_conn_actions_handler();
const struct fd_handler * get_mng_conn_actions_handler();
int start_server(char * socks_addr, char * socks_port, char * mng_addr, char * mng_port);
// void close_socks_conn(socks_conn_model * connection);
void cleanup();
void set_selector(fd_selector * new_selector);

#endif