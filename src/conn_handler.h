#include "stm/stm.h"

/*

Works as a helper function for the STM  

*/

void close(socks_conn_model * connection);

void socks_connection_read(struct selector_key * key);
void socks_connection_write(struct selector_key * key);
void socks_connection_block(struct selector_key * key);
void socks_connection_close(struct selector_key * key);