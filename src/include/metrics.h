#ifndef METRICS_H
#define METRICS_H

#include "../sniffer/pop3_sniffer.h"
/*
   6.  implementar mecanismos que permitan recolectar métricas que
       ayuden a monitorear la operación del sistema.

       A.  cantidad de conexiones históricas

       B.  cantidad de conexiones concurrentes

       C.  cantidad de bytes transferidos

       D.  cualquier otra métrica que considere oportuno para el
           entendimiento del funcionamiento dinámico del sistema
*/

void start_metrics();
void add_socks_connection();
void add_mgmt_connection();
void remove_current_socks_connection();
void remove_current_mgmt_connection();
void add_bytes_transferred(long bytes);
long get_historic_socks();
long get_current_socks();
long get_historic_mgmt();
long get_current_mgmt();
long get_historic_total();
long get_current_total();
long get_bytes_transferred();
void free_metrics();

#endif