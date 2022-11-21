#include "include/metrics.h"
#include <stdlib.h>

typedef struct metrics_t{
    long historic_socks_connections;
    long current_socks_connections;
    long historic_mgmt_connections;
    long current_mgmt_connections;
    long bytes_transferred;
} metrics_t;

static metrics_t * metrics;

void start_metrics(){
    metrics = malloc(sizeof(metrics_t));
    metrics->bytes_transferred = 0;
    metrics->current_socks_connections = 0;
    metrics->current_mgmt_connections = 0;
    metrics->historic_socks_connections = 0;
    metrics->historic_mgmt_connections = 0;
}

void add_socks_connection(){
    metrics->current_socks_connections++;
    metrics->historic_socks_connections++;
}

void add_mgmt_connection(){
    metrics->current_mgmt_connections++;
    metrics->historic_mgmt_connections++;
}

void remove_current_socks_connection(){
    metrics->current_socks_connections--;
}

void remove_current_mgmt_connection(){
    metrics->current_mgmt_connections--;
}

void add_bytes_transferred(long bytes){
    metrics->bytes_transferred += bytes;
}

long get_historic_socks(){
    return metrics->historic_socks_connections;
}

long get_current_socks(){
    return metrics->current_socks_connections;
}

long get_historic_mgmt(){
    return metrics->historic_mgmt_connections;
}

long get_current_mgmt(){
    return metrics->current_mgmt_connections;
}

long get_current_total(){
    return (metrics->current_mgmt_connections + metrics->current_socks_connections);
}

long get_historic_total(){
    return (metrics->historic_mgmt_connections + metrics->historic_socks_connections);
}

long get_bytes_transferred(){
    return metrics->bytes_transferred;
}

void
free_metrics(){
    free(metrics);
    free_list(get_sniffed_users());
}