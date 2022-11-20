#include "logger.h"
#include "../sniffer/pop3_sniffer.h"

/*
 * Implementación de "logger.h".
 */

static bool log = false;

void setLogOn(){ 
	printf("Setting logger ON...\n");
	log = true; }
void setLogOff(){ 
	printf("Setting logger OFF...\n");
	log = false; 
	}

void Log(FILE * const stream, const char * prefix, const char * const format, const char * suffix, va_list arguments) {
	if(log){
	fprintf(stream, "%s", prefix);
	vfprintf(stream, format, arguments);
	fprintf(stream, "%s", suffix);
	}
}

void LogDebug(const char * const format, ...) {
	if(log){
	va_list arguments;
	va_start(arguments, format);
	Log(stdout, "[DEBUG] ", format, "\n", arguments);
	va_end(arguments);
	}
}

void LogError(const char * const format, ...) {
	if(log){
	va_list arguments;
	va_start(arguments, format);
	Log(stderr, "[ERROR] ", format, "\n", arguments);
	va_end(arguments);
	}
}

void LogErrorRaw(const char * const format, ...) {
	if(log){
	va_list arguments;
	va_start(arguments, format);
	Log(stderr, "", format, "", arguments);
	va_end(arguments);
	}
}

void LogInfo(const char * const format, ...) {
	if(log){
	va_list arguments;
	va_start(arguments, format);
	Log(stdout, "[INFO ] ", format, "\n", arguments);
	va_end(arguments);
	}
}

char * getIpAddress(struct sockaddr_storage *addr) {
    char *ipAddress = malloc(sizeof(char) * INET6_ADDRSTRLEN);
    if(addr->ss_family == AF_INET) {
        struct sockaddr_in *ipv4Addr = (struct sockaddr_in *) addr;
        inet_ntop(AF_INET, &(ipv4Addr->sin_addr), ipAddress, INET6_ADDRSTRLEN);
    } else if(addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6Addr = (struct sockaddr_in6 *) addr;
        inet_ntop(AF_INET6, &(ipv6Addr->sin6_addr), ipAddress, INET6_ADDRSTRLEN);
    } else {
        strcpy(ipAddress, "unknown");
    }
    return ipAddress;
}

int getPort(struct sockaddr_storage *addr) {
    if(addr->ss_family == AF_INET) {
        struct sockaddr_in *ipv4Addr = (struct sockaddr_in *) addr;
        return ntohs(ipv4Addr->sin_port);
    } else if(addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6Addr = (struct sockaddr_in6 *) addr;
        return ntohs(ipv6Addr->sin6_port);
    } else {
        return -1;
    }
}

void
conn_information(socks_conn_model * connection){
	struct req_parser * parser = connection->parsers->req_parser;
	// Time string in ISO-8601 format 
	// (quoted from top answer in:
	// https://stackoverflow.com/questions/9527960/how-do-i-construct-an-iso-8601-datetime-in-c)
	time_t now;
    time(&now);
	struct tm tp; //Slight twak for time zone with respect to S.O.'s answer
    char time_buff[sizeof("2022-11-19T12:00:00Z")];
	localtime_r(&now, &tp);
    strftime(time_buff, sizeof(time_buff), "%FT%TZ", &tp);
    // this will work too, if your compiler doesn't support %F or %T:
    //strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
	
	//Username (¿Hay uno loggeado?)
	char * username = get_curr_user();
	username = username==NULL?"¿?":username;

	//Register type
	char * reg_type = "A";

	//IP origin address
	char buff[INET6_ADDRSTRLEN]={0};
	if(parser->type != FQDN){
		inet_ntop(parser->type == IPv4 ? AF_INET : AF_INET6, 
				parser->type == IPv4?
				(uint8_t *)&(parser->addr.ipv4.sin_addr):parser->addr.ipv6.sin6_addr.s6_addr, 
				buff, 
				parser->type == IPv4 ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN);
	}
	printf("Connection: %s\t%s\t%s\t%s\t%d\t%s\t%d\t%d\t\n", time_buff, username, reg_type, 
			getIpAddress(&(connection->cli_conn->addr)),
			getPort(&(connection->cli_conn->addr)), 
			parser->type==FQDN?(char*)parser->addr.fqdn:buff,
			parser->port, parser->res_parser.state);
	fflush(stdout);
}

void
pass_information(socks_conn_model * connection){
	struct req_parser * parser = connection->parsers->req_parser;
	struct pop3_parser * pop3_parser = connection->pop3_parser;
	time_t now;
    time(&now);
	struct tm tp; //Slight twak for time zone with respect to S.O.'s answer
    char time_buff[sizeof("2022-11-19T12:00:00Z")];
	localtime_r(&now, &tp);
    strftime(time_buff, sizeof(time_buff), "%FT%TZ", &tp);
	
	char * username = get_curr_user();
	username = username==NULL?"¿?":username;

	//Register type
	char * reg_type = "P";
	char * protocol = "POP3"; // TODO: man dice HTTP, deberíamos considerarlo?

	char buff[INET6_ADDRSTRLEN]={0};
	if(parser->type != FQDN){
		inet_ntop(parser->type == IPv4 ? AF_INET : AF_INET6, 
				parser->type == IPv4?
				(uint8_t *)&(parser->addr.ipv4.sin_addr):parser->addr.ipv6.sin6_addr.s6_addr, 
				buff, 
				parser->type == IPv4 ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN);
	}

	printf("POP3 sniffing: %s\t%s\t%s\t%s\t%s\t%d\t%s\t%d\t\nUser: %s\nPassword: %s\n", 
			time_buff, username, reg_type, 
			protocol,
			getIpAddress(&(connection->cli_conn->addr)),
			getPort(&(connection->cli_conn->addr)), 
			parser->type==FQDN?(char*)parser->addr.fqdn:buff,
			parser->port, pop3_parser->user, pop3_parser->pass
			);
}