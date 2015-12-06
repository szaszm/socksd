#include "Client.h"
#include "Logger.h"

#include <stdlib.h>
#include <stdio.h> // for opening log file
#include <stdarg.h>
#include <unistd.h>
#include <poll.h> // poll, struct pollfd
#include <string.h> // memset
#include <getopt.h> // getopt, getopt_long, struct option
#include <signal.h> // sigaction

#include <sys/types.h>
#include <sys/socket.h> // socket, bind, listen, accept
#include <netdb.h> // struct addrinfo, getaddrinfo
#include <arpa/inet.h> // inet_ntop

#define BACKLOG 50
#define ARRAY_LENGTH(a) (sizeof(*(a))/sizeof(a))

// http://stackoverflow.com/questions/3599160/unused-parameter-warnings-in-c-code
#define UNUSED(x) (void)(x)

struct ClientList;

struct MainContext {
	struct Logger logger;
	char bindhost[100];
	char bindport[20];
	struct ClientList *clients;
	int listener_fd;
	int af;
	FILE *logfile;
};

struct ClientList {
	struct Client c;
	struct ClientList *next;
};

void ClientList_add(struct ClientList **ctx, struct ClientList *_new);
void ClientList_removeAfter(struct ClientList **list, struct ClientList *prev, const struct Logger *);
void Client_filterClosed(struct MainContext *);
struct Client *getClientByFd(const struct MainContext *, int fd);
struct pollfd *getPollFds(const struct MainContext *, size_t *nfds);

void str_addrinfo(char *buf, size_t buflen, const struct addrinfo *);

void getOptions(struct MainContext *ctx, int argc, char **argv);
void printUsage(const struct Logger *, const char *program_name);
int setSignalHandler(int signal, void (*handler)(int));
void onExitSignal(int signum);

static int terminate = 0; // signal terminator var

int main(int argc, char *argv[]) {
	struct MainContext ctx = {
		.logger = Logger_init(LOG_LEVEL_VERBOSE),
		.bindhost = "",
		.bindport = "1080",
		.clients = NULL,
		.listener_fd = -1,
		.af = AF_UNSPEC,
		.logfile = NULL
	};

	if(setSignalHandler(SIGINT, onExitSignal) == -1 
			|| setSignalHandler(SIGTERM, onExitSignal) == -1 
			|| setSignalHandler(SIGQUIT, onExitSignal) == -1) {
		Logger_perror(&ctx.logger, LOG_LEVEL_WARNING, "setSignalHandler");
	}
	getOptions(&ctx, argc, argv);
	if(ctx.logfile) {
		Logger_setLoggerFunction(&ctx.logger, LOG_LEVEL_ALL, LOGGER_FUNCTION_LOG_TO_FILE, ctx.logfile);
	}

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ctx.af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo *srvinfo;
	int status = getaddrinfo(ctx.bindhost[0] ? ctx.bindhost : NULL, ctx.bindport, &hints, &srvinfo);
	if(status != 0) {
		Logger_error(&ctx.logger, "getaddrinfo", gai_strerror(status));
		return 1;
	} else {
		char aistrbuf[80];
		str_addrinfo(aistrbuf, sizeof(aistrbuf), srvinfo);
		Logger_verbose(&ctx.logger, "getaddrinfo", aistrbuf);
	}


	ctx.listener_fd = socket(srvinfo->ai_family, srvinfo->ai_socktype, srvinfo->ai_protocol);
	if(ctx.listener_fd == -1) {
		Logger_perror(&ctx.logger, LOG_LEVEL_ERROR, "socket");
		freeaddrinfo(srvinfo);
		return 1;
	}
	Logger_debug(&ctx.logger, "main", "socket created.");

	int reuse = 1;
	if(setsockopt(ctx.listener_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
		Logger_perror(&ctx.logger, LOG_LEVEL_WARNING, "setsockopt");
	}
	Logger_debug(&ctx.logger, "main", "Reuse address flag set.");

	int res = bind(ctx.listener_fd, srvinfo->ai_addr, srvinfo->ai_addrlen);
	if(res == -1) {
		Logger_perror(&ctx.logger, LOG_LEVEL_ERROR, "bind");
		return 1;
	}
	Logger_debug(&ctx.logger, "main", "bound.");

	freeaddrinfo(srvinfo);
	srvinfo = NULL;

	if(listen(ctx.listener_fd, BACKLOG) == -1) {
		Logger_perror(&ctx.logger, LOG_LEVEL_ERROR, "listen");
		return 1;
	}
	Logger_debug(&ctx.logger, "main", "listening...");

	struct pollfd *fds = NULL;

	while(!terminate) {
		size_t fds_len;
		if(fds) { free(fds); fds = NULL; }
		Client_filterClosed(&ctx);
		fds = getPollFds(&ctx, &fds_len);
		res = poll(fds, fds_len, -1);
		if(res == -1) { Logger_perror(&ctx.logger, LOG_LEVEL_WARNING, "poll"); continue; }
		else if(res == 0) { Logger_debug(&ctx.logger, "poll", "poll timeout"); continue; }
		else Logger_debug(&ctx.logger, "poll", "poll activity.");
		nfds_t i;
		for(i = 0; i < fds_len; ++i) {
			if(fds[i].revents == 0) continue;
			Logger_debug(&ctx.logger, "event_loop", "events: %s %s %s %s %s %s",
				(fds[i].revents & POLLHUP ? "POLLHUP" : "!pollhup"),
				(fds[i].revents & POLLERR ? "POLLERR" : "!pollerr"),
				(fds[i].revents & POLLNVAL ? "POLLNVAL" : "!pollnval"),
				(fds[i].revents & POLLIN ? "POLLIN" : "!pollin"),
				(fds[i].revents & POLLOUT ? "POLLOUT" : "!pollout"),
				(fds[i].revents & POLLPRI ? "POLLPRI" : "!pollpri")
				);
			if(fds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
				struct Client *c = getClientByFd(&ctx, fds[i].fd);
				if(!c) {
					Logger_warn(&ctx.logger, "event_loop", "Client already closed.");
					continue;
				}
				Client_close(c);
				continue;
			}
			if(!(fds[i].revents & POLLIN)) {
				fds[i].revents = 0;
				continue;
			}
			if(fds[i].fd == ctx.listener_fd) {
				res = accept(ctx.listener_fd, NULL, NULL);
				if(res == -1) continue;
				Logger_verbose(&ctx.logger, "event_loop", "accepted connection.");
				struct ClientList *new_client = (struct ClientList *)malloc(sizeof(struct ClientList));
				if(!new_client) {
					Logger_perror(&ctx.logger, LOG_LEVEL_ERROR, "malloc@event_loop");
					while(ctx.clients) {
						ClientList_removeAfter(&ctx.clients, NULL, &ctx.logger);
					}
					close(ctx.listener_fd);
					return 1;
				}

				new_client->c = Client_init(res, &ctx.logger, ctx.af);
				ClientList_add(&ctx.clients, new_client);
			} else {
				// handle client connection
				struct Client *c = getClientByFd(&ctx, fds[i].fd);
				if(!c) {
					Logger_warn(&ctx.logger, "event_loop", "Client already closed.");
					continue;
				}
				int res[2] = {0,0};
				if(c->client_fd == fds[i].fd) res[0] = Client_handleActivity(c);
				if(c->remote_fd == fds[i].fd) res[1] = Client_handleRemoteActivity(c);
				if(res[0] || res[1]) 
				{
					Client_close(c);
					continue;
				}
			}
		}
	}
	Logger_info(&ctx.logger, "main", "main loop ended, cleaning up before exiting.");
	if(fds) { free(fds); fds = NULL; }
	free(ctx.clients);
	if(ctx.logfile) fclose(ctx.logfile);

	return 0;
}

void Client_filterClosed(struct MainContext *ctx) {
	struct ClientList *it = ctx->clients;
	struct ClientList *prev = NULL;
	for(it = ctx->clients; it != NULL;) {
		struct Client *c = &it->c;
		if(c->client_fd == 0 && c->remote_fd == 0) {
			ClientList_removeAfter(&ctx->clients, prev, &ctx->logger);
			if(prev) it = prev->next; // it is invalidated so let it point to the next valid item
			else it = ctx->clients;
		} else {
			prev = it;
			it = it->next;
		}
	}
	if(!ctx->clients) {
		Logger_info(&ctx->logger, "Client_filterClosed", "no clients remaining.");
	}
}


struct Client *getClientByFd(const struct MainContext *ctx, int fd) {
	struct ClientList *it;
	for(it = ctx->clients; it; it = it->next) {
		if(it->c.client_fd == fd || it->c.remote_fd == fd)
			return &it->c;
	}
	return NULL;
}

struct pollfd *getPollFds(const struct MainContext *ctx, size_t *nfds) {
	size_t fds = 0;
	struct ClientList *it;
	for(it = ctx->clients; it; it = it->next) {
		if(it->c.client_fd) fds++;
		if(it->c.remote_fd) fds++;
	}
	fds++; // one more for the listener
	*nfds = fds;
	struct pollfd *res = (struct pollfd *)malloc(fds * sizeof(struct pollfd));
	if(!res) {
		Logger_perror(&ctx->logger, LOG_LEVEL_WARNING, "malloc");
		return NULL;
	}
	size_t j;
	for(j = 0, it = ctx->clients; it; it = it->next) {
		if(it->c.client_fd) {
			res[j++] = (struct pollfd){
				.fd = it->c.client_fd,
				.events = POLLIN,
				.revents = 0
			};
		}
		if(it->c.remote_fd) {
			res[j++] = (struct pollfd){
				.fd = it->c.remote_fd,
				.events = POLLIN,
				.revents = 0
			};
		}
	}
	res[j] = (struct pollfd){
		.fd = ctx->listener_fd,
		.events = POLLIN,
		.revents = 0
	};
	return res;
}


void str_addrinfo(char *buf, size_t buflen, const struct addrinfo *res) {
	// http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#getaddrinfo
	const struct addrinfo *p;
	char ipstr[INET6_ADDRSTRLEN];

	p = res;
	void *addr;
	char *ipver;
	unsigned short port;

	// get the pointer to the address itself,
	// different fields in IPv4 and IPv6:
	if (p->ai_family == AF_INET) { // IPv4
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
		addr = &(ipv4->sin_addr);
		port = ntohs(ipv4->sin_port);
		ipver = "IPv4";
	} else { // IPv6
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
		addr = &(ipv6->sin6_addr);
		port = ntohs(ipv6->sin6_port);
		ipver = "IPv6";
	}

	// convert the IP to a string and print it:
	inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
	snprintf(buf, buflen, "using address: %s: %s:%hu", ipver, ipstr, port);
}

void getOptions(struct MainContext *ctx, int argc, char **argv) {
	static const struct option longopts[] = {
		{"bind", required_argument, NULL, 'b' },
		{"port", required_argument, NULL, 'p' },
		{"ipv4", no_argument, NULL, '4' },
		{"ipv6", no_argument, NULL, '6' },
		{"log-level", required_argument, NULL, 'l' },
		{"log-file", required_argument, NULL, 'f' },
		{"help", no_argument, NULL, 'h' },
		{NULL, 0, NULL, 0}
	};
	int c;
	while(1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "b:p:46l:f:h", longopts, &option_index);
		if(c == -1) break;

		switch(c) {
			case 'b':
				strncpy(ctx->bindhost, optarg, 100);
				ctx->bindhost[99] = 0; // ensure terminating '\0'
				break;
			case 'p':
				strncpy(ctx->bindport, optarg, 20);
				ctx->bindport[19] = 0; // ensure terminating '\0'
				break;
			case '4':
				ctx->af = AF_INET;
				break;
			case '6':
				ctx->af = AF_INET6;
				break;
			case 'l':
				sscanf(optarg, "%d", &c);
				Logger_setMinLevel(&ctx->logger, c);
				break;
			case 'f':
				ctx->logfile = fopen(optarg, "a");
				if(ctx->logfile == NULL) {
					Logger_warn(&ctx->logger, "getOptions", "Failed to open logfile");
				}
				break;
			case 'h':
				printUsage(&ctx->logger, argv[0]);
				exit(0);
			default:
				Logger_warn(&ctx->logger, "getOptions", "unknown option -%c %s", c, optarg ? optarg : "");
				break;
		}
	}
}

void printUsage(const struct Logger *logger, const char *program_name) {
	static const char *const usagestr = 
		"%s [OPCIÓK]\n"
		"Opciók:\n"
		"    -b, --bind ADDR      A kapcsolatok várása a megadott címen (alapértelmezés: [::] vagy 0.0.0.0)\n"
		"    -p, --port PORT      A kliensek kapcsolatainak várása a megadott TCP porton (alapértelmezés: 1080)\n"
		"    -4, --ipv4           Csak IPv4 használata\n"
		"    -6, --ipv6           Csak IPv6 használata (Az OS mapelheti IPv4-re is)\n"
		"    -l, --log-level LVL  A logolás szintje \n"
		"                           0: csendben\n"
		"                           1: hibák\n"
		"                           2: figylemeztetések\n"
		"                           3: információk\n"
		"                           4: több információ (alapértelmezés)\n"
		"                           5: debug \n"
		"    -f, --log-file FILE  A logolás ebbe a fájlba történik. (alapértelmezés: hibák, figyelmeztetések - stderr, más - stdout)\n"
		"    -h, --help           Segítség megjelenítése\n"
		;

	Logger_info(logger, "usage", usagestr, program_name ? program_name : "./socksd");
}

int setSignalHandler(int signum, void (*handler)(int)) {
	struct sigaction act;
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = handler;
	return sigaction(signum, &act, NULL);
}

void onExitSignal(int signum) {
	UNUSED(signum);
	terminate = 1;
}

void ClientList_add(struct ClientList **ctx, struct ClientList *_new) {
	_new->next = *ctx;
	*ctx = _new;
}

void ClientList_removeAfter(struct ClientList **list, struct ClientList *prev, const struct Logger *logger) {
	if(prev) {
		struct ClientList *item = prev->next;
		if(!item) {
			Logger_error(logger, "ClientList_removeAfter", "Requested to remove non-existent item.");
		}
		prev->next = item->next;
		if(item->c.client_fd) close(item->c.client_fd);
		if(item->c.remote_fd) close(item->c.remote_fd);
		free(item);
	} else {
		struct ClientList *item = *list;
		*list = (*list)->next;
		if(item->c.client_fd) close(item->c.client_fd);
		if(item->c.remote_fd) close(item->c.remote_fd);
		free(item);
	}
}
