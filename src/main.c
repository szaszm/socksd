#include "Client.h"
#include "Logger.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <poll.h> // poll, struct pollfd
#include <string.h> // memset

#include <sys/types.h>
#include <sys/socket.h> // socket, bind, listen, accept
#include <netdb.h> // struct addrinfo, getaddrinfo
#include <arpa/inet.h> // inet_ntop

#define BACKLOG 50
#define HANDLE_OP continue
#define ARRAY_LENGTH(a) (sizeof(*(a))/sizeof(a))

struct MainContext {
	struct Logger logger;
	const char *bindhost;
	const char *bindport;
	struct Client *clients;
	size_t n_clients;
	int listener_fd;
};

//void Client_filterClosed(struct Client **clients, size_t *n_clients);
void Client_filterClosed(struct MainContext *);
//struct Client *getClientByFd(struct Client *clients, size_t len, int fd);
struct Client *getClientByFd(const struct MainContext *, int fd);
//struct pollfd *getPollFds(int listener_fd, struct Client *clients, size_t n_clients, size_t *nfds);
struct pollfd *getPollFds(const struct MainContext *, size_t *nfds);

void str_addrinfo(char *buf, size_t buflen, const struct addrinfo *);

int main(void) {
	struct MainContext ctx = {
		.logger = Logger_init(LOG_LEVEL_DEBUG),
		.bindhost = "localhost",
		.bindport = "1080",
		.clients = NULL,
		.n_clients = 0,
		.listener_fd = -1
	};

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	//hints.ai_family = AF_UNSPEC;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo *srvinfo;
	int status = getaddrinfo(ctx.bindhost, ctx.bindport, &hints, &srvinfo);
	if(status != 0) {
		Logger_error(&ctx.logger, "getaddrinfo", gai_strerror(status));
		return 1;
	} else {
		char aistrbuf[30];
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

	while(1) {
		size_t fds_len;
		if(fds) { free(fds); fds = NULL; }
		Client_filterClosed(&ctx);
		fds = getPollFds(&ctx, &fds_len);
		res = poll(fds, fds_len, -1);
		if(res == -1) { Logger_perror(&ctx.logger, LOG_LEVEL_WARNING, "poll"); continue; }
		else if(res == 0) { Logger_debug(&ctx.logger, "poll", "poll timeout\n"); continue; }
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
					HANDLE_OP;
				}
				size_t index = c - ctx.clients;
				Client_close(&ctx.clients[index]);
				HANDLE_OP;
			}
			if(!(fds[i].revents & POLLIN)) {
				fds[i].revents = 0;
				HANDLE_OP;
			}
			if(fds[i].fd == ctx.listener_fd) {
				res = accept(ctx.listener_fd, NULL, NULL);
				if(res == -1) HANDLE_OP;
				Logger_verbose(&ctx.logger, "event_loop", "accepted connection.\n");

				struct Client *newclients = (struct Client *)realloc(ctx.clients, ++ctx.n_clients * sizeof(struct Client));
				if(!newclients) {
					Logger_perror(&ctx.logger, LOG_LEVEL_ERROR, "realloc@event_loop");
					size_t j;
					for(j = 0; j < ctx.n_clients; ++j) {
						if(ctx.clients[j].client_fd) close(ctx.clients[j].client_fd);
						if(ctx.clients[j].remote_fd) close(ctx.clients[j].remote_fd);
					}
					free(ctx.clients);
					close(ctx.listener_fd);
					return 1;
				}
				ctx.clients = newclients;
				newclients[ctx.n_clients-1] = Client_init(res);
			} else {
				// handle client connection
				struct Client *c = getClientByFd(&ctx, fds[i].fd);
				if(!c) {
					Logger_warn(&ctx.logger, "event_loop", "Client already closed.\n");
					HANDLE_OP;
				}
				int res[2] = {0,0};
				if(c->client_fd == fds[i].fd) res[0] = Client_handleActivity(c);
				if(c->remote_fd == fds[i].fd) res[1] = Client_handleRemoteActivity(c);
				if(res[0] || res[1]) 
				{
					Client_close(c);
					HANDLE_OP;
				}
			}
		}
	}
	if(fds) { free(fds); fds = NULL; }
	free(ctx.clients);

	return 0;
}

void Client_filterClosed(struct MainContext *ctx) {
	size_t i, offset = 0;
	struct Client *clients = ctx->clients;
	size_t n_clients = ctx->n_clients;
	for(i = 0; i + offset < n_clients; ) {
		if(clients[i+offset].client_fd == 0 && clients[i+offset].remote_fd == 0)  {
			offset++;
			continue;
		}
		clients[i] = clients[i+offset];
		i++;
	}
	if(offset == 0) return;
	struct Client *newptr = (struct Client *)realloc(clients, (n_clients - offset)*sizeof(struct Client));
	if(newptr == NULL && n_clients != offset) {
		perror("realloc@filterClosed");
		exit(1);
	} else if(n_clients == offset){
		printf("no clients remaining.\n");
	}

	ctx->clients = newptr;
	ctx->n_clients -= offset;
}


struct Client *getClientByFd(const struct MainContext *ctx, int fd) {
	size_t i;
	for(i = 0; i < ctx->n_clients; ++i) {
		if(ctx->clients[i].client_fd == fd || ctx->clients[i].remote_fd == fd)
			return &ctx->clients[i];
	}
	return NULL;
}

struct pollfd *getPollFds(const struct MainContext *ctx, size_t *nfds) {
	size_t i;
	size_t fds = 0;
	for(i = 0; i < ctx->n_clients; ++i) {
		if(ctx->clients[i].client_fd) {
			fds++;
		}
		if(ctx->clients[i].remote_fd) {
			fds++;
		}
	}
	fds++; // one more for the listener
	*nfds = fds;
	struct pollfd *res = (struct pollfd *)malloc(fds * sizeof(struct pollfd));
	if(!res) {
		Logger_perror(&ctx->logger, LOG_LEVEL_WARNING, "malloc");
		return NULL;
	}
	size_t j;
	for(i = j = 0; i < ctx->n_clients; ++i) {
		if(ctx->clients[i].client_fd) {
			res[j++] = (struct pollfd){
				.fd = ctx->clients[i].client_fd,
				.events = POLLIN,
				.revents = 0
			};
		}
		if(ctx->clients[i].remote_fd) {
			res[j++] = (struct pollfd){
				.fd = ctx->clients[i].remote_fd,
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
	snprintf(buf, buflen, "using address: %s: %s:%hu\n", ipver, ipstr, port);
}
