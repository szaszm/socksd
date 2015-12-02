#include "Client.h"

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

struct Client *getClientByFd(struct Client *clients, size_t len, int fd) {
	size_t i;
	for(i = 0; i < len; ++i) {
		if(clients[i].client_fd == fd || clients[i].remote_fd == fd)
			return &clients[i];
	}
	return NULL;
}

struct pollfd *getPollFds(int listener_fd, struct Client *clients, size_t n_clients, size_t *nfds) {
	size_t i;
	size_t fds = 0;
	for(i = 0; i < n_clients; ++i) {
		if(clients[i].client_fd) {
			fds++;
		}
		if(clients[i].remote_fd) {
			fds++;
		}
	}
	fds++; // one more for the listener
	*nfds = fds;
	struct pollfd *res = (struct pollfd *)malloc(fds * sizeof(struct pollfd));
	if(!res) {
		perror("malloc");
		return NULL;
	}
	size_t j;
	for(i = j = 0; i < n_clients; ++i) {
		if(clients[i].client_fd) {
			res[j++] = (struct pollfd){
				.fd = clients[i].client_fd,
				.events = POLLIN,
				.revents = 0
			};
		}
		if(clients[i].remote_fd) {
			res[j++] = (struct pollfd){
				.fd = clients[i].remote_fd,
				.events = POLLIN,
				.revents = 0
			};
		}
	}
	res[j] = (struct pollfd){
		.fd = listener_fd,
		.events = POLLIN,
		.revents = 0
	};
	return res;
}

void Client_filterClosed(struct Client **clients, size_t *n_clients);
void print_addrinfo(const struct addrinfo *);

int main(void) {
	const char *host = "localhost";
	const char *port = "1080";

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	//hints.ai_family = AF_UNSPEC;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo *srvinfo;
	int status = getaddrinfo(host, port, &hints, &srvinfo);
	if(status != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return 1;
	}
	print_addrinfo(srvinfo);


	int srv = socket(srvinfo->ai_family, srvinfo->ai_socktype, srvinfo->ai_protocol);
	if(srv == -1) {
		perror("socket");
		freeaddrinfo(srvinfo);
		return 1;
	}
	printf("socket created.\n");

	int reuse = 1;
	if(setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
		perror("setsockopt");
	}
	printf("Reuse address flag set.\n");

	int res = bind(srv, srvinfo->ai_addr, srvinfo->ai_addrlen);
	if(res == -1) {
		perror("bind");
		return 1;
	}
	printf("bound.\n");

	freeaddrinfo(srvinfo);
	srvinfo = NULL;

	if(listen(srv, BACKLOG) == -1) {
		perror("listen");
		return 1;
	}
	printf("listening...\n");

	struct Client *clients = NULL;
	size_t clients_len = 0;
	struct pollfd *fds = NULL;

	while(1) {
		size_t fds_len;
		if(fds) { free(fds); fds = NULL; }
		Client_filterClosed(&clients, &clients_len);
		fds = getPollFds(srv, clients, clients_len, &fds_len);
		res = poll(fds, fds_len, -1);
		if(res == -1) { perror("poll"); continue; }
		else if(res == 0) { printf("poll timeout\n"); continue; }
#ifdef DEBUG
		else printf("poll activity.\n");
#endif
		nfds_t i;
		for(i = 0; i < fds_len; ++i) {
			if(fds[i].revents == 0) continue;
#ifdef DEBUG
			printf("events: ");
			if(fds[i].revents & POLLHUP) printf("POLLHUP ");
			if(fds[i].revents & POLLERR) printf("POLLERR ");
			if(fds[i].revents & POLLNVAL) printf("POLLNVAL ");
			if(fds[i].revents & POLLIN) printf("POLLIN ");
			if(fds[i].revents & POLLOUT) printf("POLLOUT ");
			if(fds[i].revents & POLLPRI) printf("POLLPRI ");
			putchar('\n');
#endif
			if(fds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
				struct Client *c = getClientByFd(clients, clients_len, fds[i].fd);
				if(!c) {
					printf("Client already closed.\n");
					HANDLE_OP;
				}
				size_t index = c - clients;
				Client_close(&clients[index]);
				HANDLE_OP;
			}
			if(!(fds[i].revents & POLLIN)) {
				fds[i].revents = 0;
				HANDLE_OP;
			}
			if(fds[i].fd == srv) {
				res = accept(srv, NULL, NULL);
				if(res == -1) HANDLE_OP;
				printf("accepted connection.\n");

				struct Client *newclients = (struct Client *)realloc(clients, ++clients_len * sizeof(struct Client));
				if(!newclients) {
					perror("realloc@mainLoop");
					size_t j;
					for(j = 0; j < clients_len; ++j) {
						if(clients[j].client_fd) close(clients[j].client_fd);
						if(clients[j].remote_fd) close(clients[j].remote_fd);
					}
					free(clients);
					close(srv);
					return 1;
				}
				clients = newclients;
				newclients[clients_len-1] = Client_init(res);
			} else {
				// handle client connection
				struct Client *c = getClientByFd(clients, clients_len, fds[i].fd);
				if(!c) {
					printf("Client already closed.\n");
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
	free(clients);

	return 0;
}

void Client_filterClosed(struct Client **clientsptr, size_t *n_clientsptr) {
	size_t i, offset = 0;
	struct Client *clients = *clientsptr;
	size_t n_clients = *n_clientsptr;
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

	*clientsptr = newptr;
	*n_clientsptr -= offset;
}

void print_addrinfo(const struct addrinfo *res) {
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
	printf("using address: %s: %s:%hu\n", ipver, ipstr, port);
}

