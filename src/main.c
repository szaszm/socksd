#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>

#define BACKLOG 50

#define REQUEST_CONNECT 1

// http://stackoverflow.com/questions/3599160/unused-parameter-warnings-in-c-code
#define UNUSED(x) (void)(x)

#define HANDLE_OP continue


enum SOCKS_STATE { STATE_INITIAL_WAIT, STATE_REQUEST_WAIT, STATE_PROXIED };
struct Client {
	int client_fd;
	int remote_fd;
	int version;
	enum SOCKS_STATE state;
	struct sockaddr_storage dst;
};

struct Client *getClientByFd(struct Client *clients, size_t len, int fd) {
	size_t i;
	for(i = 0; i < len; ++i) {
		if(clients[i].client_fd == fd || clients[i].remote_fd == fd)
			return &clients[i];
	}
	return NULL;
}

struct Client Client_init(int fd) {
	struct Client res;
	res.client_fd = fd;
	res.remote_fd = 0;
	res.version = 0;
	res.state = STATE_INITIAL_WAIT;
	return res;
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

void Client_close(struct Client *client);
int Client_handleActivity(struct Client *);
int Client_handleRemoteActivity(struct Client *);
int Client_handleInitialMessage(struct Client *);
int Client_handleSocks4Request(struct Client *);
int Client_sendSocks4RequestReply(const struct Client *client, int granted);
int Client_startForwarding(struct Client *client);
int Client_handleSocks5Request(struct Client *);
int Client_handleRequestMessage(struct Client *);
int Client_forward(const struct Client *);
int Client_backward(const struct Client *);
void Client_debugPrintInfo(const struct Client *);

void Client_filterClosed(struct Client **clients, size_t *n_clients);
void print_addrinfo(const struct addrinfo *);

/**
 * Keeps sending client until all is sent
 * @param int fd The file descriptor to send to
 * @param void* buf The data to send
 * @param size_t buflen The number of bytes to send.
 */
int sendAll(int fd, void *buf, size_t buflen);

/**
 * Keeps reading fd until len bytes are read
 * @param int fd The file descriptor to read from
 * @param void* buf The buffer to read to
 * @param size_t len The number of bytes to read
 */
int readAll(int fd, void *buf, size_t len);

char *readString(int fd);

int nslookup(struct sockaddr *dst, const char *name);

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

int Client_handleActivity(struct Client *client) {
	switch(client->state) {
		case STATE_INITIAL_WAIT:
			return Client_handleInitialMessage(client);
		case STATE_REQUEST_WAIT:
			return Client_handleRequestMessage(client);
		case STATE_PROXIED:
			return Client_forward(client);
		default:
			fprintf(stderr, "Invalid state.\n");
			return 1;
	}
}

int Client_handleRemoteActivity(struct Client *client) {
	if(client->state != STATE_PROXIED) return 1;
	return Client_backward(client);
}

int Client_handleInitialMessage(struct Client *client) {
	char version;
	int res = read(client->client_fd, &version, 1);
	if(res == 0) {
		// connection closed
		return 1;
	}
	client->version = version;
	printf("v%hhu ", version);
	switch(version) {
		case 4: return Client_handleSocks4Request(client);
		case 5: return Client_handleSocks5Request(client);
		default: return 1; // invalid version number, close connection
	}
	return 0;
}

int Client_handleSocks4Request(struct Client *client) {
	char buf[7];
	int res = readAll(client->client_fd, buf, 7);
	if(res == -1) {
		perror("read");
		return 1;
	} else if(res == 0) {
		return 1;
	}
	char req = buf[0];
	client->dst.ss_family = AF_INET;
	struct sockaddr_in *addr = (struct sockaddr_in *)&client->dst;
	memcpy(&addr->sin_addr.s_addr, &buf[3], sizeof(addr->sin_addr.s_addr));
	char *user = readString(client->client_fd);
	free(user); // ignore username, it doesn't provide any security anyway
	if(ntohl(addr->sin_addr.s_addr) == 1) {
		// Socks4a DNS
		char *dsthost = readString(client->client_fd);
		printf("LOOKUP %s\n", dsthost);
		if(nslookup((struct sockaddr *)addr, dsthost)) {
			fprintf(stderr, "name lookup failed.\n");
			free(dsthost);
			return 1;
		}
		free(dsthost);
	}
	memcpy(&addr->sin_port, &buf[1], sizeof(addr->sin_port));

	char addrstr[INET_ADDRSTRLEN];
	inet_ntop(client->dst.ss_family, &addr->sin_addr.s_addr, addrstr, sizeof(struct sockaddr_in));
	unsigned short port = ntohs(addr->sin_port);
	printf("CONNECT %s:%hu\n", addrstr, port);

	if(req != REQUEST_CONNECT) {
		Client_sendSocks4RequestReply(client, 0);
		return 1;
	}
	res = Client_sendSocks4RequestReply(client, 1);
	return res || Client_startForwarding(client);
}

int Client_sendSocks4RequestReply(const struct Client *client, int granted) {
	char buf[8];
	memset(buf, 0, 8);
	buf[1] = granted ? 90 : 91;
	int res = sendAll(client->client_fd, buf, 8);
	if(res == -1) {
		perror("send");
		return 1;
	} else if(res < 8) {
		fprintf(stderr, "Failed to send all data, closing connection.\n");
		return 1;
	}
	printf("Request %s.\n", granted ? "granted" : "denied");
	return 0;
}

int Client_handleSocks5Request(struct Client *client) {
	// TODO
	printf("TODO: Client_handleSocks5Request\n");
	UNUSED(client);
	return 1;
}

int Client_handleRequestMessage(struct Client *client) {
	// TODO
	printf("TODO: Client_handleRequestMessage\n");
	UNUSED(client);
	return 0;
}

static int Client_directedForward(const struct Client *client, int direction) {
	char buf[BUFSIZ];
	int res;
	int srcfd = (direction) ? client->client_fd : client->remote_fd;
	int dstfd = (direction) ? client->remote_fd : client->client_fd;
	res = read(srcfd, buf, BUFSIZ);
	if(res == -1) {
		perror("read");
		return 1;
	} else if(res == 0) {
		printf("%s closed connection.\n", direction ? "client" : "remote");
		return 1;
	}
	res = sendAll(dstfd, buf, res);
	return res == -1;
}

int Client_forward(const struct Client *client) {
	return Client_directedForward(client, 1);
}


int Client_backward(const struct Client *client) {
	return Client_directedForward(client, 0);
}

int Client_startForwarding(struct Client *client) {
	client->remote_fd = socket(client->dst.ss_family, SOCK_STREAM, 0);
	if(client->remote_fd == -1) {
		perror("socket");
		return 1;
	}
	socklen_t len = (client->dst.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	int res = connect(client->remote_fd, (struct sockaddr *)&client->dst, len);
	if(res == -1) {
		perror("connect");
		return 1;
	}
	client->state = STATE_PROXIED;
	printf("connected to remote.\n");

	return 0;
}

void Client_close(struct Client *client) {
	int res = 0;
	if(client->client_fd)
		res = close(client->client_fd);
	if(res == -1) {
		fprintf(stderr, "close(%d): %s\n", client->client_fd, strerror(errno)); 
	}
	else client->client_fd = 0;
	if(client->remote_fd)
		res = close(client->remote_fd);
	if(res == -1) {
		fprintf(stderr, "close(%d): %s\n", client->client_fd, strerror(errno));
	}
	else client->remote_fd = 0;
#ifdef DEBUG
	printf("connection closed.\n");
#endif
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
	struct Client *newptr = (struct Client *)realloc(clients, n_clients - offset);
	if(newptr == NULL) {
		perror("realloc@filterClosed");
		exit(1);
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

int sendAll(int fd, void *buf, size_t len) {
	if(len == 0) return 0;
	size_t sent = 0;
	int res;
	while((res = send(fd, buf+sent, len-sent, 0)) != -1 && res && (sent += res) < len);
	return res == -1 ? -1 : sent;
}

int readAll(int fd, void *buf, size_t len) {
	if(len == 0) return 0;
	size_t _read = 0;
	int res;
	while((res = read(fd, buf + _read, len - _read)) != -1 && res && (_read += res) < len);
	return res == -1 ? -1 : _read;
}

char *readString(int fd) {
	int res;
	size_t _read = 0;
	char c;
	char *dstbuf = (char *)malloc(1);
	while((res = read(fd, &c, 1)) == 1 && c) {
		char *newdstbuf = (char *)realloc(dstbuf, ++_read + 1);
		if(!newdstbuf) {
			perror("realloc@readString");
			free(dstbuf);
			return NULL;
		}
		dstbuf = newdstbuf;
		dstbuf[_read-1] = c;
	}
	if(res == -1) {
		perror("read");
		free(dstbuf);
		return NULL;
	}
	dstbuf[_read] = 0;
	return dstbuf;
}

int nslookup(struct sockaddr *dst, const char *name) {
	struct addrinfo *ai;
	printf("looking up %s\n", name);
	int status = getaddrinfo(name, NULL, NULL, &ai);
	if(status != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return 1;
	}
	printf("nslookup: af: %s.\n", ai->ai_family == AF_INET6 ? "AF_INET6" : ai->ai_family == AF_INET ? "AF_INET" : "?");
	if(ai->ai_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)dst;
		*sin = *((struct sockaddr_in *)ai->ai_addr);
	} else if(ai->ai_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)dst;
		*sin6 = *((struct sockaddr_in6 *)ai->ai_addr);
	} else {
		fprintf(stderr, "unknown address family: %d\n", dst->sa_family);
		return 1;
	}

	freeaddrinfo(ai);
	return 0;
}

void Client_debugPrintInfo(const struct Client *client) {
	// TODO
	printf("TODO: Client_debugPrintInfo\n");
	UNUSED(client);
}
