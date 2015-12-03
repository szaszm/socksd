#include "Client.h"
#include "Logger.h"

#include <unistd.h>
#include <arpa/inet.h> // struct sockaddr_in{,6}, inet_ntop
#include <stdio.h>
#include <stdlib.h> // realloc, free
#include <string.h> // memset
#include <errno.h> // errno
#include <netdb.h> // struct addrinfo, getaddrinfo, freeaddrinfo

#define REQUEST_CONNECT 1

/**
 * Keeps reading fd until len bytes are read
 * @param int fd The file descriptor to read from
 * @param void* buf The buffer to read to
 * @param size_t len The number of bytes to read
 */
static int readAll(int fd, void *buf, size_t len);

/**
 * Keeps sending client until all is sent
 * @param int fd The file descriptor to send to
 * @param void* buf The data to send
 * @param size_t buflen The number of bytes to send.
 */
static int sendAll(int fd, void *buf, size_t buflen);

static char *readString(int fd);

static int nslookup(struct sockaddr *dst, const char *name);


struct Client Client_init(int fd, const struct Logger *logger) {
	struct Client res;
	res.client_fd = fd;
	res.remote_fd = 0;
	res.version = 0;
	res.state = STATE_INITIAL_WAIT;
	res.logger = logger;
	res.socks5_method = 0xff; // no method by default
	return res;
}

void Client_close(struct Client *client) {
	int res = 0;
	if(client->client_fd)
		res = close(client->client_fd);
	if(res == -1) {
		//fprintf(stderr, "close(%d): %s\n", client->client_fd, strerror(errno)); 
		Logger_warn(client->logger, "close@Client_close", "fd=%d %s", client->client_fd, strerror(errno));
	}
	else client->client_fd = 0;
	if(client->remote_fd)
		res = close(client->remote_fd);
	if(res == -1) {
		//fprintf(stderr, "close(%d): %s\n", client->client_fd, strerror(errno));
		Logger_warn(client->logger, "close@Client_close", "fd=%d %s", client->client_fd, strerror(errno));
	}
	else client->remote_fd = 0;
	Logger_debug(client->logger, "Client_close", "connection closed.");
}

int Client_handleActivity(struct Client *client) {
	switch(client->state) {
		case STATE_INITIAL_WAIT:
			return Client_handleInitialMessage(client);
		case STATE_REQUEST_WAIT:
			return Client_handleSocks5Request(client);
		case STATE_PROXIED:
			return Client_forward(client);
		default:
			Logger_warn(client->logger, "Client_handleActivity", "Invalid state: %d", client->state);
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
	Logger_verbose(client->logger, "Client_handleInitialMessage", "client version: %hhu", version);
	switch(version) {
		case 4: return Client_handleSocks4Request(client);
		case 5: return Client_handleSocks5MethodRequest(client);
		default: return 1; // invalid version number, close connection
	}
	return 0;
}

int Client_handleSocks4Request(struct Client *client) {
	char buf[7];
	int res = readAll(client->client_fd, buf, 7);
	if(res == -1) {
		Logger_perror(client->logger, LOG_LEVEL_WARNING, "read@Client_handleSocks4Request");
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
		if(!dsthost) Logger_perror(client->logger, LOG_LEVEL_WARNING, "readString@Client_handleSocks4Request");
		Logger_verbose(client->logger, "Client_handleSocks4Request", "LOOKUP %s\n", dsthost);
		if(nslookup((struct sockaddr *)addr, dsthost)) {
			Logger_info(client->logger, "Client_handleSocks4Request", "name lookup failed.");
			free(dsthost);
			return 1;
		}
		free(dsthost);
	}
	memcpy(&addr->sin_port, &buf[1], sizeof(addr->sin_port));

	char addrstr[INET_ADDRSTRLEN];
	inet_ntop(client->dst.ss_family, &addr->sin_addr.s_addr, addrstr, sizeof(struct sockaddr_in));
	unsigned short port = ntohs(addr->sin_port);
	Logger_verbose(client->logger, "Client_handleSocks4Request", "CONNECT %s:%hu\n", addrstr, port);

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
		Logger_perror(client->logger, LOG_LEVEL_WARNING, "send@Client_sendSocks4RequestReply");
		return 1;
	} else if(res < 8) {
		Logger_warn(client->logger, "Client_sendSocks4RequestReply", "Failed to send all data, closing connection.");
		return 1;
	}
	Logger_verbose(client->logger, "Client_sendSocks4RequestReply", "Request %s.", granted ? "granted" : "denied");
	return 0;
}

int Client_startForwarding(struct Client *client) {
	client->remote_fd = socket(client->dst.ss_family, SOCK_STREAM, 0);
	if(client->remote_fd == -1) {
		Logger_perror(client->logger, LOG_LEVEL_WARNING, "socket");
		return 1;
	}
	socklen_t len = (client->dst.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	int res = connect(client->remote_fd, (struct sockaddr *)&client->dst, len);
	if(res == -1) {
		Logger_perror(client->logger, LOG_LEVEL_WARNING, "connect");
		return 1;
	}
	client->state = STATE_PROXIED;
	Logger_verbose(client->logger, "Client_startForwading", "connected to remote.");

	return 0;
}

static int Client_selectSocks5Method(struct Client *_this, unsigned char method_id) {
	unsigned char response[2];
	response[0] = 5;
	response[1] = _this->socks5_method = method_id;
	int res = sendAll(_this->client_fd, response, 2);
	if(res == -1) {
		Logger_perror(_this->logger, LOG_LEVEL_WARNING, "sendAll@Client_selectSocks5Method");
		return 1;
	} else if(res != 2) {
		Logger_warn(_this->logger, "Client_selectSocks5Method", "Couldn't select method, closing connection.");
		return 1;
	}
	_this->state = STATE_REQUEST_WAIT;
	Logger_verbose(_this->logger, "Client_selectSocks5Method", "Client selected method %hhx. Entering request wait state.", method_id);
	return 0;
}

int Client_handleSocks5MethodRequest(struct Client *_this) {
	unsigned char n_methods;
	int res = read(_this->client_fd, &n_methods, 1);
	if(res < 1) {
		Logger_perror(_this->logger, LOG_LEVEL_WARNING, "read@Client_handleSocks5MethodRequest");
		return 1;
	}
	if(n_methods < 1) {
		Logger_warn(_this->logger, "Client_handleSocks5MethodRequest", "Client doesn't support any methods");
		Client_selectSocks5Method(_this, 0xff); // 0xff: no acceptable methods
		return 1;
	}

	unsigned char methods[n_methods];
	res = readAll(_this->client_fd, methods, n_methods);
	if(res != n_methods) {
		Logger_warn(_this->logger, "Client_handleSocks5MethodRequest", "Couldn't read method list, closing connection.");
		return 1;
	}
	
	int i;
	for(i = 0; i < n_methods; ++i) {
		if(methods[i] == 0x00) break; // If client supports no auth method, then select it
	}

	if(i == n_methods) {
		// No acceptable methods found
		Client_selectSocks5Method(_this, 0xff); // 0xff: no acceptable methods
		return 1;
	}

	// If we found an acceptable method, then select it
	return Client_selectSocks5Method(_this, methods[i]);
}

//static int Client_sendSocks5RequestReply(struct Client *_this, 

int Client_handleSocks5Request(struct Client *_this) {
	char buf1[4];
	int res = readAll(_this->client_fd, buf1, 4);
	if(res == -1) {
		Logger_perror(_this->logger, LOG_LEVEL_WARN, "readAll@handleSocks5Request");
		return 1;
	} else if(res != 4) {
		Logger_warn(_this->logger, "Client_handleSocks5Request", "Couldn't read SOCKS5 request, closing connection.");
		return 1;
	}
	if(buf1[0] != 0x05) { // Version 5
		Logger_warn(_this->logger, "Client_handleSocks5Request", "Client sent a request with an invalid version number. Closing connection.");
		return 1;
	}
	if(buf1[1] != 0x01) { // buf[1]: command, 0x01: CONNECT command
		Logger_info(_this->logger, "Client_handleSocks5Request", 
				"The client requested an unsupported command: 0x%hhx. Closing connection.", buf1[1]);
		return 1;
	}

	// TODO
	Logger_warn(_this->logger, "Client_handleSocks5Request", "INCOMPLETE IMPLEMENTATION");
	return 1;
}

static int Client_directedForward(const struct Client *client, int direction) {
	char buf[BUFSIZ];
	int res;
	int srcfd = (direction) ? client->client_fd : client->remote_fd;
	int dstfd = (direction) ? client->remote_fd : client->client_fd;
	res = read(srcfd, buf, BUFSIZ);
	if(res == -1) {
		Logger_perror(client->logger, LOG_LEVEL_WARNING, "read@Client_directedForward");
		return 1;
	} else if(res == 0) {
		Logger_verbose(client->logger, "Client_directedForward", "%s closed connection.\n", direction ? "client" : "remote");
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

void Client_debugPrintInfo(const struct Client *client) {
	// TODO
	Logger_warn(client->logger, "Client_debugPrintInfo", "TODO: Client_debugPrintInfo\n");
}

static int sendAll(int fd, void *buf, size_t len) {
	if(len == 0) return 0;
	size_t sent = 0;
	int res;
	while((res = send(fd, buf+sent, len-sent, 0)) != -1 && res && (sent += res) < len);
	return res == -1 ? -1 : sent;
}

static int readAll(int fd, void *buf, size_t len) {
	if(len == 0) return 0;
	size_t _read = 0;
	int res;
	while((res = read(fd, buf + _read, len - _read)) != -1 && res && (_read += res) < len);
	return res == -1 ? -1 : _read;
}

static char *readString(int fd) {
	int res;
	size_t _read = 0;
	char c;
	char *dstbuf = (char *)malloc(1);
	while((res = read(fd, &c, 1)) == 1 && c) {
		char *newdstbuf = (char *)realloc(dstbuf, ++_read + 1);
		if(!newdstbuf) {
			free(dstbuf);
			return NULL;
		}
		dstbuf = newdstbuf;
		dstbuf[_read-1] = c;
	}
	if(res == -1) {
		free(dstbuf);
		return NULL;
	}
	dstbuf[_read] = 0;
	return dstbuf;
}

static int nslookup(struct sockaddr *dst, const char *name) {
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
