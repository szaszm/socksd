#ifndef CLIENT_H
#define CLIENT_H

#include <sys/socket.h> // struct sockaddr_storage

enum SOCKS_STATE { STATE_INITIAL_WAIT, STATE_REQUEST_WAIT, STATE_PROXIED };
struct Client {
	int client_fd;
	int remote_fd;
	unsigned char version;
	enum SOCKS_STATE state;
	struct sockaddr_storage dst;
	const struct Logger *logger;
	unsigned char socks5_method;
	int af_restriction;
};

struct Client Client_init(int fd, const struct Logger *, int af_restriction);
void Client_close(struct Client *);
int Client_handleActivity(struct Client *);
int Client_handleRemoteActivity(struct Client *);


#endif /* CLIENT_H */
