#ifndef CLIENT_H
#define CLIENT_H

#include <sys/socket.h> // struct sockaddr_storage

enum SOCKS_STATE { STATE_INITIAL_WAIT, STATE_REQUEST_WAIT, STATE_PROXIED };
struct Client {
	int client_fd;
	int remote_fd;
	int version;
	enum SOCKS_STATE state;
	struct sockaddr_storage dst;
};

struct Client Client_init(int fd);
void Client_close(struct Client *);
int Client_handleActivity(struct Client *);
int Client_handleRemoteActivity(struct Client *);
int Client_handleInitialMessage(struct Client *);
int Client_handleSocks4Request(struct Client *);
int Client_sendSocks4RequestReply(const struct Client *, int granted);
int Client_startForwarding(struct Client *client);
int Client_handleSocks5Request(struct Client *);
int Client_handleRequestMessage(struct Client *);
int Client_forward(const struct Client *);
int Client_backward(const struct Client *);
void Client_debugPrintInfo(const struct Client *);


#endif /* CLIENT_H */
