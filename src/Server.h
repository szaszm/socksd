#ifndef SERVER_H
#define SERVER_H
#include <uv.h>
#include <stdlib.h>

#define SERVER_IPV4_ANY_ADDR "0.0.0.0"
#define SERVER_IPV6_ANY_ADDR "::"
#define SERVER_ANY_ADDR NULL

struct Server_vtable {
	void (*dtor)(Server *);
};

// TODO: a típus esetleges finomhangolása
typedef void (*Server_connectionHandler)(uv_tcp_t *);

struct Server {
	Server_vtable *vtbl;
	struct sockaddr_storage addr;
	Server_connectionHandler onConnection;
	uv_loop_t *loop;
	uv_tcp_t server;
	void *userdata;
};
typedef struct Server Server;

Server *Server_create(const char *addr, int port); // success: valid pointer, failure: NULL
int Server_ctor(Server *, const char *addr, int port); // protected, success: 1
void Server_dtor(Server *); // protected
void Server_dtor_real(Server *); // protected
void Server_destroy(Server *);

void Server_onConnection(Server *, Server_connectionHandler onConnection);
void Server_setUserData(Server *, void *);

void Server_start(Server *, uv_loop_t *);
void Server_stop(Server *);


#endif /* SERVER_H */
