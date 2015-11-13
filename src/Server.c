#include "Server.h"
#include <stdio.h>

#define BACKLOG_SIZE 50

static void Server_dtor_real(Server *_this);
static void realConnectionHandler(uv_stream_t *server, int status);

static const Server_vtable vtbl = { Server_dtor_real };

static int isValidIpv4Addr(const char *addr) {
	unsigned char dummy[4];
	return sscanf(addr, "%hhu.%hhu.%hhu.%hhu", &dummy[0], &dummy[1], &dummy[2], &dummy[3]) == 4;
}

Server *Server_create(const char *addr, int port) {
	Server *dst = malloc(sizeof(Server));
	if(!dst) return NULL;
	int res = Server_ctor(dst, addr, port);
	if(!res) { 
		free(dst);
		dst = NULL;
	}
	return dst;
}


int Server_ctor(Server *_this, const char *addr, int port) {
	int res;
	if(isValidIpv4Addr(addr)) {
		res = uv_ip4_addr(addr, port, (struct sockaddr_in *)&_this->addr);
	} else {
		res = uv_ip6_addr(addr, port, (struct sockaddr_in6 *)&_this->addr);
	}
	if(res < 0) return 0;
	_this->port = port;
	_this->vtbl = vtbl;
	_this->onConnection = NULL;
	_this->loop = NULL;
	return 1;
}

void Server_dtor(Server *_this) {
	if(_this && _this->vtbl && _this->vtbl->dtor)
		_this->vtbl->dtor(_this);
}

void Server_dtor_real(Server *_this) {
	if(_this->loop) {
		Server_stop(_this);
	}
	free(_this->addr);
	_this->addr = NULL;
	free(_this->vtbl);
	_this->vtbl = NULL;
}

void Server_destroy(Server *_this) {
	Server_dtor(_this);
	free(_this);
}

void Server_onConnection(Server *_this, Server_connectionHandler onConnection) {
	_this->onConnection = onConnection;
}

void Server_setUserData(Server *_this, void *data) {
	_this->userdata = data;
}

void Server_start(Server *_this, uv_loop_t *loop) {
	_this->loop = loop;
	uv_tcp_init(loop, &_this->server);
	uv_tcp_bind(&_this->server, (const struct sockaddr *)&_this->addr, 0);
	int r = uv_listen((uv_stream_t *)&server, BACKLOG_SIZE, realConnectionHandler);
	_this->server.data = _this;
	if(!r) {
		fprintf(stderr, "Failed to listen()\n");
	}
}

static void realConnectionHandler(uv_stream_t *server, int status) {
	Server *_this = (Server *)server->data;
	if(status < 0) {
		fprintf(stderr, "New connection error: %s\n", uv_strerror(status));
		return;
	}

	uv_tcp_t *client = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
	if(!client) {
		fprintf(stderr, "malloc error\n");
		return;
	}
	uv_tcp_init(_this->loop, client);
	if(uv_accept(&_this->server, (uv_stream_t *)client) == 0) {
		if(_this->onConnection)
			_this->onConnection(client);
	}
	else {
		uv_close((uv_handle_t *)client, NULL);
		free(client);
	}
}

void Server_stop(Server *_this) {
	uv_close((uv_handle_t *)_this->server, NULL);
	_this->loop = NULL;
}
