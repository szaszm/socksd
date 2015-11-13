#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#define BACKLOG 50

// http://stackoverflow.com/questions/3599160/unused-parameter-warnings-in-c-code
#define UNUSED(x) (void)(x)

int main(void) {
	const char *host = "localhost";
	char char *port = "1080";

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo *srvinfo;
	int status = getaddrinfo(host, port, hints, &srvinfo);
	if(status != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return 1;
	}

	int srv = socket(srvinfo->ai_family, srvinfo->ai_socktype, srvinfo->ai_protocol);
	if(srv == -1) {
		perror("socket");
		freeaddrinfo(srvinfo);
		return 1;
	}

	int reuse = 1;
	if(setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1) {
		perror("setsockopt");
	}

	int res = bind(srv, srvinfo->ai_addr, srvinfo->ai_addrlen);
	if(res == -1) {
		perror("bind");
		return 1;
	}

	freeaddrinfo(srvinfo);
	srvinfo = NULL;

	if(listen(srv, BACKLOG) == -1) {
		perror("listen");
		return 1;
	}

	nfds_t fds_len = 1;
	struct pollfd *fds = (struct pollfd *)malloc(fds_len * sizeof(struct pollfd));
	if(!fds) {
		perror("malloc");
		close(srv);
		return 1;
	}

	fds[0] =  {
		.fd = srv,
		.events = POLLIN,
		.revents = 0
	};
	

	sigset_t sigmask;
	sigfillset(&sigmask);
	while(1) {
		res = ppoll(fds, fds_len, NULL, &sigmask);
		if(res == -1) { perror("poll"); continue; }
		else if(res == 0) { printf("poll timeout\n"); continue; }
		int i;
		for(i = 0; i < nfds; ++i) {
			if(fds[i].fd == srv) {
				res = accept(srv, NULL, NULL);
				struct pollfd *newfds = realloc(fds, ++fds_len * sizeof(struct pollfd));
				if(!newfds) {
					perror("realloc");
					int j;
					for(j = 0; j < fds_len-1; ++j) close(fds[j].fd);
					free(fds);
					return 1;
				}
				newfds[fds_len-1] = res;
				// handle client connection
			}
		}
	}


	return 0;
}
