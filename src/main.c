#include <uv.h>
#include <stdlib.h>
#include <string.h>

// http://stackoverflow.com/questions/3599160/unused-parameter-warnings-in-c-code
#define UNUSED(x) (void)(x)

void writeString(uv_stream_t *stream, const char *str);

int main(void) {
	uv_loop_t *loop = uv_default_loop();
	uv_pipe_t stdout_pipe;

	uv_pipe_init(loop, &stdout_pipe, 0);
	uv_pipe_open(&stdout_pipe, 1);
	writeString((uv_stream_t*)&stdout_pipe, "Kilépés...\n");

	uv_run(loop, UV_RUN_DEFAULT);

	uv_loop_close(loop);
	return 0;
}

static void free_writeString(uv_write_t *req, int status) {
	free(((uv_buf_t *)req->data)->base);
	free(req->data);
	free(req);
	UNUSED(status);
}

void writeString(uv_stream_t *stream, const char *str) {
	uv_write_t *req = malloc(sizeof(uv_write_t));
	uv_buf_t *buf = malloc(sizeof(uv_buf_t));
	if(!req || !buf) exit(1);
	size_t len = strlen(str);
	char *bufptr = (char *)malloc(len);
	if(!bufptr) exit(1);
	*buf = uv_buf_init(bufptr, len);
	memcpy(buf->base, str, len);
	req->data = buf;
	uv_write(req, stream, buf, 1, free_writeString);
}
