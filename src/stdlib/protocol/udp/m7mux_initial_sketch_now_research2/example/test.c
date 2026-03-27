#include "../m7mux.h"

#include <stdio.h>
#include <string.h>

static int sync_send_receive(void)
{
  const M7MuxLib mux = get_lib_m7mux();

  M7MuxContext ctx = {0};
  M7MuxOpen open = {0};
  M7MuxSend send = {
    .ip = "127.0.0.1",
    .port = 50000
  };
  M7MuxRecv recv = {
    .timeout_ms = -1   /* block forever */
  };
  M7MuxInspect inspect = {0};
  M7MuxMessage msg = {0};

  char buf[4096];
  M7MuxPort *port;
  M7MuxRecvResult rc;
  M7MuxPollResult ready;

  msg.buf = buf;
  msg.buf_len = sizeof(buf);

  mux.init(&ctx);

  port = mux.open(&open);
  if (!port) {
    mux.shutdown();
    return 1;
  }

  if (!mux.send(port, &send, "ls -l", 5)) {
    mux.close(port);
    mux.shutdown();
    return 1;
  }

  for (;;) {
    rc = mux.receive(port, &recv);
    if (rc == M7MUX_RECV_ERROR)
      break;

    ready = mux.poll(port);
    if (ready == M7MUX_POLL_ERROR)
      break;

    if (ready == M7MUX_POLL_READY) {
      if (mux.next(port, &msg) > 0) {
        fwrite(msg.buf, 1, msg.bytes, stdout);

        if (msg.complete)
          break;
      }
    }

    mux.inspect(port, &inspect);
  }

  mux.close(port);
  mux.shutdown();

  return 0;
}

static int async_send_receive(void)
{
  const M7MuxLib mux = get_lib_m7mux();

  M7MuxContext ctx = {0};
  M7MuxOpen open = {0};
  M7MuxSend send = {
    .ip = "127.0.0.1",
    .port = 50000
  };
  M7MuxRecv recv = {
    .timeout_ms = 0   /* poll */
  };
  M7MuxInspect inspect = {0};
  M7MuxMessage msg = {0};

  char buf[4096];
  M7MuxPort *port;
  M7MuxRecvResult rc;
  M7MuxPollResult ready;

  msg.buf = buf;
  msg.buf_len = sizeof(buf);

  mux.init(&ctx);

  port = mux.open(&open);
  if (!port) {
    mux.shutdown();
    return 1;
  }

  if (!mux.send(port, &send, "ls -l", 5)) {
    mux.close(port);
    mux.shutdown();
    return 1;
  }

  for (;;) {
    rc = mux.receive(port, &recv);
    if (rc == M7MUX_RECV_ERROR)
      break;

    ready = mux.poll(port);
    if (ready == M7MUX_POLL_ERROR)
      break;

    if (ready == M7MUX_POLL_READY) {
      if (mux.next(port, &msg) > 0) {
        fwrite(msg.buf, 1, msg.bytes, stdout);

        if (msg.complete)
          break;
      }
    }

    mux.inspect(port, &inspect);

    if (rc == M7MUX_RECV_NONE && ready == M7MUX_POLL_NONE) {
      /* idle poll */
    }
  }

  mux.close(port);
  mux.shutdown();

  return 0;
}

int main(int argc, char **argv)
{
  if (argc > 1 && strcmp(argv[1], "nonblocking") == 0)
    return async_send_receive();

  return sync_send_receive();
}
