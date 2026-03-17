/*
 * lib.udp.m7mux.c
 */
//user space transportation protocol.
#include "m7mux.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>


#define M7MUX_MAX_DATAGRAM_SIZE 65535

typedef struct {
  int message_ready;
  size_t recv_len;
  uint64_t session_id;
  uint64_t next_message_id;
  uint32_t stream_id;
  struct sockaddr_in last_peer;
  unsigned char recv_buf[M7MUX_MAX_DATAGRAM_SIZE];
} M7MuxInternal;

static M7MuxContext g_ctx;

static void m7mux_apply_context(const M7MuxContext *ctx)
{
  memset(&g_ctx, 0, sizeof(g_ctx));

  if (ctx)
    g_ctx = *ctx;
}


/*
 * Library lifecycle
 */

static int m7mux_init(const M7MuxContext *ctx)
{
  m7mux_apply_context(ctx);
  return 1;
}

static void m7mux_shutdown(void)
{
  m7mux_apply_context(NULL);
}

static int m7mux_set_context(const M7MuxContext *ctx)
{
  m7mux_apply_context(ctx);
  return 1;
}

/*
 * Port lifecycle
 */

static M7MuxPort *m7mux_open(const M7MuxOpen *opts)
{
  M7MuxPort *port = NULL;
  M7MuxInternal *internal = NULL;
  int fd = -1;

  port = (M7MuxPort *)calloc(1, sizeof(*port));
  if (!port)
    return NULL;

  internal = (M7MuxInternal *)calloc(1, sizeof(*internal));
  if (!internal)
    goto fail;

  fd = g_ctx.udp.open();
  if (fd < 0)
    goto fail;

  if (!g_ctx.socket.set_buffers(fd,
                                opts ? opts->recv_buf : 0,
                                opts ? opts->send_buf : 0))
    goto fail;

  if (!g_ctx.socket.bind(fd,
                         opts ? opts->bind_ip : NULL,
                         opts ? opts->bind_port : 0,
                         &port->port))
    goto fail;

  internal->session_id = 1;
  internal->next_message_id = 1;
  internal->stream_id = 1;

  port->fd = fd;
  port->internal = internal;

  return port;

fail:
  g_ctx.socket.close(fd);
  free(internal);
  free(port);
  return NULL;
}

static void m7mux_close(M7MuxPort *port)
{
  if (!port)
    return;

  g_ctx.socket.close(port->fd);
  free(port->internal);
  free(port);
}

static int m7mux_send(M7MuxPort *port, const M7MuxSend *opts, const void *buf, size_t len)
{
  if (!port || port->fd < 0 || !opts || !opts->ip || !buf)
    return 0;

  return g_ctx.udp.send_ipv4(port->fd, opts->ip, opts->port, buf, len);
}


static M7MuxRecvResult m7mux_receive(M7MuxPort *port, const M7MuxRecv *opts)
{
  M7MuxInternal *internal = NULL;
  int wait_rc = 0;
  int timeout_ms = -1;
  size_t received_len = 0;

  if (!port || port->fd < 0 || !port->internal)
    return M7MUX_RECV_ERROR;

  internal = (M7MuxInternal *)port->internal;
  if (internal->message_ready)
    return M7MUX_RECV_COMPLETE;

  if (opts)
    timeout_ms = opts->timeout_ms;

  if (timeout_ms >= 0) {
    wait_rc = g_ctx.socket.wait_readable(port->fd, timeout_ms);
    if (wait_rc == 0)
      return M7MUX_RECV_NONE;
    if (wait_rc < 0)
      return (errno == EINTR) ? M7MUX_RECV_NONE : M7MUX_RECV_ERROR;
  }

  if (!g_ctx.udp.recv_ipv4(port->fd,
                           internal->recv_buf,
                           sizeof(internal->recv_buf),
                           &internal->last_peer,
                           &received_len)) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
      return M7MUX_RECV_NONE;
    return M7MUX_RECV_ERROR;
  }

  internal->recv_len = received_len;
  internal->message_ready = 1;

  return M7MUX_RECV_COMPLETE;
}

static M7MuxPollResult m7mux_poll(M7MuxPort *port)
{
  M7MuxInternal *internal = NULL;

  if (!port || port->fd < 0 || !port->internal)
    return M7MUX_POLL_ERROR;

  internal = (M7MuxInternal *)port->internal;
  if (internal->message_ready)
    return M7MUX_POLL_READY;

  return M7MUX_POLL_NONE;
}
//has a potential truncation issue
static int m7mux_next(M7MuxPort *port, M7MuxMessage *msg)
{
  M7MuxInternal *internal = NULL;
  size_t copy_len = 0;

  if (!port || !port->internal || !msg)
    return 0;

  internal = (M7MuxInternal *)port->internal;
  if (!internal->message_ready)
    return 0;

  copy_len = internal->recv_len;
  if (msg->buf_len < copy_len)
    copy_len = msg->buf_len;

  msg->bytes = 0;
  if (msg->buf && copy_len > 0) {
    memcpy(msg->buf, internal->recv_buf, copy_len);
    msg->bytes = copy_len;
  }

  msg->session_id = internal->session_id;
  msg->stream_id = internal->stream_id;
  msg->message_id = internal->next_message_id++;
  msg->complete = 1;

  internal->recv_len = 0;
  internal->message_ready = 0;

  return 1;
}

static int m7mux_inspect(M7MuxPort *port, M7MuxInspect *inspect)
{
  M7MuxInternal *internal = NULL;

  if (!port || !port->internal || !inspect)
    return 0;

  internal = (M7MuxInternal *)port->internal;
  memset(inspect, 0, sizeof(*inspect));
  inspect->sessions_active = (port->fd >= 0) ? 1 : 0;
  inspect->streams_active = 1;
  inspect->messages_partial = 0;
  inspect->messages_ready = internal->message_ready ? 1 : 0;
  inspect->queue_depth = internal->message_ready ? 1 : 0;

  return 1;
}

/*
 * Installed library instance
 */

static const M7MuxLib m7mux_instance = {
  .init        = m7mux_init,
  .shutdown    = m7mux_shutdown,
  .set_context = m7mux_set_context,
  .open        = m7mux_open,
  .close       = m7mux_close,

  .send        = m7mux_send,
  .receive     = m7mux_receive,

  .poll        = m7mux_poll,
  .next        = m7mux_next,

  .inspect     = m7mux_inspect
};

const M7MuxLib *get_lib_m7mux(void)
{
  return &m7mux_instance;
}
