#include "transport.h"
#include "udp.h"

static SlTransportInstance *g_tp = NULL;

static void on_message_complete(SlTransportInstance *inst,
                                const SlTransportEndpoint *remote,
                                const SlTransportMessage *msg) {
  (void)inst;

  /*
   * Theoretical behavior:
   * - msg->type == SL_TRANSPORT_MSG_SINGLE
   * - msg->data points to the complete authenticated payload
   * - now hand it upward into siglatch policy/action handling
   */

  printf("message complete from %s:%u\n", remote->ip, remote->port);
  printf("session=%llu message=%llu stream=%u len=%zu\n",
         (unsigned long long)msg->session_id,
         (unsigned long long)msg->message_id,
         msg->stream_id,
         msg->data_len);

  /* siglatch_action_dispatch(msg->data, msg->data_len); */
}

static void on_error(SlTransportInstance *inst,
                     SlTransportError err,
                     const char *where) {
  (void)inst;
  fprintf(stderr, "transport error at %s: %s\n",
          where ? where : "unknown",
          get_lib_transport()->error_string(err));
}

int transport_server_init(void) {
  const SlTransportLib *tp = get_lib_transport();

  SlTransportContext ctx = {
    .role = SL_TRANSPORT_ROLE_SERVER,
    .max_packet_size = SL_TRANSPORT_MAX_PACKET_SIZE,
    .default_chunk_size = SL_TRANSPORT_DEFAULT_CHUNK_SIZE,
    .reassembly_ttl_seconds = 30,
    .session_ttl_seconds = 60,
    .enable_ack = 1,
    .enable_retransmit = 1,
    .enable_keepalive = 1,
    .allow_out_of_order = 1
  };

  SlTransportHooks hooks = {
    .on_message_complete = on_message_complete,
    .on_error = on_error
  };

  tp->init(&ctx);

  g_tp = tp->instance_create(&ctx);
  if (!g_tp) {
    return 0;
  }

  if (!tp->instance_set_hooks(g_tp, &hooks)) {
    tp->instance_destroy(g_tp);
    g_tp = NULL;
    return 0;
  }

  return 1;
}

int transport_server_on_udp_datagram(const char *ip,
                                     uint16_t port,
                                     const uint8_t *buf,
                                     size_t buf_len) {
  const SlTransportLib *tp = get_lib_transport();

  SlTransportEndpoint remote = {0};
  snprintf(remote.ip, sizeof(remote.ip), "%s", ip);
  remote.port = port;

  return tp->ingest_datagram(g_tp, &remote, buf, buf_len);
}
