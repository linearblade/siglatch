#include "transport.h"

int client_send_blob(int udp_fd,
                     const char *server_ip,
                     uint16_t server_port,
                     const uint8_t *blob,
                     size_t blob_len) {
  const SlTransportLib *tp = get_lib_transport();
  SlTransportInstance *inst = NULL;
  SlTransportTxMsg *tx = NULL;

  SlTransportContext ctx = {
    .role = SL_TRANSPORT_ROLE_CLIENT,
    .max_packet_size = 1200,
    .default_chunk_size = 1024,
    .enable_ack = 1,
    .enable_retransmit = 1
  };

  SlTransportEndpoint remote = {0};
  SlTransportMessage msg = {0};

  tp->init(&ctx);
  inst = tp->instance_create(&ctx);
  if (!inst) {
    return 0;
  }

  snprintf(remote.ip, sizeof(remote.ip), "%s", server_ip);
  remote.port = server_port;

  msg.type = SL_TRANSPORT_MSG_BLOB;
  msg.delivery = SL_TRANSPORT_DELIVERY_RELIABLE;
  msg.stream_mode = SL_TRANSPORT_STREAM_NONE;
  msg.session_id = 0;
  msg.message_id = tp->next_message_id(inst);
  msg.stream_id = 0;
  msg.data = blob;
  msg.data_len = blob_len;

  if (!tp->begin_send(inst, &remote, &msg, &tx)) {
    tp->instance_destroy(inst);
    return 0;
  }

  for (;;) {
    uint8_t out[1200];
    size_t written = 0;
    int done = 0;

    if (!tp->next_send_chunk(inst, tx, out, sizeof(out), &written, &done)) {
      break;
    }

    if (written > 0) {
      /*
       * udp_sendto(udp_fd, server_ip, server_port, out, written);
       */
    }

    if (done) {
      break;
    }
  }

  tp->instance_destroy(inst);
  return 1;
}
