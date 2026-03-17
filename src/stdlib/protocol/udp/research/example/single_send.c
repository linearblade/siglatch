#include "transport.h"

int client_send_single_command(int udp_fd,
                               const char *server_ip,
                               uint16_t server_port,
                               const uint8_t *payload,
                               size_t payload_len) {
  const SlTransportLib *tp = get_lib_transport();
  SlTransportInstance *inst = NULL;

  SlTransportContext ctx = {
    .role = SL_TRANSPORT_ROLE_CLIENT,
    .max_packet_size = SL_TRANSPORT_MAX_PACKET_SIZE,
    .default_chunk_size = SL_TRANSPORT_DEFAULT_CHUNK_SIZE
  };

  SlTransportMessage msg = {0};
  uint8_t out[SL_TRANSPORT_MAX_PACKET_SIZE];
  size_t written = 0;

  tp->init(&ctx);

  inst = tp->instance_create(&ctx);
  if (!inst) {
    return 0;
  }

  msg.type = SL_TRANSPORT_MSG_SINGLE;
  msg.delivery = SL_TRANSPORT_DELIVERY_RELIABLE;
  msg.stream_mode = SL_TRANSPORT_STREAM_NONE;
  msg.session_id = 0;
  msg.message_id = tp->next_message_id(inst);
  msg.stream_id = 0;
  msg.data = payload;
  msg.data_len = payload_len;

  if (!tp->build_single(inst, &msg, out, sizeof(out), &written)) {
    tp->instance_destroy(inst);
    return 0;
  }

  /*
   * your existing UDP wrapper here
   * udp_sendto(udp_fd, server_ip, server_port, out, written);
   */

  tp->instance_destroy(inst);
  return 1;
}
