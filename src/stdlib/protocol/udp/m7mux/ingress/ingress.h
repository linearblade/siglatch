#ifndef LIB_PROTOCOL_UDP_M7MUX_INGRESS_H
#define LIB_PROTOCOL_UDP_M7MUX_INGRESS_H

#include <stddef.h>
#include <stdint.h>

#include "../m7mux.h"
#include "../normalize/normalize.h"

#define M7MUX_INGRESS_QUEUE_CAPACITY 64u

typedef struct M7MuxIngress {
  uint8_t buffer[M7MUX_NORMALIZED_PACKET_BUFFER_SIZE];
  size_t len;
  uint64_t received_ms;
  char ip[64];
  uint16_t client_port;
  int encrypted;
  uint32_t magic;
  uint32_t version;
  uint8_t form;
} M7MuxIngress;

typedef struct {
  int socket_fd;
  M7MuxIngress queue[M7MUX_INGRESS_QUEUE_CAPACITY];
  size_t queue_head;
  size_t queue_tail;
  size_t queue_count;
} M7MuxIngressState;

typedef struct {
  int (*init)(const M7MuxContext *ctx);
  int (*set_context)(const M7MuxContext *ctx);
  void (*shutdown)(void);

  int (*state_init)(M7MuxIngressState *state);
  void (*state_reset)(M7MuxIngressState *state);

  int (*has_pending)(const M7MuxIngressState *state);
  int (*pump)(M7MuxIngressState *state, uint64_t timeout_ms);
  int (*drain)(M7MuxIngressState *state, M7MuxIngress *out_ingress);
} M7MuxIngressLib;

const M7MuxIngressLib *get_protocol_udp_m7mux_ingress_lib(void);

#endif
