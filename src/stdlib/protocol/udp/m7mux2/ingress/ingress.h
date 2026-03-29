#ifndef LIB_PROTOCOL_UDP_M7MUX2_INGRESS_H
#define LIB_PROTOCOL_UDP_M7MUX2_INGRESS_H

#include <stddef.h>
#include <stdint.h>

#include "../m7mux2.h"
#include "../normalize/normalize.h"

#define M7MUX2_INGRESS_QUEUE_CAPACITY 64u

typedef struct M7Mux2Ingress {
  uint8_t buffer[M7MUX2_NORMALIZED_PACKET_BUFFER_SIZE];
  size_t len;
  uint64_t received_ms;
  char ip[64];
  uint16_t client_port;
  int encrypted;
} M7Mux2Ingress;

typedef struct {
  int socket_fd;
  M7Mux2Ingress queue[M7MUX2_INGRESS_QUEUE_CAPACITY];
  size_t queue_head;
  size_t queue_tail;
  size_t queue_count;
} M7Mux2IngressState;

typedef struct {
  int (*init)(const M7Mux2Context *ctx);
  int (*set_context)(const M7Mux2Context *ctx);
  void (*shutdown)(void);

  int (*state_init)(M7Mux2IngressState *state);
  void (*state_reset)(M7Mux2IngressState *state);

  int (*has_pending)(const M7Mux2IngressState *state);
  int (*pump)(M7Mux2IngressState *state, uint64_t timeout_ms);
  int (*drain)(M7Mux2IngressState *state, M7Mux2Ingress *out_ingress);
} M7Mux2IngressLib;

const M7Mux2IngressLib *get_protocol_udp_m7mux2_ingress_lib(void);

#endif
