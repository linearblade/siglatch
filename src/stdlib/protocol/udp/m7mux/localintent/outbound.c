/*
 * Outbound readiness means the connection layer already has transport work
 * staged in its outbox and the runner should not block waiting on new ingress.
 */
static int _outbound_ready(const M7MuxState *state) {
  if (!state) {
    return 0;
  }

  return state->outbound_count > 0;
}


static int _enqueue_local(M7MuxState *state,
                                        const M7MuxLocalIntent *intent) {
  (void)state;
  return intent != NULL;
}

/*
 * The outbox is connection-owned state, not transient job state.
 *
 * By the time outbound work reaches this queue it should already be divorced
 * from the temporary job view and ready for transport delivery later in
 * flush_outbound().
 */
static int _enqueue_outbound(M7MuxState *state,
                                           const M7MuxOutbound *outbound) {
  M7MuxOutbound *slot = NULL;

  if (!state || !outbound || !outbound->available) {
    return 0;
  }

  if (outbound->len > sizeof(outbound->buffer)) {
    return 0;
  }

  if (state->outbound_count >= M7MUX_SESSION_OUTBOUND_QUEUE_CAPACITY) {
    return 0;
  }

  slot = &state->outbound_queue[state->outbound_tail];
  memset(slot, 0, sizeof(*slot));
  memcpy(slot, outbound, sizeof(*slot));
  slot->ip[sizeof(slot->ip) - 1] = '\0';
  slot->available = 1;

  state->outbound_tail = (state->outbound_tail + 1u) % M7MUX_SESSION_OUTBOUND_QUEUE_CAPACITY;
  state->outbound_count++;

  return 1;
}

static int _stage_outbound(M7MuxState *state,
                                         const M7MuxJob *job) {
  M7MuxOutbound outbound = {0};

  if (!state || !job) {
    return 0;
  }

  if (!job->complete) {
    return 0;
  }

  if (!job->should_reply && job->response_len == 0) {
    return 1;
  }

  if (job->response_len > sizeof(outbound.buffer)) {
    return 0;
  }

  outbound.len = job->response_len;
  outbound.session_id = job->session_id;
  outbound.message_id = job->message_id;
  outbound.stream_id = job->stream_id;
  outbound.client_port = job->client_port;
  outbound.encrypted = job->encrypted;
  memcpy(outbound.ip, job->ip, sizeof(outbound.ip));
  memcpy(outbound.buffer, job->response_buffer, job->response_len);
  outbound.available = 1;

  return _enqueue_outbound(state, &outbound);
}


static int _flush_outbound(M7MuxState *state, uint64_t now_ms) {
  M7MuxOutbound *outbound = NULL;
  int flushed = 0;

  if (!state) {
    return 0;
  }

  (void)now_ms;

  /*
   * Placeholder transport-delivery stage.
   *
   * This now sends queued connection-owned outbound datagrams using the
   * listener socket captured in the connection state. If send fails, the first
   * queued outbound entry is preserved so the runner can retry on a later loop
   * iteration.
   */
  while (state->outbound_count > 0) {
    outbound = &state->outbound_queue[state->outbound_head];
    if (state->sock < 0) {
      return flushed;
    }

    if (!outbound->available || outbound->len == 0) {
      memset(outbound, 0, sizeof(*outbound));
      state->outbound_head = (state->outbound_head + 1u) % M7MUX_SESSION_OUTBOUND_QUEUE_CAPACITY;
      state->outbound_count--;
      continue;
    }

    if (!lib.net.udp.send(state->sock,
                          outbound->ip,
                          outbound->client_port,
                          outbound->buffer,
                          outbound->len)) {
      return flushed;
    }

    memset(outbound, 0, sizeof(*outbound));
    state->outbound_head = (state->outbound_head + 1u) % M7MUX_SESSION_OUTBOUND_QUEUE_CAPACITY;
    state->outbound_count--;
    flushed++;
  }

  return flushed;
}



static const M7MuxLib _instance = {
  .init = _init,
  .shutdown = _shutdown,
  .outbound_ready = _outbound_ready,
  .enqueue_local = _enqueue_local,
  .stage_outbound = _stage_outbound,
  .enqueue_outbound = _enqueue_outbound,
  .flush_outbound = _flush_outbound
};

const M7MuxLib *get_protocol_udp_m7mux_lib(void) {
  return &_instance;
}
