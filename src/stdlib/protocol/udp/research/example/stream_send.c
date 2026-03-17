uint64_t session_id = 0;

if (!tp->session_open(inst, &remote, SL_TRANSPORT_STREAM_FULL, &session_id)) {
  return 0;
}

SlTransportMessage msg = {0};

msg.type = SL_TRANSPORT_MSG_STREAM;
msg.delivery = SL_TRANSPORT_DELIVERY_BEST_EFFORT;
msg.stream_mode = SL_TRANSPORT_STREAM_FULL;
msg.session_id = session_id;
msg.message_id = tp->next_message_id(inst);
msg.stream_id = 1; /* e.g. voice stream */
msg.data = audio_frame;
msg.data_len = audio_frame_len;
