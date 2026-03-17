static void on_message_complete(SlTransportInstance *inst,
                                const SlTransportEndpoint *remote,
                                const SlTransportMessage *msg) {
  (void)inst;

  switch (msg->type) {
    case SL_TRANSPORT_MSG_SINGLE:
      printf("single command from %s:%u\n", remote->ip, remote->port);
      /* dispatch small command */
      break;

    case SL_TRANSPORT_MSG_BLOB:
      printf("blob complete from %s:%u len=%zu\n",
             remote->ip,
             remote->port,
             msg->data_len);

      /*
       * Example:
       * - parse JSON
       * - write file
       * - pass to action layer
       */
      /* process_blob(msg->data, msg->data_len); */
      break;

    case SL_TRANSPORT_MSG_FILE:
      printf("file payload complete len=%zu\n", msg->data_len);
      break;

    default:
      printf("unknown message type\n");
      break;
  }
}
