/*
  pseudocode flow for mux
 */

struct mux {
  pump() {
    if (!state->connected) {
      return 0;
    }

    timeout_ms = outbox.hasReady(&outbox_state)
      ? 0u
      : time_until_ms(next_tick_at, now_ms);

    while (listener.drain(&listener_state, timeout_ms, &raw_data)) {
      demux.detect(&raw_data, &packet_info);
      decode.normalize(&raw_data, &normal_data);

      session.enqueue(&session_state, &normal_data);
      stream.enqueue(&stream_state, &normal_data);

      while (receipt = stream.drainReceipt(&stream_state)) {
        outbox.enqueue(&outbox_state, &receipt);
      }

      clear(&raw_data);
      clear(&normal_data);
      clear(&packet_info);

      timeout_ms = 0u;
    }

    stream.pump(&stream_state);
    outbox.pump(&outbox_state);
    session.pump(&session_state);

    return 1;
  }

  recv() {
    return stream.drain(&stream_state);
  }

  send() {
    return outbox.drain(&outbox_state);
  }
};




struct session {
  enqueue(data) {
    entry = findSession(data);
    if (!entry) {
      entry = createSession(data);
    }

    updateSession(entry, data);
    appendPending(entry, data);
  }

  pump() {
    for (entry of sessions) {
      updateTimers(entry);
      updateStatistics(entry);
      markExpiredIfNeeded(entry);
    }
  }

  drain() {
    for (entry of sessions) {
      if (entry.isExpired()) {
        detach(entry);
        return entry;
      }
    }
    return null;
  }
};


struct stream {
  enqueue(input) {
    curStream = findStream(input);
    if (!curStream) {
      curStream = createStream(input);
    }

    curMsg = findMessage(curStream, input);
    if (!curMsg) {
      curMsg = createMessage(curStream, input);
    }

    appendWork(curMsg, input);
  }

  pump() {
    while (work = nextWork()) {
      curMsg = work.message;
      appendToMessage(curMsg, work);
      updateMessageState(curMsg);
      produceReceiptIfNeeded(curMsg);
    }
  }

  drain() {
    for (item of messages) {
      if (item.isComplete()) {
        detach(item);
        return item;
      }
    }
    return null;
  }
};


struct outbox {
  enqueue(data) {
    item = createOutboundItem(data);
    appendToQueue(item);
  }

  pump() {
    for (item of queue) {
      validateItem(item);
      groomItem(item);
      markReadyIfNeeded(item);
    }
  }

  drain() {
    for (item of queue) {
      if (item.isReady()) {
        detach(item);
        return item;
      }
    }
    return null;
  }
};
