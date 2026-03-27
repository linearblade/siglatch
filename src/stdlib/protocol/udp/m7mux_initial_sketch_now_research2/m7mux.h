#ifndef LIB_UDP_M7MUX_H
#define LIB_UDP_M7MUX_H

#include <stdint.h>
#include <stddef.h>
#include "../../net/udp/udp.h"
#include "../../net/socket/socket.h"

#ifdef __cplusplus
extern "C" {
#endif

  typedef struct M7MuxContext M7MuxContext;
  typedef struct M7MuxPort    M7MuxPort;
  typedef struct M7MuxOpen    M7MuxOpen;
  typedef struct M7MuxSend    M7MuxSend;
  typedef struct M7MuxRecv    M7MuxRecv;
  typedef struct M7MuxMessage M7MuxMessage;
  typedef struct M7MuxInspect M7MuxInspect;
  
  typedef enum {
    M7MUX_RECV_NONE = 0,
    M7MUX_RECV_PARTIAL,
    M7MUX_RECV_COMPLETE,
    M7MUX_RECV_ERROR
  } M7MuxRecvResult;

  typedef enum {
    M7MUX_POLL_NONE = 0,
    M7MUX_POLL_READY,
    M7MUX_POLL_ERROR
  } M7MuxPollResult;
  
  typedef struct {
    int             (*init)(const M7MuxContext *ctx);
    void            (*shutdown)(void);
    int             (*set_context)(const M7MuxContext *ctx);

    M7MuxPort *     (*open)(const M7MuxOpen *opts);
    void            (*close)(M7MuxPort *port);

    int             (*send)(M7MuxPort *port,  const M7MuxSend *opts, const void *buf, size_t len);
    M7MuxRecvResult (*receive)(M7MuxPort *port, const M7MuxRecv *opts);

    M7MuxPollResult (*poll)(M7MuxPort *port);
    int             (*next)(M7MuxPort *port, M7MuxMessage *msg);

    int             (*inspect)(M7MuxPort *port, M7MuxInspect *inspect);
  
  } M7MuxLib;

  typedef struct M7MuxContext {
    const SocketLib *socket;
    const UdpLib *udp;
    void *reserved;
  } M7MuxContext;

  struct M7MuxOpen {
    const char *bind_ip;
    uint16_t    bind_port;
    int         blocking;
    int         recv_buf;
    int         send_buf;
  };

  struct M7MuxPort {
    int fd;
    uint16_t port;
    void *internal;
  };

  /*
   * Send options
   */

  struct M7MuxSend {
    const char *ip;
    uint16_t    port;
  };
  
  /*
   * Receive options
   */

  struct M7MuxRecv {
    int timeout_ms;   /* -1 = block forever, 0 = poll, >0 = wait */
  };

  /*
   * Message retrieval
   */

  struct M7MuxMessage {
    void   *buf;       /* destination buffer */
    size_t  buf_len;   /* buffer capacity */

    size_t  bytes;     /* bytes written to buf */

    uint64_t session_id;
    uint32_t stream_id;
    uint64_t message_id;

    int complete;      /* 1 if message finished */
  };

  /*
 * Inspect / monitoring snapshot
 */

struct M7MuxInspect {
  size_t sessions_active;
  size_t streams_active;
  size_t messages_partial;
  size_t messages_ready;
  size_t queue_depth;
};
  
  
  const M7MuxLib *get_lib_m7mux(void);

#ifdef __cplusplus
}
#endif

#endif
