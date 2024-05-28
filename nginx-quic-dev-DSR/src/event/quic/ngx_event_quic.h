
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_QUIC_H_INCLUDED_
#define _NGX_EVENT_QUIC_H_INCLUDED_


#include <assert.h>
#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_QUIC_MAX_UDP_PAYLOAD_SIZE        65527

#define NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT  3
#define NGX_QUIC_DEFAULT_MAX_ACK_DELAY       5
#define NGX_QUIC_DEFAULT_HOST_KEY_LEN        32
#define NGX_QUIC_SR_KEY_LEN                  32
#define NGX_QUIC_AV_KEY_LEN                  32

#define NGX_QUIC_SR_TOKEN_LEN                16

#define NGX_QUIC_MIN_INITIAL_SIZE            1100

#define NGX_QUIC_STREAM_SERVER_INITIATED     0x01
#define NGX_QUIC_STREAM_UNIDIRECTIONAL       0x02

#define NGX_QUIC_STREAM_BUFSIZE              65536
typedef struct ngx_quic_connection_s  ngx_quic_connection_t;

typedef struct {
    size_t                            in_flight;
    size_t                            window;
    size_t                            ssthresh;
    ngx_msec_t                        recovery_start;
} ngx_quic_congestion_t;


typedef struct {
    /* configurable */
    ngx_msec_t                 max_idle_timeout;
    ngx_msec_t                 max_ack_delay;

    size_t                     max_udp_payload_size;
    size_t                     initial_max_data;
    size_t                     initial_max_stream_data_bidi_local;
    size_t                     initial_max_stream_data_bidi_remote;
    size_t                     initial_max_stream_data_uni;
    ngx_uint_t                 initial_max_streams_bidi;
    ngx_uint_t                 initial_max_streams_uni;
    ngx_uint_t                 ack_delay_exponent;
    ngx_uint_t                 active_connection_id_limit;
    ngx_flag_t                 disable_active_migration;
    ngx_str_t                  original_dcid;
    ngx_str_t                  initial_scid;
    ngx_str_t                  retry_scid;
    u_char                     sr_token[NGX_QUIC_SR_TOKEN_LEN];

    /* TODO */
    void                      *preferred_address;
} ngx_quic_tp_t;


typedef struct {
    ngx_ssl_t                 *ssl;
    ngx_quic_tp_t              tp;
    ngx_flag_t                 retry;
    ngx_flag_t                 gso_enabled;
    ngx_flag_t                 require_alpn;
    ngx_flag_t                 migration_close_connection;
    ngx_str_t                  host_key;
    size_t                     stream_buf_size;
    size_t                     initial_window;
    size_t                     min_window;
    u_char                     av_token_key[NGX_QUIC_AV_KEY_LEN];
    u_char                     sr_token_key[NGX_QUIC_SR_KEY_LEN];

#if (NGX_HAVE_IP_MTU_DISCOVER)
    ngx_flag_t                 mtu;
    ngx_int_t                  mtu_attemts;
    size_t                     mtu_target;
#endif
} ngx_quic_conf_t;


struct ngx_quic_stream_s {
    ngx_rbtree_node_t          node;
    ngx_queue_t                queue;
    ngx_connection_t          *parent;
    ngx_connection_t          *connection;
    uint64_t                   id;
    uint64_t                   acked;
    uint64_t                   send_max_data;
    uint64_t                   recv_max_data;
    uint64_t                   recv_offset;
    uint64_t                   recv_window;
    uint64_t                   recv_last;
    uint64_t                   final_size;
    ngx_chain_t               *in;
    ngx_uint_t                 cancelable;  /* unsigned  cancelable:1; */
    void                      *data;
    ngx_array_t               *ack_array;
    ngx_queue_t                qsho_qc_queue;       //qc中所有qsho stream

    unsigned                   handoff:1;
    ngx_quic_client_id_t      *dsr_cid;
};

#define ACK_MSG 0xf1
#define F2B_MSG 0xf2
#define B2F_MSG 0xf3

struct qsho_ack_entry_s {
    uint64_t ack_min;
    uint64_t ack_max;
};

#pragma pack(1)
struct qsho_ack_message_s {
    uint32_t total_len;
    uint32_t type;
    uint64_t client_ack_delay;
    uint64_t lb_recv_timestamp;
    uint64_t lb_send_timestamp;
    uint64_t recv_timestamp;
    uint64_t pn_min;
    uint64_t pn_max;
    uint64_t ack_min;
    uint64_t ack_max;
};
#pragma pack()

#pragma pack(1)

struct qsho_b2f_s {
    uint32_t total_len;
    uint32_t type;
    uint64_t content_total_len;
    uint64_t finished;
    uint64_t rs_send_timestamp;
    uint64_t lb_send_timestamp;
    uint64_t rs_last_recv_timestamp;
    uint64_t unused_pn;
};

struct qsho_f2b_s {
    uint32_t total_len;
    uint32_t type;
    uint64_t finished;
    uint64_t key_update;
    uint64_t connection_migration;
};
#pragma pack()



void ngx_quic_run(ngx_connection_t *c, ngx_quic_conf_t *conf);
ngx_connection_t *ngx_quic_open_stream(ngx_connection_t *c, ngx_uint_t bidi);
void ngx_quic_finalize_connection(ngx_connection_t *c, ngx_int_t rc, ngx_uint_t err,
    const char *reason);
void ngx_quic_shutdown_connection(ngx_connection_t *c, ngx_int_t rc, ngx_uint_t err,
    const char *reason);
ngx_int_t ngx_quic_reset_stream(ngx_connection_t *c, ngx_uint_t err);
uint32_t ngx_quic_version(ngx_connection_t *c);
ngx_int_t ngx_quic_handle_read_event(ngx_event_t *rev, ngx_uint_t flags);
ngx_int_t ngx_quic_handle_write_event(ngx_event_t *wev, size_t lowat);
ngx_int_t ngx_quic_get_packet_dcid(ngx_log_t *log, u_char *data, size_t len,
    ngx_str_t *dcid);
ngx_int_t ngx_quic_derive_key(ngx_log_t *log, const char *label,
    ngx_str_t *secret, ngx_str_t *salt, u_char *out, size_t len);

void ngx_quic_add_exemptions(ngx_connection_t *c, size_t size);

ngx_chain_t * alloc_qsho_buf_chain_buf();
void free_qsho_buf_chain(ngx_chain_t *it);
void qsho_send_ack(ngx_connection_t *c, ngx_quic_stream_t *qs, uint64_t client_ack_delay);
ngx_quic_client_id_t *
allocate_dsr_client_cid(ngx_connection_t *c);

#if (NGX_HAVE_IP_MTU_DISCOVER)
size_t ngx_quic_mtu(ngx_connection_t *c);
#endif

#endif /* _NGX_EVENT_QUIC_H_INCLUDED_ */
