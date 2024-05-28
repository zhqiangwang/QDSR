#include "P_Net.h"
#include "P_QSHONet.h"
#include "tscore/ink_endian.h"
#include "I_VConnection.h"
#include "HttpTunnel.h"

//#define QSHO_DEBUG_MODE

//#define DEBUG_LOSS_TIMER 
//#define DEBUG_LOSS

//#define DEBUG_SENT_PACKET
//#define DEBUG_ACK_PACKET
//#define DEBUG_RECV_ACK_FRAME
//#define DEBUG_CONGESTION_CONTROL
//#define DEBUG_BYTES_IN_FLIGHT
//#define DEBUG_APP_LIMITED
//#define DEBUG_RTT
#define NEW_PNS
//#define DEBUG_PNS

#define num_max(x, y) (((x) > (y)) ? (x) : (y))

void
QshoStream::OnPacketSent(QshoPacket *qp, ink_hrtime now)
{
    send_ctl.time_of_last_ack_eliciting_packet = now;
    OnPacketSentCC(qp->sent_bytes);
#ifdef DEBUG_BYTES_IN_FLIGHT
    Note("bytes_in_flight %lu add sent_bytes[%lu] %lu", send_ctl.bytes_in_flight,
            qp->packet_number, qp->sent_bytes);
#endif
    SetLossDetectionTimer(now);
}

void
QshoStream::OnAckReceived(ACKFrame *ack, ink_hrtime now)
{
    if (send_ctl.largest_acked_packet == UNSET_PN) {
        send_ctl.largest_acked_packet = ack->ack_max;
    } else {
        send_ctl.largest_acked_packet = num_max(send_ctl.largest_acked_packet, ack->ack_max);
    }

    Que(QshoPacket, dlink) newly_acked_packets;
    QshoPacket *largest_acked_packet = nullptr;
    DetectAndRemoveAckedPackets(&newly_acked_packets, ack, &largest_acked_packet);

    if (newly_acked_packets.empty()) {
        return;
    }

    if (largest_acked_packet->packet_number == ack->ack_max) {
        send_ctl.latest_rtt = ack->recv_timestamp - largest_acked_packet->last_send_time;
        UpdateRTT(ack->ack_delay, now);
    }

    Que(QshoPacket, dlink) lost_packets;
    DetectAndRemoveLostPackets(&lost_packets, now);
    if (!lost_packets.empty()) {
        OnPacketsLost(&lost_packets);
        ink_assert(lost_packets.empty());
    }

    OnPacketsAcked(&newly_acked_packets);
    ink_assert(newly_acked_packets.empty());

    send_ctl.pto_count = 0;
    SetLossDetectionTimer(now);
}

void
QshoStream::UpdateRTT(ink_hrtime ack_delay, ink_hrtime now) {
    if (send_ctl.first_rtt_sample == 0) {
        send_ctl.min_rtt = send_ctl.latest_rtt;
        send_ctl.smoothed_rtt = send_ctl.latest_rtt;
        send_ctl.rttvar = send_ctl.latest_rtt / 2;
        send_ctl.first_rtt_sample = now;
        return;
    }

    send_ctl.min_rtt = std::min(send_ctl.min_rtt, send_ctl.latest_rtt);
    ink_hrtime adjusted_rtt = send_ctl.latest_rtt;
    if (send_ctl.latest_rtt >= send_ctl.min_rtt + ack_delay) {
        adjusted_rtt = send_ctl.latest_rtt - ack_delay;
    }

    send_ctl.rttvar = 0.75 * send_ctl.rttvar + 0.25 * abs(send_ctl.smoothed_rtt - adjusted_rtt);
    send_ctl.smoothed_rtt = 0.875 * send_ctl.smoothed_rtt + 0.125 * adjusted_rtt;
#ifdef DEBUG_RTT
    Note("last %ld %ld", send_ctl.latest_rtt, send_ctl.smoothed_rtt);
#endif
}

ink_hrtime
QshoStream::GetLossTimeAndSpace() {
    return send_ctl.loss_time;
}

ink_hrtime
QshoStream::GetPtoTimeAndSpace() {
    if (send_ctl.bytes_in_flight == 0) {
        return INT64_MAX;
    }

    ink_hrtime duration = (send_ctl.smoothed_rtt + num_max(4 * send_ctl.rttvar, HRTIME_MSECONDS(1))) << send_ctl.pto_count;

    ink_hrtime pto_timeout = INT64_MAX;
    duration += send_ctl.max_ack_delay << send_ctl.pto_count;
    ink_hrtime t = send_ctl.time_of_last_ack_eliciting_packet + duration;
    if (t < pto_timeout) {
        pto_timeout = t;
    }

    return pto_timeout;
}

void
QshoStream::cancel_loss_timer() {
    if (send_ctl.loss_detection_timer) {
        send_ctl.loss_detection_timer->cancel();
        send_ctl.loss_detection_timer = nullptr;
    }
    send_ctl.loss_timer = 0;
}

void
QshoStream::SetLossDetectionTimer(ink_hrtime now) {

    ink_hrtime earliest_loss_time = GetLossTimeAndSpace();
    if (earliest_loss_time != 0) {
        if (earliest_loss_time != send_ctl.loss_timer) {
#ifdef DEBUG_LOSS_TIMER
            Note("Update Loss Timer1, now %ld, last timer %ld new timer %ld",
                    now, send_ctl.loss_timer, earliest_loss_time);
#endif
            cancel_loss_timer();
            send_ctl.loss_timer = earliest_loss_time;
            send_ctl.loss_detection_timer = qsho_thread->schedule_at(&send_ctl.detectLoss,
                    earliest_loss_time + HRTIME_MSECONDS(1), VC_EVENT_READ_READY, this);
        }
        return;
    }

    if (send_ctl.bytes_in_flight == 0) {
#ifdef DEBUG_LOSS_TIMER
        if (send_ctl.loss_detection_timer) {
            Note("cancel Loss Timer, now %ld, last timer %ld", now, send_ctl.loss_timer);
        }
#endif
        cancel_loss_timer();
        return;
    }

    ink_hrtime timeout = GetPtoTimeAndSpace();
    if (timeout != INT64_MAX) {
        if (timeout != send_ctl.loss_timer) {
            cancel_loss_timer();
            send_ctl.loss_detection_timer = qsho_thread->schedule_at(&send_ctl.detectLoss,
                    timeout + HRTIME_MSECONDS(1), VC_EVENT_READ_READY, this);
            send_ctl.loss_timer = timeout;
#ifdef DEBUG_LOSS_TIMER
            Note("Set PTO Timer2, now %ld, time %ld", now, timeout);
#endif
        }
        return;
    } else {
        cancel_loss_timer();
#ifdef DEBUG_LOSS_TIMER
        Note("PTO timer INF, cancel, not possible");
#endif
    }

}

int
QshoStream::OnLossDetectionTimeout(int event, void *data) {
    Event *e = (Event *)data;
    QshoStream *qs = (QshoStream *)e->cookie;
    ink_hrtime now = Thread::get_hrtime();

    ink_hrtime earliest_loss_time = qs->GetLossTimeAndSpace();
    if (earliest_loss_time != 0) {
#ifdef DEBUG_LOSS_TIMER
        Note("Loss Timer timeout, now %ld", now);
#endif
        Que(QshoPacket, dlink) lost_packets;
        qs->DetectAndRemoveLostPackets(&lost_packets, now);
        ink_assert(!lost_packets.empty());
        qs->OnPacketsLost(&lost_packets);
        qs->SetLossDetectionTimer(now);
        return EVENT_CONT;
    }

#ifdef DEBUG_LOSS_TIMER
    Note("PTO Timer timeout, now %ld", now);
#endif


    qs->SendOneOrTwoAckElicitingPackets();
    qs->send_ctl.pto_count ++;
    qs->SetLossDetectionTimer(now);

    return EVENT_CONT;
}

void
QshoStream::SendOneOrTwoAckElicitingPackets()
{
    QshoPacket* p;
    if (unencrypt_packets.empty() && priority_packets.empty()) {
        p = create_ping_frame(1200, true);
        unencrypt_packets.enqueue(p);
        p = create_ping_frame(1200, true);
        unencrypt_packets.enqueue(p);
        encrypto_count += 2;
    }
}

void
QshoStream::HandleAckRange(Que(QshoPacket, dlink) *newly_acked_packets,
        uint64_t min, uint64_t max, QshoPacket **packet)
{
    QshoPacket *qp = sent_packets.head;
    while (qp) {
        QshoPacket *n = sent_packets.next(qp);
        if (qp->packet_number < min) {
            qp = n;
            continue;
        }
        if (qp->packet_number > max) {
            qp = n;
            break;
        }

        if (qp->packet_number == max && packet) {
            *packet = qp;
        }

        sent_packets.remove(qp);
        newly_acked_packets->enqueue(qp);
        qp = n;
    }
}

void
QshoStream::DetectAndRemoveAckedPackets(Que(QshoPacket, dlink) *newly_acked_packets,
        ACKFrame *ack, QshoPacket **qp)
{
#ifdef DEBUG_RECV_ACK_FRAME
    Note("ACK Frame: [%lu - %lu] %lu", ack->ack_min, ack->ack_max, ack->ack_delay);
#endif
    HandleAckRange(newly_acked_packets, ack->ack_min, ack->ack_max, qp);

    ACKRange *range;
    while ((range = ack->ack_ranges.dequeue())) {
#ifdef DEBUG_RECV_ACK_FRAME
        Note("ACK Range: [%lu - %lu]", range->ack_min, range->ack_max);
#endif
        HandleAckRange(newly_acked_packets, range->ack_min, range->ack_max, nullptr);
        delete range;
    }
}

void
QshoStream::DetectAndRemoveLostPackets(Que(QshoPacket, dlink) *lost_packets, ink_hrtime now)
{
    ink_assert(send_ctl.largest_acked_packet != UNSET_PN);
    send_ctl.loss_time = 0;

    ink_hrtime loss_delay = kTimeThreshold * num_max(send_ctl.latest_rtt, send_ctl.smoothed_rtt);
    loss_delay = num_max(HRTIME_MSECONDS(1), loss_delay);

    ink_hrtime lost_send_time = now - loss_delay;
    
    QshoPacket *p = sent_packets.head;
    while (p) {
        QshoPacket *n = sent_packets.next(p);
        if (p->packet_number > send_ctl.largest_acked_packet) {
            break;
        }

        if (p->last_send_time <= lost_send_time ||
                send_ctl.largest_acked_packet >= p->packet_number + kPacketThreshold)
        {
#ifdef DEBUG_LOSS
            Note("Loss Packet %lu", p->packet_number);
#endif
            sent_packets.remove(p);
            lost_packets->enqueue(p);
        } else {
            if (send_ctl.loss_time == 0) {
                send_ctl.loss_time = p->last_send_time + loss_delay;
            } else {
                send_ctl.loss_time = std::min(send_ctl.loss_time, p->last_send_time + loss_delay);
            }
#ifdef DEBUG_LOSS
            Note("set loss time %ld", send_ctl.loss_time);
#endif
        }
        p = n;
    }
}

void
QshoStream::OnPacketSentCC(uint64_t sent_bytes) {
    send_ctl.bytes_in_flight += sent_bytes;
}

bool
QshoStream::InCongestionRecovery(ink_hrtime sent_time) {
    return sent_time <= send_ctl.congestion_recovery_start_time;
}

bool IsAppOrFlowControlLimited() {
    return false;
}

bool InCongestionRecovery(ink_hrtime time) {
    return false;
}

void
QshoStream::OnPacketsAcked(Que(QshoPacket, dlink) *acked_packets)
{
    QshoPacket *qp = acked_packets->head;
    while (qp) {
        QshoPacket *n = acked_packets->next(qp);
        acked_packets->remove(qp);
        send_ctl.bytes_in_flight -= qp->sent_bytes;
#ifdef DEBUG_BYTES_IN_FLIGHT
        Note("bytes_in_flight %lu sub sent_bytes[%lu] %lu", send_ctl.bytes_in_flight,
                qp->packet_number, qp->sent_bytes);
#endif
        if (IsAppOrFlowControlLimited()) {
            ;
        } else if (InCongestionRecovery(qp->last_send_time)) {
            ;
        } else {
            if (send_ctl.cwnd < send_ctl.ssthresh) {
                send_ctl.cwnd += qp->sent_bytes;
            } else {
                send_ctl.cwnd += 1460.0 * qp->sent_bytes / send_ctl.cwnd;
            }
        }

        if (!qp->is_ping) {
            free_count ++;
        }

#ifdef DEBUG_ACK_PACKET
        Note("Acked Packet %lu", qp->packet_number);
#endif

        qp->free();
        qp = nullptr;
        qp = n;
    }
}

void
QshoStream::OnCongestionEvent(ink_hrtime sent_time)
{
    if (InCongestionRecovery(sent_time)) {
        return;
    }

    send_ctl.ssthresh = send_ctl.cwnd * kLossReductionFactor;
    send_ctl.cwnd = num_max(send_ctl.ssthresh, kMinimumWindow);
}

void
QshoStream::OnPacketsLost(Que(QshoPacket, dlink) *lost_packets)
{
    ink_hrtime sent_time_of_last_loss = 0;
    QshoPacket *p = lost_packets->head;
    while (p) {
        QshoPacket *n = lost_packets->next(p);
        lost_packets->remove(p);

        send_ctl.bytes_in_flight -= p->sent_bytes;
        sent_time_of_last_loss = num_max(sent_time_of_last_loss, p->last_send_time);

        if (p->is_ping) {
            p->free();
        } else {
            retransmit_count ++;
            priority_packets.enqueue(p);
        }


        p = n;
    }

    if (sent_time_of_last_loss != 0) {
        OnCongestionEvent(sent_time_of_last_loss);
    }

    if (send_ctl.first_rtt_sample == 0) {
        return;
    }
}



static void
debug_for_raw_socket(unsigned char *sendbuf, int send_buf_len,
        uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);
static u_char *
qsho_hex_dump(u_char *dst, u_char *src, size_t len);

EventType ET_QSHO;
#define STATE_VIO_OFFSET ((uintptr_t) & ((NetState *)0)->vio)
#define STATE_FROM_VIO(_x) ((NetState *)(((char *)(_x)) - STATE_VIO_OFFSET))

#ifdef QSHO_BORINGSSL
#define qsho_cipher_t             EVP_AEAD
#else
#define qsho_cipher_t             EVP_CIPHER
#endif

#define MAX_QSHO_PAYLOAD_UNENCRYPTO_LEN 1300

//=====================================================================================

#define NGX_QUIC_FT_STREAM                               0x08

#define NGX_QUIC_STREAM_FRAME_FIN      0x01
#define NGX_QUIC_STREAM_FRAME_LEN      0x02
#define NGX_QUIC_STREAM_FRAME_OFF      0x04

#define qsho_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
#define qsho_parse_uint32(p)                                              \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#define qsho_write_uint16(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))

#define qsho_write_uint32(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))

#define qsho_write_uint64(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 56),                                           \
     (p)[1] = (u_char) ((s) >> 48),                                           \
     (p)[2] = (u_char) ((s) >> 40),                                           \
     (p)[3] = (u_char) ((s) >> 32),                                           \
     (p)[4] = (u_char) ((s) >> 24),                                           \
     (p)[5] = (u_char) ((s) >> 16),                                           \
     (p)[6] = (u_char) ((s) >> 8),                                            \
     (p)[7] = (u_char)  (s),                                                  \
     (p) + sizeof(uint64_t))

#define qsho_write_uint24(p, s)                                           \
    ((p)[0] = (u_char) ((s) >> 16),                                           \
     (p)[1] = (u_char) ((s) >> 8),                                            \
     (p)[2] = (u_char)  (s),                                                  \
     (p) + 3)


#define qsho_write_uint16_aligned(p, s)                                   \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))

#define qsho_write_uint32_aligned(p, s)                                   \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#define qsho_build_int_set(p, value, len, bits)                           \
    (*(p)++ = ((value >> ((len) * 8)) & 0xff) | ((bits) << 6))

static inline unsigned int
qsho_varint_len(uint64_t value)
{
    if (value < (1 << 6)) {
        return 1;
    }    

    if (value < (1 << 14)) {
        return 2;
    }    

    if (value < (1 << 30)) {
        return 4;
    }    

    return 8;
}

static inline void
qsho_build_int(u_char **pos, uint64_t value)
{
    u_char  *p;

    p = *pos;

    if (value < (1 << 6)) {
        qsho_build_int_set(p, value, 0, 0);

    } else if (value < (1 << 14)) {
        qsho_build_int_set(p, value, 1, 1);
        qsho_build_int_set(p, value, 0, 0);

    } else if (value < (1 << 30)) {
        qsho_build_int_set(p, value, 3, 2);
        qsho_build_int_set(p, value, 2, 0);
        qsho_build_int_set(p, value, 1, 0);
        qsho_build_int_set(p, value, 0, 0);

    } else {
        qsho_build_int_set(p, value, 7, 3);
        qsho_build_int_set(p, value, 6, 0);
        qsho_build_int_set(p, value, 5, 0);
        qsho_build_int_set(p, value, 4, 0);
        qsho_build_int_set(p, value, 3, 0);
        qsho_build_int_set(p, value, 2, 0);
        qsho_build_int_set(p, value, 1, 0);
        qsho_build_int_set(p, value, 0, 0);
    }

    *pos = p;
}

uint64_t
QshoStream::create_stream_frame(QshoPacket *packet, MIOBufferAccessor &buf_accessor,
        uint64_t length, bool fin, bool new_pns)
{
    uint64_t    len;
    uint64_t    c_len = 0;
    u_char      type;
    IOBufferReader *tmp_reader = buf_accessor.reader()->clone();

    type = NGX_QUIC_FT_STREAM;
    type |= NGX_QUIC_STREAM_FRAME_OFF;
    type |= NGX_QUIC_STREAM_FRAME_LEN;

    if (fin) {
        type |= NGX_QUIC_STREAM_FRAME_FIN;
    }
    u_char *p = (u_char *)packet->orig_buf->end();
#ifdef NEW_PNS
    if (new_pns) {
        qsho_build_int(&p, 0x3f);
    }
#endif
    qsho_build_int(&p, type);
    qsho_build_int(&p, stream_id);
    qsho_build_int(&p, offset);
    qsho_build_int(&p, length);

    offset += length;

    //write timestamp at the beginning
    if (total_packet_count == 0) {
        packet->timestamp_position = p + header_size;
    }
    uint64_t cur_len;
    while (true) {
        cur_len = tmp_reader->block_read_avail();
        if (cur_len > length) {
            cur_len = length;
        }
        if (cur_len <= 0) {
            break;
        }
        length -= cur_len;

        memcpy(p, tmp_reader->start(), cur_len);
        p += cur_len;

        tmp_reader->consume(cur_len);
        c_len += cur_len;
    }
    tmp_reader->dealloc();

    //reader中的数据始终要比length指定的要多一些(或相等)
    ink_assert(length == 0);

    len = p - (u_char *) packet->orig_buf->start();

    packet->orig_buf->fill(len);
    buf_accessor.reader()->consume(c_len);

    return len;
}

QshoPacket *
QshoStream::create_ping_frame(int ping_len, bool new_pns)
{
    uint64_t    len;
    QshoPacket *packet = new_packet();
    u_char *p = (u_char *)packet->orig_buf->end();
#ifdef NEW_PNS
    if (new_pns) {
        qsho_build_int(&p, 0x3f);
    }
#endif
    qsho_build_int(&p, 0x01);

    int i = 0;
    for (i = 0; i < ping_len; i ++) {
        qsho_build_int(&p, 0x00);
    }

    len = p - (u_char *) packet->orig_buf->start();
    packet->orig_buf->fill(len);
    packet->is_ping = true;
#if 0
    Note("ping len %lu", len);
#endif

    return packet;
}

void
QshoStream::do_io_shutdown(ShutdownHowTo_t howto)
{
    do_io_close(-1);
}

static void 
qsho_compute_nonce(u_char *nonce, size_t len, uint64_t pn, uint64_t pnsid)
{
    nonce[len -12] ^= ((pnsid) & 0xff000000) >> 24;
    nonce[len -11] ^= ((pnsid) & 0x00ff0000) >> 16;
    nonce[len -10] ^= ((pnsid) & 0x0000ff00) >> 8;
    nonce[len - 9] ^= ((pnsid) & 0x000000ff);
    nonce[len - 8] ^= ((pn) & ((uint64_t)0xff00000000000000)) >> 56;
    nonce[len - 7] ^= ((pn) & ((uint64_t)0xff000000000000)) >> 48;
    nonce[len - 6] ^= ((pn) & ((uint64_t)0xff0000000000)) >> 40;
    nonce[len - 5] ^= ((pn) & ((uint64_t)0xff00000000)) >> 32;
    nonce[len - 4] ^= ((pn) & ((uint64_t)0xff000000)) >> 24;
    nonce[len - 3] ^= ((pn) & ((uint64_t)0xff0000)) >> 16;
    nonce[len - 2] ^= ((pn) & ((uint64_t)0xff00)) >> 8;
    nonce[len - 1] ^= ((pn) & ((uint64_t)0xff));
}

static int
qsho_tls_seal(const qsho_cipher_t *cipher, QshoSecret *secret, unsigned char *out, size_t *out_len,
        unsigned char *nonce, unsigned char *in, size_t *in_len, unsigned char *ad, size_t *ad_len)
{
#ifdef QSHO_BORINGSSL
    EVP_AEAD_CTX  *ctx;
    ctx = EVP_AEAD_CTX_new(cipher, secret->key, secret->key_len,
            EVP_AEAD_DEFAULT_TAG_LENGTH);
    if (ctx == nullptr) {
        return -1;
    }

    int ret;
    ret = EVP_AEAD_CTX_seal(ctx, out, out_len, *out_len, nonce, secret->iv_len, in, *in_len, ad, *ad_len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) {
        return -1;
    }
#else
    int              len;
    EVP_CIPHER_CTX  *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, secret->iv_len, NULL)
            == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, secret->key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptUpdate(ctx, NULL, &len, ad, *ad_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptUpdate(ctx, out, &len, in, *in_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *out_len = len;
    if (EVP_EncryptFinal_ex(ctx, out + *out_len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *out_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN,
            out + *in_len) == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    *out_len += EVP_GCM_TLS_TAG_LEN;
#endif
    return 0;
}

static int
qsho_tls_hp(const EVP_CIPHER *hp, QshoSecret *secret, unsigned char *out,
        unsigned char *in)
{
    int              outlen;
    EVP_CIPHER_CTX  *ctx;
    u_char           zero[5] = {0};

#ifdef QSHO_BORINGSSL
    uint32_t cnt;
    memcpy(&cnt, in, sizeof(uint32_t));
    if (hp == (const EVP_CIPHER *) EVP_aead_chacha20_poly1305()) {
        CRYPTO_chacha_20(out, zero, 5, secret->hp, &in[4], cnt);
        return 0;
    }
#endif

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, hp, NULL, secret->hp, in) != 1) {
        goto failed;
    }

    if (!EVP_EncryptUpdate(ctx, out, &outlen, zero, 5)) {
        goto failed;
    }

    if (!EVP_EncryptFinal_ex(ctx, out + 5, &outlen)) {
        goto failed;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;

failed:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static unsigned short
__udp_checksum1(unsigned short* buffer, int size)//校验和
{   
    unsigned long cksum = 0;
    while(size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    
    if(size) {
        cksum += *(unsigned char*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff); //将高16bit与低16bit相加
    
    cksum += (cksum >> 16); //将进位到高位的16bit与低16bit 再相加
    
    return (unsigned short)(~cksum);
}

static inline uint16_t
cal_udp_checksum(struct iphdr *ip_hdr, char *checksum_buf)
{
    struct ipv4_psd_header {
        uint32_t src_addr; /* IP address of source host. */
        uint32_t dst_addr; /* IP address of destination host. */
        uint8_t  zero;     /* zero. */
        uint8_t  proto;    /* L4 protocol type. */
        uint16_t len;      /* L4 length. */
    } psd_hdr;
    struct udphdr *udpheader = (struct udphdr *)(((char *)ip_hdr) + sizeof(struct iphdr));
    psd_hdr.src_addr = ip_hdr->saddr;
    psd_hdr.dst_addr = ip_hdr->daddr;
    psd_hdr.zero = 0;
    psd_hdr.proto = IPPROTO_UDP;
    psd_hdr.len = udpheader->len;

    int used_len = 0;
    memcpy(checksum_buf, &psd_hdr, sizeof(psd_hdr));
    memcpy(checksum_buf + sizeof(psd_hdr), udpheader, ntohs(udpheader->len));
    used_len = sizeof(psd_hdr) + ntohs(udpheader->len);

    //return raw_cksum(checksum_buf, used_len);
    return __udp_checksum1((unsigned short *)checksum_buf, used_len);
}

//=====================================================================================

QshoStream::QshoStream(unsigned char *qcid, uint32_t qcid_len, uint64_t qsid,
        uint64_t pns_id, uint64_t packet_number, uint64_t packet_number_max,
        int64_t send_timestamp, uint32_t _src_ip, uint32_t _dst_ip,
        uint16_t _src_port, uint16_t _dst_port,
        QshoSecret *input_secret) : VConnection(nullptr)
{
    qsho_thread = eventProcessor.assign_thread(ET_QSHO);
    thread = this_ethread();

    pnsid = pns_id;
    dst_cid_len = qcid_len;
    dst_cid = qcid;
    qcid = nullptr;
    qcid_len = 0;

    stream_id = qsid;
    //ngx_worker_id = nginx_worker_id;

    pn = packet_number;
    pn_max = packet_number_max;
    lb_send_timestamp = send_timestamp;
    rs_recv_timestamp = Thread::get_hrtime();

    src_ip = _src_ip;
    dst_ip = _dst_ip;
    src_port = _src_port;
    dst_port = _dst_port;

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = dst_ip;
    dst_addr.sin_port = dst_port;

    input_secret->delivery(&secret);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        Note("socket fd error %d %s", errno, strerror(errno));
    }
    const int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        Note("set opt error %d %s", errno, strerror(errno));
    }

    int sndbuf = 8286208;
    socklen_t olen = sizeof(sndbuf);
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&sndbuf, olen) < 0) {
        Note("set socket sendbuf error %d %s", errno, strerror(errno));
    }
    
    tmp_packet_buf = (unsigned char *)ats_calloc(1, 4096);

    net_header = make_ptr<IOBufferBlock>(new_IOBufferBlock());
    net_header->alloc(iobuffer_size_to_index(BUFFER_SIZE_INDEX_128,
            BUFFER_SIZE_INDEX_128));

    ipheader = (struct iphdr *)net_header->start();
    udpheader = (struct udphdr *)(((unsigned char *)ipheader) + sizeof(struct iphdr));

    memset(ipheader, 0, sizeof(struct iphdr));
    ipheader->version = 4;
    ipheader->ihl = sizeof(struct iphdr) >> 2;
    ipheader->tos = 0;
    ipheader->tot_len = 0;
    ipheader->id = 0;
    ipheader->frag_off = 0;
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_UDP;
    ipheader->saddr = src_ip;
    ipheader->daddr = dst_ip;

    memset(udpheader, 0, sizeof(struct udphdr));
    udpheader->source = src_port;
    udpheader->dest = dst_port;
    net_header->fill(sizeof(struct iphdr) + sizeof(struct udphdr));

    //SET_CONTINUATION_HANDLER(&qsho_con, &QshoStream::notify_qsho);
    qsho_con.handler = continuation_handler_void_ptr(&QshoStream::notify_qsho);
    SET_HANDLER(&QshoStream::main_handler);

    send_ctl.detectLoss.handler = continuation_handler_void_ptr(&QshoStream::OnLossDetectionTimeout);


    nh = get_QshoNetHandler(qsho_thread);
    nh->new_streams.push(this);
}

QshoStream::~QshoStream()
{
    SList(ACKFrame, ack_link) nsq(atomic_acks.popall());
    ACKFrame *qack;
    while ((qack = nsq.pop())) {
        delete qack;
    }

    QshoPacket *p;
    SList(QshoPacket, alink) aq(waitQueue.popall());
    while ((p = aq.pop())) {
        p->free();
        p = nullptr;
    }

    while ((p = unencrypt_packets.dequeue())) {
        p->free();
        p = nullptr;
    }

    while ((p = priority_packets.dequeue())) {
        p->free();
        p = nullptr;
    }

    while ((p = sent_packets.dequeue())) {
        p->free();
        p = nullptr;
    }

    while ((p = qsho_queues.dequeue())) {
        p->qsho_processor_cancel = true;
        p = nullptr;
    }

    close(fd);
    net_header = nullptr;
    secret.destroy();
    if (dst_cid) {
        ats_free(dst_cid);
        dst_cid = nullptr;
        dst_cid_len = 0;
    }

    if (tmp_packet_buf) {
        ats_free(tmp_packet_buf);
        tmp_packet_buf = nullptr;
    }    
#ifdef QSHO_DEBUG_MODE
    Note("delete QshoStream");
#endif
}


int
QshoStream::notify_qsho(int event, void *data)
{
    Event *e = (Event *)data;
    QshoStream *qs = (QshoStream *)e->cookie;
    switch (event) {
    case VC_EVENT_QSHO_STREAM_CLOSE:
        qs->stream_closed = true;
        break;

    case VC_EVENT_QSHO_UPDATE_LARGEST_ACK:
        break;

    case VC_EVENT_QSHO_WRITE_FINISHED:
#ifdef QSHO_DEBUG_MODE
        Note("qsid %lu write finished", qs->stream_id);
#endif
        qs->write_finished = true;
        break;

    default:
        ink_assert(0);
    }
    return EVENT_CONT;
}

QshoPacket *
QshoStream::new_packet()
{
    QshoPacket *qpacket = (QshoPacket *)ats_calloc(1, sizeof(QshoPacket));
    qpacket->buf = make_ptr<IOBufferBlock>(new_IOBufferBlock());
    qpacket->buf->alloc(iobuffer_size_to_index(
            MAX_QSHO_PAYLOAD_UNENCRYPTO_LEN,
            BUFFER_SIZE_INDEX_4K));
    qpacket->orig_buf = make_ptr<IOBufferBlock>(new_IOBufferBlock());
    qpacket->orig_buf->alloc(iobuffer_size_to_index(
            MAX_QSHO_PAYLOAD_UNENCRYPTO_LEN,
            BUFFER_SIZE_INDEX_4K));
    qpacket->qs = this;
    memset(&qpacket->dst_addr, 0, sizeof(struct sockaddr_in));
    qpacket->dst_addr.sin_family = AF_INET;
    qpacket->dst_addr.sin_addr.s_addr = dst_ip;
    qpacket->dst_addr.sin_port = dst_port;

    return qpacket; 
}

VIO *
QshoStream::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
    ink_assert(0);
    return nullptr;
}


VIO *
QshoStream::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *reader, bool owner)
{
  //Note("qsho stream do_io_write");
  write.vio.op        = VIO::WRITE;
  write.vio.mutex     = c ? c->mutex : this->mutex;
  write.vio.cont      = c;
  write.vio.nbytes    = nbytes;
  write.vio.ndone     = 0;
  write.vio.vc_server = (VConnection *)this;
  if (reader) {
    ink_assert(!owner);
    write.vio.buffer.reader_for(reader);
    if (nbytes && !write.enabled) {
      write.vio.reenable();
    }
  } else {
    write.enabled = 0;
  }
  return &write.vio;
}

//拥有packet number和数据，此时需要一个入口
int
QshoStream::main_handler(int event, void *data)
{
    //Note("QshoStream main_handler %d\n", event);
    Event *e = (Event *)data;
    QshoStream *qs = (QshoStream *)e->cookie;
    if (qs->stream_closed) {
        return EVENT_CONT;
    }
    switch (event) {
    case VC_EVENT_QSHO_RESCHEDULE:
    case VC_EVENT_QSHO_WRITE_POLL:
        qs->re_schedule();
        break;

    case VC_EVENT_WRITE_READY:
        //Note("Qshostream main_handler VC_EVENT_WRITE_READY");
    case VC_EVENT_WRITE_COMPLETE:
        qs->write_schedule();
        break;

    case VC_EVENT_QSHO_ACK_FINISHED:
        do {
            qs->ack_finished = true;
            if (!qshoctrl->eos) {
                qshoctrl->send_b2f_msg(qs->pn);
                //MUTEX_TRY_LOCK(lock, qs->write.vio.mutex, qs->thread);
                //qs->write.vio.cont->handleEvent(VC_EVENT_WRITE_COMPLETE, &qs->write.vio);
            } else {
                MUTEX_TRY_LOCK(lock, qs->write.vio.mutex, qs->thread);
                qs->write.vio.cont->handleEvent(VC_EVENT_EOS, &qs->write.vio);
            }
        } while (0);
        break;

    default:
        ink_assert(0);
    }
    return EVENT_CONT;
}


void
QshoStream::re_schedule()
{
    write_schedule();
}


void
QshoStream::write_schedule()
{
    bool maybe_fin = false;
    bool is_fin = false;
    int packet_num;
    int i;
    //qpacket中的block都是新的，不影响原有流程
    int64_t ntopackets = 0;
    int64_t packet_length;
    NetState *s = &write;
    VIO *vio = &s->vio;
    int64_t ntodo = s->vio.ntodo();
    if (ntodo <= 0) {
        STATE_FROM_VIO(vio)->enabled = 0;
        return ;
    }

    MUTEX_TRY_LOCK(lock, s->vio.mutex, thread);
    if (!lock.is_locked()) {
        thread->schedule_imm_local(this, VC_EVENT_QSHO_RESCHEDULE, this);
        Note("exit lock write_schedule %ld", Thread::get_hrtime_updated());
        return ;
    }

    MIOBufferAccessor &buf = s->vio.buffer;
    ink_assert(buf.writer());
    int64_t towrite = buf.reader()->read_avail();

#if 0
    int64_t ndone = s->vio.ndone;
    static thread_local int64_t stay_count = 0;
    static thread_local int64_t last_to_write = 0;
    static thread_local int64_t blocked_by_packet_number_count = 0;
    static thread_local int64_t blocked_by_packet_number_time = 0;
    static thread_local int64_t blocked_by_disk_count = 0;
    static thread_local int64_t blocked_by_disk_time = 0;
    static thread_local ink_hrtime last_call = 0;
    static thread_local int last_state;
    ink_hrtime now = Thread::get_hrtime_updated();
    ink_hrtime skip = now - last_call;
    if (last_call == 0) {
        skip = 0;
    }
    last_call = now;

    if (last_to_write == towrite) {
        stay_count ++;
    } else {
        stay_count = 0;
        last_to_write = towrite;
    }
    Note("towrite %ld ntodo %ld ndone %ld, stay_count %ld",
            towrite, ntodo, ndone, stay_count);
    Note("pn block %ld disk block %ld %ld",
        blocked_by_packet_number_count,
        blocked_by_disk_count,
        blocked_by_disk_time);
#endif

    //绝大多数情况，towrite << ntodo
    if (towrite > ntodo) {
        towrite = ntodo;
    }

    if (towrite != ntodo && buf.writer()->write_avail()) {
        write.vio.cont->handleEvent(VC_EVENT_WRITE_READY, &write.vio);

        ntodo = s->vio.ntodo();
        if (ntodo <= 0) {
            STATE_FROM_VIO(vio)->enabled = 0;
            Note("exit not todo write_schedule %ld", Thread::get_hrtime_updated());
            return ;
        }    

        towrite = buf.reader()->read_avail();
        if (towrite > ntodo) {
            towrite = ntodo;
        }
    }

#if 0
    if (towrite > ((1000 - buf_count) * MAX_QSHO_PAYLOAD_UNENCRYPTO_LEN)) {
        towrite = (1000 - buf_count) * MAX_QSHO_PAYLOAD_UNENCRYPTO_LEN;
    }
#endif
#if 0
    do {
        LimitStat state;
        int64_t now = Thread::get_hrtime();

        if (towrite < MAX_QSHO_PAYLOAD_UNENCRYPTO_LEN) {
            state = WAIT_IO;
        } else {
            state = PROCESS_WRITE;
        }

        if (state != net_last_stat) {
            if (net_last_stat == WAIT_IO) {
                net_io_2_write_time += now - net_last_timestamp;
            } else {
                net_write_2_io_time += now - net_last_timestamp;
            }
            Note("net wait time %ld, %ld %ld %ld %ld, towrite %lu",
                    now, net_io_wait_time, net_process_write_time,
                    net_io_2_write_time, net_write_2_io_time, towrite);
        } else {
            if (net_last_stat == WAIT_IO) {
                net_io_wait_time += now - net_last_timestamp;
            } else {
                net_process_write_time += now - net_last_timestamp;
            }
        }

        net_last_stat = state;
        net_last_timestamp = now;
    } while (0);
#endif
    if (towrite == 0) {
        goto DONE;
    }
    //IOBufferReader *vio_reader = buf.reader();
    maybe_fin = false;
    is_fin = false;
    packet_num = towrite / MAX_QSHO_PAYLOAD_UNENCRYPTO_LEN;
    if (towrite == ntodo) {
        maybe_fin = true;
    }
    if (towrite == ntodo &&
            (towrite % MAX_QSHO_PAYLOAD_UNENCRYPTO_LEN != 0))
    {
        packet_num ++;
    }

    ntopackets = 0;
    for (i = 0; i < packet_num; i ++) {
        if (towrite - ntopackets > MAX_QSHO_PAYLOAD_UNENCRYPTO_LEN) {
            packet_length = MAX_QSHO_PAYLOAD_UNENCRYPTO_LEN;
        } else {
            packet_length = towrite - ntopackets;
        }
        ntopackets += packet_length;
        if (maybe_fin && (i == packet_num - 1)) {
            is_fin = true;
        }

        QshoPacket *p = new_packet();
        create_stream_frame(p, buf, packet_length, is_fin, true);
        p->is_fin = is_fin;

        total_packet_count ++;

#if 0
        if (i == packet_num - 1) {
            p->need_callback = true;
        }
#endif

        waitQueue.push(p);
    }
    s->vio.ndone += ntopackets;

    if (is_fin) {
        qsho_thread->schedule_imm(&qsho_con, VC_EVENT_QSHO_WRITE_FINISHED, this);
        assert(write.vio.ntodo() <= 0);
        STATE_FROM_VIO(&write.vio)->enabled = 0;
    }

DONE:
    write_schedule_done();
}

void
QshoStream::write_schedule_done()
{
    MIOBufferAccessor &buf = write.vio.buffer;
    int wbe_event = write_buffer_empty_event;
    if (!(buf.reader()->is_read_avail_more_than(0))) {
        write_buffer_empty_event = 0;
    }

    MUTEX_TRY_LOCK(lock, write.vio.mutex, thread);
#if 0
    if (!lock.is_locked()) {
        thread->schedule_imm_local(this, VC_EVENT_QSHO_RESCHEDULE, this);
        return ;
    }
#endif
    int e = 0;
    if (wbe_event != write_buffer_empty_event) {
        e = wbe_event;
    }

    if (e) {
        write.vio.cont->handleEvent(VC_EVENT_WRITE_READY, &write.vio);
    }
    //write.vio.cont->handleEvent(VC_EVENT_WRITE_READY, &write.vio);
}

void
QshoStream::trapWriteBufferEmpty()
{
    write_buffer_empty_event = VC_EVENT_WRITE_READY;
}

void
QshoStream::reenable(VIO *vio)
{
    EThread *t = vio->mutex->thread_holding;
    ink_assert(t == this_ethread());

    NetState *s = &write;
    int64_t ntodo = s->vio.ntodo();

    int64_t readable = qshoctrl->buf_reader->read_avail();
#if 0
    if (STATE_FROM_VIO(vio)->enabled) {
        return;
    }
#endif
    STATE_FROM_VIO(vio)->enabled = 1;
    write_schedule();
}

void
QshoStream::do_io_close(int alerrno /* = -1 */)
{
#ifdef QSHO_DEBUG_MODE
    Note("qsho stream do_io_close %lu", stream_id);
#endif
    write.enabled = 0;
    write.vio.buffer.clear();
    write.vio.nbytes = 0;
    write.vio.op = VIO::NONE;
    //assert(ack_finished);
    qsho_thread->schedule_imm(&qsho_con, VC_EVENT_QSHO_STREAM_CLOSE, this);
}

int
QshoStream::getFd()
{
    return fd;
}


size_t
QshoStream::create_short_header(unsigned char *p, QshoPacket *qp)
{
    uint64_t  delta;
    int num_len;
    uint32_t trunc;
    unsigned char flags = 0x40;
    delta = send_ctl.largest_acked_packet - qp->packet_number;

    unsigned char *pnp;
    unsigned char *ad = p;
    size_t ad_len;

    if (delta <= 0x7F) {
        num_len = 1;
        trunc = qp->packet_number & 0xff;
    } else if (delta <= 0x7FFF) {
        num_len = 2;
        flags |= 0x1;
        trunc = qp->packet_number & 0xffff;
    } else if (delta <= 0x7FFFFF) {
        num_len = 3;
        flags |= 0x2;
        trunc = qp->packet_number & 0xffffff;
    } else {
        num_len = 4;
        flags |= 0x3;
        trunc = qp->packet_number & 0xffffffff;
    }
    num_len = 4;
    flags |= 0x3;
    trunc = qp->packet_number & 0xffffffff;;

    *p = flags;
    p ++;
    memcpy(p, dst_cid, dst_cid_len);
    p += dst_cid_len;

    pnp = p;

    switch (num_len) {
    case 1:
        *p ++ = trunc;
        break;

    case 2:
        p = qsho_write_uint16(p, trunc);
        break;

    case 3:
        p = qsho_write_uint24(p, trunc);
        break;

    case 4:
        p = qsho_write_uint32(p, trunc);
        break;
    }

    ad_len = p - ad;

    const qsho_cipher_t *c;
    const EVP_CIPHER *hp;
    const EVP_MD *d;
    switch (secret.cipher_id) {
    case 0x1301:
#ifdef QSHO_BORINGSSL
        c = EVP_aead_aes_128_gcm();
#else
        c = EVP_aes_128_gcm();
#endif
        hp = EVP_aes_128_ctr();
        d = EVP_sha256();
        break;

    case 0x1302:
#ifdef QSHO_BORINGSSL
        c = EVP_aead_aes_256_gcm();
#else
        c = EVP_aes_256_gcm();
#endif
        hp = EVP_aes_256_ctr();
        d = EVP_sha384();
        break;

    case 0x1303:
#ifdef QSHO_BORINGSSL
        c = EVP_aead_chacha20_poly1305();
#else
        c = EVP_chacha20_poly1305();
#endif
#ifdef QSHO_BORINGSSL
        hp = (const EVP_CIPHER *) EVP_aead_chacha20_poly1305();
#else
        hp = EVP_chacha20();
#endif
        d = EVP_sha256();
        break;
    }

    unsigned char nonce[12], mask[5];
    memcpy(nonce, secret.iv, secret.iv_len);
    qsho_compute_nonce(nonce, sizeof(nonce), qp->packet_number, 0);

#if 0
    unsigned char dump_buf[128];
    memset(dump_buf, 0, sizeof(dump_buf));
    qsho_hex_dump(dump_buf, nonce, 12);

    //Note("pn %lu pnsid %lu nonce %s", qp->packet_number, pnsid, dump_buf);
#endif

    unsigned char *out = p;
    size_t out_len = qp->orig_buf->size() + EVP_GCM_TLS_TAG_LEN;
    unsigned char *in = (unsigned char *)qp->orig_buf->start();
    size_t in_len = qp->orig_buf->size();
    qsho_tls_seal(c, &secret, out, &out_len, nonce, in, &in_len, ad, &ad_len);

    unsigned char *sample = &out[4 - num_len];
    qsho_tls_hp(hp, &secret, mask, sample);

    ad[0] ^= mask[0] & 0x1f;

    int i;
    for (i = 0; i < num_len; i ++) {
        pnp[i] ^= mask[i + 1];
    }
    
    return ad_len + out_len;
}

void
QshoStream::encrypt_packet(QshoPacket *p)
{
    size_t packet_len;
    struct iphdr *now_iphdr;
    struct udphdr *now_udphdr;
    memcpy(tmp_packet_buf, ipheader, sizeof(struct iphdr) +
            sizeof(struct udphdr));

    if (p->timestamp_position) {
        struct timespec ts;  
        clock_gettime(CLOCK_REALTIME, &ts);
        int64_t timestamp = ts.tv_sec * 1000000000 + ts.tv_nsec;
        memcpy(p->timestamp_position, &timestamp, sizeof(timestamp));
    }

    packet_len = create_short_header(tmp_packet_buf + sizeof(struct iphdr)
            + sizeof(struct udphdr), p);
    packet_len += sizeof(struct iphdr) + sizeof(struct udphdr);
    if (packet_len > p->buf->size()) {
        p->buf->fill(packet_len - p->buf->size());
    } else {
        p->buf->reset();
        p->buf->fill(packet_len - p->buf->size());
    }

    packet_len -= sizeof(struct iphdr);

    now_iphdr = (struct iphdr *)tmp_packet_buf;
    now_udphdr = (struct udphdr *)(((char *)now_iphdr) + sizeof(struct iphdr));

    now_udphdr->len = htons(packet_len);
    now_udphdr->check = cal_udp_checksum(now_iphdr, nh->checksum_buf);

    memcpy(p->buf->start(), tmp_packet_buf, packet_len + sizeof(struct iphdr));

    p->pktLength = p->buf->size();
    p->sent_bytes = packet_len - sizeof(struct udphdr);

}

void
QshoStream::qsho_process_wait_packet(ink_hrtime now)
{
#if 0
    if (!write_finished) {
        return;
    }
#endif
    QshoPacket *p;
    int position = 0;
    SList(QshoPacket, alink) aq(waitQueue.popall());
    Queue<QshoPacket> stk;

    while ((p = aq.pop())) {
        stk.push(p);
    }
    while ((p = stk.pop())) {
        if (p->need_callback) {
            exist_callback ++;
        }
        unencrypt_packets.enqueue(p);
        encrypto_count ++;
        stream_packet_count ++;
    }

SEND:
    while (!priority_packets.empty() || !unencrypt_packets.empty()) {
        if (!priority_packets.empty()) {
            p = priority_packets.head;
            position = 1;
        } else if (!unencrypt_packets.empty()) {
            p = unencrypt_packets.head;
            position = 2;
        }

        //if pn_state is PN_UNUSED, the RS neglects the cwnd and the in flight.
        if (send_ctl.bytes_in_flight + p->orig_buf->size() > send_ctl.cwnd &&
                pn_state != PN_UNUSED)
        {
            break;
        }

        if (pn_max != 0 && pn >= pn_max) {
            ink_assert(pn_state != PN_UNUSED);
            break;
        }

        if (position == 1) {
            priority_packets.remove(p);
        } else if (position == 2) {
            unencrypt_packets.remove(p);
            encrypto_count --;
        }

        position = 0;

        p->packet_number = pn;
        pn ++;
        if (pn_state == PN_UNUSED) {
            pn_state = PN_USED;
        }
        encrypt_packet(p);

        OnPacketSent(p, now);

        qsho_queues.enqueue(p);
        nh->qshoOutQueue.send(p);
    }

    if (pn_state == PN_UNUSED) {
        ink_assert(priority_packets.empty() && unencrypt_packets.empty());
        //app limited, sending ping frame to elicit ack.
        p = create_ping_frame(1200, true);
        unencrypt_packets.enqueue(p);
        encrypto_count += 1;
        goto SEND;
    }

    //ink_assert(pn_max == 0 || pn < pn_max);
#ifdef DEBUG_APP_LIMITED
    if (last_app_limited_timestamp != 0 && encrypto_count == 0 && send_ctl.bytes_in_flight < send_ctl.cwnd) {
        total_app_limited_time += now - last_app_limited_timestamp;
        Note("app limited acc time %lu at %ld, %lu", total_app_limited_time, now, stream_packet_count);
    }

    if (!(encrypto_count == 0 && send_ctl.bytes_in_flight < send_ctl.cwnd)) {
        last_app_limited_timestamp = 0;
    } else {
        last_app_limited_timestamp = now;
    }
#endif

#if 0
    if ((encrypto_count < 1000) && (now - last_callback > HRTIME_MSECONDS(1))) {
        Note("activate net thread %lu %lu", now, stream_packet_count);
        buf_count = encrypto_count;
        thread->schedule_imm(this, VC_EVENT_WRITE_READY, this);
        last_callback = now;
    }
#endif
}


void
QshoStream::process_ack(ink_hrtime now)
{
    bool lb_finished = false;

    SList(ACKFrame, ack_link) nsq(atomic_acks.popall());
    ACKFrame *qack;
    Queue<ACKFrame> stk;
    while ((qack = nsq.pop())) {
        stk.push(qack);
    }

    while ((qack = stk.pop())) {
#if 0
        if (qack->finished) {
            Note("get ack finished");
        } else {
            Note("ack packet min:max %lu-%lu", qack->ack_min, qack->ack_max);
        }
#endif
        if (qack->finished) {
            /* *** 与前端的连接出错 或前端确认连接结束 *** */
            lb_finished = true;
        } else {
            if (qack->pn_min != 0) {
#ifdef DEBUG_PNS
                Note("new pn [%ld - %ld], old pn %ld", qack->pn_min, qack->pn_max, pn);
#endif
                pn = qack->pn_min;
                pn_max = qack->pn_max;
                pn_state = PN_UNUSED;
            }
            /* *** 处理ACKed 报文 *** */
            if (qack->ack_max >= qack->ack_min) {
                OnAckReceived(qack, now);
            }
            delete qack;
        }
    }

    if ((lb_finished || write_finished && total_packet_count == free_count)
            && !sent_finish_notify)
    {
#if QSHO_DEBUG_MODE
        unsigned char dump_buf[128];
        memset(dump_buf, 0, sizeof(dump_buf));
        qsho_hex_dump(dump_buf, dst_cid, dst_cid_len);
        Note("stream finished %s, id %lu, %lu, %lu", dump_buf,
                stream_id, free_count, retransmit_count);
#endif
        thread->schedule_imm(this, VC_EVENT_QSHO_ACK_FINISHED, this);
        sent_finish_notify = true;
        return;
    }
}


using QshoNetContHandler = int (QshoNetHandler::*)(int, void *);


//
// Global Data
//

QshoNetProcessor qshoNet;

void
initialize_thread_for_qsho_net(EThread *thread)
{
  QshoNetHandler *nh = get_QshoNetHandler(thread);

  new (reinterpret_cast<ink_dummy_for_new *>(nh)) QshoNetHandler;
  new (reinterpret_cast<ink_dummy_for_new *>(get_QshoPollCont(thread))) PollCont(thread->mutex);
  // The QshoNetHandler cannot be accessed across EThreads.
  // Because the QshoNetHandler should be called back immediately after QshoPollCont.
  nh->mutex  = thread->mutex.get();
  nh->thread = thread;
  nh->qshoOutQueue.thread = thread;

  PollCont *qpc       = get_QshoPollCont(thread);
  PollDescriptor *qpd = qpc->pollDescriptor;
  // TODO: fixed size
  qpc->poll_timeout = 100;
  thread->set_tail_handler(nh);
  thread->ep = static_cast<EventIO *>(ats_malloc(sizeof(EventIO)));
  new (thread->ep) EventIO();
  thread->ep->type = EVENTIO_ASYNC_SIGNAL;
#if HAVE_EVENTFD
  thread->ep->start(qpd, thread->evfd, nullptr, EVENTIO_READ);
#else
  thread->ep->start(qpd, thread->evpipe[0], nullptr, EVENTIO_READ);
#endif
  Note("initialize_thread_for_qsho_net %d", getpid());
  nh->startNetEvent();
}

int
QshoNetProcessor::start(int n_qsho_threads, size_t stacksize)
{
  if (n_qsho_threads < 1) {
    return -1;
  }

  int i;
  for (i = 0; i < n_qsho_threads; i ++) {
    pollCont_offset[i] = eventProcessor.allocate(sizeof(PollCont));
    qshoNetHandler_offset[i] = eventProcessor.allocate(sizeof(QshoNetHandler));
  }

  ET_QSHO = eventProcessor.register_event_type("ET_QSHO");
  eventProcessor.schedule_spawn(&initialize_thread_for_qsho_net, ET_QSHO);
  eventProcessor.spawn_event_threads(ET_QSHO, n_qsho_threads, stacksize);

  //std::cout << "qsho QshoNetProcessor::start " << getpid() << std::endl;
  return 0;
}

// send out all packets that need to be sent out as of time=now
QshoQueue::QshoQueue()
{
}

QshoQueue::~QshoQueue() {}

/*
 * Driver function that aggregates packets across cont's and sends them
 */
void
QshoQueue::service(QshoNetHandler *nh)
{
  (void)nh;
  ink_hrtime now     = Thread::get_hrtime_updated();
  uint64_t timeSpent = 0;
  uint64_t pktSendStartTime;
  ink_hrtime pktSendTime;
  QshoPacket *p = nullptr;

  SList(QshoPacket, blink) aq(outQueue.popall());
  Que(QshoPacket, clink) stk;
  while ((p = aq.pop())) {
    stk.push(p);
  }

  // walk backwards down list since this is actually an atomic stack.
  while ((p = stk.pop())) {
    //ink_assert(p->link.prev == nullptr);
    //ink_assert(p->link.next == nullptr);
    p->delivery_time = std::max(now, p->delivery_time);

    pipeInfo.addPacket(p, now);
  }

  pipeInfo.advanceNow(now);
  SendPackets();
}

void
QshoQueue::SendPackets()
{
  QshoPacket *p;
  ink_hrtime now                    = Thread::get_hrtime_updated();
  ink_hrtime send_threshold_time    = now + SLOT_TIME;
  int32_t bytesThisSlot = INT_MAX, bytesUsed = 0;
  int32_t bytesThisPipe, sentOne;
  int64_t pktLen;

  bytesThisSlot = INT_MAX;

sendPackets:
  sentOne       = false;
  bytesThisPipe = bytesThisSlot;

  while ((bytesThisPipe > 0) && (pipeInfo.firstPacket(send_threshold_time))) {
    p = pipeInfo.getFirstPacket();
    pktLen = p->getPktLength();
    p->last_send_time = now;

    if (p->qsho_processor_cancel) {
        //maybe qs have been destoryed 
        p->free();
        p = nullptr;
    } else {
        SendQshoPacket(p, pktLen);
        bytesUsed += pktLen;
        bytesThisPipe -= pktLen;
    }

  next_pkt:
    sentOne = true;
    //p->free();

    if (bytesThisPipe < 0) {
      break;
    }
  }

  bytesThisSlot -= bytesUsed;

  if ((bytesThisSlot > 0) && sentOne) {
    // redistribute the slack...
    now = Thread::get_hrtime_updated();
    if (pipeInfo.firstPacket(now) == nullptr) {
      pipeInfo.advanceNow(now);
    }
    goto sendPackets;
  }
}

void
QshoQueue::SendQshoPacket(QshoPacket *p, int32_t /* pktLen ATS_UNUSED */)
{
  struct msghdr msg;
  struct iovec iov;
  int real_len = 0;
  int n, count, iov_len = 0;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name    = &p->qs->dst_addr;
  msg.msg_namelen = sizeof(struct sockaddr_in);

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = p->buf->start();
  iov.iov_len  = p->buf->size();
  real_len += iov.iov_len;
  msg.msg_iov    = &iov;
  msg.msg_iovlen = 1;

  count = 0;
  while (true) {
    // stupid Linux problem: sendmsg can return EAGAIN
    n = sendmsg(p->qs->getFd(), &msg, 0);
    if ((n >= 0) || ((n < 0) && (errno != EAGAIN))) {
      // send succeeded or some random error happened.
      if (n < 0) {
        Note("qsho-send Error: %s (%d)", strerror(errno), errno);
      }

      break;
    }
    if (errno == EAGAIN) {
      ++count;
      if (count > 1000) {
        // tried too many times; give up
        Note("qshonet Send failed: too many retries");
        break;
      }
    }
  }

#ifdef DEBUG_SENT_PACKET
  Note("Sent packet %lu buff_count %lu, cwnd %lu, bytes_in_flight %lu\n",
            p->packet_number, p->qs->encrypto_count, p->qs->send_ctl.cwnd,
            p->qs->send_ctl.bytes_in_flight);
#endif

  p->qs->qsho_queues.remove(p);
  p->qs->sent_packets.enqueue(p);
  p->qs->sent_packet_count ++;

  if (p->need_callback) {
    p->qs->callback_event = VC_EVENT_WRITE_COMPLETE;
    QshoNetHandler *nh = p->qs->nh;
    if (!p->qs->in_callback_que) {
        nh->callbacks.push(p->qs);
        p->qs->in_callback_que = true;
    }
    p->qs->exist_callback --;
  }
#if 0
#endif
}

void
QshoQueue::send(QshoPacket *p)
{
  outQueue.push(p);
}

#undef LINK

static void
net_signal_hook_callback(EThread *thread)
{
#if HAVE_EVENTFD
  uint64_t counter;
  ATS_UNUSED_RETURN(read(thread->evfd, &counter, sizeof(uint64_t)));
#elif TS_USE_PORT
/* Nothing to drain or do */
#else
  char dummy[1024];
  ATS_UNUSED_RETURN(read(thread->evpipe[0], &dummy[0], 1024));
#endif
}

QshoNetHandler::QshoNetHandler()
{
  nextCheck = Thread::get_hrtime_updated() + HRTIME_MSECONDS(1000);
  lastCheck = 0;
  checksum_buf = (char *)ats_calloc(1, 4096);
  SET_HANDLER((QshoNetContHandler)&QshoNetHandler::mainNetEvent);
}

void
QshoNetHandler::startNetEvent()
{
  thread->schedule_every_local(this, HRTIME_NSECONDS(1), EVENT_POLL, this);

  debug_con.handler = continuation_handler_void_ptr(&QshoNetHandler::debugEvent);
  thread->schedule_every_local(&debug_con, HRTIME_MSECONDS(100), EVENT_POLL, this);
}

int
QshoNetHandler::debugEvent(int event, Event *e)
{
    QshoNetHandler *nh = (QshoNetHandler *)e->cookie;
    //Note("main_exec_count %lu", nh->main_exec_count);
    if (nh->last_in_flight_count != nh->in_flight_count) {
        Note("in flight count %u", nh->in_flight_count);
    }
    nh->last_in_flight_count = nh->in_flight_count;
#if QSHO_DEBUG_MODE
    if (nh->last_retransmit_count != nh->retransmit_count) {
        Note("retransmit_count %lu", nh->retransmit_count);
    }
#endif
    nh->last_retransmit_count = nh->retransmit_count;
}

int
QshoNetHandler::mainNetEvent(int event, Event *e)
{
  QshoNetHandler *nh = (QshoNetHandler *)e->cookie;
  main_exec_count ++;
  return nh->waitForActivity(net_config_poll_timeout);
}

int
QshoNetHandler::waitForActivity(ink_hrtime timeout)
{
  ink_hrtime now = Thread::get_hrtime_updated();
  SList(QshoStream, qsho_alink) nsq(new_streams.popall());
  QshoStream *qs;
  while ((qs = nsq.pop())) {
    //ink_assert(qs->mutex && qs->continuation);
    open_streams.in_or_enqueue(qs);
    //Note("new qsho stream in qsho thread");
  }

  //组装、加密报文、根据packet number发送报文
  forl_LL(QshoStream, qs, open_streams) {
    if (qs->write_finished && qs->waitQueue.empty() && qs->unencrypt_packets.empty()
            && qs->priority_packets.empty() && qs->sent_packets.empty())
    {
        continue;
    }

    if (qs->sent_finish_notify) {
        continue;
    }

    qs->qsho_process_wait_packet(now);
  }

  //处理ack，接收新的packet number
  forl_LL(QshoStream, qs, open_streams) {
    qs->process_ack(now);
  }

  qs = open_streams.head;
  while (qs) {
    QshoStream *n = open_streams.next(qs);
    if (qs->stream_closed) {
      open_streams.remove(qs);
      removing_qs.enqueue(qs);
      qs->remove_time = now;
    }
    qs = n;
  }

  qs = removing_qs.head;
  while (qs) {
    QshoStream *n = removing_qs.next(qs);
    if (qs->remove_time + HRTIME_MSECONDS(10) < now) {
        removing_qs.remove(qs);
        delete qs;
    } else {
        qs = nullptr;
        break;
    }
    qs = n;
  }

  // handle qsho outgoing engine
  qshoOutQueue.service(this);

  //回调主线程
  while((qs = callbacks.pop())) {
    qs->in_callback_que = false;
    qs->thread->schedule_imm(qs, qs->callback_event, qs);
    qs->last_callback = now;
  }

  return EVENT_CONT;
}

void
QshoNetHandler::signalActivity()
{
#if HAVE_EVENTFD
  uint64_t counter = 1;
  ATS_UNUSED_RETURN(write(thread->evfd, &counter, sizeof(uint64_t)));
#elif TS_USE_PORT
  PollDescriptor *pd = get_PollDescriptor(thread);
  ATS_UNUSED_RETURN(port_send(pd->port_fd, 0, thread->ep));
#else
  char dummy = 1;
  ATS_UNUSED_RETURN(write(thread->evpipe[1], &dummy, 1));
#endif
}

void
QshoSecret::destroy()
{
    cipher_id = -1;
    if (secret) {
        ats_free(secret);
        secret = nullptr;
        secret_len = 0;
    }

    if (key) {
        ats_free(key);
        key = nullptr;
        key_len = 0;
    }

    if (iv) {
        ats_free(iv);
        iv = nullptr;
        iv_len = 0;
    }

    if (hp) {
        ats_free(hp);
        hp = nullptr;
        hp_len = 0;
    }
}

int
QshoSecret::delivery(QshoSecret *s)
{
    memcpy(s, this, sizeof(QshoSecret));
    
    cipher_id = -1;
    secret = nullptr;
    secret_len = 0;
    key = nullptr;
    key_len = 0;
    iv = nullptr;
    iv_len = 0;
    hp = nullptr;
    hp_len = 0;

    return 0;
}

void
QshoPacket::free()
{
    buf = nullptr;
    orig_buf = nullptr;
    ats_free(this);   
}

int64_t
QshoPacket::getPktLength()
{
    return pktLength;
}

uintptr_t
ngx_http_v3_encode_varlen_int(u_char *p, uint64_t value)
{
    if (value <= 63) {
        if (p == NULL) {
            return 1;
        }

        *p++ = value;
        return (uintptr_t) p;
    }

    if (value <= 16383) {
        if (p == NULL) {
            return 2;
        }

        *p++ = 0x40 | (value >> 8);
        *p++ = value;
        return (uintptr_t) p;
    }

    if (value <= 1073741823) {
        if (p == NULL) {
            return 4;
        }

        *p++ = 0x80 | (value >> 24);
        *p++ = (value >> 16);
        *p++ = (value >> 8);
        *p++ = value;
        return (uintptr_t) p;
    }

    if (p == NULL) {
        return 8;
    }

    *p++ = 0xc0 | (value >> 56);
    *p++ = (value >> 48);
    *p++ = (value >> 40);
    *p++ = (value >> 32);
    *p++ = (value >> 24);
    *p++ = (value >> 16);
    *p++ = (value >> 8);
    *p++ = value;
    return (uintptr_t) p;
}


uintptr_t
ngx_http_v3_encode_prefix_int(u_char *p, uint64_t value, uint64_t prefix)
{
    uint64_t  thresh, n;

    thresh = (1 << prefix) - 1;

    if (value < thresh) {
        if (p == NULL) {
            return 1;
        }

        *p++ |= value;
        return (uintptr_t) p;
    }

    value -= thresh;

    if (p == NULL) {
        for (n = 2; value >= 128; n++) {
            value >>= 7;
        }

        return n;
    }

    *p++ |= thresh;

    while (value >= 128) {
        *p++ = 0x80 | value;
        value >>= 7;
    }

    *p++ = value;

    return (uintptr_t) p;
}


uintptr_t
ngx_http_v3_encode_field_section_prefix(u_char *p, uint64_t insert_count,
    uint64_t sign, uint64_t delta_base)
{
    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, insert_count, 8)
               + ngx_http_v3_encode_prefix_int(NULL, delta_base, 7);
    }

    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, insert_count, 8);

    *p = sign ? 0x80 : 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, delta_base, 7);

    return (uintptr_t) p;
}


uintptr_t
ngx_http_v3_encode_field_ri(u_char *p, uint64_t dynamic, uint64_t index)
{
    /* Indexed Field Line */

    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, index, 6);
    }

    *p = dynamic ? 0x80 : 0xc0;

    return ngx_http_v3_encode_prefix_int(p, index, 6);
}


uintptr_t
ngx_http_v3_encode_field_lri(u_char *p, uint64_t dynamic, uint64_t index,
    u_char *data, size_t len)
{
    size_t   hlen;
    u_char  *p1, *p2;

    /* Literal Field Line With Name Reference */

    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, index, 4)
               + ngx_http_v3_encode_prefix_int(NULL, len, 7)
               + len;
    }

    *p = dynamic ? 0x40 : 0x50;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, index, 4);

    p1 = p;
    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, len, 7);

    if (data) {
        p2 = p;
        hlen = ngx_http_v2_huff_encode(data, len, p, 0);

        if (hlen) {
            p = p1;
            *p = 0x80;
            p = (u_char *) ngx_http_v3_encode_prefix_int(p, hlen, 7);

            if (p != p2) {
                memmove(p, p2, hlen);
            }

            p += hlen;

        } else {
            p = cpymem(p, data, len);
        }
    }

    return (uintptr_t) p;
}

#define tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)

void
strlow(u_char *dst, u_char *src, size_t n)
{
    while (n) {
        *dst = tolower(*src);
        dst++;
        src++;
        n--; 
    }    
}

uintptr_t
ngx_http_v3_encode_field_l(u_char *p, u_char *name_data, uint64_t name_len,
        u_char *value_data, uint64_t value_len)
{
    size_t   hlen;
    u_char  *p1, *p2;

    /* Literal Field Line With Literal Name */

    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, name_len, 3)
               + name_len
               + ngx_http_v3_encode_prefix_int(NULL, value_len, 7)
               + value_len;
    }

    p1 = p;
    *p = 0x20;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, name_len, 3);

    p2 = p;
    hlen = ngx_http_v2_huff_encode(name_data, name_len, p, 1);

    if (hlen) {
        p = p1;
        *p = 0x28;
        p = (u_char *) ngx_http_v3_encode_prefix_int(p, hlen, 3);

        if (p != p2) {
            memmove(p, p2, hlen);
        }

        p += hlen;

    } else {
        strlow(p, name_data, name_len);
        p += name_len;
    }

    p1 = p;
    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, value_len, 7);

    p2 = p;
    hlen = ngx_http_v2_huff_encode(value_data, value_len, p, 0);

    if (hlen) {
        p = p1;
        *p = 0x80;
        p = (u_char *) ngx_http_v3_encode_prefix_int(p, hlen, 7);

        if (p != p2) {
            memmove(p, p2, hlen);
        }

        p += hlen;

    } else {
        p = cpymem(p, value_data, value_len);
    }

    return (uintptr_t) p;
}


uintptr_t
ngx_http_v3_encode_field_pbi(u_char *p, uint64_t index)
{
    /* Indexed Field Line With Post-Base Index */

    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, index, 4);
    }

    *p = 0x10;

    return ngx_http_v3_encode_prefix_int(p, index, 4);
}


uintptr_t
ngx_http_v3_encode_field_lpbi(u_char *p, uint64_t index, u_char *data,
    size_t len)
{
    size_t   hlen;
    u_char  *p1, *p2;

    /* Literal Field Line With Post-Base Name Reference */

    if (p == NULL) {
        return ngx_http_v3_encode_prefix_int(NULL, index, 3)
               + ngx_http_v3_encode_prefix_int(NULL, len, 7)
               + len;
    }

    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, index, 3);

    p1 = p;
    *p = 0;
    p = (u_char *) ngx_http_v3_encode_prefix_int(p, len, 7);

    if (data) {
        p2 = p;
        hlen = ngx_http_v2_huff_encode(data, len, p, 0);

        if (hlen) {
            p = p1;
            *p = 0x80;
            p = (u_char *) ngx_http_v3_encode_prefix_int(p, hlen, 7);

            if (p != p2) {
                memmove(p, p2, hlen);
            }

            p += hlen;

        } else {
            p = cpymem(p, data, len);
        }
    }

    return (uintptr_t) p;
}

typedef struct {
    uint32_t  code;
    uint32_t  len;
} ngx_http_v2_huff_encode_code_t;


static ngx_http_v2_huff_encode_code_t  ngx_http_v2_huff_encode_table[256] =
{
    {0x00001ff8, 13}, {0x007fffd8, 23}, {0x0fffffe2, 28}, {0x0fffffe3, 28},
    {0x0fffffe4, 28}, {0x0fffffe5, 28}, {0x0fffffe6, 28}, {0x0fffffe7, 28},
    {0x0fffffe8, 28}, {0x00ffffea, 24}, {0x3ffffffc, 30}, {0x0fffffe9, 28},
    {0x0fffffea, 28}, {0x3ffffffd, 30}, {0x0fffffeb, 28}, {0x0fffffec, 28},
    {0x0fffffed, 28}, {0x0fffffee, 28}, {0x0fffffef, 28}, {0x0ffffff0, 28},
    {0x0ffffff1, 28}, {0x0ffffff2, 28}, {0x3ffffffe, 30}, {0x0ffffff3, 28},
    {0x0ffffff4, 28}, {0x0ffffff5, 28}, {0x0ffffff6, 28}, {0x0ffffff7, 28},
    {0x0ffffff8, 28}, {0x0ffffff9, 28}, {0x0ffffffa, 28}, {0x0ffffffb, 28},
    {0x00000014,  6}, {0x000003f8, 10}, {0x000003f9, 10}, {0x00000ffa, 12},
    {0x00001ff9, 13}, {0x00000015,  6}, {0x000000f8,  8}, {0x000007fa, 11},
    {0x000003fa, 10}, {0x000003fb, 10}, {0x000000f9,  8}, {0x000007fb, 11},
    {0x000000fa,  8}, {0x00000016,  6}, {0x00000017,  6}, {0x00000018,  6},
    {0x00000000,  5}, {0x00000001,  5}, {0x00000002,  5}, {0x00000019,  6},
    {0x0000001a,  6}, {0x0000001b,  6}, {0x0000001c,  6}, {0x0000001d,  6},
    {0x0000001e,  6}, {0x0000001f,  6}, {0x0000005c,  7}, {0x000000fb,  8},
    {0x00007ffc, 15}, {0x00000020,  6}, {0x00000ffb, 12}, {0x000003fc, 10},
    {0x00001ffa, 13}, {0x00000021,  6}, {0x0000005d,  7}, {0x0000005e,  7},
    {0x0000005f,  7}, {0x00000060,  7}, {0x00000061,  7}, {0x00000062,  7},
    {0x00000063,  7}, {0x00000064,  7}, {0x00000065,  7}, {0x00000066,  7},
    {0x00000067,  7}, {0x00000068,  7}, {0x00000069,  7}, {0x0000006a,  7},
    {0x0000006b,  7}, {0x0000006c,  7}, {0x0000006d,  7}, {0x0000006e,  7},
    {0x0000006f,  7}, {0x00000070,  7}, {0x00000071,  7}, {0x00000072,  7},
    {0x000000fc,  8}, {0x00000073,  7}, {0x000000fd,  8}, {0x00001ffb, 13},
    {0x0007fff0, 19}, {0x00001ffc, 13}, {0x00003ffc, 14}, {0x00000022,  6},
    {0x00007ffd, 15}, {0x00000003,  5}, {0x00000023,  6}, {0x00000004,  5},
    {0x00000024,  6}, {0x00000005,  5}, {0x00000025,  6}, {0x00000026,  6},
    {0x00000027,  6}, {0x00000006,  5}, {0x00000074,  7}, {0x00000075,  7},
    {0x00000028,  6}, {0x00000029,  6}, {0x0000002a,  6}, {0x00000007,  5},
    {0x0000002b,  6}, {0x00000076,  7}, {0x0000002c,  6}, {0x00000008,  5},
    {0x00000009,  5}, {0x0000002d,  6}, {0x00000077,  7}, {0x00000078,  7},
    {0x00000079,  7}, {0x0000007a,  7}, {0x0000007b,  7}, {0x00007ffe, 15},
    {0x000007fc, 11}, {0x00003ffd, 14}, {0x00001ffd, 13}, {0x0ffffffc, 28},
    {0x000fffe6, 20}, {0x003fffd2, 22}, {0x000fffe7, 20}, {0x000fffe8, 20},
    {0x003fffd3, 22}, {0x003fffd4, 22}, {0x003fffd5, 22}, {0x007fffd9, 23},
    {0x003fffd6, 22}, {0x007fffda, 23}, {0x007fffdb, 23}, {0x007fffdc, 23},
    {0x007fffdd, 23}, {0x007fffde, 23}, {0x00ffffeb, 24}, {0x007fffdf, 23},
    {0x00ffffec, 24}, {0x00ffffed, 24}, {0x003fffd7, 22}, {0x007fffe0, 23},
    {0x00ffffee, 24}, {0x007fffe1, 23}, {0x007fffe2, 23}, {0x007fffe3, 23},
    {0x007fffe4, 23}, {0x001fffdc, 21}, {0x003fffd8, 22}, {0x007fffe5, 23},
    {0x003fffd9, 22}, {0x007fffe6, 23}, {0x007fffe7, 23}, {0x00ffffef, 24},
    {0x003fffda, 22}, {0x001fffdd, 21}, {0x000fffe9, 20}, {0x003fffdb, 22},
    {0x003fffdc, 22}, {0x007fffe8, 23}, {0x007fffe9, 23}, {0x001fffde, 21},
    {0x007fffea, 23}, {0x003fffdd, 22}, {0x003fffde, 22}, {0x00fffff0, 24},
    {0x001fffdf, 21}, {0x003fffdf, 22}, {0x007fffeb, 23}, {0x007fffec, 23},
    {0x001fffe0, 21}, {0x001fffe1, 21}, {0x003fffe0, 22}, {0x001fffe2, 21},
    {0x007fffed, 23}, {0x003fffe1, 22}, {0x007fffee, 23}, {0x007fffef, 23},
    {0x000fffea, 20}, {0x003fffe2, 22}, {0x003fffe3, 22}, {0x003fffe4, 22},
    {0x007ffff0, 23}, {0x003fffe5, 22}, {0x003fffe6, 22}, {0x007ffff1, 23},
    {0x03ffffe0, 26}, {0x03ffffe1, 26}, {0x000fffeb, 20}, {0x0007fff1, 19},
    {0x003fffe7, 22}, {0x007ffff2, 23}, {0x003fffe8, 22}, {0x01ffffec, 25},
    {0x03ffffe2, 26}, {0x03ffffe3, 26}, {0x03ffffe4, 26}, {0x07ffffde, 27},
    {0x07ffffdf, 27}, {0x03ffffe5, 26}, {0x00fffff1, 24}, {0x01ffffed, 25},
    {0x0007fff2, 19}, {0x001fffe3, 21}, {0x03ffffe6, 26}, {0x07ffffe0, 27},
    {0x07ffffe1, 27}, {0x03ffffe7, 26}, {0x07ffffe2, 27}, {0x00fffff2, 24},
    {0x001fffe4, 21}, {0x001fffe5, 21}, {0x03ffffe8, 26}, {0x03ffffe9, 26},
    {0x0ffffffd, 28}, {0x07ffffe3, 27}, {0x07ffffe4, 27}, {0x07ffffe5, 27},
    {0x000fffec, 20}, {0x00fffff3, 24}, {0x000fffed, 20}, {0x001fffe6, 21},
    {0x003fffe9, 22}, {0x001fffe7, 21}, {0x001fffe8, 21}, {0x007ffff3, 23},
    {0x003fffea, 22}, {0x003fffeb, 22}, {0x01ffffee, 25}, {0x01ffffef, 25},
    {0x00fffff4, 24}, {0x00fffff5, 24}, {0x03ffffea, 26}, {0x007ffff4, 23},
    {0x03ffffeb, 26}, {0x07ffffe6, 27}, {0x03ffffec, 26}, {0x03ffffed, 26},
    {0x07ffffe7, 27}, {0x07ffffe8, 27}, {0x07ffffe9, 27}, {0x07ffffea, 27},
    {0x07ffffeb, 27}, {0x0ffffffe, 28}, {0x07ffffec, 27}, {0x07ffffed, 27},
    {0x07ffffee, 27}, {0x07ffffef, 27}, {0x07fffff0, 27}, {0x03ffffee, 26}
};


/* same as above, but embeds lowercase transformation */
static ngx_http_v2_huff_encode_code_t  ngx_http_v2_huff_encode_table_lc[256] =
{
    {0x00001ff8, 13}, {0x007fffd8, 23}, {0x0fffffe2, 28}, {0x0fffffe3, 28},
    {0x0fffffe4, 28}, {0x0fffffe5, 28}, {0x0fffffe6, 28}, {0x0fffffe7, 28},
    {0x0fffffe8, 28}, {0x00ffffea, 24}, {0x3ffffffc, 30}, {0x0fffffe9, 28},
    {0x0fffffea, 28}, {0x3ffffffd, 30}, {0x0fffffeb, 28}, {0x0fffffec, 28},
    {0x0fffffed, 28}, {0x0fffffee, 28}, {0x0fffffef, 28}, {0x0ffffff0, 28},
    {0x0ffffff1, 28}, {0x0ffffff2, 28}, {0x3ffffffe, 30}, {0x0ffffff3, 28},
    {0x0ffffff4, 28}, {0x0ffffff5, 28}, {0x0ffffff6, 28}, {0x0ffffff7, 28},
    {0x0ffffff8, 28}, {0x0ffffff9, 28}, {0x0ffffffa, 28}, {0x0ffffffb, 28},
    {0x00000014,  6}, {0x000003f8, 10}, {0x000003f9, 10}, {0x00000ffa, 12},
    {0x00001ff9, 13}, {0x00000015,  6}, {0x000000f8,  8}, {0x000007fa, 11},
    {0x000003fa, 10}, {0x000003fb, 10}, {0x000000f9,  8}, {0x000007fb, 11},
    {0x000000fa,  8}, {0x00000016,  6}, {0x00000017,  6}, {0x00000018,  6},
    {0x00000000,  5}, {0x00000001,  5}, {0x00000002,  5}, {0x00000019,  6},
    {0x0000001a,  6}, {0x0000001b,  6}, {0x0000001c,  6}, {0x0000001d,  6},
    {0x0000001e,  6}, {0x0000001f,  6}, {0x0000005c,  7}, {0x000000fb,  8},
    {0x00007ffc, 15}, {0x00000020,  6}, {0x00000ffb, 12}, {0x000003fc, 10},
    {0x00001ffa, 13}, {0x00000003,  5}, {0x00000023,  6}, {0x00000004,  5},
    {0x00000024,  6}, {0x00000005,  5}, {0x00000025,  6}, {0x00000026,  6},
    {0x00000027,  6}, {0x00000006,  5}, {0x00000074,  7}, {0x00000075,  7},
    {0x00000028,  6}, {0x00000029,  6}, {0x0000002a,  6}, {0x00000007,  5},
    {0x0000002b,  6}, {0x00000076,  7}, {0x0000002c,  6}, {0x00000008,  5},
    {0x00000009,  5}, {0x0000002d,  6}, {0x00000077,  7}, {0x00000078,  7},
    {0x00000079,  7}, {0x0000007a,  7}, {0x0000007b,  7}, {0x00001ffb, 13},
    {0x0007fff0, 19}, {0x00001ffc, 13}, {0x00003ffc, 14}, {0x00000022,  6},
    {0x00007ffd, 15}, {0x00000003,  5}, {0x00000023,  6}, {0x00000004,  5},
    {0x00000024,  6}, {0x00000005,  5}, {0x00000025,  6}, {0x00000026,  6},
    {0x00000027,  6}, {0x00000006,  5}, {0x00000074,  7}, {0x00000075,  7},
    {0x00000028,  6}, {0x00000029,  6}, {0x0000002a,  6}, {0x00000007,  5},
    {0x0000002b,  6}, {0x00000076,  7}, {0x0000002c,  6}, {0x00000008,  5},
    {0x00000009,  5}, {0x0000002d,  6}, {0x00000077,  7}, {0x00000078,  7},
    {0x00000079,  7}, {0x0000007a,  7}, {0x0000007b,  7}, {0x00007ffe, 15},
    {0x000007fc, 11}, {0x00003ffd, 14}, {0x00001ffd, 13}, {0x0ffffffc, 28},
    {0x000fffe6, 20}, {0x003fffd2, 22}, {0x000fffe7, 20}, {0x000fffe8, 20},
    {0x003fffd3, 22}, {0x003fffd4, 22}, {0x003fffd5, 22}, {0x007fffd9, 23},
    {0x003fffd6, 22}, {0x007fffda, 23}, {0x007fffdb, 23}, {0x007fffdc, 23},
    {0x007fffdd, 23}, {0x007fffde, 23}, {0x00ffffeb, 24}, {0x007fffdf, 23},
    {0x00ffffec, 24}, {0x00ffffed, 24}, {0x003fffd7, 22}, {0x007fffe0, 23},
    {0x00ffffee, 24}, {0x007fffe1, 23}, {0x007fffe2, 23}, {0x007fffe3, 23},
    {0x007fffe4, 23}, {0x001fffdc, 21}, {0x003fffd8, 22}, {0x007fffe5, 23},
    {0x003fffd9, 22}, {0x007fffe6, 23}, {0x007fffe7, 23}, {0x00ffffef, 24},
    {0x003fffda, 22}, {0x001fffdd, 21}, {0x000fffe9, 20}, {0x003fffdb, 22},
    {0x003fffdc, 22}, {0x007fffe8, 23}, {0x007fffe9, 23}, {0x001fffde, 21},
    {0x007fffea, 23}, {0x003fffdd, 22}, {0x003fffde, 22}, {0x00fffff0, 24},
    {0x001fffdf, 21}, {0x003fffdf, 22}, {0x007fffeb, 23}, {0x007fffec, 23},
    {0x001fffe0, 21}, {0x001fffe1, 21}, {0x003fffe0, 22}, {0x001fffe2, 21},
    {0x007fffed, 23}, {0x003fffe1, 22}, {0x007fffee, 23}, {0x007fffef, 23},
    {0x000fffea, 20}, {0x003fffe2, 22}, {0x003fffe3, 22}, {0x003fffe4, 22},
    {0x007ffff0, 23}, {0x003fffe5, 22}, {0x003fffe6, 22}, {0x007ffff1, 23},
    {0x03ffffe0, 26}, {0x03ffffe1, 26}, {0x000fffeb, 20}, {0x0007fff1, 19},
    {0x003fffe7, 22}, {0x007ffff2, 23}, {0x003fffe8, 22}, {0x01ffffec, 25},
    {0x03ffffe2, 26}, {0x03ffffe3, 26}, {0x03ffffe4, 26}, {0x07ffffde, 27},
    {0x07ffffdf, 27}, {0x03ffffe5, 26}, {0x00fffff1, 24}, {0x01ffffed, 25},
    {0x0007fff2, 19}, {0x001fffe3, 21}, {0x03ffffe6, 26}, {0x07ffffe0, 27},
    {0x07ffffe1, 27}, {0x03ffffe7, 26}, {0x07ffffe2, 27}, {0x00fffff2, 24},
    {0x001fffe4, 21}, {0x001fffe5, 21}, {0x03ffffe8, 26}, {0x03ffffe9, 26},
    {0x0ffffffd, 28}, {0x07ffffe3, 27}, {0x07ffffe4, 27}, {0x07ffffe5, 27},
    {0x000fffec, 20}, {0x00fffff3, 24}, {0x000fffed, 20}, {0x001fffe6, 21},
    {0x003fffe9, 22}, {0x001fffe7, 21}, {0x001fffe8, 21}, {0x007ffff3, 23},
    {0x003fffea, 22}, {0x003fffeb, 22}, {0x01ffffee, 25}, {0x01ffffef, 25},
    {0x00fffff4, 24}, {0x00fffff5, 24}, {0x03ffffea, 26}, {0x007ffff4, 23},
    {0x03ffffeb, 26}, {0x07ffffe6, 27}, {0x03ffffec, 26}, {0x03ffffed, 26},
    {0x07ffffe7, 27}, {0x07ffffe8, 27}, {0x07ffffe9, 27}, {0x07ffffea, 27},
    {0x07ffffeb, 27}, {0x0ffffffe, 28}, {0x07ffffec, 27}, {0x07ffffed, 27},
    {0x07ffffee, 27}, {0x07ffffef, 27}, {0x07fffff0, 27}, {0x03ffffee, 26}
};

#define ngx_http_v2_huff_encode_buf(dst, buf)                                 \
    (*(uint64_t *) (dst) = __builtin_bswap64(buf))

#define ngx_align(d, a)     (((d) + (a - 1)) & ~(a - 1))

size_t
ngx_http_v2_huff_encode(u_char *src, size_t len, u_char *dst, uint64_t lower)
{
    u_char                          *end;
    size_t                           hlen;
    uint64_t                       buf, pending, code;
    ngx_http_v2_huff_encode_code_t  *table, *next;

    table = lower ? ngx_http_v2_huff_encode_table_lc
                  : ngx_http_v2_huff_encode_table;
    hlen = 0;
    buf = 0;
    pending = 0;

    end = src + len;

    while (src != end) {
        next = &table[*src++];

        code = next->code;
        pending += next->len;

        /* accumulate bits */
        if (pending < sizeof(buf) * 8) {
            buf |= code << (sizeof(buf) * 8 - pending);
            continue;
        }

        if (hlen + sizeof(buf) >= len) {
            return 0;
        }

        pending -= sizeof(buf) * 8;

        buf |= code >> pending;

        ngx_http_v2_huff_encode_buf(&dst[hlen], buf);

        hlen += sizeof(buf);

        buf = pending ? code << (sizeof(buf) * 8 - pending) : 0;
    }

    if (pending == 0) {
        return hlen;
    }

    buf |= (uint64_t) -1 >> pending;

    pending = ngx_align(pending, 8);

    if (hlen + pending / 8 >= len) {
        return 0;
    }

    buf >>= sizeof(buf) * 8 - pending;

    do {
        pending -= 8;
        dst[hlen++] = (u_char) (buf >> pending);
    } while (pending);

    return hlen;
}


static void
debug_for_raw_socket(unsigned char *sendbuf, int send_buf_len,
        uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    Note("debug_for_raw_socket %d", send_buf_len);
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        printf("socket failed %s\n", strerror(errno));
        return;
    }

    const int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        printf("setsockopt error: %s\n", strerror(errno));
        return ;
    }

    struct iphdr *ipheader = (struct iphdr *)sendbuf;
    struct udphdr *udpheader = (struct udphdr *)(sendbuf + sizeof(struct iphdr));
    memset(ipheader, 0, sizeof(struct iphdr));
    memset(udpheader, 0, sizeof(struct udphdr));

    ipheader->version = 4;
    ipheader->ihl = sizeof(struct iphdr) >> 2;
    ipheader->tos = 0;
    ipheader->tot_len = 0;
    ipheader->id = 0;
    ipheader->frag_off = 0;
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_UDP;
    ipheader->saddr = sip;
    ipheader->daddr = dip;
    //cal_ipv4_checksum(ipheader);

    udpheader->source = sport;
    udpheader->dest = dport;
    udpheader->len = htons(send_buf_len - sizeof(struct iphdr));
    //udpheader->check = cal_udp_checksum(ipheader);

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = dip;
    dest_addr.sin_port = dport;

    struct iovec iov;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = sendbuf;
    iov.iov_len = send_buf_len;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    unsigned char dump_buf[4096];
    memset(dump_buf, 0, sizeof(dump_buf));
    qsho_hex_dump(dump_buf, (unsigned char *)&msg, sizeof(msg));
    Note("dump buf %s", dump_buf);
    int ret;
    int i;
    for (i = 0; i < 1; i ++) {
        if ((ret = sendmsg(fd, &msg, 0)) <= 0) {
            printf("sendmsg error: %s\n", strerror(errno));
            return;
        }
    }
    Note("send ok %d %d\n", i, ret);
}

static u_char *
qsho_hex_dump(u_char *dst, u_char *src, size_t len) 
{
    static u_char  hex[] = "0123456789abcdef";

    while (len--) {
        *dst++ = hex[*src >> 4];
        *dst++ = hex[*src++ & 0xf];
    }    

    return dst; 
}
