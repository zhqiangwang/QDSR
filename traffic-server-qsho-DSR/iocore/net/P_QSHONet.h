#pragma once

#include "tscore/ink_platform.h"
#include "tscore/ink_inet.h"
#include "tscore/List.h"
#include "tscore/ink_hrtime.h"
#include "I_Continuation.h"
#include "P_EventSystem.h"
#include "P_IOBuffer.h"
#include "P_UnixNet.h"
#include "P_VConnection.h"
#include "P_UnixNetState.h"
#include "I_Event.h"
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define UNSET_PN UINT64_MAX
#define INIT_WINDOW (2*65536)
#define kInitialRtt HRTIME_MSECONDS(50)
#define kTimeThreshold 1.125
#define kPacketThreshold 3
#define kInitialWindow 65536
#define kMinimumWindow 65536
#define kLossReductionFactor 0.5

static inline PollCont *get_QshoPollCont(EThread *);

extern EventType ET_QSHO;

enum Packet_State {
    QSHO_FIRST_SENT,
    QSHO_FAST_RETRANSMITING,
    QSHO_FAST_RETRANSMITED,
    QSHO_TIMEOUT_RETRANSMITED,
    QSHO_TIMEOUT_RETRANSMITING,
};

struct LostPacket {
    uint64_t packet_number;
    SLINK(LostPacket, lost_alink);
    LINK(LostPacket, link);
};

struct ACKRange {
    uint64_t ack_min;
    uint64_t ack_max;
    LINK(ACKRange, link);
};

struct ACKFrame {
    uint64_t ack_min;
    uint64_t ack_max;
    bool     finished = false;
    uint64_t ack_delay;
    uint64_t lb_ack_delay;
    uint64_t recv_timestamp;
    uint64_t pn_min;
    uint64_t pn_max;
    SLINK(ACKFrame, ack_link);
    LINK(ACKFrame, link);
    Que(ACKRange, link) ack_ranges;
};

struct QshoSecret {
    int32_t             cipher_id = -1;
    unsigned char      *secret = nullptr;
    int32_t             secret_len = 0;
    unsigned char      *key = nullptr;
    int32_t             key_len = 0;
    unsigned char      *iv = nullptr;
    int32_t             iv_len = 0;
    unsigned char      *hp = nullptr;
    int32_t             hp_len = 0;
    void destroy();
    int delivery(QshoSecret *s);
};

class QshoStream;
class QshoCtrl;
class QshoNetHandler;


struct SendCtl {
    ink_hrtime       latest_rtt                         = 0;
    ink_hrtime       smoothed_rtt                       = kInitialRtt;
    ink_hrtime       rttvar                             = kInitialRtt / 2;
    ink_hrtime       min_rtt                            = 0;
    ink_hrtime       first_rtt_sample                   = 0;
    ink_hrtime       max_ack_delay                      = HRTIME_MSECONDS(25);
    int              pto_count                          = 0;
    ink_hrtime       time_of_last_ack_eliciting_packet  = 0;
    uint64_t         largest_acked_packet               = UNSET_PN;
    ink_hrtime       loss_time                          = 0;
    ink_hrtime       loss_timer                         = 0;
    Event           *loss_detection_timer               = nullptr;
    Continuation     detectLoss;

    uint64_t         cwnd                               = kInitialWindow;
    uint64_t         bytes_in_flight                    = 0;
    ink_hrtime       congestion_recovery_start_time     = 0;
    uint64_t         ssthresh                           = UINT64_MAX;
    
};

class QshoPacket
{
public:
    QshoStream         *qs;
    uint64_t            pktLength = 0;
    uint64_t            sent_bytes;
    struct sockaddr_in  dst_addr;
    uint64_t            packet_number;
    ink_hrtime          delivery_time = 0;
    bool                need_callback = false;
    bool                is_fin = false;

    bool                in_flight = false;
    bool                in_qsho_processor = false;
    bool                qsho_processor_cancel = false;

    bool                in_retransmitting_queue = false;
    bool                in_retransmitted_queue = false;
    bool                retransmit_use_new_pn = false;

    unsigned char      *timestamp_position = nullptr;

    uint32_t            retransmitting = 0;
    bool                is_ping = false;

    Packet_State        state = QSHO_FIRST_SENT;
    ink_hrtime          last_send_time = 0;
    uint32_t            timeout_retransmit_count = 0;

    int                 in_the_priority_queue = 0;
    int                 in_heap = 0;

    Ptr<IOBufferBlock>  buf;
    Ptr<IOBufferBlock>  orig_buf;

    SLINK(QshoPacket, alink);
    SLINK(QshoPacket, blink);
    SLINK(QshoPacket, atomic_link);
    LINK(QshoPacket, clink);
    LINK(QshoPacket, dlink);
    LINK(QshoPacket, elink);
    LINK(QshoPacket, fflink);
    LINK(QshoPacket, link);

    //tmp
    LINK(QshoPacket, flink);

    void free();
    int64_t getPktLength();
};

enum LimitStat {
    WAIT_IO,
    PROCESS_WRITE,
};

class QshoStream: public VConnection
{
public:
    QshoStream(unsigned char *qcid, uint32_t qcid_len, uint64_t qsid,
        uint64_t, uint64_t packet_number, uint64_t packet_number_max,
        int64_t, uint32_t _src_ip, uint32_t _dst_ip,
        uint16_t _src_port, uint16_t _dst_port, QshoSecret *input_secret);
    QshoStream() = delete;
    ~QshoStream();
    int getFd();
    QshoPacket *new_packet();

    //for debug
    ink_hrtime net_last_timestamp;
    LimitStat net_last_stat = WAIT_IO;
    ink_hrtime net_io_wait_time;
    ink_hrtime net_process_write_time;
    ink_hrtime net_io_2_write_time;
    ink_hrtime net_write_2_io_time;

    ink_hrtime dsr_last_timestamp;
    LimitStat dsr_last_stat = WAIT_IO;
    ink_hrtime dsr_io_wait_time;
    ink_hrtime drs_process_write_time;

    uint64_t header_size;

    QshoPacket *create_ping_frame(int ping_len, bool new_pns);

    //VConnection
    VIO *do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf) override;
    //切包、加密、回调
    VIO *do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner = false) override;

    void reenable(VIO *vio) override;
    //void reenable_re(VIO *vio) override;
    void do_io_close(int lerrno = -1) override;
    void do_io_shutdown(ShutdownHowTo_t howto);
    void trapWriteBufferEmpty();
    void write_schedule();
    void re_schedule();
    void write_schedule_done();
    int main_handler(int event, void *data);

    uint64_t last_app_limited_timestamp = 0;
    uint64_t total_app_limited_time = 0;
    

    SendCtl send_ctl;
    void OnPacketSent(QshoPacket *qp, ink_hrtime now);
    void OnAckReceived(ACKFrame *ack, ink_hrtime now);
    void UpdateRTT(ink_hrtime ack_delay, ink_hrtime now);
    ink_hrtime GetLossTimeAndSpace();
    ink_hrtime GetPtoTimeAndSpace();
    void cancel_loss_timer();
    void SetLossDetectionTimer(ink_hrtime now);
    int OnLossDetectionTimeout(int event, void *data);
    void SendOneOrTwoAckElicitingPackets();
    void HandleAckRange(Que(QshoPacket, dlink) *newly_acked_packets, uint64_t min,
            uint64_t max, QshoPacket **packet);
    void DetectAndRemoveAckedPackets(Que(QshoPacket, dlink) *newly_acked_packets,
            ACKFrame *ack, QshoPacket **qp);
    void DetectAndRemoveLostPackets(Que(QshoPacket, dlink) *lost_packets, ink_hrtime now);

    //for congestion control
    void OnPacketSentCC(uint64_t sent_bytes);
    bool InCongestionRecovery(ink_hrtime sent_time);
    void OnPacketsAcked(Que(QshoPacket, dlink) *acked_packets);
    void OnCongestionEvent(ink_hrtime sent_time);
    void OnPacketsLost(Que(QshoPacket, dlink) *lost_packets);

    void encrypt_packet(QshoPacket *p);

    int write_buffer_empty_event = 0;
    NetState write{};
    uint64_t pnsid;
    int64_t pn;
    int64_t pn_max;

#define PN_UNUSED 0
#define PN_USED 1
    int pn_state = 0;


    uint32_t pn_len;
    uint32_t sent_pn_request = false;
    ink_hrtime lb_send_timestamp;
    ink_hrtime rs_recv_timestamp;
    

    ASLL(ACKFrame, ack_link) atomic_acks;
    ASLL(LostPacket, lost_alink) lps;



    /* ============== qsho thread ======= */


    bool in_callback_que = false;
    ink_hrtime last_callback = 0;
    ink_hrtime remove_time;
    int exist_callback = 0;
    int callback_event;

    ASLL(QshoPacket, alink) waitQueue;
    Que(QshoPacket, dlink) unencrypt_packets;
    Que(QshoPacket, dlink) priority_packets;

    Que(QshoPacket, dlink) qsho_queues;
    Que(QshoPacket, dlink) sent_packets;

    SLINK(QshoStream, qsho_alink);
    LINK(QshoStream, qsho_blink);
    LINK(QshoStream, qsho_callback_link);
    
    LINK(QshoStream, tmp_link);

    size_t create_short_header(unsigned char *p, QshoPacket *qp);
    uint64_t create_stream_frame(QshoPacket *packet, MIOBufferAccessor &buf_accessor,
            uint64_t length, bool fin, bool new_pns);
    void qsho_process_wait_packet(ink_hrtime);
    void process_ack(ink_hrtime);

    QshoCtrl *qshoctrl;

    /* ============== read & write ====== */
    bool write_finished = false;
    bool ack_finished = false;
    bool stream_closed = false;
    bool sent_finish_notify = false;
    Continuation qsho_con;
    int notify_qsho(int event, void *data);

    uint64_t offset = 0;
    uint64_t total_len;
    /* ============== read only ========= */
    QshoNetHandler *nh;
    EThread    *thread;
    EThread    *qsho_thread;
    int         fd = -1;
    uint64_t     stream_id;
    unsigned char *dst_cid = nullptr;
    int         dst_cid_len;
    char       *src_cid = nullptr;
    int         src_cid_len;
    QshoSecret  secret;

    uint32_t    dst_ip;
    uint16_t    dst_port;
    uint32_t    src_ip;
    uint16_t    src_port;
    struct sockaddr_in    dst_addr;

    unsigned char          *tmp_packet_buf = nullptr;
    Ptr<IOBufferBlock>      net_header;
    struct iphdr           *ipheader = nullptr;
    struct udphdr          *udpheader = nullptr;

    uint64_t retransmit_count = 0;
    uint64_t encrypto_count = 0;

    uint64_t buf_count = 0;

    uint64_t free_count = 0;
    uint64_t total_packet_count = 0;

    uint64_t stream_packet_count = 0;

    uint64_t sent_packet_count = 0;

    void thread_finished();
};


class QshoNetHandler;

class QshoNetProcessor : public Processor
{
public:
  int start(int n_upd_threads, size_t stacksize) override;

  off_t pollCont_offset[64];
  off_t qshoNetHandler_offset[64];
};

extern QshoNetProcessor qshoNet;

// 20 ms slots; 2048 slots  => 40 sec. into the future
#define SLOT_TIME_MSEC 20
#define SLOT_TIME HRTIME_MSECONDS(SLOT_TIME_MSEC)
#define N_SLOTS 2048

constexpr int QSHO_PERIOD    = 9;
constexpr int QSHO_NH_PERIOD = QSHO_PERIOD + 1;

class QshoPacketQueue
{
public:
  QshoPacketQueue() { init(); }

  virtual ~QshoPacketQueue() {}
  int nPackets                 = 0;
  ink_hrtime lastPullLongTermQ = 0;
  Que(QshoPacket, clink) longTermQ;
  Que(QshoPacket, clink) bucket[N_SLOTS];
  ink_hrtime delivery_time[N_SLOTS];
  int now_slot = 0;

  void
  init()
  {
    now_slot       = 0;
    ink_hrtime now = ink_get_hrtime_internal();
    int i          = now_slot;
    int j          = 0;
    while (j < N_SLOTS) {
      delivery_time[i] = now + j * SLOT_TIME;
      i                = (i + 1) % N_SLOTS;
      j++;
    }
  }

  void
  addPacket(QshoPacket *e, ink_hrtime now = 0)
  {
    int before = 0;
    int slot;

/*
*    if (IsCancelledPacket(e)) {
*      e->free();
*      return;
*    }
*/

    nPackets++;

    ink_assert(delivery_time[now_slot]);

    if (e->delivery_time < now)
      e->delivery_time = now;

    ink_hrtime s = e->delivery_time - delivery_time[now_slot];

    if (s < 0) {
      before = 1;
      s      = 0;
    }
    s = s / SLOT_TIME;
    // if s >= N_SLOTS, either we are *REALLY* behind or someone is trying
    // queue packets *WAY* too far into the future.
    // need a thingy to hold packets in a "long-term" slot; then, pull packets
    // from long-term slot whenever you advance.
    if (s >= N_SLOTS - 1) {
      longTermQ.enqueue(e);
      e->in_heap               = 0;
      e->in_the_priority_queue = 1;
      return;
    }
    slot = (s + now_slot) % N_SLOTS;

    // so that slot+1 is still "in future".
    ink_assert((before || delivery_time[slot] <= e->delivery_time) && (delivery_time[(slot + 1) % N_SLOTS] >= e->delivery_time));
    e->in_the_priority_queue = 1;
    e->in_heap               = slot;
    bucket[slot].enqueue(e);
  }

  QshoPacket *
  firstPacket(ink_hrtime t)
  {
    if (t > delivery_time[now_slot]) {
      return bucket[now_slot].head;
    } else {
      return nullptr;
    }
  }

  QshoPacket *
  getFirstPacket()
  {
    nPackets--;
    return dequeue_ready(0);
  }

  int
  size()
  {
    ink_assert(nPackets >= 0);
    return nPackets;
  }

#if 0
  bool
  IsCancelledPacket(QshoPacket *p)
  {
    // discard packets that'll never get sent...
    return ((p->conn->shouldDestroy()) || (p->conn->GetSendGenerationNumber() != p->reqGenerationNum));
  }
#endif

#if 0
  void
  FreeCancelledPackets(int numSlots)
  {
    Queue<QshoPacket> tempQ;
    int i;

    for (i = 0; i < numSlots; i++) {
      int s = (now_slot + i) % N_SLOTS;
      QshoPacket *p;
      while (nullptr != (p = bucket[s].dequeue())) {
#if 0
        if (IsCancelledPacket(p)) {
          p->free();
          continue;
        }
#endif
        tempQ.enqueue(p);
      }
      // remove and flip it over
      while (nullptr != (p = tempQ.dequeue())) {
        bucket[s].enqueue(p);
      }
    }
  }
#endif

//维护本身特性QshoPacketQueue
  void
  advanceNow(ink_hrtime t)
  {
    int s = now_slot;

    //维护longtermQ
    if (ink_hrtime_to_msec(t - lastPullLongTermQ) >= SLOT_TIME_MSEC * ((N_SLOTS - 1) / 2)) {
      Que(QshoPacket, clink) tempQ;
      QshoPacket *p;
      // pull in all the stuff from long-term slot
      lastPullLongTermQ = t;
      // this is to handle weirdness where someone is trying to queue a
      // packet to be sent in SLOT_TIME_MSEC * N_SLOTS * (2+)---the packet
      // will get back to longTermQ and we'll have an infinite loop.
      while ((p = longTermQ.dequeue()) != nullptr)
        tempQ.enqueue(p);
      while ((p = tempQ.dequeue()) != nullptr)
        addPacket(p);
    }

    //维护bucket中的delivery time
    while (!bucket[s].head && (t > delivery_time[s] + SLOT_TIME)) {
      int prev;

      prev             = (s + N_SLOTS - 1) % N_SLOTS;
      delivery_time[s] = delivery_time[prev] + SLOT_TIME;
      s                = (s + 1) % N_SLOTS;
      prev             = (s + N_SLOTS - 1) % N_SLOTS;
      ink_assert(delivery_time[prev] > delivery_time[s]);

      if (s == now_slot) {
        init();
        s = 0;
        break;
      }
    }

    if (s != now_slot)
      Debug("v_udpnet-service", "Advancing by (%d slots): behind by %" PRId64 " ms", s - now_slot,
            ink_hrtime_to_msec(t - delivery_time[now_slot]));
    now_slot = s;
  }

private:
#if 0
  void
  remove(QshoPacket *e)
  {
    nPackets--;
    ink_assert(e->in_the_priority_queue);
    e->in_the_priority_queue = 0;
    bucket[e->in_heap].remove(e);
  }
#endif

public:
  QshoPacket *
  dequeue_ready(ink_hrtime t)
  {
    (void)t;
    QshoPacket *e = bucket[now_slot].dequeue();
    if (e) {
      ink_assert(e->in_the_priority_queue);
      e->in_the_priority_queue = 0;
    }
    advanceNow(t);
    return e;
  }

  void
  check_ready(ink_hrtime now)
  {
    (void)now;
  }

  ink_hrtime
  earliest_timeout()
  {
    int s = now_slot;
    for (int i = 0; i < N_SLOTS; i++) {
      if (bucket[s].head) {
        return delivery_time[s];
      }
      s = (s + 1) % N_SLOTS;
    }
    return HRTIME_FOREVER;
  }
};

class QshoQueue
{
  QshoPacketQueue pipeInfo{};
  ink_hrtime last_report  = 0;
  ink_hrtime last_service = 0;
  int packets             = 0;
  int added               = 0;

public:
  EThread *thread;
  ASLL(QshoPacket, blink) outQueue;

  void service(QshoNetHandler *);

  void SendPackets();
  void SendQshoPacket(QshoPacket *p, int32_t pktLen);

  // Interface exported to the outside world
  void send(QshoPacket *p);

  QshoQueue();
  ~QshoQueue();
};

void initialize_thread_for_qsho_net(EThread *thread);

class QshoNetHandler : public Continuation, public EThread::LoopTailHandler
{
public:
  // engine for outgoing packets
  QshoQueue qshoOutQueue{};
  ASLL(QshoStream, qsho_alink) new_streams;
  Que(QshoStream, qsho_blink) open_streams;
  Que(QshoStream, qsho_callback_link) callbacks;
  Que(QshoStream, tmp_link) removing_qs;

  Event *trigger_event = nullptr;
  EThread *thread      = nullptr;
  ink_hrtime nextCheck;
  ink_hrtime lastCheck;

  uint32_t in_flight_count = 0;
  uint32_t last_in_flight_count = 0;

  uint64_t retransmit_count = 0;
  uint64_t last_retransmit_count = 0;

  void startNetEvent();
  int mainNetEvent(int event, Event *data);

  int waitForActivity(ink_hrtime timeout) override;
  void signalActivity() override;

  //for debug
  uint64_t main_exec_count = 0;
  Continuation debug_con;
  int debugEvent(int event, Event *data);

  char *checksum_buf;
  

  QshoNetHandler();
};

struct PollCont;
static inline PollCont *
get_QshoPollCont(EThread *t)
{
  return static_cast<PollCont *>(ETHREAD_GET_PTR(t, qshoNet.pollCont_offset[t->id]));
}

static inline QshoNetHandler *
get_QshoNetHandler(EThread *t)
{
  return static_cast<QshoNetHandler *>(ETHREAD_GET_PTR(t, qshoNet.qshoNetHandler_offset[t->id]));
}

uintptr_t ngx_http_v3_encode_varlen_int(u_char *p, uint64_t value);
uintptr_t ngx_http_v3_encode_prefix_int(u_char *p, uint64_t value,
    uint64_t prefix);

uintptr_t ngx_http_v3_encode_field_section_prefix(u_char *p, 
    uint64_t insert_count, uint64_t sign, uint64_t delta_base);
uintptr_t ngx_http_v3_encode_field_ri(u_char *p, uint64_t dynamic,
    uint64_t index);
uintptr_t ngx_http_v3_encode_field_lri(u_char *p, uint64_t dynamic,
    uint64_t index, u_char *data, size_t len);
uintptr_t ngx_http_v3_encode_field_l(u_char *p, u_char *name_data,
    uint64_t name_len, u_char *value_data, uint64_t value_len);
uintptr_t ngx_http_v3_encode_field_pbi(u_char *p, uint64_t index);
uintptr_t ngx_http_v3_encode_field_lpbi(u_char *p, uint64_t index,
    u_char *data, size_t len);

size_t ngx_http_v2_huff_encode(u_char *src, size_t len, u_char *dst, uint64_t lower);

#define cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))

#if 0
inline QshoStream::QshoStream(unsigned char *qcid, uint32_t qcid_len, uint64_t qsid,
        uint32_t nginx_worker_id, uint64_t packet_number,
        uint32_t packet_number_len, uint32_t _src_ip, uint32_t _dst_ip,
        uint16_t _src_port, uint16_t _dst_port,
        QshoSecret *input_secret) : VConnection(nullptr)
{
    qsho_thread = eventProcessor.assign_thread(ET_QSHO);
    thread = this_ethread();

    dst_cid_len = qcid_len;
    dst_cid = qcid;
    qcid = nullptr;
    qcid_len = 0;

    stream_id = qsid;
    ngx_worker_id = nginx_worker_id;

    pn = packet_number;
    pn_len = packet_number_len;

    src_ip = _src_ip;
    dst_ip = _dst_ip;
    src_port = _src_port;
    dst_port = _dst_port;

    input_secret->delivery(&secret);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    const int on = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    
    tmp_packet_buf = ats_calloc(1, 4096);

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
    net_header->fill(sizeof(struct iphdr) + sizeof(struct udpheader));

    qsho_con.SET_HANDLER(&QshoStream::notify_qsho);
    SET_HANDLER(&QshoStream::main_handler);

    QshoNetHandler *nh = get_QshoNetHandler(qsho_thread);
    nh->new_streams.push(this);
}
#endif
