/******************************************************************************

            版权所有 (C), 2017-2018, xxx Co.xxx, Ltd.

 ******************************************************************************
    文 件 名 : ss_common.h
    版 本 号 : V1.0
    作    者 : zc
    生成日期 : 2018年11月15日
    功能描述 : 公共数据头文件
    修改历史 :
******************************************************************************/
#ifndef _SS_COMMON_H_
#define _SS_COMMON_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PREFETCH_OFFSET         4
#define KNI_ENET_FCS_SIZE       4
#define NB_SOCKETS              8
#define KNI_ENET_HEADER_SIZE    14
#define MAX_RX_QUEUE_PER_LCORE  16
#define MAX_PKT_BURST           32
#define MEMPOOL_CACHE_SIZE      256
#define RX_QUEUE_SIZE           512
#define TX_QUEUE_SIZE           512
#define KNI_QUEUE_SIZE          2048
#define MAX_PACKET_SZ           2048

#define SS_CHECK_INTERVAL       100 /* 100ms */
#define SS_MAX_CHECK_TIME       90  /* 9s (90 * 100ms) in total */

#define SS_IGNORE_PARAM(x)  (void)(x)

#define SS_CTRL_CORE_INIT(v) rte_atomic32_init(v);
#define SS_CTRL_CORE_SUB(v) rte_atomic32_sub(v, 1)
#define SS_CTRL_CORE_INC(v) rte_atomic32_inc(v, 1)
#define SS_CTRL_CORE_READ(v) rte_atomic32_read(v)

#define SS_IF_RETURN(x) \
    if (x) return
#define SS_IF_RETURN_RES(x, v) \
    if (x) return v
#define SS_IF_EXIT_RES(x, v) \
    if (x) exit(v)
#define SS_IF_GOTO_LABLE(x, v) \
    if (x) goto v

enum ss_port_type_e {
    SS_PORT_TYPE_NONE   = 0,
    SS_PORT_TYPE_BYPASS = 1,
    SS_PORT_TYPE_DIRECT = 2,
    SS_PORT_TYPE_MIRROR = 3,
    SS_PORT_TYPE_SWITCH = 4,
    SS_PORT_TYPE_ROUTE  = 5,
    SS_PORT_TYPE_TRUNK  = 6,
    SS_PORT_TYPE_ACCESS = 7,
    SS_PORT_TYPE_MAX,
};

enum ss_pkt_flow_type_e {
    SS_PKT_FLOW_NONE    = 0,
    SS_RECV_FROM_PORT   = 1,
    SS_SEND_TO_KERNEL   = 2,
    SS_RECV_FROM_KERNEL = 3,
    SS_SEND_TO_PORT     = 4,
    SS_PKT_FLOW_MAX,
};

/* Structure type for recording kni interface specific stats */
struct ss_kni_interface_stats {
    struct rte_kni *kni;

    /* number of pkts received from NIC, and sent to KNI */
    uint64_t rx_packets;

    /* number of pkts received from NIC, but failed to send to KNI */
    uint64_t rx_dropped;

    /* number of pkts received from KNI, and sent to NIC */
    uint64_t tx_packets;

    /* number of pkts received from KNI, but failed to send to NIC */
    uint64_t tx_dropped;
} __rte_cache_aligned;

struct mbuf_table {
    unsigned len;
    struct rte_mbuf *m_table[MAX_PKT_BURST];
} __rte_cache_aligned;

struct ss_lcore_rx_queue {
    uint16_t port_id;
    uint16_t queue_id;
} __rte_cache_aligned;

struct ss_lcore_conf {
    int numa_on;
    int promiscuous_on;
    unsigned lcore_id;
    unsigned ctrl_core;

    uint16_t proc_id;
    uint16_t socket_id;
    uint16_t nb_queue_list[RTE_MAX_ETHPORTS];
    struct ss_port_cfg *port_cfgs;

    uint16_t nb_rx_queue;
    struct ss_lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];

    uint16_t nb_tx_port;
    uint16_t tx_port_id[RTE_MAX_ETHPORTS];
    uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
    struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
    char *pcap[RTE_MAX_ETHPORTS];

    int port_eth[RTE_MAX_ETHPORTS];
    int eth_port[RTE_MAX_ETHPORTS];

    struct rte_ring **kni_rp;
    struct ss_kni_interface_stats **kni_stat;
} __rte_cache_aligned;

#ifdef __cplusplus
}
#endif

#endif
