/******************************************************************************

            版权所有 (C), 2017-2018, xxx Co.xxx, Ltd.

 ******************************************************************************
    文 件 名 : main.c
    版 本 号 : V1.0
    作    者 : zc
    生成日期 : 2018年11月15日
    功能描述 : 数据包收发处理流程，支持多队列
    修改历史 :
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_bus_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>

#include "ss_common.h"
#include "ss_config.h"

static rte_atomic32_t g_ctrl_core;

static struct ss_lcore_conf g_lcore_conf;

static struct rte_mempool *g_pktmbuf_pool[NB_SOCKETS];

static uint8_t ss_default_rsskey_40bytes[40] = {
    0xd1, 0x81, 0xc6, 0x2c, 0xf7, 0xf4, 0xdb, 0x5b,
    0x19, 0x83, 0xa2, 0xfc, 0x94, 0x3e, 0x1a, 0xdb,
    0xd9, 0x38, 0x9e, 0x6b, 0xd1, 0x03, 0x9c, 0x2c,
    0xa7, 0x44, 0x99, 0xad, 0x59, 0x3d, 0x56, 0xd9,
    0xf3, 0x25, 0x3c, 0x06, 0x2a, 0xdc, 0x1f, 0xfc
};

/*****************************************************************************
    函 数 名 : ss_pkt_send_to_port
    功能描述 : 向网卡发包
    输入参数 : uint16_t port_id
               uint16_t queue_id
               struct rte_mbuf **pkts_burst
               uint16_t count
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_pkt_send_to_port(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, uint16_t count)
{
    uint16_t nb_tx;

    nb_tx = rte_eth_tx_burst(port_id, queue_id, pkts_burst, count);
    if (nb_tx < count) {
        uint16_t i;
        for (i = nb_tx; i < count; i++) {
            rte_pktmbuf_free(pkts_burst[i]);
        }
        g_lcore_conf.kni_stat[port_id]->tx_dropped += (count - nb_tx);        
    }

    g_lcore_conf.kni_stat[port_id]->tx_packets += nb_tx;

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_pkt_recv_form_kernel
    功能描述 : 从内核接包
    输入参数 : uint16_t port_id
               uint16_t queue_id
               struct rte_mbuf **pkts_burst
               uint16_t count
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_pkt_recv_form_kernel(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, uint16_t count)
{
    uint16_t nb_kni_rx; 

    SS_IGNORE_PARAM(queue_id);

    /* read packet from kni, and transmit to phy port */
    nb_kni_rx = rte_kni_rx_burst(g_lcore_conf.kni_stat[port_id]->kni,
        pkts_burst, count);

    return nb_kni_rx;
}

/*****************************************************************************
    函 数 名 : ss_pkt_send_to_kernel
    功能描述 : 向内核发包
    输入参数 : uint16_t port_id
               uint16_t queue_id
               struct rte_mbuf **pkts_burst
               uint16_t count
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_pkt_send_to_kernel(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, uint16_t count)
{
    uint16_t nb_tx, nb_kni_tx;

    SS_IGNORE_PARAM(queue_id);

    /* read packet from kni ring(phy port) and transmit to kni */
    nb_tx = rte_ring_dequeue_burst(g_lcore_conf.kni_rp[port_id],
        (void **)pkts_burst, count, NULL);

    /* NB.
     * if nb_tx is 0,it must call rte_kni_tx_burst
     * must Call regularly rte_kni_tx_burst(kni, NULL, 0).
     * detail https://embedded.communities.intel.com/thread/6668
     */
    nb_kni_tx = rte_kni_tx_burst(g_lcore_conf.kni_stat[port_id]->kni,
        pkts_burst, nb_tx);
    if (nb_kni_tx < nb_tx) {
        uint16_t i;
        for (i = nb_kni_tx; i < nb_tx; i++) {
            rte_pktmbuf_free(pkts_burst[i]);
        }
        g_lcore_conf.kni_stat[port_id]->rx_dropped += (nb_tx - nb_kni_tx);
    }

    g_lcore_conf.kni_stat[port_id]->rx_packets += nb_kni_tx;

    rte_kni_handle_request(g_lcore_conf.kni_stat[port_id]->kni);

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_pkt_recv_from_port
    功能描述 : 从网卡接包
    输入参数 : uint16_t port_id
               uint16_t queue_id
               struct rte_mbuf **pkts_burst
               uint16_t count
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_pkt_recv_from_port(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, uint16_t count)
{
    int ret;
    uint16_t i;

    SS_IGNORE_PARAM(queue_id);

    for (i = 0; i < count; i++) {
        struct rte_mbuf *rtem = pkts_burst[i];
        ret = rte_ring_enqueue(g_lcore_conf.kni_rp[port_id], rtem);
        if (ret < 0) {
            rte_pktmbuf_free(rtem);
        }
    }

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_process_packets
    功能描述 : 处理数据包
    输入参数 : int type
               uint16_t port_id
               uint16_t queue_id
               struct rte_mbuf **pkts_burst
               uint16_t count
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_process_packets(int type, uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, uint16_t count)
{
    int ret = 0;

    switch (type) {
        case SS_RECV_FROM_PORT:
            ret = ss_pkt_recv_from_port(port_id, queue_id, pkts_burst, count);
            break;

        case SS_SEND_TO_KERNEL:
            ret = ss_pkt_send_to_kernel(port_id, queue_id, pkts_burst, count);
            break;

        case SS_RECV_FROM_KERNEL:
            ret = ss_pkt_recv_form_kernel(port_id, queue_id, pkts_burst, count);
            break;

        case SS_SEND_TO_PORT:
            ret = ss_pkt_send_to_port(port_id, queue_id, pkts_burst, count);
            break;
    }

    return ret;
}

/*****************************************************************************
    函 数 名 : ss_rxtx_core_process
    功能描述 : 逻辑核处理流程
    输入参数 : unsigned core_id
    输出参数 : 无
    返 回 值 : 无
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static void
ss_logic_core_process(unsigned core_id)
{
    while (SS_CTRL_CORE_READ(&g_ctrl_core) == 0) usleep(100000);

    printf("The logic core(%u) is ready...\n", core_id);

    int i, j, nb_rx;
    uint16_t port_id;
    uint16_t queue_id;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct ss_lcore_conf *qconf = &g_lcore_conf;

    while (1) {
        for (i = 0; i < qconf->nb_rx_queue; i++) {
            port_id = qconf->rx_queue_list[i].port_id;
            queue_id = qconf->rx_queue_list[i].queue_id;

            nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts_burst,
                MAX_PKT_BURST);
            if (nb_rx > 0) {
                /* Prefetch first packets */
                for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
                    rte_prefetch0(rte_pktmbuf_mtod(
                        pkts_burst[j], void *));
                }
                /* Prefetch and handle already prefetched packets */
                for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
                    rte_prefetch0(rte_pktmbuf_mtod(
                        pkts_burst[j + PREFETCH_OFFSET], void *));
                    ss_process_packets(SS_RECV_FROM_PORT,
                        port_id, queue_id, &pkts_burst[j], 1);
                }
                /* Handle remaining prefetched packets */
                for (; j < nb_rx; j++) {
                    ss_process_packets(SS_RECV_FROM_PORT,
                        port_id, queue_id, &pkts_burst[j], 1);
                }
            }

            if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
                ss_process_packets(SS_SEND_TO_KERNEL,
                    port_id, queue_id, pkts_burst, MAX_PKT_BURST);

                nb_rx = ss_process_packets(SS_RECV_FROM_KERNEL,
                    port_id, queue_id, pkts_burst, MAX_PKT_BURST);
                if (nb_rx > 0) {
                    ss_process_packets(SS_SEND_TO_PORT,
                        port_id, queue_id, pkts_burst, nb_rx);
                }
            }
        }
    }
}

/*****************************************************************************
    函 数 名 : ss_ctrl_core_process
    功能描述 : 控制核处理流程
    输入参数 : unsigned core_id
    输出参数 : 无
    返 回 值 : 无
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static void
ss_ctrl_core_process(unsigned core_id)
{
    printf("The control core(%u) is ready...\n", core_id);

    SS_CTRL_CORE_SUB(&g_ctrl_core);

    while (1) {
        sleep(10);
    }
}

/*****************************************************************************
    函 数 名 : ss_main_loop
    功能描述 : 数据包收发流程
    输入参数 : __rte_unused void *arg
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_main_loop(__rte_unused void *arg)
{
    unsigned lcore_id = rte_lcore_id();

    if (lcore_id == g_lcore_conf.ctrl_core) {
        ss_ctrl_core_process(lcore_id);
    } else if (lcore_id == g_lcore_conf.lcore_id) {
        ss_logic_core_process(lcore_id);
    } else {
        printf("This core(%u) is not used!\n", lcore_id);
    }

	return 0;
}

/*****************************************************************************
    函 数 名 : ss_check_all_ports_link_status
    功能描述 : 检测网卡链路状态
    输入参数 : 无
    输出参数 : 无
    返 回 值 : 无
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static void
ss_check_all_ports_link_status(void)
{
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status\n");
	fflush(stdout);

    int i, nb_ports;
    nb_ports = g_ss_cfg.nb_ports;
	for (count = 0; count <= SS_MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
        for (i = 0; i < nb_ports; i++) {
            uint16_t portid = g_ss_cfg.port_id_list[i];
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);

			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status) {
					printf("Port %d Link Up - speed %uMbps - %s\n",
						portid, link.link_speed,
						(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
						("full-duplex") : ("half-duplex\n"));
				} else {
					printf("Port %d Link Down\n", portid);
		        }
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}

		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(SS_CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (SS_MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

/*****************************************************************************
    函 数 名 : ss_set_rss_table
    功能描述 : 设置网卡RSS表
    输入参数 : uint16_t port_id
               uint16_t reta_size
               uint16_t nb_queues
    输出参数 : 无
    返 回 值 : 无
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static void
ss_set_rss_table(uint16_t port_id, uint16_t reta_size, uint16_t nb_queues)
{
    if (reta_size == 0) {
        return;
    }

    int reta_conf_size = RTE_MAX(1, reta_size / RTE_RETA_GROUP_SIZE);
    struct rte_eth_rss_reta_entry64 reta_conf[reta_conf_size];

    /* config HW indirection table */
    int i, j;
    unsigned hash = 0;
    for (i = 0; i < reta_conf_size; i++) {
        reta_conf[i].mask = ~0ULL;
        for (j = 0; j < RTE_RETA_GROUP_SIZE; j++) {
            reta_conf[i].reta[j] = hash++ % nb_queues;
        }
    }

    if (rte_eth_dev_rss_reta_update(port_id, reta_conf, reta_size)) {
        rte_exit(EXIT_FAILURE, "port[%d], failed to update rss table\n",
            port_id);
    }
}

/*****************************************************************************
    函 数 名 : ss_init_port_start
    功能描述 : 初始化端口
    输入参数 : 无
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_init_port_start(void)
{
    int nb_ports = g_ss_cfg.nb_ports;
    unsigned socketid = 0;
    struct rte_mempool *mbuf_pool;
    uint16_t i;

    for (i = 0; i < nb_ports; i++) {
        uint16_t port_id = g_ss_cfg.port_id_list[i];
        struct ss_port_cfg *pc = &g_ss_cfg.port_cfgs[port_id];
        uint16_t nb_queues = pc->nb_lcores;

        struct rte_eth_dev_info dev_info;
        rte_eth_dev_info_get(port_id, &dev_info);

        if (nb_queues > dev_info.max_rx_queues) {
            rte_exit(EXIT_FAILURE, "num_procs[%d] bigger than "
                "max_rx_queues[%d]\n", nb_queues, dev_info.max_rx_queues);
        }

        if (nb_queues > dev_info.max_tx_queues) {
            rte_exit(EXIT_FAILURE, "num_procs[%d] bigger than "
                "max_tx_queues[%d]\n", nb_queues, dev_info.max_tx_queues);
        }

        struct ether_addr addr;
        rte_eth_macaddr_get(port_id, &addr);
        printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
            " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            (unsigned)port_id,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

        /* Clear txq_flags - we do not need multi-mempool and refcnt */
        dev_info.default_txconf.txq_flags = ETH_TXQ_FLAGS_NOMULTMEMP |
            ETH_TXQ_FLAGS_NOREFCOUNT;
        
        /* Disable features that are not supported by port's HW */
        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMUDP;
        }
        
        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMTCP;
        }
        
        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_SCTP_CKSUM)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMSCTP;
        }
        
        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOVLANOFFL;
        }
        
        if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_TSO) &&
            !(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_TSO)) {
            dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOMULTSEGS;
        }

        struct rte_eth_conf port_conf;

        memset(&port_conf, 0, sizeof(struct rte_eth_conf));
        port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_PROTO_MASK;
        port_conf.rx_adv_conf.rss_conf.rss_key = ss_default_rsskey_40bytes;
        port_conf.rx_adv_conf.rss_conf.rss_key_len = 40;

        /* Enable HW CRC stripping */
        port_conf.rxmode.hw_strip_crc = 1;

        /* Set Rx checksum checking */
        if ((dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) &&
            (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM) &&
            (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM)) {
            printf("RX checksum offload supported\n");
            port_conf.rxmode.hw_ip_checksum = 1;
        }

        if (dev_info.reta_size) {
            /* reta size must be power of 2 */
            assert((dev_info.reta_size & (dev_info.reta_size - 1)) == 0);

            printf("port[%d]: rss table size: %d\n", port_id,
                dev_info.reta_size);
        }

        if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
            continue;
        }

        int ret = rte_eth_dev_configure(port_id, nb_queues, nb_queues,
            &port_conf);
        SS_IF_RETURN_RES(ret != 0, -1);

        uint16_t j;
        for (j = 0; j < nb_queues; j++) {
            if (g_lcore_conf.numa_on) {
                uint16_t lcore_id =
                    g_lcore_conf.port_cfgs[port_id].lcore_list[j];
                socketid = rte_lcore_to_socket_id(lcore_id);
            }
            mbuf_pool = g_pktmbuf_pool[socketid];

            ret = rte_eth_rx_queue_setup(port_id, j, RX_QUEUE_SIZE,
                socketid, &dev_info.default_rxconf, mbuf_pool);
            SS_IF_RETURN_RES(ret < 0, -1);

            ret = rte_eth_tx_queue_setup(port_id, j, TX_QUEUE_SIZE,
                socketid, &dev_info.default_txconf);
            SS_IF_RETURN_RES(ret < 0, -1);
        }

        ret = rte_eth_dev_start(port_id);
        SS_IF_RETURN_RES(ret < 0, -1);

        if (nb_queues > 1) {
            /* set HW rss hash function to Toeplitz. */
            if (!rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_HASH)) {
                struct rte_eth_hash_filter_info info = {0};
                info.info_type = RTE_ETH_HASH_FILTER_GLOBAL_CONFIG;
                info.info.global_conf.hash_func = RTE_ETH_HASH_FUNCTION_TOEPLITZ;
        
                if (rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH,
                    RTE_ETH_FILTER_SET, &info) < 0) {
                    rte_exit(EXIT_FAILURE, "port[%d] set hash func failed\n",
                        port_id);
                }
            }
            ss_set_rss_table(port_id, dev_info.reta_size, nb_queues);
        }

        if (g_lcore_conf.promiscuous_on) {
            rte_eth_promiscuous_enable(port_id);
            ret = rte_eth_promiscuous_get(port_id);
            if (ret == 1) {
                printf("set port %u to promiscuous mode ok\n", port_id);
            } else {
                printf("set port %u to promiscuous mode error\n", port_id);
            }
        }
    }

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        ss_check_all_ports_link_status();
    }

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_print_ethaddr
    功能描述 : 打印MAC地址
    输入参数 : const char *name
               struct ether_addr *mac_addr
    输出参数 : 无
    返 回 值 : 无
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static void
ss_print_ethaddr(const char *name, struct ether_addr *mac_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, mac_addr);
	RTE_LOG(INFO, KNI, "\t%s%s\n", name, buf);
}

/*****************************************************************************
    函 数 名 : ss_kni_config_mac_address
    功能描述 : 设置网卡MAC地址
    输入参数 : uint16_t port_id
               uint8_t mac_addr[]
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[])
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, KNI, "Configure mac address of %d\n", port_id);
	ss_print_ethaddr("Address:", (struct ether_addr *)mac_addr);

	ret = rte_eth_dev_default_mac_addr_set(port_id,
					       (struct ether_addr *)mac_addr);
	if (ret < 0)
		RTE_LOG(ERR, KNI, "Failed to config mac_addr for port %d\n",
			port_id);

	return ret;
}

/*****************************************************************************
    函 数 名 : ss_kni_config_network_interface
    功能描述 : 设置网卡状态
    输入参数 : uint16_t port_id
               uint8_t if_up
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, KNI, "Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);

	if (ret < 0)
		RTE_LOG(ERR, KNI, "Failed to start port %d\n", port_id);

	return ret;
}

/*****************************************************************************
    函 数 名 : ss_kni_change_mtu
    功能描述 : 设置网卡MTU
    输入参数 : uint16_t port_id
               unsigned int new_mtu
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
    SS_IGNORE_PARAM(port_id);
    SS_IGNORE_PARAM(new_mtu);

	return 0;
}

/*****************************************************************************
    函 数 名 : ss_kni_alloc
    功能描述 : 创建KNI
    输入参数 : uint16_t port_id
               unsigned socket_id
               struct rte_mempool *mbuf_pool
               unsigned ring_queue_size
    输出参数 : 无
    返 回 值 : 无
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static void
ss_kni_alloc(uint16_t port_id, unsigned socket_id,
    struct rte_mempool *mbuf_pool, unsigned ring_queue_size)
{
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        struct rte_kni_conf conf;
        struct rte_kni_ops ops;
		struct rte_eth_dev_info dev_info;
		const struct rte_pci_device *pci_dev;
		const struct rte_bus *bus = NULL;

        g_lcore_conf.kni_stat[port_id] =
            (struct ss_kni_interface_stats *)rte_zmalloc(
                "kni:stat_lcore",
                sizeof(struct ss_kni_interface_stats),
                RTE_CACHE_LINE_SIZE);
        if (g_lcore_conf.kni_stat[port_id] == NULL) {
            rte_exit(EXIT_FAILURE, "rte_zmalloc kni_interface_stats failed\n");
        }

        memset(&conf, 0, sizeof(conf));
        snprintf(conf.name, RTE_KNI_NAMESIZE, "%s",
            g_ss_cfg.port_cfgs[port_id].name);
        conf.core_id = g_ss_cfg.ctrl_core_id;
        conf.force_bind = 1;
        conf.group_id = port_id;
        uint16_t mtu;
        rte_eth_dev_get_mtu(port_id, &mtu);
        conf.mbuf_size = mtu + KNI_ENET_HEADER_SIZE + KNI_ENET_FCS_SIZE;

		memset(&dev_info, 0, sizeof(dev_info));
		rte_eth_dev_info_get(port_id, &dev_info);
		if (dev_info.device) {
			bus = rte_bus_find_by_device(dev_info.device);
        }
		if (bus && !strcmp(bus->name, "pci")) {
			pci_dev = RTE_DEV_TO_PCI(dev_info.device);
			conf.addr = pci_dev->addr;
			conf.id = pci_dev->id;
		}

		/* Get the interface default mac address */
		rte_eth_macaddr_get(port_id,
		    (struct ether_addr *)&conf.mac_addr);

		memset(&ops, 0, sizeof(ops));
		ops.port_id = port_id;
		ops.change_mtu = ss_kni_change_mtu;
		ops.config_network_if = ss_kni_config_network_interface;
		ops.config_mac_address = ss_kni_config_mac_address;

		g_lcore_conf.kni_stat[port_id]->kni = rte_kni_alloc(
		    mbuf_pool, &conf, &ops);
		if (g_lcore_conf.kni_stat[port_id]->kni == NULL) {
            rte_exit(EXIT_FAILURE, "create kni on port %u failed!\n",
                port_id);
		} else {
            printf("create kni on port %u success!\n", port_id);
		}

		g_lcore_conf.kni_stat[port_id]->rx_packets = 0;
		g_lcore_conf.kni_stat[port_id]->rx_dropped = 0;
		g_lcore_conf.kni_stat[port_id]->tx_packets = 0;
		g_lcore_conf.kni_stat[port_id]->tx_dropped = 0;
    }

    char ring_name[RTE_KNI_NAMESIZE];
    snprintf(ring_name, sizeof(ring_name), "kni_ring_%u", port_id);

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        g_lcore_conf.kni_rp[port_id] = rte_ring_create(
            ring_name, ring_queue_size, socket_id, RING_F_SC_DEQ);
        if (rte_ring_lookup(ring_name) != g_lcore_conf.kni_rp[port_id]) {
            rte_exit(EXIT_FAILURE, "lookup kni ring failed!\n");
        }
    } else {
        g_lcore_conf.kni_rp[port_id] = rte_ring_lookup(ring_name);
    }

    if (g_lcore_conf.kni_rp[port_id] == NULL) {
        rte_exit(EXIT_FAILURE, "create kni ring failed!\n");
    } else {
        printf("create kni ring success, %u ring entries are now free!\n",
            rte_ring_free_count(g_lcore_conf.kni_rp[port_id]));
    }
}

/*****************************************************************************
    函 数 名 : ss_init_kni
    功能描述 : 初始化KNI
    输入参数 : 无
    输出参数 : 无
    返 回 值 : int 
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_init_kni(void)
{
    uint16_t nb_ports = rte_eth_dev_count_avail();

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        g_lcore_conf.kni_stat = rte_zmalloc("kni:stat",
            sizeof(struct ss_kni_interface_stats *) * nb_ports,
            RTE_CACHE_LINE_SIZE);
        if (g_lcore_conf.kni_stat == NULL) {
            rte_exit(EXIT_FAILURE, "rte_zmalloc(1 (struct netio_kni_stat *)) "
                "failed\n");
        }

        rte_kni_init(nb_ports);
    }

    uint16_t lcore_id = rte_lcore_id();
    char name_buf[RTE_RING_NAMESIZE];
    snprintf(name_buf, sizeof(name_buf), "kni::ring_%d", lcore_id);
    g_lcore_conf.kni_rp = rte_zmalloc(name_buf,
        sizeof(struct rte_ring *) * nb_ports,
        RTE_CACHE_LINE_SIZE);
    if (g_lcore_conf.kni_rp == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (struct rte_ring*)) "
            "failed\n", name_buf);
    }

    unsigned socket_id = g_lcore_conf.socket_id;
    struct rte_mempool *mbuf_pool = g_pktmbuf_pool[socket_id];

    int i;
    nb_ports = g_ss_cfg.nb_ports;
    for (i = 0; i < nb_ports; i++) {
        uint16_t port_id = g_ss_cfg.port_id_list[i];
        ss_kni_alloc(port_id, socket_id, mbuf_pool, KNI_QUEUE_SIZE);
    }

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_init_mem_pool
    功能描述 : 初始化内存池
    输入参数 : 无
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_init_mem_pool(void)
{
    uint8_t nb_ports = g_ss_cfg.nb_ports;
    uint32_t nb_lcores = g_ss_cfg.nb_procs;
    uint32_t nb_tx_queue = nb_lcores;
    uint32_t nb_rx_queue = g_lcore_conf.nb_rx_queue * nb_lcores;

    unsigned nb_mbuf = RTE_MAX(
        (nb_rx_queue * RX_QUEUE_SIZE            +
         nb_ports * nb_lcores * MAX_PKT_BURST   +
         nb_ports * nb_tx_queue * TX_QUEUE_SIZE +
         nb_lcores * MEMPOOL_CACHE_SIZE), (unsigned)8192);

    unsigned socketid = 0;
    uint16_t i, lcore_id;
    char s[128];

    for (i = 0; i < g_ss_cfg.nb_procs; i++) {
        lcore_id = g_ss_cfg.proc_core_list[i];
        if (g_lcore_conf.numa_on) {
            socketid = rte_lcore_to_socket_id(lcore_id);
        }

        if (socketid >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out "
                "of range %d\n", socketid, i, NB_SOCKETS);
        }
    }

    if (g_pktmbuf_pool[socketid] == NULL) {
        if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            g_pktmbuf_pool[socketid] =
                rte_pktmbuf_pool_create(s, nb_mbuf,
                    MEMPOOL_CACHE_SIZE, 0,
                    RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
        } else {
            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            g_pktmbuf_pool[socketid] = rte_mempool_lookup(s);
        }
    }

    if (g_pktmbuf_pool[socketid] == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool on socket %d\n",
            socketid);
    } else {
        printf("Create mbuf pool on socket %d success\n", socketid);
    }

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_init_lcore_conf
    功能描述 : 初始化lcore_conf
    输入参数 : 无
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_init_lcore_conf(void)
{
	uint16_t nb_dev_ports = rte_eth_dev_count_avail();
	if (nb_dev_ports == 0) {
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");
    }

    if (g_ss_cfg.max_port_id >= nb_dev_ports) {
        rte_exit(EXIT_FAILURE, "this machine doesn't have port %d.\n",
            g_ss_cfg.max_port_id);
    }

    g_lcore_conf.numa_on = g_ss_cfg.numa_on;
    g_lcore_conf.proc_id = g_ss_cfg.proc_id;
    g_lcore_conf.port_cfgs = g_ss_cfg.port_cfgs;
    g_lcore_conf.ctrl_core = g_ss_cfg.ctrl_core_id;
    g_lcore_conf.promiscuous_on = g_ss_cfg.promiscuous;

    uint16_t proc_id;
    for (proc_id = 0; proc_id < g_ss_cfg.nb_procs; proc_id++) {
        uint16_t lcore_id = g_ss_cfg.proc_core_list[proc_id];
        if (!lcore_config[lcore_id].detected) {
            rte_exit(EXIT_FAILURE, "lcore %u unavailable\n", lcore_id);
        }
    }

    uint16_t socket_id = 0;
    if (g_lcore_conf.numa_on) {
        socket_id = rte_lcore_to_socket_id(rte_lcore_id());
    }
    g_lcore_conf.socket_id = socket_id;

    uint16_t lcore_id = g_ss_cfg.proc_core_list[g_lcore_conf.proc_id];
    g_lcore_conf.lcore_id = lcore_id;
    int j;
    for (j = 0; j < g_ss_cfg.nb_ports; j++) {
        uint16_t port_id = g_ss_cfg.port_id_list[j];
        struct ss_port_cfg *pc = &g_ss_cfg.port_cfgs[port_id];

        int i;
        int queueid = -1;
        for (i = 0; i < pc->nb_lcores; i++) {
            if (pc->lcore_list[i] == lcore_id) {
                queueid = i;
            }
        }
        if (queueid < 0) {
            continue;
        }
        printf("lcore: %u, port: %u, queue: %u\n", lcore_id, port_id, queueid);
        uint16_t nb_rx_queue = g_lcore_conf.nb_rx_queue;
        g_lcore_conf.rx_queue_list[nb_rx_queue].port_id = port_id;
        g_lcore_conf.rx_queue_list[nb_rx_queue].queue_id = queueid;
        g_lcore_conf.nb_rx_queue++;

        g_lcore_conf.tx_queue_id[port_id] = queueid;
        g_lcore_conf.tx_port_id[g_lcore_conf.nb_tx_port] = port_id;
        g_lcore_conf.nb_tx_port++;

        g_lcore_conf.pcap[port_id] = pc->pcap;
        g_lcore_conf.nb_queue_list[port_id] = pc->nb_lcores;
    }

    if (g_lcore_conf.nb_rx_queue == 0) {
        rte_exit(EXIT_FAILURE, "lcore %u has nothing to do\n", lcore_id);
    }

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_init_dpdk
    功能描述 : 初始化DPDK
    输入参数 : int argc
               char **argv
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_init_dpdk(int argc, char **argv)
{
    int ret;

    if (g_ss_cfg.nb_procs < 1 ||
        g_ss_cfg.nb_procs > RTE_MAX_LCORE ||
        g_ss_cfg.proc_id >= g_ss_cfg.nb_procs ||
        g_ss_cfg.proc_id < 0) {
        rte_exit(EXIT_FAILURE,
            "param num_procs[%d] or proc_id[%d] error!\n",
            g_ss_cfg.nb_procs, g_ss_cfg.proc_id);
    }

    SS_CTRL_CORE_INIT(&g_ctrl_core);

	/* Initialise EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
    }

    ss_init_lcore_conf();

    ss_init_mem_pool();

    ss_init_kni();

    ret = ss_init_port_start();
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "init_port_start failed\n");
    }

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_exec_shell_cmd
    功能描述 : 执行命令
    输入参数 : const char *cmd
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_exec_shell_cmd(const char *cmd)
{
    FILE *fd;

    fd = popen(cmd, "r");
    if (fd == NULL) {
        printf("exec shell command: '%s' failed\n", cmd);
        return -1;
    }

    pclose(fd);

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_init_port_pci
    功能描述 : 初始化接口PCI
    输入参数 : 无
    输出参数 : 无
    返 回 值 : 无
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static void
ss_init_port_pci(void)
{
    int i;
    char cmd[128];
    struct ss_config *cfg = &g_ss_cfg;

    for (i = 0; i < cfg->nb_ports; i++) {
        snprintf(cmd, sizeof(cmd),
                 "/usr/sbin/ifconfig %s down >/dev/null 2>&1",
                 cfg->port_cfgs[i].name);
        if (ss_exec_shell_cmd(cmd) < 0) {
            rte_exit(EXIT_FAILURE,
                "exec shell command: '%s' failed\n", cmd);
        }

        snprintf(cmd, sizeof(cmd),
                 "/usr/sbin/dpdk-devbind.py --bind=igb_uio %s >/dev/null 2>&1",
                 cfg->port_cfgs[i].pci);
        if (ss_exec_shell_cmd(cmd) < 0) {
            rte_exit(EXIT_FAILURE,
                "exec shell command: '%s' failed\n", cmd);
        }
    }
}

/*****************************************************************************
    函 数 名 : ss_init_port_map
    功能描述 : 初始化端口列表
    输入参数 : 无
    输出参数 : 无
    返 回 值 : 无
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static void
ss_init_port_map(void)
{
    int i;

    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        g_lcore_conf.port_eth[i] = -1;
        g_lcore_conf.eth_port[i] = -1;
    }

    for (i = 0; i < g_ss_cfg.nb_ports; i++) {
        int port_id, eth_id;
        char eth_buf[10] = {0};
        port_id = g_ss_cfg.port_cfgs[i].port_id;

        #define SS_ETH_MATCH(prefix, n) \
            !strncmp(g_ss_cfg.port_cfgs[i].name, prefix, n)
        if (SS_ETH_MATCH("eth", 3) ||
            SS_ETH_MATCH("ens", 3)) {
            sscanf(g_ss_cfg.port_cfgs[i].name, "%*[^a-z]%s", eth_buf);
            eth_id = atoi(eth_buf);
        } else {
            rte_exit(EXIT_FAILURE, "port name %s not support\n",
                g_ss_cfg.port_cfgs[i].name);
        }
        g_lcore_conf.port_eth[eth_id] = port_id;
        g_lcore_conf.eth_port[port_id] = eth_id;
    }
}

/*****************************************************************************
    函 数 名 : ss_init
    功能描述 : 初始化
    输入参数 : int argc
               char * const argv[]
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
static int
ss_init(int argc, char * const argv[])
{
    int ret;

    ret = ss_load_config(argc, argv);
    SS_IF_EXIT_RES(ret < 0, 1);

    ss_init_port_map();

    ss_init_port_pci();

    ret = ss_init_dpdk(ss_argc, (char **)&ss_argv);
    SS_IF_EXIT_RES(ret < 0, 1);

    return 0;
}

/*****************************************************************************
    函 数 名 : main
    功能描述 : 主函数
    输入参数 : int argc
               char * const argv[]
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
int
main(int argc, char * const argv[])
{
	int ret;

    ret = ss_init(argc, argv);
    SS_IF_RETURN_RES(ret < 0, 1);

	/* Launch per-lcore function on every lcore */
	rte_eal_mp_remote_launch(ss_main_loop, NULL, CALL_MASTER);
    rte_eal_mp_wait_lcore();

	return 0;
}
