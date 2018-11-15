/******************************************************************************

            版权所有 (C), 2017-2018, xxx Co.xxx, Ltd.

 ******************************************************************************
    文 件 名 : ss_config.h
    版 本 号 : V1.0
    作    者 : zc
    生成日期 : 2018年11月15日
    功能描述 : 配置文件解析头文件
    修改历史 :
******************************************************************************/
#ifndef _SS_CONFIG_H_
#define _SS_CONFIG_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SS_MAX_SECTION    50
#define SS_MAX_NAME       50
#define SS_INI_MAX_LINE   200
#define SS_MAX_KNI_LCORE  32

#define SS_CONFIG_NUM     16
#define SS_CONFIG_MAXLEN  64

#define SS_CONFIG_FILE  "dpdk.conf"

extern int ss_argc;
extern char *ss_argv[SS_CONFIG_NUM + 1];

struct ss_queue_cfg {
    uint8_t queue_id;
    uint8_t lcore_id;
};

struct ss_port_cfg {
    char *pci;
    char *name;
    char *pcap;
    int socket_id;
    int port_id;
    int nb_lcores;
    uint16_t lcore_list[RTE_MAX_LCORE];
    int queue_num;
    struct ss_queue_cfg queue[16];
};

struct ss_config {
    char *filename;
    char *core_list;
    char *proc_type;

    int numa_on;
    int nb_channel;
    int promiscuous;
    int ctrl_core_id;           /**< 控制核ID，同时是KNI线程绑定的核 */

    int proc_id;                /**< 当前进程ID，--proc-id = ? */
    int nb_procs;               /**< 运行进程个数 */
    uint16_t proc_core_id;      /**< 当前进程所在逻辑核ID */
    uint16_t *proc_core_list;   /**< 保存所有进程对应逻辑核ID列表 */

    int nb_ports;
    uint16_t max_port_id;
    uint16_t *port_id_list;
    struct ss_port_cfg *port_cfgs;
};

extern struct ss_config g_ss_cfg;

int ss_load_config(int argc, char * const argv[]);

#ifdef __cplusplus
}
#endif

#endif