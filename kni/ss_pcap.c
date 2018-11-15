/******************************************************************************

            版权所有 (C), 2017-2018, xxx Co.xxx, Ltd.

 ******************************************************************************
    文 件 名 : ss_pcap.c
    版 本 号 : V1.0
    作    者 : zc
    生成日期 : 2018年11月15日
    功能描述 : 抓包接口实现
    修改历史 :
******************************************************************************/
#include <sys/time.h>
#include <unistd.h>

#include <rte_config.h>
#include <rte_mbuf.h>

#include "ss_pcap.h"

struct pcap_file_header {
    uint32_t magic;
    u_short version_major;
    u_short version_minor;
    int32_t thiszone;        /* gmt to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length saved portion of each pkt */
    uint32_t linktype;       /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
    uint32_t sec;            /* time stamp */
    uint32_t usec;           /* struct timeval time_t, in linux64: 8*2=16, in cap: 4 */
    uint32_t caplen;         /* length of portion present */
    uint32_t len;            /* length this packet (off wire) */
};

/*****************************************************************************
    函 数 名 : ss_enable_pcap
    功能描述 : 使能pcap文件
    输入参数 : const char *dump_path
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
int
ss_enable_pcap(const char *dump_path)
{
    FILE *fp = fopen(dump_path, "w");
    if (fp == NULL) { 
        rte_exit(EXIT_FAILURE, "Cannot open pcap dump path: %s\n", dump_path);
        return -1;
    }

    struct pcap_file_header pcap_file_hdr;
    void *file_hdr = &pcap_file_hdr;

    pcap_file_hdr.magic = 0xA1B2C3D4;
    pcap_file_hdr.version_major = 0x0002;
    pcap_file_hdr.version_minor = 0x0004;
    pcap_file_hdr.thiszone = 0x00000000;
    pcap_file_hdr.sigfigs = 0x00000000;
    pcap_file_hdr.snaplen = 0x0000FFFF;  //65535
    pcap_file_hdr.linktype = 0x00000001; //DLT_EN10MB, Ethernet (10Mb)

    fwrite(file_hdr, sizeof(struct pcap_file_header), 1, fp);
    fclose(fp);

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_dump_packets
    功能描述 : 数据包写入pcap文件
    输入参数 : const char *dump_path
               struct rte_mbuf *pkt
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月15日
*****************************************************************************/
int
ss_dump_packets(const char *dump_path, struct rte_mbuf *pkt)
{
    FILE *fp = fopen(dump_path, "a");
    if (fp == NULL) {
        return -1;
    }

    struct pcap_pkthdr pcap_hdr;
    void *hdr = &pcap_hdr;

    struct timeval ts;
    gettimeofday(&ts, NULL);
    pcap_hdr.sec = ts.tv_sec;
    pcap_hdr.usec = ts.tv_usec;
    pcap_hdr.caplen = pkt->pkt_len;
    pcap_hdr.len = pkt->pkt_len;
    fwrite(hdr, sizeof(struct pcap_pkthdr), 1, fp);

    while(pkt != NULL) {
        fwrite(rte_pktmbuf_mtod(pkt, char*), pkt->data_len, 1, fp);
        pkt = pkt->next;
    }

    fclose(fp);

    return 0;
}

