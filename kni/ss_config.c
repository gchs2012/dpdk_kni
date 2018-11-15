/******************************************************************************

            版权所有 (C), 2017-2018, xxx Co.xxx, Ltd.

 ******************************************************************************
    文 件 名 : ss_config.c
    版 本 号 : V1.0
    作    者 : zc
    生成日期 : 2018年11月15日
    功能描述 : 配置文件解析
    修改历史 :
******************************************************************************/
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <rte_memory.h>
#include <rte_config.h>
#include <rte_string_fns.h>

#include "ss_common.h"
#include "ss_config.h"

#define SS_MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

struct ss_config g_ss_cfg;
int ss_argc;
char *ss_argv[SS_CONFIG_NUM + 1];

const char *ss_short_options = "c:t:p:";
const struct option ss_long_options[] = {
    { "conf", 1, NULL, 'c'},
    { "proc-type", 1, NULL, 't'},
    { "proc-id", 1, NULL, 'p'},
    { 0, 0, 0, 0},
};

typedef int (*ss_conf_handler)(void *user, const char *section,
    const char *name, const char *value);
typedef char * (*ss_conf_reader)(char *str, int num, void *stream);

static char *
ss_rstrip(char *s)
{
    char* p = s + strlen(s);
    while (p > s && isspace((unsigned char)(*--p)))
        *p = '\0';
    return s;
}

static char *
ss_lskip(const char *s)
{
    while (*s && isspace((unsigned char)(*s)))
        s++;
    return (char *)(uintptr_t)s;
}

static char *
ss_find_chars_or_comment(const char *s, const char *chars)
{
    int was_space = 0;
    while (*s && (!chars || !strchr(chars, *s)) &&
           !(was_space && strchr(";", *s))) {
        was_space = isspace((unsigned char)(*s));
        s++;
    }

    return (char*)(uintptr_t)s;
}

static int
ss_uint16_cmp(const void *a, const void *b)
{
    return (*(uint16_t *)(uintptr_t)a - *(uint16_t *)(uintptr_t)b);
}

static inline void
ss_sort_uint16_array(uint16_t arr[], int n)
{
    qsort(arr, n, sizeof(uint16_t), ss_uint16_cmp);
}

static inline char *
ss_strstrip(char *s)
{
    char *end = s + strlen(s) - 1;
    while(*s == ' ') s++;
    for (; end >= s; --end) {
        if (*end != ' ') break;
    }
    *(++end) = '\0';
    return s;
}

static char *
ss_strncpy0(char *dest, const char *src, size_t size)
{
    strncpy(dest, src, size);
    dest[size - 1] = '\0';
    return dest;
}

/*****************************************************************************
    函 数 名 : ss_parse_config_list
    功能描述 : 处理配置列表数据
    输入参数 : uint16_t *arr
               int *sz
               const char *value
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_parse_config_list(uint16_t *arr, int *sz, const char *value)
{
    int i, j;
    char input[4096];
    char *tokens[128];
    int nTokens = 0;
    char *endptr;
    int nr_ele = 0;
    int max_ele = *sz;

    strncpy(input, value, 4096);
    nTokens = rte_strsplit(input, sizeof(input), tokens, 128, ',');
    for (i = 0; i < nTokens; i++) {
        char *tok = tokens[i];
        char *middle = strchr(tok, '-');
        if (middle == NULL) {
            tok = ss_strstrip(tok);
            long v = strtol(tok, &endptr, 10);
            if (*endptr != '\0') {
                printf("%s is not a integer.", tok);
                return 0;
            }
            if (nr_ele > max_ele) {
                printf("too many elements in list %s\n", value);
                return 0;
            }
            arr[nr_ele++] = (uint16_t)v;
        } else {
            *middle = '\0';
            char *lbound = ss_strstrip(tok);
            char *rbound = ss_strstrip(middle+1);
            long lv = strtol(lbound, &endptr, 10);
            if (*endptr != '\0') {
                printf("%s is not a integer.", lbound);
                return 0;
            }
            long rv = strtol(rbound, &endptr, 10);
            if (*endptr != '\0') {
                printf("%s is not a integer.", rbound);
                return 0;
            }
            for (j = lv; j <= rv; ++j) {
                if (nr_ele > max_ele) {
                    printf("too many elements in list %s.\n", value);
                    return 0;
                }
                arr[nr_ele++] = (uint16_t)j;
            }
        }
    }

    if (nr_ele <= 0) {
        printf("list %s is empty\n", value);
        return 1;
    }

    ss_sort_uint16_array(arr, nr_ele);
    *sz = nr_ele;

    return 1;
}

/*****************************************************************************
    函 数 名 : ss_parse_port_lcore_list
    功能描述 : 处理端口对应逻辑核配置
    输入参数 : struct ss_port_cfg *cfg
               const char *v_str
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_parse_port_lcore_list(struct ss_port_cfg *cfg, const char *v_str)
{
    cfg->nb_lcores = RTE_MAX_LCORE;
    uint16_t *cores = cfg->lcore_list;
    return ss_parse_config_list(cores, &cfg->nb_lcores, v_str);
}

/*****************************************************************************
    函 数 名 : ss_port_cfg_handler
    功能描述 : 端口配置处理
    输入参数 : struct ss_config *cfg
               const char *section
               const char *name
               const char *value
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_port_cfg_handler(struct ss_config *cfg, const char *section,
    const char *name, const char *value)
{
    if (cfg->nb_ports == 0) {
        printf("ss_port_cfg_handler: must config port_list first\n");
        return 0;
    }

    if (cfg->port_cfgs == NULL) {
        struct ss_port_cfg *pc = calloc(RTE_MAX_ETHPORTS,
                                        sizeof(struct ss_port_cfg));
        if (pc == NULL) {
            printf("ss port_cfg_handler malloc failed\n");
            return 0;
        }

        int i;
        for (i = 0; i < cfg->nb_ports; i++) {
            uint16_t portid = cfg->port_id_list[i];

            struct ss_port_cfg *pconf = &pc[portid];
            pconf->port_id = portid;
            pconf->nb_lcores = cfg->nb_procs;
            memcpy(pconf->lcore_list, cfg->proc_core_list,
                pconf->nb_lcores * sizeof(uint16_t));
        }
        cfg->port_cfgs = pc;
    }

    int portid;
    int ret = sscanf(section, "port%d", &portid);
    if (ret != 1) {
        printf("ss_port_cfg_handler section[%s] error\n", section);
        return 0;
    }

    if (portid > cfg->max_port_id) {
        printf("ss_port_cfg_handler section[%s] bigger than max port id\n", section);
        return 0;
    }

    struct ss_port_cfg *cur = &cfg->port_cfgs[portid];
    if (cur->name == NULL) {
        cur->port_id = portid;
    }

    if (strcmp(name, "name") == 0) {
        cur->name = strdup(value);
    } else if (strcmp(name, "solt") == 0) {
        cur->pci = strdup(value);
    } else if (strcmp(name, "lcore_list") == 0) {
        return ss_parse_port_lcore_list(cur, value);
    } else if (strcmp(name, "pcap") == 0) {
        cur->pcap = strdup(value);
    }

    return 1;
}

/*****************************************************************************
    函 数 名 : ss_parse_port_list
    功能描述 : 处理端口列表
    输入参数 : struct ss_config *cfg
               const char *v_str
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_parse_port_list(struct ss_config *cfg, const char *v_str)
{
    int res;
    int sz = RTE_MAX_ETHPORTS;
    uint16_t ports[RTE_MAX_ETHPORTS];

    res = ss_parse_config_list(ports, &sz, v_str);
    SS_IF_RETURN_RES(!res, res);

    uint16_t *portid_list = malloc(sz * sizeof(uint16_t));
    if (portid_list == NULL) {
        printf("ss_parse_port_list malloc failed\n");
        return 0;
    }

    memcpy(portid_list, ports, sz * sizeof(uint16_t));
    cfg->nb_ports = sz;
    cfg->port_id_list = portid_list;
    cfg->max_port_id = portid_list[sz-1];

    return res;
}

/*****************************************************************************
    函 数 名 : ss_parse_core_list
    功能描述 : 处理DPDK逻辑核列表
    输入参数 : struct ss_config *cfg
               const char *corelist
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_parse_core_list(struct ss_config *cfg, const char *corelist)
{
    int idx = 0;
    int count = 0;
    char *end = NULL;
    uint16_t *proc_lcore;

    if (corelist == NULL) {
        return 0;
    }

    cfg->proc_core_list = (uint16_t *)calloc(RTE_MAX_LCORE, sizeof(uint16_t));
    if (cfg->proc_core_list == NULL) {
        printf("ss_parse_lcore_list malloc failed\n");
        return 0;
    }
    proc_lcore = cfg->proc_core_list;

    /* Remove all blank characters ahead and after */
    while (isblank(*corelist)) corelist++;
    cfg->core_list = strdup(corelist);

    /* Get list of cores */
    do {
        while (isblank(*corelist)) corelist++;
        if (*corelist == '\0') {
            return 0;
        }

        idx = strtoul(corelist, &end, 10);
        if (end == NULL) {
            return 0;
        }

        while (isblank(*end)) end++;
        if ((*end == ',') || (*end == '\0')) {
            proc_lcore[count] = idx;

            if (cfg->proc_id == count) {
                cfg->proc_core_id = idx;
            }
            count++;
        } else {
            return 0;
        }
        corelist = end + 1;
    } while (*end != '\0');

    if (cfg->proc_id >= count) {
        return 0;
    }

    cfg->nb_procs = count;

    return 1;
}

/*****************************************************************************
    函 数 名 : ss_conf_parse_handler
    功能描述 : 解析配置文件命令
    输入参数 : void *user
               const char *section
               const char *name
               const char *value
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_conf_parse_handler(void *user, const char *section,
    const char *name, const char *value)
{
    struct ss_config *pconfig = (struct ss_config *)user;

    printf("[%s]: %s = %s\n", section, name, value);

    if (SS_MATCH("dpdk", "core_list")) {
        return ss_parse_core_list(pconfig, value);
    } else if (SS_MATCH("dpdk", "numa_on")) {
        pconfig->numa_on = atoi(value);
    } else if (SS_MATCH("dpdk", "channel")) {
        pconfig->nb_channel = atoi(value);
    } else if (SS_MATCH("dpdk", "promiscuous")) {
        pconfig->promiscuous = atoi(value);
    } else if (SS_MATCH("dpdk", "ctrl_core")) {
        pconfig->ctrl_core_id = atoi(value);
    } else if (SS_MATCH("dpdk", "port_list")) {
        return ss_parse_port_list(pconfig, value);
    } else if (strncmp(section, "port", 4) == 0) {
        return ss_port_cfg_handler(pconfig, section, name, value);
    }

    return 1;
}

/*****************************************************************************
    函 数 名 : ss_conf_parse_stream
    功能描述 : 循环读取文件文件
    输入参数 : ss_conf_reader reader
               void *stream
               ss_conf_handler handler
               void *user
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_conf_parse_stream(ss_conf_reader reader, void *stream,
    ss_conf_handler handler, void *user)
{
    char line[SS_INI_MAX_LINE];
    char section[SS_MAX_SECTION] = "";
    char prev_name[SS_MAX_NAME] = "";

    char *start;
    char *end;
    char *name;
    char *value;
    int lineno = 0;
    int error = 0;

    /* Scan through stream line by line */
    while (reader(line, SS_INI_MAX_LINE, stream) != NULL) {
        lineno++;

        start = line;
        if (lineno == 1 && (unsigned char)start[0] == 0xEF &&
                           (unsigned char)start[1] == 0xBB &&
                           (unsigned char)start[2] == 0xBF) {
            start += 3;
        }
        start = ss_lskip(ss_rstrip(start));

        if (*start == ';' || *start == '#') {
            /* Per Python configparser, allow both ; and # comments at the
               start of a line */
        }
        else if (*prev_name && *start && start > line) {
            /* Non-blank line with leading whitespace, treat as continuation
               of previous name's value (as per Python configparser). */
            if (!handler(user, section, prev_name, start) && !error)
                error = lineno;
       }
        else if (*start == '[') {
            /* A "[section]" line */
            end = ss_find_chars_or_comment(start + 1, "]");
            if (*end == ']') {
                *end = '\0';
                ss_strncpy0(section, start + 1, sizeof(section));
                *prev_name = '\0';
            }
            else if (!error) {
                /* No ']' found on section line */
                error = lineno;
            }
        }
        else if (*start) {
            /* Not a comment, must be a name[=:]value pair */
            end = ss_find_chars_or_comment(start, "=:");
            if (*end == '=' || *end == ':') {
                *end = '\0';
                name = ss_rstrip(start);
                value = end + 1;
                end = ss_find_chars_or_comment(value, NULL);
                if (*end)
                    *end = '\0';

                value = ss_lskip(value);
                ss_rstrip(value);

                /* Valid name[=:]value pair found, call handler */
                ss_strncpy0(prev_name, name, sizeof(prev_name));
                if (!handler(user, section, name, value) && !error)
                    error = lineno;
            }
            else if (!error) {
                /* No '=' or ':' found on name[=:]value line */
                error = lineno;
            }
        }

        if (error)
            break;
    }

    return error;
}

/*****************************************************************************
    函 数 名 : ss_conf_parse_file
    功能描述 : 解析配置文件
    输入参数 : FILE* file
               ss_conf_handler handler
               void* user
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_conf_parse_file(FILE* file, ss_conf_handler handler, void* user)
{
    return ss_conf_parse_stream((ss_conf_reader)fgets, file, handler, user);
}

/*****************************************************************************
    函 数 名 : ss_setup_args
    功能描述 : 设置DPDK参数
    输入参数 : struct ss_config *cfg
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_setup_args(struct ss_config *cfg)
{
    int i, n = 0;
    char temp[SS_CONFIG_MAXLEN];

    ss_argv[n++] = strdup("kni");
    sprintf(temp, "-l%s,%d", cfg->core_list, cfg->ctrl_core_id);
    ss_argv[n++] = strdup(temp);
    sprintf(temp, "-n%d", cfg->nb_channel);
    ss_argv[n++] = strdup(temp);
    sprintf(temp, "--proc-type=%s", cfg->proc_type);
    ss_argv[n++] = strdup(temp);

    ss_argc = n;

    for (i = 0; i < n; i++) {
        printf("--> argv[%d] = %s\n", i, ss_argv[i]);
    }

    return n;
}

#define SS_CHECK_VALID(n) do { \
    if (!pc->n) { \
        printf("port%d if config error: no %s\n", pc->port_id, #n); \
        return -1; \
    } \
} while (0)

/*****************************************************************************
    函 数 名 : ss_uint16_binary_search
    功能描述 : 查找是否存在相同数据
    输入参数 : uint16_t arr[]
               int l
               int r
               uint16_t x
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_uint16_binary_search(uint16_t arr[], int l, int r, uint16_t x)
{
    if (r >= l) {
        int mid = l + (r - l)/2;

        // If the element is present at the middle itself
        if (arr[mid] == x)  return mid;

        // If element is smaller than mid, then it can only be present
        // in left subarray
        if (arr[mid] > x) return ss_uint16_binary_search(arr, l, mid-1, x);

        // Else the element can only be present in right subarray
        return ss_uint16_binary_search(arr, mid+1, r, x);
    }

    // We reach here when element is not present in array
    return -1;
}

/*****************************************************************************
    函 数 名 : ss_check_config
    功能描述 : 检查配置
    输入参数 : struct ss_config *cfg
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_check_config(struct ss_config *cfg)
{
    int i, j;

    if (ss_uint16_binary_search(cfg->proc_core_list, 0,
                                cfg->nb_procs - 1,
                                cfg->ctrl_core_id) >= 0) {
        printf("control core %d in proc_core_list %s\n",
            cfg->ctrl_core_id, cfg->core_list);
        return -1;
    }

    for (i = 0; i < cfg->nb_ports; i++) {
        uint16_t portid = cfg->port_id_list[i];
        struct ss_port_cfg *pc = &cfg->port_cfgs[portid];

        SS_CHECK_VALID(name);
        SS_CHECK_VALID(pci);

        for (j = 0; j < pc->nb_lcores; j++) {
            uint16_t lcore_id = pc->lcore_list[j];
            if (ss_uint16_binary_search(cfg->proc_core_list, 0,
                                        cfg->nb_procs - 1,
                                        lcore_id) < 0) {
                printf("lcore %d is not enabled\n", lcore_id);
                return -1;
            }
        }
    }

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_conf_parse
    功能描述 : 解析配置
    输入参数 : const char *filename
               ss_conf_handler handler
               void *user
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_conf_parse(const char *filename, ss_conf_handler handler, void *user)
{
    FILE *file;
    int error;

    file = fopen(filename, "r");
    if (!file) {
        return -1;
    }

    error = ss_conf_parse_file(file, handler, user);
    fclose(file);

    return error;
}

/*****************************************************************************
    函 数 名 : ss_parse_args
    功能描述 : 解析参数命令
    输入参数 : struct ss_config *cfg
               int argc
               char * const argv[]
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static int
ss_parse_args(struct ss_config *cfg, int argc, char * const argv[])
{
    int c;
    int index = 0;
    optind = 1;

     while((c = getopt_long(argc,
                            argv,
                            ss_short_options,
                            ss_long_options,
                            &index)) != -1) {
        switch (c) {
            case 'c':
                cfg->filename = strdup(optarg);
                break;
            case 'p':
                cfg->proc_id = atoi(optarg);
                break;
            case 't':
                cfg->proc_type = strdup(optarg);
                break;
            default:
                return -1;
        }
     }

     if (cfg->proc_type == NULL) {
        cfg->proc_type = strdup("auto");
     }

     if (strcmp(cfg->proc_type, "primary") &&
         strcmp(cfg->proc_type, "secondary") &&
         strcmp(cfg->proc_type, "auto")) {
        printf("invalid proc-type:%s\n", cfg->proc_type);
        return -1;
    }

    if ((uint16_t)cfg->proc_id > RTE_MAX_LCORE) {
        printf("invalid proc_id:%d, use default 0\n", cfg->proc_id);
        cfg->proc_id = 0;
    }

    return 0;
}

/*****************************************************************************
    函 数 名 : ss_default_config
    功能描述 : 设置默认配置
    输入参数 : struct ss_config *cfg
    输出参数 : 无
    返 回 值 : 无
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
static void
ss_default_config(struct ss_config *cfg)
{
    memset(cfg, 0, sizeof(struct ss_config));

    cfg->filename = (char *)(uintptr_t)SS_CONFIG_FILE;

    cfg->proc_id = -1;
    cfg->numa_on = 1;
    cfg->promiscuous = 1;
}

/*****************************************************************************
    函 数 名 : ss_load_config
    功能描述 : 加载配置
    输入参数 : int argc
               char * const argv[]
    输出参数 : 无
    返 回 值 : int
    作    者 : zc
    日    期 : 2018年11月13日
*****************************************************************************/
int
ss_load_config(int argc, char * const argv[])
{
    int ret;

    ss_default_config(&g_ss_cfg);

    ret = ss_parse_args(&g_ss_cfg, argc, argv);
    SS_IF_RETURN_RES(ret < 0, -1);

    ret = ss_conf_parse(g_ss_cfg.filename, ss_conf_parse_handler,
        &g_ss_cfg);
    if (ret != 0) {
        printf("parse %s failed on line %d\n", g_ss_cfg.filename, ret);
        return -1;
    }

    ret = ss_check_config(&g_ss_cfg);
    SS_IF_RETURN_RES(ret < 0, -1);

    ret = ss_setup_args(&g_ss_cfg);
    SS_IF_RETURN_RES(ret <= 0, -1);

    return 0;
}

