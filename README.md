# dpdk kni 多进程多队列

## 配置文件如下所示
```
[dpdk]
core_list = 2
numa_on = 0
channel = 4
promiscuous = 1
ctrl_core = 3
port_list = 0,1

[port0]
name = ens38
solt = 0000:02:06.0
pcap = /tmp/kni_ens38.pcap

[port1]
name = ens34
solt = 0000:02:02.0
pcap = /tmp/kni_ens34.pcap
```
