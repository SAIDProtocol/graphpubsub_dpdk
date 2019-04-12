# DPDK Implementation of Graph Pub/Sub and variants  

## Test Environment  
**DPDK:** 18.11 (CONFIG_RTE_LIBRTE_MLX5_PMD=y)  
**CPU:** Intel(R) Xeon(R) CPU E5-2640 v4 @ 2.40GHz  
**NIC:** Mellanox MT27710 Family [ConnectX-4 Lx] on socket 1 (CPUs 10-19).  
**RAM:** 32GB*8 @ 2667MHz  
**OS:** Ubuntu 16.04 with Linux 4.15.0-47-generic.  
**CPU frequency driver/governor:** intel_pstate/performance  
**Other settings:** See [Mellanox NIC’s Performance Report with DPDK 18.11 ](http://fast.dpdk.org/doc/perf/DPDK_18_11_Mellanox_NIC_performance_report.pdf)  
```
GRUB_CMDLINE_LINUX_DEFAULT="default_hugepagesz=1G hugepagesz=1G hugepages=64 isolcpus=10-19 nohz_full=10-19 rcu_nocbs=10-19 rcu_nocb_poll audit=0 nosoftlockup"
```  

## basic  
Basic benchmark.  
* **generator**  
Multi-core packet generator. Allows multiple cores to send to different queues of port 0.  
Tested with ```-l 10-13 -n 4 -w 0000:81:00.0,txq_mpw_en=1,txq_inline=200 --socket-mem=8192```  

* **sink**  
Single-core packet sink.  
Basic function: receive and discard packets.  
Added function: receive, check the source ethernet address and ethernet protocol type, then discard.  

* **forwarder**  
Single-core packet forwarder.  
Rx burst, check packet type then Tx burst.  

* **forwarder_mq**  
3-core packet forwarder.  
1st core for Rx burst, 2nd core for processing, 3rd core for Tx burst.  
The processing takes n-level hanoi (operation count close to 2<sup>n</sup>).  

* **forwarder_mq2**  
2-core packet forwarder. For a fair comparison with forwarder_mq, 3rd core kept idle (sleep, but can drag down the CPU frequency).  
1st core for Rx burst and processing, 2nd core for Tx burst.  
The processing takes n-level hanoi (operation count close to 2<sup>n</sup>).  
**Issue found with the setting:** Even when the processing is very slow, Rx burst does not receive full burst with very high percentage.  

* **hash**  
Test functions on rte_hash.  
**Issue found with the setting:** When performing rte_hash_free_key_with_position(hash, i) (uses RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF), the code frees hash at position (i-1).  
Therefore, it cannot be used with RCU. RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY would be preferred. Can create another array that stores the values. Perform RCU on the value array then.

## gps_i
Graph pub/sub implemented in the information-layer. The network-layer performs unicast and multicast.  

* **include**  
Common headers needed by all the applications . 

* **forwarder**   
Forwarding engine (with RP).  
Using a 4-core solution (Rx, data-plane processing, control-plane processing, Tx) in this particular implementation. It be easily adapted to multi-port scenarios (1 Rx for data-plane processing on each port, 1 control-plane processing, send to multiple Tx queues for each port).

* **sink**  
Application sink, verifies if the content is correctly received, counts received and missed.  

* **generator**  
Application packet generator.  

* **test**  
Test functions.

## gps_n
Graph pub/sub, expanded on each router (in the network-layer).  

## hierarchical_n
Implementation similar to NDN (hierarchical namespace), expanded on each router (in the network-layer).  

