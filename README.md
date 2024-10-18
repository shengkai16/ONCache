# ONCache
ONCache (**O**verlay **N**etwork **Cache**) is a container overlay network featuring a cache-based and low-overhead fast path. 
With ONCache, containers attain network performance akin to that of bare metal while maintaining network flexibility and compatibility. 
ONCache can be seamlessly integrated into existing standard overlay networks and has been tested with [Antrea](https://github.com/antrea-io/antrea) and [Flannel](https://github.com/flannel-io/flannel).

Our [NSDI'25 paper](https://shengkai16.github.io/assets/pdf/ONCache-nsdi25.pdf) describes the technical details of ONCache.

## In this repo
This repo includes all the code and scripts that are required to run ONCache.

`common` folder includes the frequently used definitions in the C++ code and Makefiles.

`headers` folder includes the header files.

`rpeer_kernel_patch` folder is the kernel source code that are modified to support `bpf_redirect_rpeer`. The modification is based on Linux kernel 5.14. The main modification is in `filter.c`. You can search `rpeer` to see the detail. 

`scripts` includes the scripts to provision a simple kubernetes cluster and to run a iperf3/netperf test.

`tc_prog` and `user_prog` include the source code of the eBPF programs and the user space programs of ONCache.

`libbpf` and `yaml-cpp` are the submodules included in the repo, and are used in compiling.
## Tutorial to try ONCache
Before the start of the tutorial, you should prepare two hosts (e.g. VM or cloud server), with Linux kernel verion>=v5.13 . Our tutorial has been tested on Ubuntu 20.04, with Linux kernel v5.14.

### Step0: Clone this repo on all the hosts
The repo includes libbpf and yaml-cpp as submodules, and should be cloned at the same time.
```
git clone --recurse-submodules https://github.com/shengkai16/ONCache.git ~/ONCache
```

### Step1: Provision a container cluster
The Kubernetes is the most common container orchestrater. We take Kubernetes as an example in this tutorial. We have prepared a script that helps to provision a simple Kubernetes cluster with two nodes. You should first install docker, kubeadm, kubelet, and kubectl on all of your hosts. You can reference to these pages: 

> [Install docker using the script](https://docs.docker.com/engine/install/ubuntu/#install-using-the-convenience-script) \
[Installing kubeadm, kubelet and kubectl](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl)

Then, run the script **only on the master node** to provision a two-node kubernetes cluster with Antrea as the CNI. Note that some environment varibles in the script should be modified to match your testbed. 

```
cd ~/ONCache/scripts; bash ./provision.sh
```

### Step2: Install Compilation Requirements
```
sudo apt install -y -qq clang llvm libelf-dev libpcap-dev gcc-multilib build-essential cmake python3 >/dev/null
```

### Step3: Compile ONCache
ONCache should be compiled on all the hosts.
```
make all -C ~/ONCache
```

### Step4: Start the ONCache daemon. 
To use ONCache, you can simply run the daemon.py on all the hosts to start the ONCache daemon. And the daemon will attach the eBPF program on all of the containers. Remember to change the NODE_IFNAME and POD_IFNAME to that of your testbed in daemon.py. **Skip this step to use the standard overlay network (Antrea in this tutorial).**
```
cd ~/ONCache/user_prog/; sudo python3 daemon.py
```

### Step5: Run iperf3/netperf tests
To do the performance test, we prepare a script to provision a test server and a client on the two hosts. Run the following commands **only on the master node**:
```
cd ~/ONCache/scripts; bash ./netperf_test.sh
```
On the return of the script, it prints the privision result of the two container.
```
ubuntu@node-0:~$ cd ~/ONCache/scripts; bash ./netperf_test.sh
some outputs...
+ kubectl get pods -owide
NAME          READY   STATUS    RESTARTS   AGE   IP          NODE    NOMINATED NODE   READINESS GATES
test-client   1/1     Running   0          5s    10.10.1.2   node2   <none>           <none>
test-server   1/1     Running   0          6s    10.10.0.4   node1   <none>           <none>
```

Then you can run iperf3 test on the containers:
```
kubectl exec -it test-server -- iperf3 -s
# On another terminal
kubectl exec -it test-client -- iperf3 -l1M -c <test-server-ip>
```
Or the netperf test:
```
kubectl exec -it test-server -- netserver -D
# On another terminal
kubectl exec -it test-client -- netperf -t TCP_RR -H <test-server-ip>
```

## Results
Here are our experiment results in the tutorial.

### ONCache
```
ubuntu@node-0:~# kubectl exec -it test-client -- iperf3 -l1M -c 10.10.0.30
Connecting to host 10.10.0.30, port 5201
[  5] local 10.10.1.29 port 37960 connected to 10.10.0.30 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  4.25 GBytes  36.5 Gbits/sec  118   3.11 MBytes
[  5]   1.00-2.00   sec  4.55 GBytes  39.0 Gbits/sec   58   2.66 MBytes
[  5]   2.00-3.00   sec  4.13 GBytes  35.5 Gbits/sec  151   4.11 MBytes
[  5]   3.00-4.00   sec  4.30 GBytes  36.9 Gbits/sec  265   1.93 MBytes
[  5]   4.00-5.00   sec  4.55 GBytes  39.1 Gbits/sec  116    999 KBytes
[  5]   5.00-6.00   sec  4.23 GBytes  36.3 Gbits/sec  206   2.56 MBytes
[  5]   6.00-7.00   sec  4.56 GBytes  39.1 Gbits/sec  100   2.93 MBytes
[  5]   7.00-8.00   sec  4.43 GBytes  38.0 Gbits/sec   14   3.00 MBytes
[  5]   8.00-9.00   sec  4.31 GBytes  37.0 Gbits/sec    0   3.02 MBytes
[  5]   9.00-10.00  sec  4.00 GBytes  34.4 Gbits/sec  200   2.31 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  43.3 GBytes  37.2 Gbits/sec  1228             sender
[  5]   0.00-10.00  sec  43.3 GBytes  37.2 Gbits/sec                  receiver

iperf Done.

ubuntu@node-0:~# kubectl exec -it test-client -- netperf -H 10.10.0.30 -t TCP_RR
MIGRATED TCP REQUEST/RESPONSE TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 10.10.0.30 (10.10.0) port 0 AF_INET : first burst 0
Local /Remote
Socket Size   Request  Resp.   Elapsed  Trans.
Send   Recv   Size     Size    Time     Rate
bytes  Bytes  bytes    bytes   secs.    per sec

16384  131072 1        1       10.00    36977.42
16384  131072
```

### Antrea
```
ubuntu@node-0:~# kubectl exec -it test-client -- iperf3 -l1M -c 10.10.0.29
Connecting to host 10.10.0.29, port 5201
[  5] local 10.10.1.28 port 54742 connected to 10.10.0.29 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  4.01 GBytes  34.4 Gbits/sec   83   3.34 MBytes
[  5]   1.00-2.00   sec  4.24 GBytes  36.4 Gbits/sec    0   3.34 MBytes
[  5]   2.00-3.00   sec  3.96 GBytes  34.0 Gbits/sec   89   4.57 MBytes
[  5]   3.00-4.00   sec  4.00 GBytes  34.4 Gbits/sec   82    965 KBytes
[  5]   4.00-5.00   sec  4.29 GBytes  36.8 Gbits/sec    0   3.15 MBytes
[  5]   5.00-6.00   sec  4.35 GBytes  37.4 Gbits/sec    0   3.15 MBytes
[  5]   6.00-7.00   sec  4.33 GBytes  37.1 Gbits/sec    0   3.15 MBytes
[  5]   7.00-8.00   sec  4.20 GBytes  36.1 Gbits/sec   53   2.89 MBytes
[  5]   8.00-9.00   sec  4.19 GBytes  36.0 Gbits/sec   45   3.22 MBytes
[  5]   9.00-10.00  sec  4.34 GBytes  37.3 Gbits/sec    0   3.22 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  41.9 GBytes  36.0 Gbits/sec  352             sender
[  5]   0.00-10.00  sec  41.9 GBytes  36.0 Gbits/sec                  receiver

iperf Done.

ubuntu@node-0:~# kubectl exec -it test-client -- netperf -H 10.10.0.29 -t TCP_RR
MIGRATED TCP REQUEST/RESPONSE TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 10.10.0.29 (10.10.0) port 0 AF_INET : first burst 0
Local /Remote
Socket Size   Request  Resp.   Elapsed  Trans.
Send   Recv   Size     Size    Time     Rate
bytes  Bytes  bytes    bytes   secs.    per sec

16384  131072 1        1       10.00    28246.08
16384  131072
```
### Bare Metal
```
ubuntu@node-0:~# iperf3 -c 192.168.0.101 -l1M
Connecting to host 192.168.0.101, port 5201
[  5] local 192.168.0.100 port 51930 connected to 192.168.0.101 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  4.31 GBytes  37.0 Gbits/sec  115    743 KBytes
[  5]   1.00-2.00   sec  3.95 GBytes  33.9 Gbits/sec  139   2.14 MBytes
[  5]   2.00-3.00   sec  4.33 GBytes  37.2 Gbits/sec  176   2.53 MBytes
[  5]   3.00-4.00   sec  4.98 GBytes  42.8 Gbits/sec   50   1.44 MBytes
[  5]   4.00-5.00   sec  4.33 GBytes  37.2 Gbits/sec  218   2.63 MBytes
[  5]   5.00-6.00   sec  5.07 GBytes  43.5 Gbits/sec   40   2.22 MBytes
[  5]   6.00-7.00   sec  4.47 GBytes  38.4 Gbits/sec  435    944 KBytes
[  5]   7.00-8.00   sec  4.52 GBytes  38.9 Gbits/sec  284    804 KBytes
[  5]   8.00-9.00   sec  5.12 GBytes  43.9 Gbits/sec   98   2.71 MBytes
[  5]   9.00-10.00  sec  4.90 GBytes  42.1 Gbits/sec   55    891 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  46.0 GBytes  39.5 Gbits/sec  1610             sender
[  5]   0.00-10.00  sec  46.0 GBytes  39.5 Gbits/sec                  receiver

iperf Done.

ubuntu@node-0:~# netperf -H 192.168.0.101 -t TCP_RR
MIGRATED TCP REQUEST/RESPONSE TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 192.168.0.101 () port 0 AF_INET : demo : first burst 0
Local /Remote
Socket Size   Request  Resp.   Elapsed  Trans.
Send   Recv   Size     Size    Time     Rate
bytes  Bytes  bytes    bytes   secs.    per sec

16384  131072 1        1       10.00    39271.76
16384  131072
```