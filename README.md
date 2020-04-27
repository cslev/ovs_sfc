# ovs_sfc
Fire up two OVS instances and L2,L3, or even L4 Service Function Chaining on top of them

# Requirements
1) Open vSwitch
2) Docker

## Install requirements (on debian/ubuntu)
Simply run `bootstrap.sh -d debian/ubuntu`.
```
chmod +x bootstrap.sh
sudo ./bootstrap.sh -d debian
```
For other systems, please adjust `bootstrap.sh` to support different repositories and install packages in a different way. It should be pretty straightforward


# Playing with the scripts
## Topology
```
+------+           +--------+
| user |           | filter |
+------+           +--------+
     |                  |            
10.10.10.100/24   10.10.10.101/24   
     |                  |          
+----------------------------------+                   +------------------------------+
|                            ______|                   |____                          |
| OVSBR-INT                 |veth0 --------------------veth1|                OVSBR-PUB---------- INTERNET
|                            ------|                   |-----          10.10.10.1/24  |
+----------------------------------+                   +------------------------------+
```

## Basic concept
The purpose of this repository is to show how a basic service function chaining can be materialized with OVS.

- As can be seen above, we have two OVS bridges, one for (OVSBR-INT) connecting the hosts that are two containers (user and filter).

- The second OVS bridge (OVSBR-PUB) is directly connected to the previous one, and serves as an L3 gateway for it.

  - `iptables` rules are responsible to do NAT for packets coming from OVSBR-INT and vice versa.

- Flow rules in OVSBR-INT takes care of: 
  - making `user` and `filter` to be able to communicate
  - sending all other packets from `filter` towards the Internet without restriction
  - sending all other packets BUT DNS packets from `user` towards the Internet without restriction
  - sending all DNS packets (destined to port 53) from `user` towards `filter`

- `filter` should run `filter.py` application which can monitor DNS traffic and occasionally block a specific one if set (see details later)

## Let's play
To fire up the system, first we have to become aware which interface we are using to access the Internet in order to install our NAT rules.
You can figure this out by `ifconfig` and `route -n`. 

Next, we assume this interface is `enp3s0` (a typical made-up ID in a VM :D)
```
sudo ./start_sfc_architecture.sh -o enp3s0
```
This will bring up everything.
Open two terminals to access the containers via these commands:

In the first terminal:
```
sudo docker attach user
```
In the second terminal:
```
sudo docker attach filter
```

Now, ensure that connection is working! First, try to ping one container from the other.

Ping from `user` to `filter`.
```
<user>: ping 10.10.10.101
PING 10.10.10.101 (10.10.10.101) 56(84) bytes of data.
64 bytes from 10.10.10.101: icmp_seq=1 ttl=64 time=0.716 ms
64 bytes from 10.10.10.101: icmp_seq=2 ttl=64 time=0.097 ms
64 bytes from 10.10.10.101: icmp_seq=3 ttl=64 time=0.100 ms
```
It is working!

Now, ping 8.8.8.8 within the containers.
Ping from `user` OR `filter`
```
<user>: ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=61 time=7.84 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=61 time=6.81 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=61 time=6.75 ms
```

Next, ping `google.com` from `filter`.
```
<filter>: ping google.com
PING google.com (74.125.130.113) 56(84) bytes of data.
64 bytes from sb-in-f113.1e100.net (74.125.130.113): icmp_seq=1 ttl=61 time=8.35 ms
64 bytes from sb-in-f113.1e100.net (74.125.130.113): icmp_seq=2 ttl=61 time=6.94 ms
```

So far, everything is working as normal.

Now, we will do the same ping but from the `user`.
```
<filter>: ping google.com
```
You can see that tothing happens now as the DNS request is sent to the filter, which does nothing with the incoming packets (yet).
Let's try with other tools as well to ensure I am not lying here :D
```
<filter>: dig google.com
```
It can be seen that `dig` also does not go through.


Let's start our `filter.py` in `filter`
```
<filter>: python3 filter.py -f -d index.hu
```
This will start the filter application that will let all DNS request through except the one which looks for `index.hu`.
In other words, this system now implements a DNS-based content filtering most ISPs/censors/authoritarian governments apply nowadays (of course, not in the form of such a simply python script).
It is difficult for such systems to block IPs since the list of possible IPs should be up-to-date. 
However, this is a daunting task due to fact that nowadays CDNs are deployed (the same IP list in the USA may be different than the one in Singapore), and many web services are offloaded to the cloud (resulting in continuous IP address change).
Therefore, pasive DNS data is used to monitor customer activities and do law enforcements.

Let's do a `dig` or `ping` now at `user` for a domain that is not blocked, e.g., `google.com`.
```
<user>: dig google.com
; <<>> DiG 9.11.16-2-Debian <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61994
;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		293	IN	A	172.217.194.102
google.com.		293	IN	A	172.217.194.139
google.com.		293	IN	A	172.217.194.138
google.com.		293	IN	A	172.217.194.100
google.com.		293	IN	A	172.217.194.101
google.com.		293	IN	A	172.217.194.113

;; Query time: 13 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Mon Apr 27 09:28:50 UTC 2020
;; MSG SIZE  rcvd: 135
```
As we can see, it works. Observer, on the other hand, the output at the `filter` terminal.
```
FORWARDING DNS query (b'google.com.')...
```
It saw that `user` was looking for `google.com` and it let the query through.

Finally, do the same query at `user` but for the domain that supposed to be blocked.
```
<user>: dig index.hu
```
As you can see, nothing really happens at the `user` because the queries for that domain are not forwarded at all.

Take a look at the output at `filter`:
```
Gotcha index.hu  - DROP
Gotcha index.hu  - DROP

```
There were even two packets asking for the DNS records of `index.hu`, namely the A (IPv4) and AAAA (IPv6) records, but both were captured and black-holed.

This is pretty much it.

## Further use-cases
You can alter the flow rules of OVS to achieve a different use case! 

It is also pretty straightforward to extend the main scipt with more containers for a more compex use case.
Just do NOT forget to update all parts of it (running an extra container, connect to it to the switch, install flow rules).
And, most importantly, switch off the checksum offloading for the new interface in the new container otherwise the it will mess the checksums up, and nothing will work above Layer-3. 
Don't get fooled when you see `ping` is working (that is ICMP and is still in Layer-3), try `wget` or something similar to check the connection is working.
