# Master port-to-skill routing table

Read this when a scan shows an open port and you need to know which skill to
load. A port number is a hint; the service's own protocol response decides
(`SKILL.md` Step 5). Load only the owner of the port in front of you.

`hes` below is short for `hunt-exposed-services`; the file after it is the one
reference file to load inside that skill. Ports are TCP unless marked `/udp`.

Ownership sources: the `hunt-exposed-services` Step 3 table and its reference
port maps, the `hunt-exposed-panels` port list, `hunt-k8s` Phase 1,
`vmware-vcenter-attack` (OpenSLP on 427), `enterprise-vpn-attack` "When to use",
and the sibling `infra-*` skills' declared port lists. Every port number in
those sources was diffed mechanically against this file. Where nothing in the bundle covers a
port, the row says so instead of inventing an owner.

---

## TCP

| Port | Expected service | Owner | Notes |
|---|---|---|---|
| Any port | JDWP, gdbserver | hes `remote-debug.md` | Answer on arbitrary ports. The JDWP handshake or a gdb remote reply identifies them |
| 7 | echo | hes `legacy-and-infoleak.md` | Value is the UDP reflector, not TCP |
| 21 | FTP | `infra-ftp` | |
| 22 | SSH, SFTP | `infra-ssh` | SSH banners on 2222 and other alternate ports route here too, once the banner confirms SSH |
| 23 | Telnet | hes `legacy-and-infoleak.md` | Banner only |
| 25 | SMTP | `infra-mail` | SPF, DKIM and DMARC records go to `hunt-tls-network` |
| 53 | DNS | `infra-dns` | AXFR stays in `hunt-tls-network` |
| 79 | finger | hes `legacy-and-infoleak.md` | |
| 80 | HTTP | Web routing, see below | |
| 88 | Kerberos | `infra-windows-perimeter` | Exposure only. No roasting, by `SECURITY.md` |
| 110, 995 | POP3, POP3S | `infra-mail` | |
| 111 | rpcbind | hes `printers-and-storage.md` | |
| 113 | ident | hes `legacy-and-infoleak.md` | |
| 135, dynamic RPC high ports | MSRPC | `infra-windows-perimeter` | |
| 139 | NetBIOS session | `infra-windows-perimeter` | |
| 143, 993 | IMAP, IMAPS | `infra-mail` | |
| 264 | Check Point FW-1 topology | hes `management-interfaces.md` | |
| 389, 636, 3268, 3269 | LDAP, LDAPS, global catalog | hes `management-interfaces.md` | rootDSE only. Directory enumeration against AD is out of scope |
| 427 | SLP (ESXi OpenSLP) | `vmware-vcenter-attack` | That skill names TCP/427 for the OpenSLP CVEs |
| 443 | HTTPS | Web routing, see below | Also SSTP (`infra-vpn-ike`), SSL VPN portals (`enterprise-vpn-attack`), vCenter (`vmware-vcenter-attack`) |
| 445 | SMB | `infra-windows-perimeter` | |
| 465, 587 | SMTPS, submission | `infra-mail` | |
| 502 | Modbus | hes `industrial-and-iot.md` | Detection only. See Fragile estates in `SKILL.md` |
| 512, 513, 514 | rexec, rlogin, rsh | hes `legacy-and-infoleak.md` | |
| 515 | LPD | hes `printers-and-storage.md` | |
| 548 | AFP | hes `printers-and-storage.md` | |
| 554, 8554 | RTSP | hes `industrial-and-iot.md` | `OPTIONS` and `DESCRIBE` only |
| 631 | IPP, CUPS | hes `printers-and-storage.md` | |
| 873 | rsync | hes `printers-and-storage.md` | |
| 990 | FTPS (implicit) | `infra-ftp` | |
| 1080 | SOCKS | hes `legacy-and-infoleak.md` | Open-proxy test only with a canary you control |
| 1026 | rusersd (via rpcbind) | hes `legacy-and-infoleak.md` | |
| 1050, 1098, 1099 | Java RMI registry, RMI-IIOP | hes `remote-debug.md` | |
| 992 | SoftEther | `infra-vpn-ike` | |
| 1194 | OpenVPN over TCP | `infra-vpn-ike` | OpenVPN port-share and SoftEther can also sit on 443 |
| 1414 | IBM MQ | hes `message-brokers.md` | |
| 1433 | MSSQL | `infra-windows-perimeter` | |
| 1521, 1522-1529 | Oracle TNS | hes `databases.md` | |
| 1720 | H.323 | `infra-voip-sip` | |
| 1723 | PPTP | `infra-vpn-ike` | Control channel; the tunnel is GRE, IP protocol 47 |
| 1883, 8883 | MQTT, MQTT over TLS | hes `message-brokers.md` | Never publish |
| 2049 | NFS | hes `printers-and-storage.md` | `showmount` only, never mount |
| 2222 | SSH (alternate) or EtherNet/IP I/O | `infra-ssh` or hes `industrial-and-iot.md` | Collision. The banner decides |
| 2375, 2376 | Docker API | `hunt-k8s` | |
| 2379, 2380 | etcd | `hunt-k8s` | |
| 3000 | Grafana | `hunt-exposed-panels` | |
| 3128 | Squid | hes `legacy-and-infoleak.md` | |
| 3260 | iSCSI | hes `printers-and-storage.md` | `sendtargets` only |
| 3299 | SAProuter | hes `management-interfaces.md` | Never route through it |
| 3306, 33060 | MySQL, MySQL X protocol | hes `databases.md` | |
| 3389 | RDP | `infra-windows-perimeter` | |
| 3632 | distcc | hes `remote-debug.md` | Never `distcc-cve2004-2687` |
| 3690 | svnserve | hes `printers-and-storage.md` | |
| 4040 | Spark UI | `hunt-exposed-panels` | |
| 4222, 6222, 8222 | NATS, cluster routes, monitoring | hes `message-brokers.md` | |
| 4194 | cAdvisor | `hunt-k8s` | |
| 4369 | Erlang EPMD | hes `message-brokers.md` | |
| 4443, 8443, 10443 | SSL VPN web management | `enterprise-vpn-attack` when the fingerprint is a VPN appliance, otherwise web routing | |
| 4646 | Nomad | `hunt-exposed-panels` | |
| 4786 | Cisco Smart Install | hes `management-interfaces.md` | A single reachability probe. Everything else is Stage B |
| 4840, 4843 | OPC UA | hes `industrial-and-iot.md` | |
| 5060, 5061 | SIP, SIP over TLS | `infra-voip-sip` | hes `legacy-and-infoleak.md` also lists a SIP `OPTIONS` probe. Use the voip skill, not both |
| 5432 | PostgreSQL | hes `databases.md` | |
| 5555 | ADB, or SoftEther | hes `remote-debug.md` or `infra-vpn-ike` | Collision. The handshake decides |
| 5601 | Kibana | hes `databases.md` | |
| 5671, 5672, 15671, 15672 | AMQP (and TLS), RabbitMQ management (and TLS) | hes `message-brokers.md` | |
| 5900-5906 | VNC | hes `management-interfaces.md` | Shared, view-only |
| 5984, 6984 | CouchDB, CouchDB TLS | hes `databases.md` | |
| 5985, 5986 | WinRM, OMI | hes `management-interfaces.md` | NTLM metadata goes to `hunt-ntlm-info` |
| 6000-6005 | X11 | hes `remote-debug.md` | IANA registers 6000-6063; 0-5 is the common case |
| 6379, 16379 | Redis, Redis cluster bus | hes `databases.md` | Stop at `INFO` |
| 6443 | Kubernetes API | `hunt-k8s` | |
| 8009 | AJP | hes `remote-debug.md` | |
| 8080 | HTTP alternate, Squid, Airflow, Tomcat | Web routing; proxies go to hes `legacy-and-infoleak.md` | |
| 8081 | Flink | `hunt-exposed-panels` | |
| 8086 | InfluxDB or HTTP alternate | hes `databases.md` or web routing | Collision. The response decides |
| 8088, 9864, 9870 | Hadoop YARN, DataNode, NameNode | hes `databases.md` | |
| 8089 | splunkd | hes `databases.md` | |
| 8500 | Consul | `hunt-exposed-panels` | |
| 8888 | Jupyter | `hunt-exposed-panels` | |
| 9000 | FastCGI, or HTTP on many products | hes `remote-debug.md` or web routing | Collision. An FCGI record decides |
| 9001 | HSQLDB | hes `databases.md` | |
| 9993 | ZeroTier local API | `infra-vpn-ike` | |
| 9042, 7199 | Cassandra CQL, JMX | hes `databases.md` | |
| 9090 | Prometheus | `hunt-exposed-panels` | `hunt-k8s` also lists it on cluster nodes |
| 9100-9107 | Raw PJL printing, or Prometheus node exporter (HTTP) | hes `printers-and-storage.md` for PJL; `infra-monitoring-logging` for the exporter | Collision. `-sV` skips these ports on purpose. Identify the service before sending any payload |
| 9200, 9300 | Elasticsearch HTTP, transport | hes `databases.md` | |
| 9401 | Veeam B&R | hes `management-interfaces.md` | |
| 9443 | Portainer | `hunt-exposed-panels` | |
| 10000 | NDMP or Webmin | hes `management-interfaces.md` | Collision. Webmin is HTTP and goes to web routing |
| 10250, 10255, 10256 | kubelet, read-only kubelet, kube-proxy health | `hunt-k8s` | |
| 11211 | memcached | hes `databases.md` | TCP `stats` only |
| 19999 | Netdata | `hunt-exposed-panels` | |
| 20000 | DNP3 | hes `industrial-and-iot.md` | |
| 24007, 24008, 49152+ | GlusterFS management, bricks | hes `printers-and-storage.md` | |
| 27017, 27018, 27019 | MongoDB, shard member, config server | hes `databases.md` | |
| 30000-32767 | Kubernetes NodePort range | `hunt-k8s` for the cluster, then the service's own owner | Fingerprint what answers. The range says nothing about the service |
| 44818 | EtherNet/IP | hes `industrial-and-iot.md` | |

### Web routing (HTTP or HTTPS on any port)

Fingerprint first (title, `Server`, certificate, product version endpoint), then:

| Fingerprint | Owner |
|---|---|
| SSL VPN or remote-access gateway (Cisco, Fortinet, Citrix, Palo Alto, Ivanti/Pulse, SonicWall, F5) | `enterprise-vpn-attack` |
| vCenter, ESXi web, Workspace ONE, Aria | `vmware-vcenter-attack` |
| SSTP endpoint, OpenVPN port-share, SoftEther, Tailscale DERP or Headscale | `infra-vpn-ike` |
| Infrastructure admin console (Zabbix, Grafana, Prometheus, JBoss, Tomcat Manager, phpMyAdmin, Jupyter, Consul, Portainer and the rest of its table) | `hunt-exposed-panels` |
| CI/CD (Jenkins, GitLab CI, TeamCity, Argo) | `hunt-cicd` |
| Kubernetes Dashboard | `hunt-k8s` |
| `WWW-Authenticate: NTLM` or `Negotiate` | `hunt-ntlm-info` |
| The client's own application | `web2-recon`, then `hunt-dispatch` |
| Anything on a CDN edge address | HTTP-layer testing of the client's hostname only. No port scan (`SKILL.md` Step 2) |

TLS on any port, whatever the service, also goes to `hunt-tls-network` as a
separate finding.

---

## UDP

| Port | Expected service | Owner | Notes |
|---|---|---|---|
| 7/udp | echo | hes `legacy-and-infoleak.md` | A reflection amplifier; that is the finding |
| 53/udp | DNS | `infra-dns` | Open resolver, version, cache snooping |
| 69/udp | TFTP | hes `printers-and-storage.md` | One targeted get, no wordlist |
| 88/udp | Kerberos | `infra-windows-perimeter` | |
| 123/udp | NTP | hes `legacy-and-infoleak.md` | `monlist` is one measured request |
| 137/udp, 138/udp | NetBIOS name and datagram | `infra-windows-perimeter` | |
| 161/udp, 162/udp | SNMP, traps | hes `management-interfaces.md` | Documented defaults once each |
| 389/udp | CLDAP | `infra-windows-perimeter` | Also an amplification reflector |
| 427/udp | SLP | `vmware-vcenter-attack` for ESXi | The skill's CVE text names TCP/427. Treat UDP as a reachability signal (verify) |
| 500/udp, 4500/udp | IKE, IPsec NAT-T | `infra-vpn-ike` | |
| 623/udp (also 623/tcp, 664/udp) | IPMI, BMC | hes `management-interfaces.md` | `ipmi-version`, never `ipmi-cipher-zero` |
| 631/udp | `cups-browsed` | hes `printers-and-storage.md` | Any crafted datagram is Stage B |
| 1194/udp | OpenVPN | `infra-vpn-ike` | Outside UDP top 100. Add by name |
| 1434/udp | MSSQL Browser | `infra-windows-perimeter` | |
| 1701/udp | L2TP | `infra-vpn-ike` | |
| 1900/udp | SSDP, UPnP | Partial: hes Step 6 grades it as an amplification reflector | No probe recipe in the bundle. One packet, measured |
| 2222/udp, 44818/udp | EtherNet/IP | hes `industrial-and-iot.md` | |
| 3702/udp | WS-Discovery | hes `legacy-and-infoleak.md` | |
| 3478/udp | STUN, as a Tailscale DERP relay | `infra-vpn-ike` | Any other STUN or TURN server has no owner, see below |
| 5060/udp | SIP | `infra-voip-sip` | |
| 9993/udp | ZeroTier | `infra-vpn-ike` | |
| 5353/udp | mDNS | hes `legacy-and-infoleak.md` | |
| 11211/udp | memcached | hes `databases.md` | At most one unspoofed packet |
| 12346/udp | Cisco SD-WAN | hes `management-interfaces.md` | |
| 32100/udp | PPPP / CS2 cameras | hes `industrial-and-iot.md` | |
| 47808/udp | BACnet/IP | hes `industrial-and-iot.md` | |
| 51820/udp | WireGuard | `infra-vpn-ike` | Silent to unauthenticated packets by design, so absence of a reply proves nothing |
| RTP media range | RTP | `infra-voip-sip` | The range is configured per PBX. Find it from the SIP/SDP exchange, not by sweeping |

---

## Owners added in the second infrastructure wave

These skills own the ports below; their own Step 3 tables carry the full
list, the collisions and the first read-only probe.

| Owner | Ports and services |
|---|---|
| `infra-network-devices` | 8291 Winbox, 8728/8729 RouterOS API, 2000 btest (SCCP otherwise), 10001/udp Ubiquiti discovery, 8443/8080 UniFi plus 3478/udp UniFi STUN, 7547 TR-069, 7557/7567 GenieACS, 541 FGFM, 4343 Aruba WebUI, 8211/udp Aruba PAPI, 1812/1813 and 1645/1646 udp RADIUS, 49 TACACS+, 179 BGP, 520/udp RIP, 514/udp syslog (514/tcp rsh stays with `hes`), 2055/udp NetFlow, 6343/udp sFlow, 1900/udp SSDP, vendor admin HTTPS on Cisco, Juniper, Fortinet, Palo Alto, SOHO and WLC devices |
| `infra-rmm-remote-support` | ScreenConnect, SimpleHelp, BeyondTrust, N-central, Kaseya, ManageEngine, TeamViewer and AnyDesk relays; 1494 ICA, 2598 CGP, 4000 NoMachine, SPICE on 5900+ |
| `infra-backup-nas` | Veeam 9392/9393/9401, Commvault 8400, NetBackup 1556/13724, Bacula 9101-9103, Acronis, Nakivo, QNAP, Synology 5000/5001, TrueNAS, MinIO 9000/9001, Nextcloud/ownCloud, Syncthing 8384 |
| `infra-enterprise-appservers` | SAP 32NN/33NN/36NN/80NN/443NN/5NN00, WebLogic 7001/7002, WebSphere 9060/9080/8880, JBoss 9990/4447, GlassFish 4848, ColdFusion 8500, Atlassian 8090/7990/8085 |
| `infra-data-platforms` | Hadoop 9870/8020/8088, Spark 7077/6066, Hive 10000, HBase 16010, Livy 8998, Flink 8081, Kafka 9092/9093, ZooKeeper 2181, ActiveMQ 61616/8161/61613, Solr 8983, ClickHouse 8123/9000, Neo4j 7474/7687, DB2 50000, Firebird 3050, ASE 5000, HANA 3NN15, CockroachDB 26257, ArangoDB 8529, RethinkDB 28015, Vertica 5433, Hazelcast 5701 |
| `infra-ai-ml-services` | Ollama 11434, Ray 8265/10001, Triton 8000-8002, TorchServe 8080-8082, MLflow 5000, Gradio/Langflow 7860, ComfyUI 8188, AnythingLLM 3001, n8n 5678, Prefect 4200, LM Studio 1234, ggml-rpc 50052, MCP `/mcp` and `/sse` |
| `infra-devops-platforms` | Vault 8200, Consul 8500/8600, Nomad 4646, Eureka 8761, Jenkins agent 50000, TeamCity 8111, Gerrit 29418, git daemon 9418, Nexus/Artifactory 8081, Docker Registry 5000, Verdaccio 4873, SonarQube 9000, Portainer 9000/9443, Rundeck 4440 |
| `infra-monitoring-logging` | Zabbix 10050/10051, NRPE 5666, Icinga 5665, Checkmk 6556, NSClient++ 8443/12489, Prometheus 9090, exporters 9100+, Alertmanager 9093, Pushgateway 9091, Graphite 2003/2004, StatsD 8125/udp, Loki 3100, Jaeger 16686, OTel 4317/4318, Graylog 9000 and GELF 12201, Logstash 5044/9600, Fluentd 24224, Fluent Bit 2020, Elastic APM 8200, Netdata 19999, SNMP traps 162/udp |

---

## Ports with no owner in the bundle

Describe these generically: service, version if the banner gives it, why it
should not face the internet. Do not invent probes, default credentials or CVEs.

| Port | Service | Why it still matters |
|---|---|---|
| 3478/udp and tcp (not DERP) | STUN, TURN | A TURN relay that allows arbitrary peers is a relay into the network (verify per implementation) |
| 5683/udp | CoAP | IoT protocol; `offensive-osint` sector notes list it, with no probe |

---

## Two collisions worth memorising

- **The same number, a different protocol.** Every collision row above is
  settled by the response, never by `nmap-services`' name for the port.
  Without `-sV`, nmap's SERVICE column is only that table lookup.
- **The same service, a different owner by layer.** LDAP on TCP goes to `hes`,
  and CLDAP on UDP goes to `infra-windows-perimeter`. WinRM's service goes to
  `hes`, and its NTLM metadata goes to `hunt-ntlm-info`. DNS server behaviour
  goes to `infra-dns`, and zone transfer goes to `hunt-tls-network`.
