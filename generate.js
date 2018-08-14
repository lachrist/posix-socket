
const export_integer = (name) =>
`  #ifdef ${name}
    exports->Set(context, v8::String::NewFromUtf8(isolate, ${JSON.stringify(name)}), v8::Integer::New(isolate, ${name})).FromJust();
  #endif`

console.log("\n  // Address Family -- http://man7.org/linux/man-pages/man2/socket.2.html //");
console.log([
  "AF_UNIX",
  "AF_LOCAL",
  "AF_INET",
  "AF_INET6"].map(export_integer).join("\n"));

console.log("\n  // Socket Type -- http://man7.org/linux/man-pages/man2/socket.2.html //");
console.log([
  "SOCK_STREAM",
  "SOCK_DGRAM",
  "SOCK_SEQPACKET",
  "SOCK_RAW"].map(export_integer).join("\n"));

console.log("\n  // Send Flags -- http://man7.org/linux/man-pages/man2/send.2.html //");
console.log([
  "MSG_CONFIRM",
  "MSG_DONTROUTE",
  "MSG_DONTWAIT",
  "MSG_EOR",
  "MSG_MORE",
  "MSG_NOSIGNAL",
  "MSG_OOB"].map(export_integer).join("\n"));

console.log("\n  // Recv Flags -- http://man7.org/linux/man-pages/man2/recv.2.html //");
console.log([
  "MSG_CMSG_CLOEXEC",
  "MSG_DONTWAIT",
  "MSG_ERRQUEUE",
  "MSG_OOB",
  "MSG_PEEK",
  "MSG_TRUNC",
  "MSG_WAITALL"].map(export_integer).join("\n"));

console.log("\n  // Shutdown Flags -- http://man7.org/linux/man-pages/man2/shutdown.2.html //");
console.log([
  "SHUT_RD",
  "SHUT_WR",
  "SHUT_RDWR"].map(export_integer).join("\n"));

console.log("\n // Socket-Level Options -- http://man7.org/linux/man-pages/man7/socket.7.html");
console.log([
  "SOL_SOCKET",
  "SO_ACCEPTCONN",
  "SO_ATTACH_FILTER",
  "SO_ATTACH_REUSEPORT_CBPF",
  "SO_ATTACH_REUSEPORT_EBPF",
  "SO_BINDTODEVICE",
  "SO_BROADCAST",
  "SO_BSDCOMPAT",
  "SO_DEBUG",
  "SO_DETACH_FILTER",
  "SO_DOMAIN",
  "SO_ERROR",
  "SO_DONTROUTE",
  "SO_INCOMING_CPU",
  "SO_KEEPALIVE",
  "SO_LINGER",
  "SO_LOCK_FILTER",
  "SO_MARK",
  "SO_OOBINLINE",
  "SO_PASSCRED",
  "SO_PEEK_OFF",
  "SO_PEERCRED",
  "SO_PRIORITY",
  "SO_PROTOCOL",
  "SO_RCVBUF",
  "SO_RCVBUFFORCE",
  "SO_RCVLOWAT",
  "SO_SNDLOWAT",
  "SO_RCVTIMEO",
  "SO_SNDTIMEO",
  "SO_REUSEADDR",
  "SO_REUSEPORT",
  "SO_RXQ_OVFL",
  "SO_SNDBUF",
  "SO_SNDBUFFORCE",
  "SO_TIMESTAMP",
  "SO_TYPE",
  "SO_BUSY_POLL"].map(export_integer).join("\n"));

console.log("\n  // IP-Level Options -- http://man7.org/linux/man-pages/man7/ip.7.html //");
console.log([
  "IPPROTO_IP",
  "IP_ADD_MEMBERSHIP",
  "IP_ADD_SOURCE_MEMBERSHIP",
  "IP_BIND_ADDRESS_NO_PORT",
  "IP_BLOCK_SOURCE",
  "IP_DROP_MEMBERSHIP",
  "IP_DROP_SOURCE_MEMBERSHIP",
  "IP_FREEBIND",
  "IP_HDRINCL",
  "IP_MSFILTER",
  "IP_MTU",
  "IP_MTU_DISCOVER",
  "IP_MULTICAST_ALL",
  "IP_MULTICAST_IF",
  "IP_MULTICAST_LOOP",
  "IP_MULTICAST_TTL",
  "IP_NODEFRAG",
  "IP_OPTIONS",
  "IP_PKTINFO",
  "IP_RECVERR",
  "IP_RECVOPTS",
  "IP_RECVORIGDSTADDR",
  "IP_RECVTOS",
  "IP_RECVTTL",
  "IP_RETOPTS",
  "IP_ROUTER_ALERT",
  "IP_TOS",
  "IP_TRANSPARENT",
  "IP_TTL",
  "IP_UNBLOCK_SOURCE"
].map(export_integer).join("\n"));

console.log("\n  // IPV6-Level Options -- http://man7.org/linux/man-pages/man7/ipv6.7.html //");
console.log([
  "IPPROTO_IPV6",
  "IPV6_ADDRFORM",
  "IPV6_ADD_MEMBERSHIP",
  "IPV6_DROP_MEMBERSHIP",
  "IPV6_MTU",
  "IPV6_MTU_DISCOVER",
  "IPV6_MULTICAST_HOPS",
  "IPV6_MULTICAST_IF",
  "IPV6_MULTICAST_LOOP",
  "IPV6_RECVPKTINFO",
  "IPV6_RTHDR",
  "IPV6_AUTHHDR",
  "IPV6_DSTOPTS",
  "IPV6_HOPOPTS",
  "IPV6_FLOWINFO",
  "IPV6_HOPLIMIT"].map(export_integer).join("\n"));

console.log("\n  // TCP-Level Options -- http://man7.org/linux/man-pages/man7/tcp.7.html //");
console.log([
  "IPPROTO_TCP",
  "TCP_CORK",
  "TCP_DEFER_ACCEPT",
  "TCP_INFO",
  "TCP_KEEPCNT",
  "TCP_KEEPIDLE",
  "TCP_KEEPINTVL",
  "TCP_LINGER2",
  "TCP_MAXSEG",
  "TCP_NODELAY",
  "TCP_QUICKACK",
  "TCP_SYNCNT",
  "TCP_WINDOW_CLAMP"].map(export_integer).join("\n"));

console.log("\n  // UDP-Level Options -- http://man7.org/linux/man-pages/man7/udp.7.html//");
console.log([
  "IPPROTO_UDP",
  "UDP_CORK"].map(export_integer).join("\n"));
