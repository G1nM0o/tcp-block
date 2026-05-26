#include <pcap.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

using namespace std;

#pragma pack(push, 1)

struct PseudoHdr {
    uint32_t sip;
    uint32_t dip;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
};

#pragma pack(pop)

struct Ctx {
    pcap_t* handle;
    int raw_sock;
    string pattern;
    uint8_t my_mac[6];
};

uint16_t checksum(const void* data, size_t len)
{
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;

    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (p[i] << 8) | p[i + 1];

    if (len & 1)
        sum += p[len - 1] << 8;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return htons(static_cast<uint16_t>(~sum));
}

uint16_t tcp_checksum(IpHdr* ip, TcpHdr* tcp, size_t tcp_len)
{
    PseudoHdr ph{};

    ph.sip = ip->sip;
    ph.dip = ip->dip;
    ph.zero = 0;
    ph.proto = IP_PROTO_TCP;
    ph.len = htons(static_cast<uint16_t>(tcp_len));

    vector<uint8_t> buf(sizeof(PseudoHdr) + tcp_len);

    memcpy(buf.data(), &ph, sizeof(PseudoHdr));
    memcpy(buf.data() + sizeof(PseudoHdr), tcp, tcp_len);

    return checksum(buf.data(), buf.size());
}

void get_my_mac(const char* ifname, uint8_t mac[6])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifreq ifr{};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    close(fd);
}

void send_forward_rst(Ctx* ctx, const EthHdr* org_eth, const IpHdr* org_ip, const TcpHdr* org_tcp, uint32_t tcp_data_size)
{
    vector<uint8_t> pkt(sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr));

    EthHdr* eth = reinterpret_cast<EthHdr*>(pkt.data());
    IpHdr* ip = reinterpret_cast<IpHdr*>(pkt.data() + sizeof(EthHdr));
    TcpHdr* tcp = reinterpret_cast<TcpHdr*>(pkt.data() + sizeof(EthHdr) + sizeof(IpHdr));

    memcpy(eth->dmac, org_eth->dmac, 6);
    memcpy(eth->smac, ctx->my_mac, 6);
    eth->type = htons(ETH_TYPE_IP);

    ip->vhl = 0x45;
    ip->tos = 0;
    ip->len = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    ip->id = 0;
    ip->off = 0;
    ip->ttl = org_ip->ttl;
    ip->proto = IP_PROTO_TCP;
    ip->sum = 0;
    ip->sip = org_ip->sip;
    ip->dip = org_ip->dip;
    ip->sum = checksum(ip, sizeof(IpHdr));

    tcp->sport = org_tcp->sport;
    tcp->dport = org_tcp->dport;
    tcp->seq = htonl(ntohl(org_tcp->seq) + tcp_data_size);
    tcp->ack = org_tcp->ack;
    tcp->off = 0x50;
    tcp->flags = TCP_RST | TCP_ACK;
    tcp->win = 0;
    tcp->sum = 0;
    tcp->urp = 0;
    tcp->sum = tcp_checksum(ip, tcp, sizeof(TcpHdr));

    pcap_sendpacket(ctx->handle, pkt.data(), static_cast<int>(pkt.size()));
}

void send_backward_fin(Ctx* ctx, const IpHdr* org_ip, const TcpHdr* org_tcp, uint32_t tcp_data_size)
{
    const char msg[] =
        "HTTP/1.0 302 Redirect\r\n"
        "Location: http://warning.or.kr\r\n"
        "\r\n";

    size_t msg_len = sizeof(msg) - 1;
    size_t ip_len = sizeof(IpHdr) + sizeof(TcpHdr) + msg_len;

    vector<uint8_t> pkt(ip_len);

    IpHdr* ip = reinterpret_cast<IpHdr*>(pkt.data());
    TcpHdr* tcp = reinterpret_cast<TcpHdr*>(pkt.data() + sizeof(IpHdr));
    uint8_t* payload = pkt.data() + sizeof(IpHdr) + sizeof(TcpHdr);

    ip->vhl = 0x45;
    ip->tos = 0;
    ip->len = htons(static_cast<uint16_t>(ip_len));
    ip->id = 0;
    ip->off = 0;
    ip->ttl = 128;
    ip->proto = IP_PROTO_TCP;
    ip->sum = 0;
    ip->sip = org_ip->dip;
    ip->dip = org_ip->sip;
    ip->sum = checksum(ip, sizeof(IpHdr));

    tcp->sport = org_tcp->dport;
    tcp->dport = org_tcp->sport;
    tcp->seq = org_tcp->ack;
    tcp->ack = htonl(ntohl(org_tcp->seq) + tcp_data_size);
    tcp->off = 0x50;
    tcp->flags = TCP_FIN | TCP_ACK;
    tcp->win = 0;
    tcp->sum = 0;
    tcp->urp = 0;

    memcpy(payload, msg, msg_len);

    tcp->sum = tcp_checksum(ip, tcp, sizeof(TcpHdr) + msg_len);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->dip;

    sendto(ctx->raw_sock, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
}

void on_packet(u_char* user, const pcap_pkthdr* h, const u_char* bytes)
{
    Ctx* ctx = reinterpret_cast<Ctx*>(user);

    if (h->caplen < sizeof(EthHdr) + sizeof(IpHdr))
        return;

    const EthHdr* eth = reinterpret_cast<const EthHdr*>(bytes);

    if (ntohs(eth->type) != ETH_TYPE_IP)
        return;

    const IpHdr* ip = reinterpret_cast<const IpHdr*>(bytes + sizeof(EthHdr));

    uint8_t ip_version = ip->vhl >> 4;
    uint32_t ip_hlen = (ip->vhl & 0x0f) * 4;

    if (ip_version != 4)
        return;

    if (ip->proto != IP_PROTO_TCP)
        return;

    uint16_t frag = ntohs(ip->off);
    if ((frag & 0x2000) || (frag & 0x1fff))
        return;

    if (h->caplen < sizeof(EthHdr) + ip_hlen + sizeof(TcpHdr))
        return;

    const TcpHdr* tcp = reinterpret_cast<const TcpHdr*>(bytes + sizeof(EthHdr) + ip_hlen);

    uint32_t tcp_hlen = (tcp->off >> 4) * 4;
    uint32_t ip_total_len = ntohs(ip->len);

    if (ip_total_len < ip_hlen + tcp_hlen)
        return;

    uint32_t tcp_data_size = ip_total_len - ip_hlen - tcp_hlen;

    if (tcp_data_size == 0)
        return;

    if (h->caplen < sizeof(EthHdr) + ip_hlen + tcp_hlen + tcp_data_size)
        return;

    const char* payload = reinterpret_cast<const char*>(bytes + sizeof(EthHdr) + ip_hlen + tcp_hlen);

    const char* payload_end = payload + tcp_data_size;

    auto found = search(payload, payload_end, ctx->pattern.begin(), ctx->pattern.end());

    if (found == payload_end)
        return;

    send_forward_rst(ctx, eth, ip, tcp, tcp_data_size);
    send_backward_fin(ctx, ip, tcp, tcp_data_size);

    char sip[16];
    char dip[16];

    inet_ntop(AF_INET, &ip->sip, sip, sizeof(sip));
    inet_ntop(AF_INET, &ip->dip, dip, sizeof(dip));

    printf("blocked %s:%u -> %s:%u\n", sip, ntohs(tcp->sport), dip, ntohs(tcp->dport));
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        printf("syntax : %s <interface> <pattern>\n", argv[0]);
        printf("sample : %s wlan0 \"Host: test.gilgil.net\"\n", argv[0]);
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    Ctx ctx{};
    ctx.pattern = argv[2];

    get_my_mac(argv[1], ctx.my_mac);

    ctx.handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);

    ctx.raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    int on = 1;
    setsockopt(ctx.raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    bpf_program fp{};
    pcap_compile(ctx.handle, &fp, "tcp", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(ctx.handle, &fp);

    printf("tcp-block on %s\n", argv[1]);
    printf("pattern: %s\n", argv[2]);

    pcap_loop(ctx.handle, 0, on_packet, reinterpret_cast<u_char*>(&ctx));

    return 0;
}