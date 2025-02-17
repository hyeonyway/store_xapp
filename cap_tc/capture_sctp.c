// capture_sctp.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// 필요한 상수 및 SCTP 헤더 정의
#define IPPROTO_SCTP 132
#define TC_ACT_OK 0

struct sctphdr {
    __be16 source;
    __be16 dest;
    __be32 vtag;
    __be32 checksum;
};

SEC("tc")
int capture_sctp_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Ethernet 헤더 위치 확인
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;

    // IPv4만 확인
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    // IP 헤더 위치 확인
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // SCTP 프로토콜인지 확인
    if (ip->protocol != IPPROTO_SCTP)
        return TC_ACT_OK;

    // SCTP 헤더 위치 확인
    struct sctphdr *sctp = (void *)(ip + 1);
    if ((void *)(sctp + 1) > data_end)
        return TC_ACT_OK;

    // SCTP 패킷 캡처 로그 출력
    bpf_printk("Captured Egress SCTP packet: source port %d, dest port %d\n",
               __bpf_ntohs(sctp->source), __bpf_ntohs(sctp->dest));

    return TC_ACT_OK;  // 패킷 통과
}

char LICENSE[] SEC("license") = "GPL";
