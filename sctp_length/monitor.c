#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// SCTP 헤더의 필요한 필드를 정의합니다.
struct sctphdr {
    __be16 source;
    __be16 dest;
    __be32 vtag;
    __be32 checksum;
};

// SCTP 패킷 길이를 저장하기 위한 맵
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} events SEC(".maps");

SEC("xdp")
int monitor_sctp_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 이더넷 헤더 확인
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // IP 프로토콜인지 확인
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    // IP 헤더 확인
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // SCTP 프로토콜인지 확인
    if (ip->protocol != IPPROTO_SCTP) return XDP_PASS;

    // SCTP 헤더 확인
    struct sctphdr *sctp = (void *)ip + sizeof(struct iphdr);
    if ((void *)(sctp + 1) > data_end) return XDP_PASS;

    // 패킷 길이 계산
    __u32 packet_length = (__u32)(data_end - data);

    // 패킷 길이를 이벤트로 전송
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &packet_length, sizeof(packet_length));

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
