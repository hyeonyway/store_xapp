//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define THRESHOLD 50
#define MAX_ARR_LEN 50
#define ETH_HLEN	14
#define ETH_P_IP 0x0800

struct event {
    u32 saddr;
    u32 size;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

const struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32[MAX_ARR_LEN]);
    __uint(max_entries, MAX_ARR_LEN);
} length_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32[3]);
    __uint(max_entries, MAX_ARR_LEN);
} status_hash SEC(".maps");


SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void* data = (void*)ctx->data;
    void* data_end = (void*)ctx->data_end;
    __u32 packet_length = data_end - data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // IP 헤더 가져오기
    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // SCTP 프로토콜인지 확인 (프로토콜 번호 132)
    if (ip->protocol != IPPROTO_SCTP) {

        // SCTP 패킷을 드롭하거나 특정 작업을 수행할 수 있음
        return XDP_PASS;  // SCTP 패킷을 드롭합니다
    }
    __u32 saddr = (__u32)ip->saddr;

    bpf_printk("XDP triggered! packet length : %d", packet_length);

    __u32 temp_status_arr[3];
    __u32 temp_length_arr[MAX_ARR_LEN];
    __u32 *status_arr = bpf_map_lookup_elem(&status_hash, &saddr);
    if(!status_arr){
        status_arr = temp_status_arr;
        status_arr[0] = 0;
        status_arr[1] = 0;
        status_arr[2] = 0;
    }
    __u32 *length_arr = bpf_map_lookup_elem(&length_hash, &saddr);
    if(!length_arr){
        length_arr = temp_length_arr;
        for(int i = 0; i < MAX_ARR_LEN; i++)
            length_arr[i] = 0;
    }
    __u32 idx = status_arr[0];
    __u32 avg = status_arr[1];
    __u32 is_full = status_arr[2];

    if(!is_full){
        status_arr[0] = idx + 1;
        if(idx > MAX_ARR_LEN - 2){
            status_arr[2] = 1;
            status_arr[0] = 0;
        }
        if(idx == 0)
            status_arr[1] = packet_length;
        else{
            status_arr[1] = (avg * idx + packet_length) / (idx + 1);
        }
        if(idx < 0 || idx > MAX_ARR_LEN - 1)
            return XDP_PASS;
        length_arr[idx] = packet_length;
        bpf_map_update_elem(&length_hash, &saddr, length_arr, BPF_ANY);
        bpf_map_update_elem(&status_hash, &saddr, status_arr, BPF_ANY);
        return XDP_PASS;
    }

    if(packet_length > avg * (THRESHOLD + 100 / 100)){
        struct event *new_event = NULL;
        new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (new_event == NULL) {
            return XDP_PASS;
        }

        new_event->size = packet_length;
        new_event->saddr = saddr;
        bpf_ringbuf_submit(new_event, 0);
        return XDP_DROP;
    }

    status_arr[0] = idx + 1;
    if(idx > MAX_ARR_LEN - 2)
        status_arr[0] = 0;
    if(idx < 0 || idx > MAX_ARR_LEN - 1)
        return XDP_PASS;
    __u32 old_value = length_arr[idx];
    status_arr[1] = (avg * MAX_ARR_LEN - old_value + packet_length) / MAX_ARR_LEN;
    length_arr[idx] = packet_length;
    bpf_map_update_elem(&length_hash, &saddr, length_arr, BPF_ANY);
    bpf_map_update_elem(&status_hash, &saddr, status_arr, BPF_ANY);
    return XDP_PASS;
}