//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define THRESHOLD 50
#define MAX_ARR_LEN 10
#define ETH_HLEN	14
#define ETH_P_IP 0x0800
#define SECOND 60000000000
#define COUNT_THRESHOLD 5

struct event {
    u32 saddr;
	u16 sport;
    u32 size;
};

struct chaser {
    u64 count;
    u64 time;
    u64 is_banned;
};

struct address {
    u32 ip;
    u32 port;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

const struct event *unused __attribute__((unused));

// Inner map with a single possible entry.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_ARR_LEN);
} length_arr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32[3]);
    __uint(max_entries, 1); // 0 : idx, 1 : avg, 2 : is_full
} status_arr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct address);
    __type(value, struct chaser);
    __uint(max_entries, MAX_ARR_LEN); 
} blacklist_arr SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    // if ((void *)(eth + 1) > data_end)
    //     return XDP_PASS;

    // IP 헤더 가져오기
    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // SCTP 프로토콜인지 확인 (프로토콜 번호 132)
    if (ip->protocol != IPPROTO_SCTP) {
        // SCTP 패킷을 드롭하거나 특정 작업을 수행할 수 있음
        return XDP_PASS;  // SCTP 패킷을 드롭합니다
    }
    struct sctphdr *sctp = (struct sctphdr *)((__u8 *)ip + sizeof(struct iphdr));
    if ((void *)(sctp + 1) > data_end){        
        return XDP_PASS;
    }
    u32 saddr = ip->saddr;
    u32 sport = sctp->source;
    u32 packet_length = data_end - data;
    struct address addr;
    addr.ip = saddr;
    addr.port = sport;
    struct chaser temp;
    temp.count = 0;
    temp.time = 0;
    temp.is_banned = 0;
    struct chaser *chas = bpf_map_lookup_elem(&blacklist_arr, &addr);
    if(chas){
        u64 time = bpf_ktime_get_ns();
        bpf_printk("time : %lu\nchas->time : %lu", time, chas->time);
        if(time - chas->time > SECOND){
            chas->count = 0;
            chas->time = time;
            chas->is_banned = 0;
        }

        if(chas->is_banned)
            return XDP_DROP;

        if(chas->count > COUNT_THRESHOLD){
            chas->is_banned = 1;
            bpf_map_update_elem(&blacklist_arr, &addr, chas, BPF_ANY);
            struct event *new_event = NULL;
            new_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
            if (new_event == NULL) {
                return XDP_PASS;
            }

            new_event->size = packet_length;
            new_event->saddr = saddr;
            new_event->sport = sport;
            bpf_ringbuf_submit(new_event, 0);
            
            return XDP_DROP;
        }
    }
    __u32 idx_idx = 0;
    __u32 temp_arr[3];
    for(int i = 0; i < 3; i++)
        temp_arr[i] = 0;
    __u32 *status = bpf_map_lookup_elem(&status_arr, &idx_idx);
    if(!status){
        status = temp_arr;
    }

    __u32 idx = status[0];
    __u32 avg = status[1];
    __u32 is_full = status[2];
 
    if(!is_full){
        u32 next_idx = idx + 1;
        u32 next_is_full = is_full;
        u32 next_avg;

        if(idx > MAX_ARR_LEN-2){
            next_is_full = 1;
            next_idx = 0;
        }
        if(idx == 0)
            next_avg = packet_length;
        else{
            next_avg = (avg * idx + packet_length) / (idx + 1);
        }

        status[0] = next_idx;
        status[1] = next_avg;
        status[2] = next_is_full;
        bpf_map_update_elem(&length_arr, &idx, &packet_length, BPF_ANY);
        bpf_map_update_elem(&status_arr, &idx_idx, status, BPF_ANY);
        return XDP_PASS;
    }

    if(packet_length > avg * (THRESHOLD + 100) / 100){
        if(!chas)
            chas = &temp;
        chas->count = chas->count + 1;
        bpf_map_update_elem(&blacklist_arr, &addr, chas, BPF_ANY);
        return XDP_PASS;
    }

    bpf_printk("XDP triggered! packet length : %d, source IP : %ld, source Port : %ld", packet_length, saddr, sport);

    u32 next_idx = idx + 1;
    u32 next_avg;
    if(idx > MAX_ARR_LEN - 2)
        next_idx = 0;
    u32 *old_value = bpf_map_lookup_elem(&length_arr, &idx);
    if(!old_value)
        return XDP_PASS;

    status[0] = next_idx;
    next_avg = (avg * MAX_ARR_LEN - (*old_value) + packet_length) / MAX_ARR_LEN;
    status[1] = next_avg;
    bpf_map_update_elem(&length_arr, &idx, &packet_length, BPF_ANY);
    bpf_map_update_elem(&status_arr, &idx_idx, status, BPF_ANY);

    return XDP_PASS;
}
