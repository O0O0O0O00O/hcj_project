#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

struct arp_t{
  unsigned short htype;//硬件类型
  unsigned short ptype;
  unsigned char hlen;	
  unsigned char plen;
  unsigned short oper;
  unsigned long long sha:48;
  unsigned long long spa:32;
  unsigned long long tha:48;
  unsigned long long tha:48;
  unsigned int	tpa;
}__attribute__((packed));

struct bpf_map_def SEC("maps") ip_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 100000,
};

struct bpf_map_def SEC("maps") tcp_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 100000,
};

struct bpf_map_def SEC("maps") udp_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 100000,
};




SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx){
    //获取报文
    void *data = (void *)(long)ctx->data;
    void *date_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    int offset;
    __u8 protocol;

    if(eth->h_proto == htons(ETH_P_ARP)){
        //arp报文 处理步骤
    }

    if(eth->h_proto == htons(ETH_P_IP)){
        offset = sizeof(struct ethhdr);
        ip = data + offset;
        protocol = ip->protocol;
        //如果在黑名单内
        if(bpf_map_lookup_elem(&ip_blacklist, protocol)){
            return XDP_DROP;
        }
        //如果传输层协议为TCP
        if(protocol == IPPROTO_TCP){
            offset += sizeof(struct iphdr);
            struct tcphdr *tcp = data + offset;
            if(bpf_map_lookup_elem(&tcp_blacklist, tcp->dest)){
                return XDP_DROP;
            }
        }

    }


    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";