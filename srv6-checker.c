#define IPV6_EXT_ROUTING 43
#define IPV6_ENCAP 41 // [RFC2473]

#define ipv6_optlen(p) (((p)->hdrlen + 1) << 3)

#define MAX_SEG_LIST 1
#define AF_INET6 10

#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

struct ip6_addr_t {
  unsigned long long hi;
  unsigned long long lo;
};

struct ip6_srh_t {
  unsigned char nexthdr;
  unsigned char hdrlen;
  unsigned char type;
  unsigned char segments_left;
  unsigned char first_segment;
  unsigned char flags;
  unsigned short tag;

  struct ip6_addr_t segments[0];
};

SEC("srv6-checker")
int xdp_srv6_checker(struct xdp_md *ctx) {
  volatile struct ethhdr old_ehdr;
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  int rc;

  struct ethhdr *ehdr = data;
  if (ehdr + 1 > data_end) // bounds checking
    goto out;
  old_ehdr = *ehdr;

  if (bpf_ntohs(ehdr->h_proto) != ETH_P_IPV6) {
    goto out;
  }

  // IPv6 Header
  struct ipv6hdr *ip6_srv6_hdr = (void *)(ehdr + 1);
  if (ip6_srv6_hdr + 1 > data_end)
    goto out;
  if (ip6_srv6_hdr->nexthdr != IPV6_EXT_ROUTING) {
    goto out;
  }

  // Routing Header
  struct ip6_srh_t *ip6_hdr = (struct ip6_srh_t *)(ip6_srv6_hdr + 1);
  if (ip6_hdr + 1 > data_end)
    goto out;
  if (ip6_hdr->nexthdr != IPV6_ENCAP)
    goto out;

  struct ip6_addr_t *seg;
  seg = (struct ip6_addr_t *)(ip6_hdr + 1);

  if (seg + ip6_hdr->segments_left + 1 > data_end)
    goto out;
  seg = seg + ip6_hdr->segments_left;

  struct bpf_fib_lookup fib_params = {};
  struct in6_addr *src = (struct in6_addr *)fib_params.ipv6_src;
  struct in6_addr *dst = (struct in6_addr *)fib_params.ipv6_dst;

  fib_params.family = AF_INET6;
  __u16 protocol = 60;
  fib_params.l4_protocol = bpf_ntohs(protocol); // udp
  fib_params.sport = 0;
  fib_params.dport = 0;
  *src = ip6_srv6_hdr->saddr;
  *dst = *(struct in6_addr *)seg;

  fib_params.ifindex = ctx->ingress_ifindex;
  rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 3);

  bpf_printk("rc: %d, if_ctx: %d, ifindex: %d", rc, fib_params.ifindex, ctx->ingress_ifindex);
  bpf_printk("%x%x%x", \
    dst->s6_addr[0], \
    dst->s6_addr[1], \
    dst->s6_addr[2]);

    bpf_printk("%x%x%x", \
    dst->s6_addr[3], \
    dst->s6_addr[4], \
    dst->s6_addr[5]);

    bpf_printk("%x%x%x", \
    dst->s6_addr[13], \
    dst->s6_addr[14], \
    dst->s6_addr[15]);

  
  /*
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
      return XDP_PASS;
  */

  if (fib_params.ifindex != ctx->ingress_ifindex)
    return XDP_DROP;

out:
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";