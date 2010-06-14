/*
 * Copyright (C) 1998
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: net_read.c,v 1.7 2001/03/26 07:23:03 kjc Exp kjc $
 */
/* net_read.c -- a module to read ethernet packets.
   most parts are derived from tcpdump. */
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * tcpdump - monitor tcp/ip traffic on an ethernet.
 *
 * First written in 1987 by Van Jacobson, Lawrence Berkeley Laboratory.
 * Mercilessly hacked and occasionally improved since then via the
 * combined efforts of Van, Steve McCanne and Craig Leres of LBL.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#if defined(LINUX)
#include "queue.h"
#else
#include <sys/queue.h>
#endif
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#if defined(LINUX)
#define __FAVOR_BSD
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <pcap.h>
#ifdef PCAP_HEADERS
#include "llc.h"
#include "fddi.h"
#else
#include "ttt_pcap.h"
#endif
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include "tcpdstat.h"

#define	NULL_HDRLEN 4	/* DLT_NULL header length */

#define IP4F_TABSIZE		64	/* IPv4 fragment cache size */

#if defined(FREEBSD)
/*
 * the following macros are FreeBSD extension.  there are two incompatible
 * TAILQ_LAST defines in FreeBSD (changed after 2.2.6), so use the new one.
 */
#ifndef TAILQ_EMPTY
#define	TAILQ_EMPTY(head) ((head)->tqh_first == NULL)
#endif
#undef TAILQ_LAST
#define	TAILQ_LAST(head, headname) \
	(*(((struct headname *)((head)->tqh_last))->tqh_last))
#endif

void net_read(int clientdata, int mask);
static void dump_reader(u_char *user, const struct
			  pcap_pkthdr *h, const u_char *p);
static void ether_if_read(u_char *user, const struct pcap_pkthdr *h,
			  const u_char *p);
static void fddi_if_read(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *p);
static void atm_if_read(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *p);
static void ppp_if_read(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *p);
static void null_if_read(u_char *user, const struct pcap_pkthdr *h,
			 const u_char *p);
static int ether_encap_read(const u_short ethtype, const u_char *p,
			    const int length, const int caplen);
static int llc_read(const u_char *p, const int length, const int caplen);
static int ip_read(const u_char *bp, const int length, const int caplen);
static void ip4f_cache(struct ip *, struct udphdr *);
static struct udphdr *ip4f_lookup(struct ip *);
static int ip4f_init(void);
static struct ip4_frag *ip4f_alloc(void);
static void ip4f_free(struct ip4_frag *);
#ifdef INET6
static int ip6_read(const u_char *bp, const int length, const int caplen);
static int read_ip6hdr(struct ip6_hdr *ip6, int *proto, int caplen);
#endif
static void check_port(int sport, int dport, enum protos type);

char errbuf[PCAP_ERRBUF_SIZE];
char *device;
char *cmdbuf;
pcap_t *pd;
int pcapfd;

static int packet_length;		/* length of current packet */

#define STAT_ADD(name) \
    { tcpdstat[(name)].packets++; tcpdstat[(name)].bytes += packet_length; }


/* a function switch to read different types of frames */
static void (*net_reader)(u_char *user, const struct
			  pcap_pkthdr *h, const u_char *p);

struct ip4_frag {
    TAILQ_ENTRY(ip4_frag) ip4f_chain;
    char    ip4f_valid;
    u_char ip4f_proto;
    u_short ip4f_id;
    struct in_addr ip4f_src, ip4f_dst;
    struct udphdr ip4f_udphdr;
};

static TAILQ_HEAD(ip4f_list, ip4_frag) ip4f_list; /* IPv4 fragment cache */

struct printer {
	pcap_handler f;
	int type;
};

static struct printer printers[] = {
	{ ether_if_read,	DLT_EN10MB },
	{ fddi_if_read,	DLT_FDDI },
#ifdef DLT_ATM_RFC1483
	{ atm_if_read,	DLT_ATM_RFC1483 },
#endif
	{ ppp_if_read,	DLT_PPP },
	{ null_if_read,	DLT_NULL },
	{ NULL,			0 },
};

static pcap_handler
lookup_printer(int type)
{
	struct printer *p;

	for (p = printers; p->f; ++p)
		if (type == p->type)
			return p->f;

	err(1, "lookup_printer: unknown data link type 0x%x", type);
	/* NOTREACHED */
	return NULL;
}

void close_dump(void)
{
    pcap_close(pd);
}

int open_dump(char *file)
{
    int fd;

    pd = pcap_open_offline(file, errbuf);
    if (pd == NULL)
	err(1, "%s", errbuf);

    net_reader = lookup_printer(pcap_datalink(pd));

    fd = fileno(pcap_file(pd));

    return fd;
}

int read_dump(void)
{
    int rval;

    if (read_count > 0 && tcpdstat[TOTAL].packets == read_count)
	return (0);

    rval = pcap_dispatch(pd, 1, dump_reader, 0);
    if (rval < 0)
	(void)fprintf(stderr, "pcap_dispatch:%s\n", pcap_geterr(pd));

    return (rval);
}

static void dump_reader(u_char *user, const struct
			  pcap_pkthdr *h, const u_char *p)
{
    double diff, bps;
    static long cur_sec;
    static u_int bytes_per_sec = 0;

    if (start_time.tv_sec == 0) {
	/* first packet. do initialization. */
	start_time = h->ts;
	cur_sec = h->ts.tv_sec;
    }
    end_time = h->ts;	/* keep the timestamp of the last packet */

    if (h->caplen > caplen_max)
	caplen_max = h->caplen;
    caplen_total += h->caplen;

    packet_length = h->len;
    pktsize_add(packet_length);
    STAT_ADD(TOTAL);

    /* measure the traffic rate in bps every second. */
    if (cur_sec == start_time.tv_sec) {
	/* start the measurement at the next time interval. */
	if (h->ts.tv_sec > cur_sec) {
	    cur_sec = h->ts.tv_sec;
	    bytes_per_sec += packet_length;
	}
    }
    else {
	if (h->ts.tv_sec > cur_sec) {
	    rate_count += h->ts.tv_sec - cur_sec;
	    bps = (double)(bytes_per_sec * 8);
	    diff = bps - rate_mean;
	    
	    rate_mean += diff / rate_count;
	    rate_var += (rate_count - 1) * diff * diff / rate_count;

            if (bps > rate_max)
                rate_max = bps;

	    bytes_per_sec = 0;
	    cur_sec = h->ts.tv_sec;
	}
	bytes_per_sec += packet_length;
    }

    (*net_reader)(user, h, p);
}


static void ether_if_read(u_char *user, const struct pcap_pkthdr *h,
			  const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;
    struct ether_header *ep;
    u_short ether_type;

    if (caplen < sizeof(struct ether_header)) {
	return;
    }

    ep = (struct ether_header *)p;
    p += sizeof(struct ether_header);
    length -= sizeof(struct ether_header);
    caplen -= sizeof(struct ether_header);

    ether_type = ntohs(ep->ether_type);
    if (ether_type < ETHERMTU) {
	if (llc_read(p, length, caplen) == 0) {
	    /* ether_type not known */
	}
    }
    else if (ether_encap_read(ether_type, p, length, caplen) == 0) {
	/* ether_type not known */
    }
}

static int ether_encap_read(const u_short ethtype, const u_char *p,
			    const int length, const int caplen)
{

#if 0
    /* people love to see the total traffic! */
    if (ethtype != ETHERTYPE_IP)
#endif
#if 0
	eth_addsize(ethtype, length);
#endif

    if (ethtype == ETHERTYPE_IP)
	ip_read(p, length, caplen);
#ifdef INET6
    else if (ethtype == ETHERTYPE_IPV6)
	ip6_read(p, length, caplen);
#endif
    return (1);
}


static void fddi_if_read(u_char *pcap, const struct pcap_pkthdr *h,
			 const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;
    const struct fddi_header *fddip = (struct fddi_header *)p;

    if (caplen < FDDI_HDRLEN)
	return;
    
    /* Skip over FDDI MAC header */
    length -= FDDI_HDRLEN;
    p += FDDI_HDRLEN;
    caplen -= FDDI_HDRLEN;

    /* Frame Control field determines interpretation of packet */
    if ((fddip->fddi_fc & FDDIFC_CLFF) == FDDIFC_LLC_ASYNC) {
	/* Try to print the LLC-layer header & higher layers */
	if (llc_read(p, length, caplen) == 0) {
	    /* some kinds of LLC packet we cannot handle intelligently */
	}
    }
    else {
	/* Some kinds of FDDI packet we cannot handle intelligently */
    }
}

#ifndef min
#define min(a, b)	(((a)<(b))?(a):(b))
#endif

static int llc_read(const u_char *p, const int length, const int caplen)
{
    struct llc llc;
    register u_short et;
    register int ret;
    
    if (caplen < 3) {
	return(0);
    }

    /* Watch out for possible alignment problems */
    bcopy((char *)p, (char *)&llc, min(caplen, sizeof(llc)));

#if 0  /* we are not interested in these */
    if (llc.ssap == LLCSAP_GLOBAL && llc.dsap == LLCSAP_GLOBAL) {
	/* ipx */
	return (1);
    }
    else if (p[0] == 0xf0 && p[1] == 0xf0) {
	/* netbios */
    }
    if (llc.ssap == LLCSAP_ISONS && llc.dsap == LLCSAP_ISONS
	&& llc.llcui == LLC_UI) {
	/* iso */
    }
#endif /* 0 */

    if (llc.ssap == LLCSAP_SNAP && llc.dsap == LLCSAP_SNAP
	&& llc.llcui == LLC_UI) {
	/* snap */
	if (caplen < sizeof(llc)) {
	    return (0);
	}
	/* This is an encapsulated Ethernet packet */
#ifdef ALIGN_WORD
    {
	u_short tmp;
	bcopy(&llc.ethertype[0], &tmp, sizeof(u_short));
	et = ntohs(tmp);
    }
#else
	et = ntohs(*(u_short *)&llc.ethertype[0]);
#endif
	ret = ether_encap_read(et, p + sizeof(llc),
			       length - sizeof(llc), caplen - sizeof(llc));
	if (ret)
	    return (ret);
    }
    /* llcsap */
    return(0);
}

static void atm_if_read(u_char *pcap, const struct pcap_pkthdr *h,
			const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;
    u_short ether_type;

    if (caplen < 8)
	return;

    if (p[0] != 0xaa || p[1] != 0xaa || p[2] != 0x03) {
	/* unknown format! */
	return;
    }
    ether_type = p[6] << 8 | p[7];

#if 0
    eth_addsize(ether_type, length);
#endif

    length -= 8;
    caplen -= 8;
    p += 8;

    switch (ether_type) {
    case ETHERTYPE_IP:
	ip_read(p, length, caplen);
	break;
#ifdef INET6
    case ETHERTYPE_IPV6:
	ip6_read(p, length, caplen);
	break;
#endif
    }
}

/* just trim 4 byte ppp header */
static void ppp_if_read(u_char *pcap, const struct pcap_pkthdr *h,
			const u_char *p)
{
    int caplen = h->caplen;
    int length = h->len;

    if (caplen < 4)
	return;

    length -= 4;
    caplen -= 4;
    p += 4;

    ip_read(p, length, caplen);
}

static void null_if_read(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	int length = h->len;
	int caplen = h->caplen;
	const struct ip *ip;

	length -= NULL_HDRLEN;
	caplen -= NULL_HDRLEN;
	ip = (struct ip *)(p + NULL_HDRLEN);

	ip_read((const u_char *)ip, length, caplen);
}

static int ip_read(const u_char *bp, const int length, const int caplen)
{
    struct ip *ip;
    int hlen, len, proto, off;
    u_short srcport, dstport;
    struct tcphdr *tcp;
    struct udphdr *udp;
    
    ip = (struct ip *)bp;
    if (length < sizeof (struct ip))
	return 0;
#ifdef ALIGN_WORD
    /*
     * The IP header is not word aligned, so copy into abuf.
     * This will never happen with BPF.  It does happen raw packet
     * dumps from -r.
     */
    if ((int)ip & (sizeof(long)-1)) {
	static u_char *abuf;

	if (abuf == 0)
	    abuf = (u_char *)malloc(DEFAULT_SNAPLEN);
	bcopy((char *)ip, (char *)abuf, caplen);
	ip = (struct ip *)abuf;
    }
#endif /* ALIGN_WORD */

    STAT_ADD(IP);

    hlen = ip->ip_hl * 4;
    len = min(ntohs(ip->ip_len), length);

    if (use_ipflow) {
	if (ipflow_count(AF_INET, ip, packet_length) < 0) {
	    fprintf(stderr, "malloc failed!  disable ip flow count.\n");
	    ipflow_destroy();
	    use_ipflow = 0;
	}
    }

    len -= hlen;
    bp = (u_char *)ip + hlen;

    proto = ip->ip_p;

    switch(proto) {
    case 1: 		STAT_ADD(ICMP_IP); break;
    case 2: 		STAT_ADD(IGMP_IP); break;
    case 3:		STAT_ADD(GGP_IP); break;
    case 4: 		STAT_ADD(IP_IP); break;
    case 5:		STAT_ADD(ST_IP); break;
    case 6:		STAT_ADD(TCP_IP); break;
    case 7:		STAT_ADD(CBT_IP); break;
    case 8:		STAT_ADD(EGP_IP); break;
    case 9:		STAT_ADD(IGP_IP); break;
    case 10:		STAT_ADD(BBN_RCC_MON_IP); break;
    case 11:		STAT_ADD(NVP_IP); break;
    case 12:		STAT_ADD(PUP_IP); break;
    case 13:		STAT_ADD(ARGUS_IP); break;
    case 14:		STAT_ADD(EMCON_IP); break;
    case 15:		STAT_ADD(XNET_IP); break;
    case 16:		STAT_ADD(CHAOS_IP); break;
    case 17:		STAT_ADD(UDP_IP); break;
    case 18:		STAT_ADD(MUX_IP); break;
    case 19:		STAT_ADD(DCN_MEAS_IP); break;
    case 20:		STAT_ADD(HMP_IP); break;
    case 21:		STAT_ADD(PRM_IP); break;
    case 22:		STAT_ADD(XNS_IDP_IP); break;
    case 23:		STAT_ADD(TRUNK1_IP); break;
    case 24:		STAT_ADD(TRUNK2_IP); break;
    case 25:		STAT_ADD(LEAF1_IP); break;
    case 26:		STAT_ADD(LEAF2_IP); break;
    case 27: 		STAT_ADD(RDP_IP); break;
    case 28: 		STAT_ADD(IRTP_IP); break;
    case 29: 		STAT_ADD(ISO_TP4_IP); break;
    case 30:		STAT_ADD(NETBLT_IP); break;
    case 31:		STAT_ADD(MFE_NSP_IP); break;
    case 32:		STAT_ADD(MERIT_INP_IP); break;
    case 33:		STAT_ADD(SEP_IP); break;
    case 34:		STAT_ADD(THREE_PC_IP); break;
    case 35:		STAT_ADD(IDPR_IP); break;
    case 36:		STAT_ADD(XTP_IP); break;
    case 37:		STAT_ADD(DDP_IP); break;
    case 38:		STAT_ADD(IDPR_CMTP_IP); break;
    case 39:		STAT_ADD(TPTP_IP); break;
    case 40:		STAT_ADD(IL_IP); break;
    case 41: 		STAT_ADD(IP6_IP); break;
    case 42: 		STAT_ADD(SDRP_IP); break;
    case 43: 		STAT_ADD(IP6_RH_IP); break;
    case 44: 		STAT_ADD(IP6_FH_IP); break;
    case 45: 		STAT_ADD(IDRP_IP); break;
    case 46: 		STAT_ADD(RSVP_IP); break;
    case 47: 		STAT_ADD(GRE_IP); break;
    case 48: 		STAT_ADD(MHRP_IP); break;
    case 49: 		STAT_ADD(BNA_IP); break;
    case 50: 		STAT_ADD(ESP_IP); break;
    case 51: 		STAT_ADD(AH_IP); break;
    case 52: 		STAT_ADD(I_NLSP_IP); break;
    case 53: 		STAT_ADD(SWIPE_IP); break;
    case 54: 		STAT_ADD(NARP_IP); break;
    case 55: 		STAT_ADD(MOBILE_IP); break;
    case 56: 		STAT_ADD(TLSP_IP); break;
    case 57: 		STAT_ADD(SKIP_IP); break;
    case 58: 		STAT_ADD(IP6_ICMP_IP); break;
    case 59: 		STAT_ADD(IP6_NNH_IP); break;
    case 60: 		STAT_ADD(IP6_OPTS_IP); break;
    case 61: 		STAT_ADD(AHI_IP); break;
    case 62: 		STAT_ADD(CFTP_IP); break;
    case 63: 		STAT_ADD(ANY_LOCAL_IP); break;
    case 64: 		STAT_ADD(SAT_EXPAK_IP); break;
    case 65: 		STAT_ADD(KRYPTOLAN_IP); break;
    case 66: 		STAT_ADD(RVD_IP); break;
    case 67: 		STAT_ADD(IPPC_IP); break;
    case 68: 		STAT_ADD(ANY_DIST_IP); break;
    case 69: 		STAT_ADD(SAT_MON_IP); break;
    case 70: 		STAT_ADD(VISA_IP); break;
    case 71: 		STAT_ADD(IPCV_IP); break;
    case 72: 		STAT_ADD(CPNX_IP); break;
    case 73: 		STAT_ADD(CPHB_IP); break;
    case 74: 		STAT_ADD(WSN_IP); break;
    case 75: 		STAT_ADD(PVP_IP); break;
    case 76: 		STAT_ADD(BR_SAT_MON_IP); break;
    case 77: 		STAT_ADD(SUN_ND_IP); break;
    case 78: 		STAT_ADD(WB_MON_IP); break;
    case 79: 		STAT_ADD(WB_EXPAK_IP); break;
    case 80: 		STAT_ADD(ISO_IP_IP); break;
    case 81: 		STAT_ADD(VMTP_IP); break;
    case 82: 		STAT_ADD(SECURE_VMTP_IP); break;
    case 83: 		STAT_ADD(VINES_IP); break;
    case 84: 		STAT_ADD(TTP_IP); break;
    case 85: 		STAT_ADD(NSFNET_IGP_IP); break;
    case 86: 		STAT_ADD(DGP_IP); break;
    case 87: 		STAT_ADD(TCF_IP); break;
    case 88: 		STAT_ADD(EIRGP_IP); break;
    case 89: 		STAT_ADD(OSPFIGP_IP); break;
    case 90: 		STAT_ADD(SPRITE_RPC_IP); break;
    case 91: 		STAT_ADD(LARP_IP); break;
    case 92: 		STAT_ADD(MTP_IP); break;
    case 93: 		STAT_ADD(AX25_IP); break;
    case 94: 		STAT_ADD(IPIP_IP); break;
    case 95: 		STAT_ADD(MICP_IP); break;
    case 96: 		STAT_ADD(SCC_SP_IP); break;
    case 97: 		STAT_ADD(ETHERIP_IP); break;
    case 98: 		STAT_ADD(ENCAP_IP); break;
    case 99: 		STAT_ADD(ANY_ENCRYPT_IP); break;
    case 100: 		STAT_ADD(GMTP_IP); break;
    case 101: 		STAT_ADD(IFMP_IP); break;
    case 102: 		STAT_ADD(PNMI_IP); break;
    case 103: 		STAT_ADD(PIM_IP); break;
    case 104: 		STAT_ADD(ARIS_IP); break;
    case 105: 		STAT_ADD(SCPS_IP); break;
    case 106: 		STAT_ADD(QNX_IP); break;
    case 107: 		STAT_ADD(ACTIVE_NETWORKS_IP); break;
    case 108: 		STAT_ADD(IPCOMP_IP); break;
    case 109: 		STAT_ADD(SNP_IP); break;
    case 110: 		STAT_ADD(COMPAQP_IP); break;
    case 111: 		STAT_ADD(IPX_IP_IP); break;
    case 112: 		STAT_ADD(VRRP_IP); break;
    case 113: 		STAT_ADD(PGM_IP); break;
    case 114: 		STAT_ADD(ANY_ZERO_IP); break;
    case 115: 		STAT_ADD(L2TP_IP); break;
    case 116: 		STAT_ADD(DDX_IP); break;
    case 117: 		STAT_ADD(IATP_IP); break;
    case 118: 		STAT_ADD(STP_IP); break;
    case 119: 		STAT_ADD(SRP_IP); break;
    case 120: 		STAT_ADD(UTI_IP); break;
    case 121: 		STAT_ADD(SMP_IP); break;
    case 122: 		STAT_ADD(SM_IP); break;
    case 123: 		STAT_ADD(PTP_IP); break;
    case 124: 		STAT_ADD(ISIS_IP_IP); break;
    case 125: 		STAT_ADD(FIRE_IP); break;
    case 126: 		STAT_ADD(CRTP_IP); break;
    case 127: 		STAT_ADD(CRUDP_IP); break;
    case 128: 		STAT_ADD(SSCOPMCE_IP); break;
    case 129: 		STAT_ADD(IPLT_IP); break;
    case 130: 		STAT_ADD(SPS_IP); break;
    case 131: 		STAT_ADD(PIPE_IP); break;
    case 132: 		STAT_ADD(SCTP_IP); break;
    case 133:		STAT_ADD(FC_IP); break;
    case 134:		STAT_ADD(UNASSIGNED_PROTO_134_IP); break;
    case 135:		STAT_ADD(UNASSIGNED_PROTO_135_IP); break;
    case 136:		STAT_ADD(UNASSIGNED_PROTO_136_IP); break;
    case 137:		STAT_ADD(UNASSIGNED_PROTO_137_IP); break;
    case 138:		STAT_ADD(UNASSIGNED_PROTO_138_IP); break;
    case 139:		STAT_ADD(UNASSIGNED_PROTO_139_IP); break;
    case 140:		STAT_ADD(UNASSIGNED_PROTO_140_IP); break;
    case 141:		STAT_ADD(UNASSIGNED_PROTO_141_IP); break;
    case 142:		STAT_ADD(UNASSIGNED_PROTO_142_IP); break;
    case 143:		STAT_ADD(UNASSIGNED_PROTO_143_IP); break;
    case 144:		STAT_ADD(UNASSIGNED_PROTO_144_IP); break;
    case 145:		STAT_ADD(UNASSIGNED_PROTO_145_IP); break;
    case 146:		STAT_ADD(UNASSIGNED_PROTO_146_IP); break;
    case 147:		STAT_ADD(UNASSIGNED_PROTO_147_IP); break;
    case 148:		STAT_ADD(UNASSIGNED_PROTO_148_IP); break;
    case 149:		STAT_ADD(UNASSIGNED_PROTO_149_IP); break;
    case 150:		STAT_ADD(UNASSIGNED_PROTO_150_IP); break;
    case 151:		STAT_ADD(UNASSIGNED_PROTO_151_IP); break;
    case 152:		STAT_ADD(UNASSIGNED_PROTO_152_IP); break;
    case 153:		STAT_ADD(UNASSIGNED_PROTO_153_IP); break;
    case 154:		STAT_ADD(UNASSIGNED_PROTO_154_IP); break;
    case 155:		STAT_ADD(UNASSIGNED_PROTO_155_IP); break;
    case 156:		STAT_ADD(UNASSIGNED_PROTO_156_IP); break;
    case 157:		STAT_ADD(UNASSIGNED_PROTO_157_IP); break;
    case 158:		STAT_ADD(UNASSIGNED_PROTO_158_IP); break;
    case 159:		STAT_ADD(UNASSIGNED_PROTO_159_IP); break;
    case 160:		STAT_ADD(UNASSIGNED_PROTO_160_IP); break;
    case 161:		STAT_ADD(UNASSIGNED_PROTO_161_IP); break;
    case 162:		STAT_ADD(UNASSIGNED_PROTO_162_IP); break;
    case 163:		STAT_ADD(UNASSIGNED_PROTO_163_IP); break;
    case 164:		STAT_ADD(UNASSIGNED_PROTO_164_IP); break;
    case 165:		STAT_ADD(UNASSIGNED_PROTO_165_IP); break;
    case 166:		STAT_ADD(UNASSIGNED_PROTO_166_IP); break;
    case 167:		STAT_ADD(UNASSIGNED_PROTO_167_IP); break;
    case 168:		STAT_ADD(UNASSIGNED_PROTO_168_IP); break;
    case 169:		STAT_ADD(UNASSIGNED_PROTO_169_IP); break;
    case 170:		STAT_ADD(UNASSIGNED_PROTO_170_IP); break;
    case 171:		STAT_ADD(UNASSIGNED_PROTO_171_IP); break;
    case 172:		STAT_ADD(UNASSIGNED_PROTO_172_IP); break;
    case 173:		STAT_ADD(UNASSIGNED_PROTO_173_IP); break;
    case 174:		STAT_ADD(UNASSIGNED_PROTO_174_IP); break;
    case 175:		STAT_ADD(UNASSIGNED_PROTO_175_IP); break;
    case 176:		STAT_ADD(UNASSIGNED_PROTO_176_IP); break;
    case 177:		STAT_ADD(UNASSIGNED_PROTO_177_IP); break;
    case 178:		STAT_ADD(UNASSIGNED_PROTO_178_IP); break;
    case 179:		STAT_ADD(UNASSIGNED_PROTO_179_IP); break;
    case 180:		STAT_ADD(UNASSIGNED_PROTO_180_IP); break;
    case 181:		STAT_ADD(UNASSIGNED_PROTO_181_IP); break;
    case 182:		STAT_ADD(UNASSIGNED_PROTO_182_IP); break;
    case 183:		STAT_ADD(UNASSIGNED_PROTO_183_IP); break;
    case 184:		STAT_ADD(UNASSIGNED_PROTO_184_IP); break;
    case 185:		STAT_ADD(UNASSIGNED_PROTO_185_IP); break;
    case 186:		STAT_ADD(UNASSIGNED_PROTO_186_IP); break;
    case 187:		STAT_ADD(UNASSIGNED_PROTO_187_IP); break;
    case 188:		STAT_ADD(UNASSIGNED_PROTO_188_IP); break;
    case 189:		STAT_ADD(UNASSIGNED_PROTO_189_IP); break;
    case 190:		STAT_ADD(UNASSIGNED_PROTO_190_IP); break;
    case 191:		STAT_ADD(UNASSIGNED_PROTO_191_IP); break;
    case 192:		STAT_ADD(UNASSIGNED_PROTO_192_IP); break;
    case 193:		STAT_ADD(UNASSIGNED_PROTO_193_IP); break;
    case 194:		STAT_ADD(UNASSIGNED_PROTO_194_IP); break;
    case 195:		STAT_ADD(UNASSIGNED_PROTO_195_IP); break;
    case 196:		STAT_ADD(UNASSIGNED_PROTO_196_IP); break;
    case 197:		STAT_ADD(UNASSIGNED_PROTO_197_IP); break;
    case 198:		STAT_ADD(UNASSIGNED_PROTO_198_IP); break;
    case 199:		STAT_ADD(UNASSIGNED_PROTO_199_IP); break;
    case 200:		STAT_ADD(UNASSIGNED_PROTO_200_IP); break;
    case 201:		STAT_ADD(UNASSIGNED_PROTO_201_IP); break;
    case 202:		STAT_ADD(UNASSIGNED_PROTO_203_IP); break;
    case 203:		STAT_ADD(UNASSIGNED_PROTO_203_IP); break;
    case 204:		STAT_ADD(UNASSIGNED_PROTO_204_IP); break;
    case 205:		STAT_ADD(UNASSIGNED_PROTO_205_IP); break;
    case 206:		STAT_ADD(UNASSIGNED_PROTO_206_IP); break;
    case 207:		STAT_ADD(UNASSIGNED_PROTO_207_IP); break;
    case 208:		STAT_ADD(UNASSIGNED_PROTO_208_IP); break;
    case 209:		STAT_ADD(UNASSIGNED_PROTO_209_IP); break;
    case 210:		STAT_ADD(UNASSIGNED_PROTO_210_IP); break;
    case 211:		STAT_ADD(UNASSIGNED_PROTO_211_IP); break;
    case 212:		STAT_ADD(UNASSIGNED_PROTO_212_IP); break;
    case 213:		STAT_ADD(UNASSIGNED_PROTO_213_IP); break;
    case 214:		STAT_ADD(UNASSIGNED_PROTO_214_IP); break;
    case 215:		STAT_ADD(UNASSIGNED_PROTO_215_IP); break;
    case 216:		STAT_ADD(UNASSIGNED_PROTO_216_IP); break;
    case 217:		STAT_ADD(UNASSIGNED_PROTO_217_IP); break;
    case 218:		STAT_ADD(UNASSIGNED_PROTO_218_IP); break;
    case 219:		STAT_ADD(UNASSIGNED_PROTO_219_IP); break;
    case 220:		STAT_ADD(UNASSIGNED_PROTO_220_IP); break;
    case 221:		STAT_ADD(UNASSIGNED_PROTO_221_IP); break;
    case 222:		STAT_ADD(UNASSIGNED_PROTO_222_IP); break;
    case 223:		STAT_ADD(UNASSIGNED_PROTO_223_IP); break;
    case 224:		STAT_ADD(UNASSIGNED_PROTO_224_IP); break;
    case 225:		STAT_ADD(UNASSIGNED_PROTO_225_IP); break;
    case 226:		STAT_ADD(UNASSIGNED_PROTO_226_IP); break;
    case 227:		STAT_ADD(UNASSIGNED_PROTO_227_IP); break;
    case 228:		STAT_ADD(UNASSIGNED_PROTO_228_IP); break;
    case 229:		STAT_ADD(UNASSIGNED_PROTO_229_IP); break;
    case 230:		STAT_ADD(UNASSIGNED_PROTO_230_IP); break;
    case 231:		STAT_ADD(UNASSIGNED_PROTO_231_IP); break;
    case 232:		STAT_ADD(UNASSIGNED_PROTO_232_IP); break;
    case 233:		STAT_ADD(UNASSIGNED_PROTO_233_IP); break;
    case 234:		STAT_ADD(UNASSIGNED_PROTO_234_IP); break;
    case 235:		STAT_ADD(UNASSIGNED_PROTO_235_IP); break;
    case 236:		STAT_ADD(UNASSIGNED_PROTO_236_IP); break;
    case 237:		STAT_ADD(UNASSIGNED_PROTO_237_IP); break;
    case 238:		STAT_ADD(UNASSIGNED_PROTO_238_IP); break;
    case 239:		STAT_ADD(UNASSIGNED_PROTO_239_IP); break;
    case 240:		STAT_ADD(UNASSIGNED_PROTO_240_IP); break;
    case 241:		STAT_ADD(UNASSIGNED_PROTO_241_IP); break;
    case 242:		STAT_ADD(UNASSIGNED_PROTO_242_IP); break;
    case 243:		STAT_ADD(UNASSIGNED_PROTO_243_IP); break;
    case 244:		STAT_ADD(UNASSIGNED_PROTO_244_IP); break;
    case 245:		STAT_ADD(UNASSIGNED_PROTO_245_IP); break;
    case 246:		STAT_ADD(UNASSIGNED_PROTO_246_IP); break;
    case 247:		STAT_ADD(UNASSIGNED_PROTO_247_IP); break;
    case 248:		STAT_ADD(UNASSIGNED_PROTO_248_IP); break;
    case 249:		STAT_ADD(UNASSIGNED_PROTO_249_IP); break;
    case 250:		STAT_ADD(UNASSIGNED_PROTO_250_IP); break;
    case 251:		STAT_ADD(UNASSIGNED_PROTO_251_IP); break;
    case 252:		STAT_ADD(UNASSIGNED_PROTO_252_IP); break;
    case 253:		STAT_ADD(UNASSIGNED_PROTO_253_IP); break;
    case 254:		STAT_ADD(UNASSIGNED_PROTO_254_IP); break;
    case 255:		STAT_ADD(RESERVED_255_IP); break;
    default: 		STAT_ADD(OTHER_IP);
	    		if (debug)
				printf("debug: other proto=%d\n", proto);
	    		break;
    }

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
	/* if this is fragment zero, hand it to the next higher
	   level protocol. */
	off = ntohs(ip->ip_off);
	if (off & 0x1fff) {
	    /* process fragments */
	    STAT_ADD(FRAG_IP);
	    if ((bp = (u_char *)ip4f_lookup(ip)) == NULL)
		/* lookup failed */
		return 1;
	}

	if (proto == IPPROTO_TCP) {
	    if (len < sizeof (struct tcphdr))
		return 0;
	    tcp = (struct tcphdr *)bp;
	    srcport = ntohs(tcp->th_sport);
	    dstport = ntohs(tcp->th_dport);

	    check_port(srcport, dstport, TCP_IP);
	}
	else {
	    if (len < sizeof (struct udphdr))
		return 0;
	    udp = (struct udphdr *)bp;
	    srcport = ntohs(udp->uh_sport);
	    dstport = ntohs(udp->uh_dport);

	    if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
		STAT_ADD(MCAST_UDP);
	    }
	    else
		check_port(srcport, dstport, UDP_IP);
	}

	/* if this is a first fragment, cache it. */
	if ((off & IP_MF) && (off & 0x1fff) == 0) {
	    STAT_ADD(FRAG_IP);
	    ip4f_cache(ip, (struct udphdr *)bp);
	}
    }

    return 1;
}

#ifdef INET6
/* this version doesn't handle fragments */
static int ip6_read(const u_char *bp, const int length, const int caplen)
{
    struct ip6_hdr *ip6;
    int hlen, len, proto;
    u_short srcport, dstport;
    struct tcphdr *tcp;
    struct udphdr *udp;
    
    ip6 = (struct ip6_hdr *)bp;
    if (length < sizeof (struct ip6_hdr))
	return 0;
#ifdef ALIGN_WORD
    /*
     * The IP header is not word aligned, so copy into abuf.
     * This will never happen with BPF.  It does happen raw packet
     * dumps from -r.
     */
    if ((int)ip6 & (sizeof(long)-1)) {
	static u_char *abuf;

	if (abuf == 0)
	    abuf = (u_char *)malloc(DEFAULT_SNAPLEN);
	bcopy((char *)ip6, (char *)abuf, caplen);
	ip6 = (struct ip6_hdr *)abuf;
    }
#endif /* ALIGN_WORD */

    hlen = read_ip6hdr(ip6, &proto, caplen);
    len = min(ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr), length) - hlen;
    bp = (u_char *)ip6 + hlen;

    STAT_ADD(IP6);

    if (use_ipflow) {
	if (ipflow_count(AF_INET6, (struct ip *)ip6, packet_length) < 0) {
	    fprintf(stderr, "malloc failed!  disable ip flow count.\n");
	    ipflow_destroy();
	    use_ipflow = 0;
	}
    }

    switch(proto) {
    case IPPROTO_TCP:	STAT_ADD(TCP_IP6); break;
    case IPPROTO_UDP:	STAT_ADD(UDP_IP6); break;
    case 58: 		STAT_ADD(ICMP_IP6); break;
    case 89: 		STAT_ADD(OSPF_IP6); break;
    case 4: 		STAT_ADD(IP_IP6); break;
    case 41: 		STAT_ADD(IP6_IP6); break;
    case 51: 		/* ah */
    case 50: 		STAT_ADD(IPSEC_IP6); break;
    case 0: 		STAT_ADD(HBHOPT_IP6); break;
    case 43: 		STAT_ADD(RTOPT_IP6); break;
    case 60: 		STAT_ADD(DSTOPT_IP6); break;
    case 103: 		STAT_ADD(PIM_IP6); break;
    case 132: 		STAT_ADD(SCTP_IP6); break;
    default: 		STAT_ADD(OTHER_IP6);
	    		if (debug)
				printf("debug: other ip6 proto=%d\n", proto);
	    		break;
    }

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)  {
	if (proto == IPPROTO_TCP) {
	    if (len < sizeof (struct tcphdr))
		return 0;
	    tcp = (struct tcphdr *)bp;
	    srcport = ntohs(tcp->th_sport);
	    dstport = ntohs(tcp->th_dport);

	    check_port(srcport, dstport, TCP_IP6);
	}
	else {
	    if (len < sizeof (struct udphdr))
		return 0;
	    udp = (struct udphdr *)bp;
	    srcport = ntohs(udp->uh_sport);
	    dstport = ntohs(udp->uh_dport);
	
	    check_port(srcport, dstport, UDP_IP6);
	}
    }
    return 1;
}

static int read_ip6hdr(struct ip6_hdr *ip6, int *proto, int caplen)
{
    int hlen, opt_len;
    struct ip6_hbh *ip6ext;
    u_char nh;

    hlen = sizeof(struct ip6_hdr);
    caplen -= hlen;
    nh = ip6->ip6_nxt;
    ip6ext = (struct ip6_hbh *)(ip6 + 1);
    while (nh == IPPROTO_HOPOPTS || nh == IPPROTO_ROUTING ||
	   nh == IPPROTO_AH || nh == IPPROTO_DSTOPTS) {
	if (nh == IPPROTO_AH)
	    opt_len = 8 + (ip6ext->ip6h_len * 4);
	else
	    opt_len = (ip6ext->ip6h_len + 1) * 8;
	hlen += opt_len;
	if ((caplen -= opt_len) < 0)
	    break;
	nh = ip6ext->ip6h_nxt;
	ip6ext = (struct ip6_hbh *)((caddr_t)ip6ext  + opt_len);
    }
    *proto = (int)nh;
    return hlen;
}

#endif /* INET6 */

static void check_port(int sport, int dport, enum protos type)
{
	int port;

	port = sport;

	if (type == TCP_IP) {
	tcp:
		switch (port) {
		case 20:	STAT_ADD(FTPDATA_TCP); break;
		case 21:	STAT_ADD(FTP_TCP); break;
		case 22:	STAT_ADD(SSH_TCP); break;
		case 23:	STAT_ADD(TELNET_TCP); break;
		case 25:	STAT_ADD(SMTP_TCP); break;
		case 42:	STAT_ADD(NAME_TCP); break;
		case 53:	STAT_ADD(DNS_TCP); break;
		case 80:/* special rule for http: distinguish src & dst */
			if (port == sport) { 
				STAT_ADD(HTTP_S_TCP);
			} else {
				STAT_ADD(HTTP_C_TCP);
			}
			break;
		case 88:	STAT_ADD(KERB5_TCP); break;
		case 110:	STAT_ADD(POP3_TCP); break;
		case 111:	STAT_ADD(SUNRPC_TCP); break;
		case 113:	STAT_ADD(IDENT_TCP); break;
		case 119:	STAT_ADD(NNTP_TCP); break;
		case 123:	STAT_ADD(NTP_TCP); break;
		case 135:	STAT_ADD(EPMAP_TCP); break;
		case 137:	STAT_ADD(NETBIOS_NS_TCP); break;
		case 139:	STAT_ADD(NETBIOS_SSN_TCP); break;
		case 143:	STAT_ADD(IMAP_TCP); break;
		case 179:	STAT_ADD(BGP_TCP); break;
		case 389:	STAT_ADD(LDAP_TCP); break;
		case 443:	STAT_ADD(HTTPS_TCP); break;
		case 445:	STAT_ADD(MS_DS_TCP); break;
		case 513:	STAT_ADD(RLOGIN_TCP); break;
		case 554:	STAT_ADD(RTSP_TCP); break;
		case 636:	STAT_ADD(LDAPS_TCP); break;
		case 1080:	STAT_ADD(SOCKS_TCP); break;
		case 1214:	STAT_ADD(KAZAA_TCP); break;
		case 1433:	STAT_ADD(MS_SQL_S_TCP); break;
		case 3128:	STAT_ADD(SQUID_TCP); break;
		case 3268:	STAT_ADD(MS_GC_TCP); break;
		case 3269:	STAT_ADD(MS_GCS_TCP); break;
		case 3306:	STAT_ADD(MYSQL_TCP); break;
		case 5501:	STAT_ADD(HOTLINE_TCP); break;
		case 6346:	STAT_ADD(GNU6346_TCP); break;
		case 6347:	STAT_ADD(GNU6347_TCP); break;
		case 6348:	STAT_ADD(GNU6348_TCP); break;
		case 6349:	STAT_ADD(GNU6349_TCP); break;
		case 6350:	STAT_ADD(GNU6350_TCP); break;
		case 6355:	STAT_ADD(GNU6355_TCP); break;
		case 6666:	STAT_ADD(IRC6666_TCP); break;
		case 6667:	STAT_ADD(IRC6667_TCP); break;
		case 6668:	STAT_ADD(IRC6668_TCP); break;
		case 6669:	STAT_ADD(IRC6669_TCP); break;
		case 6688:	/* napster */
		case 6699:	STAT_ADD(NAPSTER_TCP); break;
		case 7000:	STAT_ADD(IRC7000_TCP); break;
		case 7070:	STAT_ADD(REALAUDIO_TCP); break;
		case 8000:	STAT_ADD(SHOUTCAST_TCP); break;
		case 8080:	STAT_ADD(HTTP_A_TCP); break;
		case 9000:	STAT_ADD(HTTP_TW_TCP); break;
		case 9443:	STAT_ADD(HTTP_TWS_TCP); break;
		case 11211:	STAT_ADD(MEMCACHED_TCP); break;
		case 22133:	STAT_ADD(KESTREL_TCP); break;
		default:
			if (port == dport) {
				STAT_ADD(OTHER_TCP);
				if (debug)
					printf("debug: other tcp sport=%d,dport=%d\n",
					       sport, dport);
				break;
			}
			port = dport;
			goto tcp;
		}
	}
	else if (type == UDP_IP) {
	udp:
		switch (port) {
		case 42:	STAT_ADD(NAME_UDP); break;
		case 53:	STAT_ADD(DNS_UDP); break;
		case 88:	STAT_ADD(KERB5_UDP); break;
		case 111:	STAT_ADD(SUNRPC_UDP); break;
		case 123:	STAT_ADD(NTP_UDP); break;
		case 135:	STAT_ADD(EPMAP_UDP); break;
		case 137:	STAT_ADD(NETBIOS_NS_UDP); break;
		case 138:	STAT_ADD(NETBIOS_SSN_UDP); break;
		case 445:	STAT_ADD(MS_DS_UDP); break;
		case 520:	STAT_ADD(RIP_UDP); break;
		case 1214:	STAT_ADD(KAZAA_UDP); break;
		case 1433:	STAT_ADD(MS_SQL_S_UDP); break;
		case 6970:	/* realaudio */
		case 7070:	STAT_ADD(REALAUDIO_UDP); break;
		case 27005:	/* halflife */
		case 27015:	STAT_ADD(HALFLIFE_UDP); break;
		case 6112:	STAT_ADD(STARCRAFT_UDP); break;
		case 9000:	/* everquest */
		case 9001:	/* everquest */
		case 9005:	STAT_ADD(EVERQUEST_UDP); break;
		case 7777:	STAT_ADD(UNREAL_UDP); break;
		case 27901:	/* quake2 */
		case 27910:	/* quake2 */
		case 27960:	STAT_ADD(QUAKE_UDP); break;
		case 7648:	STAT_ADD(CUSEEME_UDP); break;
		default:
			if (port == dport) {
				STAT_ADD(OTHER_UDP);
				if (debug)
					printf("debug: other udp sport=%d,dport=%d\n",
					       sport, dport);
				break;
			}
			port = dport;
			goto udp;
		}
	}
#ifdef INET6
	else if (type == TCP_IP6) {
	tcp6:
		switch (port) {
		case 443:	/* https */
		case 80:/* special rule for http: distinguish src & dst */
			if (port == sport) {
				STAT_ADD(HTTP_S_TCP6);
			} else {
				STAT_ADD(HTTP_C_TCP6);
			}
			break;
		case 8080:	STAT_ADD(HTTP_TCP6); break;
		case 3128:	STAT_ADD(SQUID_TCP6); break;
		case 25:	STAT_ADD(SMTP_TCP6); break;
		case 119:	STAT_ADD(NNTP_TCP6); break;
		case 21:
		case 20:	STAT_ADD(FTP_TCP6); break;
		case 110:	STAT_ADD(POP3_TCP6); break;
		case 143:	STAT_ADD(IMAP_TCP6); break;
		case 513:	/* rlogin */
		case 23:	STAT_ADD(TELNET_TCP6); break;
		case 22:	STAT_ADD(SSH_TCP6); break;
		case 53:	STAT_ADD(DNS_TCP6); break;
		case 179:	STAT_ADD(BGP_TCP6); break;
		case 6688:	/* napster */
		case 6699:	STAT_ADD(NAPSTER_TCP6); break;
		case 7070:	STAT_ADD(REALAUDIO_TCP6); break;
		case 554:	STAT_ADD(RTSP_TCP6); break;
		case 8000:	STAT_ADD(SHOUTCAST_TCP6); break;
		case 5501:	STAT_ADD(HOTLINE_TCP6); break;
		default:
			if (port == dport) {
				STAT_ADD(OTHER_TCP6);
				if (debug)
					printf("debug: other tcp6 sport=%d,dport=%d\n",
					       sport, dport);
				break;
			}
			port = dport;
			goto tcp6;
		}
	}
	else if (type == UDP_IP6) {
	udp6:
		switch (port) {
		case 53:	STAT_ADD(DNS_UDP6); break;
		case 520:	STAT_ADD(RIP_UDP6); break;
		case 6970:	/* realaudio */
		case 7070:	STAT_ADD(REALAUDIO_UDP6); break;
		case 27005:	/* halflife */
		case 27015:	STAT_ADD(HALFLIFE_UDP6); break;
		case 6112:	STAT_ADD(STARCRAFT_UDP6); break;
		case 9000:	/* everquest */
		case 9001:	/* everquest */
		case 9005:	STAT_ADD(EVERQUEST_UDP6); break;
		case 7777:	STAT_ADD(UNREAL_UDP6); break;
		case 27901:	/* quake2 */
		case 27910:	/* quake2 */
		case 27960:	STAT_ADD(QUAKE_UDP6); break;
		case 7648:	STAT_ADD(CUSEEME_UDP6); break;
		default:
			if (port == dport) {
				STAT_ADD(OTHER_UDP6);
				if (debug)
					printf("debug: other udp6 sport=%d,dport=%d\n",
					       sport, dport);
				break;
			}
			port = dport;
			goto udp6;
		}
	}
#endif /* INET6 */
}

/*
 * helper functions to handle IPv4 fragments.
 * currently only in-sequence fragments are handled.
 *	- fragment info is cached in a LRU list.
 *	- when a first fragment is found, cache its flow info.
 *	- when a non-first fragment is found, lookup the cache.
 */
static void ip4f_cache(ip, udp)
    struct ip *ip;
    struct udphdr *udp;
{
    struct ip4_frag *fp;

    if (TAILQ_EMPTY(&ip4f_list)) {
	/* first time call, allocate fragment cache entries. */
	if (ip4f_init() < 0)
	    /* allocation failed! */
	    return;
    }

    fp = ip4f_alloc();
    fp->ip4f_proto = ip->ip_p;
    fp->ip4f_id = ip->ip_id;
    fp->ip4f_src = ip->ip_src;
    fp->ip4f_dst = ip->ip_dst;
    fp->ip4f_udphdr.uh_sport = udp->uh_sport;
    fp->ip4f_udphdr.uh_dport = udp->uh_dport;
}

static struct udphdr *ip4f_lookup(ip)
    struct ip *ip;
{
    struct ip4_frag *fp;
    struct udphdr *udphdr;
    
    for (fp = TAILQ_FIRST(&ip4f_list); fp != NULL && fp->ip4f_valid;
	 fp = TAILQ_NEXT(fp, ip4f_chain))
	if (ip->ip_id == fp->ip4f_id &&
	    ip->ip_src.s_addr == fp->ip4f_src.s_addr &&
	    ip->ip_dst.s_addr == fp->ip4f_dst.s_addr &&
	    ip->ip_p == fp->ip4f_proto) {

	    /* found the matching entry */
	    udphdr = &fp->ip4f_udphdr;
	    if ((ntohs(ip->ip_off) & IP_MF) == 0)
		/* this is the last fragment, release the entry. */
		ip4f_free(fp);

	    return (udphdr);
	}

    /* no matching entry found */
    return (NULL);
}

static int ip4f_init(void)
{
    struct ip4_frag *fp;
    int i;
    
    TAILQ_INIT(&ip4f_list);
    for (i=0; i<IP4F_TABSIZE; i++) {
	fp = (struct ip4_frag *)malloc(sizeof(struct ip4_frag));
	if (fp == NULL) {
	    printf("ip4f_initcache: can't alloc cache entry!\n");
	    return (-1);
	}
	fp->ip4f_valid = 0;
	TAILQ_INSERT_TAIL(&ip4f_list, fp, ip4f_chain);
    }
    return (0);
}

static struct ip4_frag *ip4f_alloc(void)
{
    struct ip4_frag *fp;

    /* reclaim an entry at the tail, put it at the head */
    fp = TAILQ_LAST(&ip4f_list, ip4f_list);
    TAILQ_REMOVE(&ip4f_list, fp, ip4f_chain);
    fp->ip4f_valid = 1;
    TAILQ_INSERT_HEAD(&ip4f_list, fp, ip4f_chain);
    return (fp);
}

static void ip4f_free(fp)
    struct ip4_frag *fp;
{
    TAILQ_REMOVE(&ip4f_list, fp, ip4f_chain);
    fp->ip4f_valid = 0;
    TAILQ_INSERT_TAIL(&ip4f_list, fp, ip4f_chain);
}


