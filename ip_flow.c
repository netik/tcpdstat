/*
 * Copyright (C) 1998-2000
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
 * $Id: ip_flow.c,v 1.7 2001/03/26 06:48:48 kjc Exp kjc $
 */

#include <sys/types.h>
#include <sys/socket.h>
#if defined(LINUX)
#include "queue.h"
#else
#include <sys/queue.h>
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <math.h>
#include "tcpdstat.h"

struct flow {
	int flow_af;		/* address family */
	union {
		struct {
			struct in_addr ip_src;
			struct in_addr ip_dst;
		} _ip;
#ifdef INET6
		struct {
			struct in6_addr ip6_src;
			struct in6_addr ip6_dst;
		} _ip6;
#endif
	} flow_un;
};

#define flow_ip		flow_un._ip
#define flow_ip6	flow_un._ip6

struct flow_entry {
	LIST_ENTRY(flow_entry) f_next;

	struct flow f_flow;
	int	f_packets;
	long long f_bytes;
};

#define FLOW_HASHSIZE	256

static LIST_HEAD(flow_head, flow_entry) flow_hash[FLOW_HASHSIZE];
int	total_packets;
long long total_bytes;

static __inline int ip_hash4 __P((struct in_addr *, struct in_addr *));
#ifdef INET6
static __inline int ip_hash6 __P((struct in6_addr *, struct in6_addr *));
#endif
static void addr_show(void);

/* hash function for IPv4 packets */
static __inline int ip_hash4(src, dst)
	struct in_addr *src, *dst;
{
	int val;

	val = (ntohl(src->s_addr) ^ ntohl(dst->s_addr)) & (FLOW_HASHSIZE-1);
	return (val);
}

#ifdef INET6

/* hash function for IPv6 packets */
static __inline int ip_hash6(src, dst)
	struct in6_addr *src, *dst;
{
	int val;
	
	val = (ntohl(*((u_int32_t *)&src->s6_addr[12])) ^
	       ntohl(*((u_int32_t *)&dst->s6_addr[12])))
		& (FLOW_HASHSIZE-1);
	return (val);
}

#endif /* INET6 */

int ipflow_count(af, ip, size)
	int af;
	struct ip *ip;
	int size;
{
	struct flow_entry *flow;
	int hash;
#ifdef INET6
	struct ip6_hdr *ip6;
#endif

	switch (af) {
	case AF_INET:
		hash = ip_hash4(&ip->ip_src, &ip->ip_dst);
		for (flow = LIST_FIRST(&flow_hash[hash]); flow != NULL;
		     flow = LIST_NEXT(flow, f_next)) {
			if (flow->f_flow.flow_af != AF_INET)
				continue;
			if (flow->f_flow.flow_ip.ip_src.s_addr
			    == ip->ip_src.s_addr &&
			    flow->f_flow.flow_ip.ip_dst.s_addr
			    == ip->ip_dst.s_addr)
				break;
		}
		break;
#ifdef INET6
	case AF_INET6:
		ip6 = (struct ip6_hdr *)ip;
		hash = ip_hash6(&ip6->ip6_src, &ip6->ip6_dst);
		for (flow = LIST_FIRST(&flow_hash[hash]); flow != NULL;
		     flow = LIST_NEXT(flow, f_next)) {
			if (flow->f_flow.flow_af != AF_INET6)
				continue;
			if (IN6_ARE_ADDR_EQUAL(&flow->f_flow.flow_ip6.ip6_src,
					       &ip6->ip6_src) &&
			    IN6_ARE_ADDR_EQUAL(&flow->f_flow.flow_ip6.ip6_dst,
					       &ip6->ip6_dst))
				break;
		}
		break;
#endif

	default:
		total_packets++;
		return (0);
	}

	if (flow == NULL) {
		/* allocate a new entry */
		if ((flow = malloc(sizeof(*flow))) == NULL)
			return (-1);

		switch (af) {
		case AF_INET:
			flow->f_flow.flow_af = AF_INET;
			flow->f_flow.flow_ip.ip_src = ip->ip_src;
			flow->f_flow.flow_ip.ip_dst = ip->ip_dst;
			break;

#ifdef INET6
		case AF_INET6:
			flow->f_flow.flow_af = AF_INET6;
			flow->f_flow.flow_ip6.ip6_src = ip6->ip6_src;
			flow->f_flow.flow_ip6.ip6_dst = ip6->ip6_dst;
			break;
#endif
		}
		
		flow->f_packets = 0;
		flow->f_bytes = 0;

		LIST_INSERT_HEAD(&flow_hash[hash], flow, f_next);
	}

	flow->f_packets++;
	flow->f_bytes += size;

	total_packets++;
	total_bytes += ntohs(ip->ip_len);

	return (0);
}

void ipflow_destroy(void)
{
	struct flow_entry  *flow;
	int i;

	for (i = 0; i < FLOW_HASHSIZE; i++) {
		while ((flow = LIST_FIRST(&flow_hash[i])) != NULL) {
			LIST_REMOVE(flow, f_next);
			free(flow);
		}
	}
}

#define NTOP	10

void ipflow_show(void)
{
	struct flow_entry  *flow, *big_flows[NTOP];
	int fhash[FLOW_HASHSIZE], total, i, j, k;


	printf("### IP flow (unique src/dst pair) Information ###\n");

	/*
	 * find out the total number of flows
	 */
	total = 0;
	for (i = 0; i < NTOP; i++)
		big_flows[i] = NULL;
	for (i = 0; i < FLOW_HASHSIZE; i++) {
		fhash[i] = 0;
		for (flow = LIST_FIRST(&flow_hash[i]); flow != NULL;
		     flow = LIST_NEXT(flow, f_next)) {
			fhash[i]++;
			/*
			 * keep the sorted big flow list
			 */
			for (j = 0; j < NTOP; j++) {
				if (big_flows[j] == NULL ||
				    (long long)flow->f_bytes > big_flows[j]->f_bytes) {
					/* insert the entry */
					for (k = NTOP-1; k > j; k--)
						big_flows[k] = big_flows[k-1];
					big_flows[j] = flow;
					break;
				}
			}
		}
		total += fhash[i];
	}

	if (total == 0)
		return;

	printf("# of flows: %d  (avg. %.2f pkts/flow)\n",
	       total, (double)tcpdstat[TOTAL].packets / total);

	printf("Top %d big flow size (bytes/total in %%):\n", NTOP);
	for (i = 0; i < NTOP; i++) {
		if (big_flows[i] == NULL)
			break;
		printf(" %4.1f%%", 
		       (double)big_flows[i]->f_bytes /
		       (double)tcpdstat[TOTAL].bytes * 100);
	}
	printf("\n");

	if (debug) {
		double avg, var;
		int max, min;

		/*
		 * hash info
		 */

		avg = (double)total / (double)FLOW_HASHSIZE;

		max = 0;
		min = INT_MAX;
		var = 0.0;
		for (i = 0; i < FLOW_HASHSIZE; i++) {
			var += (double)fhash[i] * (double)fhash[i];
			if (fhash[i] > max)
				max = fhash[i];
			if (fhash[i] < min)
				min = fhash[i];

		}

		var = var / (double)FLOW_HASHSIZE - avg * avg;
		
		printf("flow hash: min/avg/max:%d/%.3f/%d stddev:%.3f\n",
		       min, avg, max, sqrt(var));

		printf("hash: [");
		for (i = 0; i < FLOW_HASHSIZE; i++) {
			printf(" %d", fhash[i]);
			if (i % 10 == 9)
				printf("\n\t");
		}
		printf("]\n");
	}

	/*
	 * extract address information
	 */
	addr_show();
}

/*
 * addr_show() extracts IPv4/v6 address information from the flow list
 */
struct addr_entry {
	LIST_ENTRY(addr_entry) addr_next;

	union {
		struct in_addr ua_ip;
#ifdef INET6
		struct in6_addr ua_ip6;
#endif
	} a_un;
	int	addr_packets;
	long long addr_bytes;
};

#define addr_ip		a_un.ua_ip
#define addr_ip6	a_un.ua_ip6

#define IP_HASH4(a)	(ntohl((a)->s_addr) & (FLOW_HASHSIZE-1))
#define IP_HASH6(a)	(ntohl(*((u_int32_t *)&(a)->s6_addr[12])) \
			 & (FLOW_HASHSIZE-1))

static LIST_HEAD(addr_head, addr_entry) addr_hash[FLOW_HASHSIZE];
static int total_addr = 0;
static long long v4_total_bytes = 0;
#ifdef INET6
static LIST_HEAD(addr_head6, addr_entry) addr_hash6[FLOW_HASHSIZE];
static int total_addr6 = 0;
static long long v6_total_bytes = 0;
#endif

static int addr_count(af, ip_addr, packets, bytes)
	int	af;
	struct in_addr *ip_addr;
	int	packets;
	long long bytes;
{
	struct addr_entry *addr;
	int hash;

	/*
	 * find addr in the list.  if not found, allocate a new entry.
	 */
	if (af == AF_INET) {
		v4_total_bytes += bytes;
		hash = IP_HASH4(ip_addr);
		for (addr = LIST_FIRST(&addr_hash[hash]); addr != NULL;
		     addr = LIST_NEXT(addr, addr_next)) 
			if (addr->addr_ip.s_addr == ip_addr->s_addr)
				break;
		if (addr == NULL) {
			if ((addr = calloc(sizeof(*addr), 1)) == NULL)
				return (-1);
			addr->addr_ip = *ip_addr;
			total_addr++;
			LIST_INSERT_HEAD(&addr_hash[hash], addr, addr_next);
		}
		else if (LIST_FIRST(&addr_hash[hash]) != addr) {
			/* move the entry to the head of the list */
			LIST_REMOVE(addr, addr_next);
			LIST_INSERT_HEAD(&addr_hash[hash], addr, addr_next);
		}
	}
#ifdef INET6
	else if (af == AF_INET6) {
		v6_total_bytes += bytes;
		hash = IP_HASH6((struct in6_addr *)ip_addr);
		for (addr = LIST_FIRST(&addr_hash6[hash]); addr != NULL;
		     addr = LIST_NEXT(addr, addr_next)) 
			if (IN6_ARE_ADDR_EQUAL(&addr->addr_ip6,
					       (struct in6_addr *)ip_addr))
				break;
		if (addr == NULL) {
			if ((addr = calloc(sizeof(*addr), 1)) == NULL)
				return (-1);
			addr->addr_ip6 = *((struct in6_addr *)ip_addr);
			total_addr6++;
			LIST_INSERT_HEAD(&addr_hash6[hash], addr, addr_next);
		}
		else if (LIST_FIRST(&addr_hash6[hash]) != addr) {
			/* move the entry to the head of the list */
			LIST_REMOVE(addr, addr_next);
			LIST_INSERT_HEAD(&addr_hash6[hash], addr, addr_next);
		}
	}
#endif
	addr->addr_packets += packets;
	addr->addr_bytes += bytes;
	return (0);
}

static void addr_show(void)
{
	struct flow_entry *flow;
	struct in_addr *src, *dst;
	struct addr_entry *addr, *big_addrs[NTOP];
	int af, hash, i, j, k;

	printf("\n### IP address Information ###\n");

	/*
	 * find unique addresses in the flow list.
	 */
	for (i = 0; i < FLOW_HASHSIZE; i++) {
		for (flow = LIST_FIRST(&flow_hash[i]); flow != NULL;
		     flow = LIST_NEXT(flow, f_next)) {
			af = flow->f_flow.flow_af;
			if (af == AF_INET) {
				src = &flow->f_flow.flow_ip.ip_src;
				dst = &flow->f_flow.flow_ip.ip_dst;
			}
#ifdef INET6
			else if (af == AF_INET6) {
				src = (struct in_addr *)
					&flow->f_flow.flow_ip6.ip6_src;
				dst = (struct in_addr *)
					&flow->f_flow.flow_ip6.ip6_dst;
			}
#endif
			else
				continue;
			if (addr_count(af, src, flow->f_packets,
				       flow->f_bytes) != 0)
				goto out;
			if (addr_count(af, dst, flow->f_packets,
				       flow->f_bytes) != 0)
				goto out;
		}
	}

	if (total_addr > 0) {
		/*
		 * find out the top 10 addresses
		 */
		for (i = 0; i < NTOP; i++)
			big_addrs[i] = NULL;
		for (hash = 0; hash < FLOW_HASHSIZE; hash++)
			for (addr = LIST_FIRST(&addr_hash[hash]); addr != NULL;
			     addr = LIST_NEXT(addr, addr_next)) {
				for (j = 0; j < NTOP; j++) {
					if (big_addrs[j] == NULL ||
					    addr->addr_bytes >
					    big_addrs[j]->addr_bytes) {
						/* insert the entry */
						for (k = NTOP-1; k > j; k--)
							big_addrs[k] = big_addrs[k-1];
						big_addrs[j] = addr;
						break;
					}
				}
			}

		printf("# of IPv4 addresses: %d \n", total_addr);
		printf("Top %d bandwidth usage (bytes/total in %%):\n", NTOP);
		for (i = 0; i < NTOP; i++) {
			if (big_addrs[i] == NULL)
				break;
			printf(" %4.1f%%", 
			       (double)big_addrs[i]->addr_bytes /
			       (double)(v4_total_bytes / 2) * 100);
		}
		printf("\n");
	}

#ifdef INET6
	if (total_addr6 > 0) {
		for (i = 0; i < NTOP; i++)
			big_addrs[i] = NULL;
		for (hash = 0; hash < FLOW_HASHSIZE; hash++)
			for (addr = LIST_FIRST(&addr_hash6[hash]); addr != NULL;
			     addr = LIST_NEXT(addr, addr_next)) {
				for (j = 0; j < NTOP; j++) {
					if (big_addrs[j] == NULL ||
					    addr->addr_bytes >
					    big_addrs[j]->addr_bytes) {
						/* insert the entry */
						for (k = NTOP-1; k > j; k--)
							big_addrs[k] = big_addrs[k-1];
						big_addrs[j] = addr;
						break;
					}
				}
			}

		printf("# of IPv6 addresses: %d \n", total_addr6);
		printf("Top %d bandwidth usage (bytes/total in %%):\n", NTOP);
		for (i = 0; i < NTOP; i++) {
			if (big_addrs[i] == NULL)
				break;
			printf(" %4.1f%%", 
			       (double)big_addrs[i]->addr_bytes /
			       (double)(v6_total_bytes / 2) * 100);
		}
		printf("\n");
	}
#endif /* INET6 */

  out:
	/* cleanup */
	for (hash = 0; hash < FLOW_HASHSIZE; hash++)
		while ((addr = LIST_FIRST(&addr_hash[hash])) != NULL) {
			LIST_REMOVE(addr, addr_next);
			free(addr);
		}
#ifdef INET6
	for (hash = 0; hash < FLOW_HASHSIZE; hash++)
		while ((addr = LIST_FIRST(&addr_hash6[hash])) != NULL) {
			LIST_REMOVE(addr, addr_next);
			free(addr);
		}
#endif
}

