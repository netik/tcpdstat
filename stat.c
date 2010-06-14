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
 * $Id: stat.c,v 1.8 2001/03/26 07:23:03 kjc Exp kjc $
 */

#include <sys/types.h>
#if defined(LINUX)
#include <time.h>
#endif
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>

#include "tcpdstat.h"

struct timeval start_time, end_time;
long long int read_count = 0;
long long int caplen_total = 0;
long int caplen_max = 0;
double rate_max = 0;
double rate_mean = 0;
double rate_var = 0;
long int rate_count = 0;

int use_ipflow = 1;
char *pktlen_filename = NULL;
FILE *pktlen_file = NULL;
int debug = 0;

static char *file = "-";	/* stdin is the default input */

struct pkt_cnt tcpdstat[PROTOTYPE_MAX];

#define PKTSIZE_BUCKETS		16
static int pktsize_buckets[PKTSIZE_BUCKETS];

static void show_stat(void);
static void sigint_handler(int sig);
static void pktsize_print(void);
static void write_pktlen_dist(FILE *fp);

static void
sigint_handler(int sig)
{
    fprintf(stderr, "got signal %d. exiting...\n", sig);
    exit(1);
}

static void
usage(void)
{
    fprintf(stderr, "usage: tcpdstat [-dn] [-c count] [-w len_file] [dumpfile]\n");
    fprintf(stderr, "            -d: debug\n");
    fprintf(stderr, "            -n: no flow info\n");
    fprintf(stderr, "            -c: exit after \"count\" packets\n");
    fprintf(stderr, "            -l: write packet length distributions to a file\n");
    exit(1);
}


int main(argc, argv)
    int argc;
    char **argv;
{
    int fd, ch, len;

    while ((ch = getopt(argc, argv, "c:dnw:")) != EOF) {
	switch (ch) {
	case 'c':
	    read_count = atoi(optarg);
	    break;
	case 'd':
	    debug = 1;
	    break;
	case 'n':
	    use_ipflow = 0;
	    break;
	case 'w':
	    pktlen_filename = optarg;
	    break;
	default:
	    usage();
	}
    }
    argc -= optind;
    argv += optind;
    if (argc > 0)
	file = argv[0];

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("\nDumpFile:  %s\n", file);
    if (strcmp(file, "-") != 0) {
	struct stat statbuf;

	if (stat(file, &statbuf) == 0)
	    printf("FileSize: %.2fMB\n", (double)statbuf.st_size/1024/1024);
    }

    if (pktlen_filename != NULL) {
	if ((pktlen_file = fopen(pktlen_filename, "w")) == NULL) {
	    fprintf(stderr, "can't open packet lenght output file: %s!\n",
		    pktlen_filename);
	    exit(1);
	}
    }

    fd = open_dump(file);

    do {
	len = read_dump();
    } while (len > 0);

    close_dump();

    show_stat();

    if (pktlen_file != NULL) {
	write_pktlen_dist(pktlen_file);
	fclose(pktlen_file);
    }

    ipflow_destroy();
    
    return (0);
}

/* the names must match "enum protos" */
struct {
    char *name;
    int level;
} protos[] = {
	{"total    ",	0}, 
        {"ip       ",	1},
        {" tcp     ",	2},
        {"  ftpdata",	3},
        {"  ftp    ",	3},
        {"  ssh    ",	3},
        {"  telnet ",	3},
        {"  smtp   ",	3},
	{"  name   ",   3},
        {"  dns    ",	3},
        {"  http(s)",	3},
        {"  http(c)",	3},
	{"  kerb5  ",   3},
        {"  pop3   ",	3},
        {"  sunrpc ",	3},
	{"  ident  ",   3},
        {"  nntp   ",	3},
        {"  ntp    ",	3},
        {"  epmap  ",	3},
        {"  netb-ns",	3},
        {"  netb-se",	3},
        {"  imap   ",	3},
        {"  bgp    ",	3},
        {"  ldap   ",	3},
	{"  https  ",   3},
	{"  ms-ds  ",   3},
	{"  rlogin ",   3},
        {"  rtsp   ",	3},
        {"  ldaps  ",	3},
	{"  socks  ",   3},
        {"  kasaa  ",	3},
        {"  mssql-s",	3},
        {"  squid  ",	3},
	{"  ms-gc  ",   3},
	{"  ms-gcs ",   3},
        {"  hotline",	3},
        {"  realaud",	3},
        {"  icecast",	3},
        {"  gnu6346",	3},
        {"  gnu6347",	3},
        {"  gnu6348",	3},
        {"  gnu6349",	3},
        {"  gnu6350",	3},
        {"  gnu6355",	3},
        {"  irc6666",	3},
        {"  irc6667",	3},
        {"  irc6668",	3},
        {"  irc6669",	3},
        {"  napster",	3},
        {"  irc7000",	3},
	{"  http-a ",   3},
	{"  http-tw",   3},
	{"  http-ts",   3},
	{"  memcach",   3},
	{"  kestrel",   3},
 	{"  other  ",	3},
        {" udp     ",	2},
	{"  name   ",   3},
        {"  dns    ",	3},
	{"  kerb5  ",   3},
        {"  sunrpc ",	3},
        {"  ntp    ",	3},
        {"  epmap  ",	3},
        {"  netb-ns",	3},
        {"  netb-se",	3},
	{"  ms-ds  ",   3},
        {"  rip    ",	3},
        {"  kazaa  ",	3},
        {"  mssql-s",	3},
        {"  mcast  ",	3},
        {"  realaud",	3},
        {"  halflif",	3},
        {"  starcra",	3},
        {"  everque",	3},
        {"  unreal ",	3},
        {"  quake  ",	3},
        {"  cuseeme",	3},
        {"  other  ",	3},
        {" icmp    ",	2},
        {" igmp    ",	2},
        {" ggp     ",	2},
        {" ipip    ",	2},
        {" st      ",	2},
        {" cbt     ",	2},
        {" egp     ",	2},
        {" igp     ",	2},
        {" bbn_rcc_",	2},
        {" nvp     ",	2},
        {" pup     ",	2},
        {" argus   ",	2},
        {" emcon   ",	2},
        {" xnet    ",	2},
        {" chaos   ",	2},
        {" mux     ",	2},
        {" dcn_meas",	2},
        {" hmp     ",	2},
        {" prm     ",	2},
        {" xns-idp ",	2},
        {" trunk1  ",	2},
        {" trunk2  ",	2},
        {" leaf1   ",	2},
        {" leaf2   ",	2},
        {" rdp     ",	2},
        {" irtp    ",	2},
        {" iso-tp4 ",	2},
        {" netblt  ",	2},
        {" mfe-nsp ",	2},
        {" merit-in",	2},
        {" sep     ",	2},
        {" 3pc     ",	2},
        {" idpr    ",	2},
        {" xtp     ",	2},
        {" ddp     ",	2},
        {" idpr-cmt",	2},
        {" tp++    ",	2},
        {" il      ",	2},
        {" ip6     ",	2},
        {" sdrp    ",	2},
        {" ip6-rh  ",	2},
        {" ip6-fh  ",	2},
        {" idrp    ",	2},
        {" rsvp    ",	2},
        {" gre     ",	2},
        {" mhrp    ",	2},
        {" bna     ",	2},
        {" esp     ",	2},
        {" ah      ",	2},
        {" i-nlsp  ",	2},
        {" swipe   ",	2},
        {" narp    ",	2},
        {" mobile  ",	2},
        {" tlsp    ",	2},
        {" skip    ",	2},
        {" ip6-icmp",	2},
        {" ip6-nnh ",	2},
        {" ip6-opts",	2},
        {" host-int",	2},
        {" cftp    ",	2},
        {" any-loca",	2},
        {" sat-expa",	2},
        {" kryptola",	2},
        {" rvd     ",	2},
        {" ippc    ",	2},
        {" any-dist",	2},
        {" sat-mon ",	2},
        {" visa    ",	2},
        {" ipcv    ",	2},
        {" cpnx    ",	2},
        {" cphb    ",	2},
        {" wsn     ",	2},
        {" pvp     ",	2},
        {" br-sat-m",	2},
        {" sun-nd  ",	2},
        {" wb-mon  ",	2},
        {" wb-expak",	2},
        {" iso-ip  ",	2},
        {" vmtp    ",	2},
        {" sec-vmtp",	2},
        {" vines   ",	2},
        {" ttp     ",	2},
        {" nsfn-igp",	2},
        {" dgp     ",	2},
        {" tcf     ",	2},
        {" eirgp   ",	2},
        {" ospfigp ",	2},
        {" spri-rpc",	2},
        {" larp    ",	2},
        {" mtp     ",	2},
        {" ax.25   ",	2},
        {" ipip    ",	2},
        {" micp    ",	2},
        {" scc-sp  ",	2},
        {" etherip ",	2},
        {" encap   ",	2},
        {" any-encr",	2},
        {" gmtp    ",	2},
        {" ifmp    ",	2},
        {" pnmi    ",	2},
        {" pim     ",	2},
        {" aris    ",	2},
        {" scps    ",	2},
        {" qnx     ",	2},
        {" active-n",	2},
        {" ip-comp ",	2},
        {" snp     ",	2},
        {" compaq-p",	2},
        {" ipx-ip  ",	2},
        {" vrrp    ",	2},
        {" pgm     ",	2},
        {" any-zero",	2},
        {" l2tp    ",	2},
        {" ddx     ",	2},
        {" iatp    ",	2},
        {" stp     ",	2},
        {" srp     ",	2},
        {" uti     ",	2},
        {" smp     ",	2},
        {" sm      ",	2},
        {" ptp     ",	2},
        {" isis-ip ",	2},
        {" fire    ",	2},
        {" crtp    ",	2},
        {" crudp   ",	2},
        {" sscopmce",	2},
        {" iplt    ",	2},
        {" sps     ",	2},
        {" pipe    ",	2},
        {" sctp    ",	2},
        {" fc      ",	2},
        {" unas_134",	2},
	{" unas_135",   2},
	{" unas_136",   2},
	{" unas_137",   2},
	{" unas_138",   2},
	{" unas_139",   2},
	{" unas_140",   2},
	{" unas_141",   2},
	{" unas_142",   2},
	{" unas_143",   2},
	{" unas_144",   2},
	{" unas_145",   2},
	{" unas_146",   2},
	{" unas_147",   2},
	{" unas_148",   2},
	{" unas_149",   2},
	{" unas_150",   2},
	{" unas_151",   2},
	{" unas_152",   2},
	{" unas_153",   2},
	{" unas_154",   2},
	{" unas_155",   2},
	{" unas_156",   2},
	{" unas_157",   2},
	{" unas_158",   2},
	{" unas_159",   2},
	{" unas_160",   2},
	{" unas_161",   2},
	{" unas_162",   2},
	{" unas_163",   2},
	{" unas_164",   2},
	{" unas_165",   2},
	{" unas_166",   2},
	{" unas_167",   2},
	{" unas_168",   2},
	{" unas_169",   2},
	{" unas_170",   2},
	{" unas_171",   2},
	{" unas_172",   2},
	{" unas_173",   2},
	{" unas_174",   2},
	{" unas_175",   2},
	{" unas_176",   2},
	{" unas_177",   2},
	{" unas_178",   2},
	{" unas_179",   2},
	{" unas_180",   2},
	{" unas_181",   2},
	{" unas_182",   2},
	{" unas_183",   2},
	{" unas_184",   2},
	{" unas_185",   2},
	{" unas_186",   2},
	{" unas_187",   2},
	{" unas_188",   2},
	{" unas_189",   2},
	{" unas_190",   2},
	{" unas_191",   2},
	{" unas_192",   2},
	{" unas_193",   2},
	{" unas_194",   2},
	{" unas_195",   2},
	{" unas_196",   2},
	{" unas_197",   2},
	{" unas_198",   2},
	{" unas_199",   2},
	{" unas_200",   2},
	{" unas_201",   2},
	{" unas_202",   2},
	{" unas_203",   2},
	{" unas_204",   2},
	{" unas_205",   2},
	{" unas_206",   2},
	{" unas_207",   2},
	{" unas_208",   2},
	{" unas_209",   2},
	{" unas_210",   2},
	{" unas_211",   2},
	{" unas_212",   2},
	{" unas_213",   2},
	{" unas_214",   2},
	{" unas_215",   2},
	{" unas_216",   2},
	{" unas_217",   2},
	{" unas_218",   2},
	{" unas_219",   2},
	{" unas_220",   2},
	{" unas_221",   2},
	{" unas_222",   2},
	{" unas_223",   2},
	{" unas_224",   2},
	{" unas_225",   2},
	{" unas_226",   2},
	{" unas_227",   2},
	{" unas_228",   2},
	{" unas_229",   2},
	{" unas_230",   2},
	{" unas_231",   2},
	{" unas_232",   2},
	{" unas_233",   2},
	{" unas_234",   2},
	{" unas_235",   2},
	{" unas_236",   2},
	{" unas_237",   2},
	{" unas_238",   2},
	{" unas_239",   2},
	{" unas_240",   2},
	{" unas_241",   2},
	{" unas_242",   2},
	{" unas_243",   2},
	{" unas_244",   2},
	{" unas_245",   2},
	{" unas_246",   2},
	{" unas_247",   2},
	{" unas_248",   2},
	{" unas_249",   2},
	{" unas_250",   2},
	{" unas_251",   2},
	{" unas_252",   2},
	{" unas_253",   2},
	{" unas_254",   2},
	{" res_255 ",   2},
        {" other   ",	2},
        {" frag    ",	2},
        {"ip6      ",	1},
        {" tcp6    ",	2},
        {"  http(s)",	3},
        {"  http(c)",	3},
        {"  squid  ",	3},
        {"  smtp   ",	3},
        {"  nntp   ",	3},
        {"  ftp    ",	3},
        {"  pop3   ",	3},
        {"  imap   ",	3},
        {"  telnet ",	3},
        {"  ssh    ",	3},
        {"  dns    ",	3},
        {"  bgp    ",	3},
        {"  napster",	3},
        {"  realaud",	3},
        {"  rtsp   ",	3},
        {"  icecast",	3},
        {"  hotline",	3},
        {"  other  ",	3},
        {" udp6    ",	2},
        {"  dns    ",	3},
        {"  rip    ",	3},
        {"  mcast  ",	3},
        {"  realaud",	3},
        {"  halflif",	3},
        {"  starcra",	3},
        {"  everque",	3},
        {"  unreal ",	3},
        {"  quake  ",	3},
        {"  cuseeme",	3},
        {"  other  ",	3},
        {" icmp6   ",	2},
        {" ospf6   ",	2},
        {" ip4     ",	2},
        {" ip6     ",	2},
        {" ipsec6  ",	2},
        {" hbhopt6 ",	2},
        {" rtopt6  ",	2},
        {" dstopt6 ",	2},
        {" pim6    ",	2},
        {" sctp6   ",	2},
        {" other6  ",	2},
        {" frag6   ",	2},
        {"other    ",	1},
        {NULL,		-1}
};

static void show_stat(void)
{
    int i;
    time_t t;
    struct tm *tm;
    double sec, stddev;
    double frac_pkts, frac_bytes, avg_bytes;

    /* create Id from start_time. provide time info.  */
    t = start_time.tv_sec;
    tm = localtime(&t);
    printf("Id: %.4d%.2d%.2d%.2d%.2d\n", tm->tm_year + 1900, tm->tm_mon + 1,
	   tm->tm_mday, tm->tm_hour, tm->tm_min);
    printf("StartTime: %s", ctime(&t));
    t = end_time.tv_sec;
    printf("EndTime:   %s", ctime(&t));
    sec = (double)(end_time.tv_sec - start_time.tv_sec)
	    + (double)(end_time.tv_usec - start_time.tv_usec) / 1000000.0;
    printf("TotalTime: %.2f seconds\n", sec);

    printf("TotalCapSize: %.2fMB  CapLen: %d bytes\n",
	   (double)caplen_total/(1024*1024), caplen_max);
    printf("# of packets: %d", tcpdstat[TOTAL].packets);

    if (tcpdstat[TOTAL].bytes > 1024*1024)
	    printf(" (%.2fMB)\n",
		   (double)tcpdstat[TOTAL].bytes/(1024*1024));
    else 
	    printf(" (%.2fKB)\n", (double)tcpdstat[TOTAL].bytes / 1024);

    stddev = sqrt(rate_var / (rate_count - 1));
    printf("AvgRate: ");
    if (rate_mean > 1000000.0)
	    printf("%.2fMbps  stddev:%.2fM   ",
		   rate_mean / 1000000.0, stddev / 1000000.0);
    else if (rate_mean > 1000.0)
	    printf("%.2fKbps  stddev:%.2fK   ",
		   rate_mean / 1000.0, stddev / 1000.0);
    else
	    printf("%.2fbps  stddev:%.2f   ",
		   rate_mean, stddev);

    printf("PeakRate: ");
    if (rate_max > 1000000.0)
	    printf("%.2fMbps\n",
		   rate_max / 1000000.0);
    else if (rate_max > 1000.0)
	    printf("%.2fKbps\n",
		   rate_max / 1000.0);
    else
	    printf("%.2fbps\n",
		   rate_max);

    printf("\n");

    if (use_ipflow)
	    ipflow_show();

    pktsize_print();

    printf("\n### Protocol Breakdown ###\n");
    printf("<<<<\n");
    printf("     protocol\t\tpackets\t\t\tbytes\t\tbytes/pkt\n");
    printf("------------------------------------------------------------------------\n");
    for (i = 0; i < PROTOTYPE_MAX; i++) {
	if (tcpdstat[i].packets != 0) {
	    frac_pkts = (double)tcpdstat[i].packets
		/ (double)tcpdstat[TOTAL].packets * 100.0;
	    frac_bytes = (double)tcpdstat[i].bytes
		/ (double)tcpdstat[TOTAL].bytes * 100.0;
	    avg_bytes = (double)tcpdstat[i].bytes
		/ (double)tcpdstat[i].packets;
	    printf("[%d] %s %12d (%6.2f%%) %16lld (%6.2f%%)  %8.2f\n",
		   protos[i].level,
		   protos[i].name,
		   tcpdstat[i].packets, frac_pkts,
		   tcpdstat[i].bytes, frac_bytes,
		   avg_bytes);
	}
    }
    printf(">>>>\n");
    printf("\n\n");
}

#define MAX_PACKET_SIZE		9180  /* MTU for ATM */
static int pktlen_dist[MAX_PACKET_SIZE+1];

void pktsize_add(int size)
{
    int n = 0;

    if (pktlen_file != NULL) {
	int len = size;
	if (len > MAX_PACKET_SIZE)
	    len = MAX_PACKET_SIZE;
	pktlen_dist[len]++;
    }

    while (size > 1) {
	size >>= 1;
	n++;
    }
    if (n >= PKTSIZE_BUCKETS)
	n = PKTSIZE_BUCKETS - 1;
    pktsize_buckets[n]++;
}

static void pktsize_print(void)
{
    int i;

    printf("### Packet Size Distribution (including MAC headers) ###\n");
    printf("<<<<\n");
    for (i = 0; i < PKTSIZE_BUCKETS; i++)
	if (pktsize_buckets[i] > 0)
	    printf(" [%5d-%5d]: %10d\n",
		   1 << i, (1 << (i+1))-1, pktsize_buckets[i]);
    printf(">>>>\n");
    printf("\n");
}

static void write_pktlen_dist(FILE *fp)
{
    int len, count;

    fprintf(fp, "# packet_size  count  bytes\n");
    for (len = 0; len <= MAX_PACKET_SIZE; len++) {
	if ((count = pktlen_dist[len]) != 0)
	    fprintf(fp, "%d %d %lld\n", len,  count, (long long)len*count);
    }
}
