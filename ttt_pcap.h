/* $Id: ttt_pcap.h,v 1.1 1998/10/22 04:43:41 kjc Exp $ */
/* ttt_pcap.h -- minimum set from tcpdump to read 802.3 frames */

/*
 * Copyright (c) 1993, 1994
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
 *
 */

/* from llc.h */
struct llc {
	u_char dsap;
	u_char ssap;
	union {
		u_char u_ctl;
		u_short is_ctl;
		struct {
			u_char snap_ui;
			u_char snap_pi[5];
		} snap;
		struct {
			u_char snap_ui;
			u_char snap_orgcode[3];
			u_char snap_ethertype[2];
		} snap_ether;
	} ctl;
};

#define	llcui		ctl.snap.snap_ui
#define	ethertype	ctl.snap_ether.snap_ethertype

#ifndef LLCSAP_SNAP
#define	LLCSAP_SNAP		0xaa
#endif
#ifndef LLC_UI
#define	LLC_UI		0x03
#endif

/*
 * @(#) $Header: /src/kjc/tcpd-tools/tcpdstat/RCS/ttt_pcap.h,v 1.1 1998/10/22 04:43:41 kjc Exp $ (LBL)
 */

struct fddi_header {
#if defined(ultrix) || defined(__alpha)
	/* Ultrix pads to make everything line up on a nice boundary */
#define	FDDIPAD	3
	u_char  fddi_ph[FDDIPAD];
#else
#define	FDDIPAD	0
#endif
	u_char  fddi_fc;		/* frame control */
	u_char  fddi_dhost[6];
	u_char  fddi_shost[6];
};

#define FDDI_HDRLEN (sizeof(struct fddi_header))

#define	FDDIFC_LLC_ASYNC	0x50		/* Async. LLC frame */
#define	FDDIFC_CLFF		0xF0		/* Class/Length/Format bits */
