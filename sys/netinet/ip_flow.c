/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by the 3am Software Foundry ("3am").  It was developed by Matt Thomas.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/netinet/ip_flow.c,v 1.9.2.2 2001/11/04 17:35:31 luigi Exp $
 * $DragonFly: src/sys/netinet/ip_flow.c,v 1.14 2008/05/14 11:59:24 sephe Exp $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/thread2.h>

#include <machine/smp.h>

#include <net/if.h>
#include <net/route.h>
#include <net/netisr.h>
#include <net/netmsg2.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_flow.h>

#define	IPFLOW_TIMER		(5 * PR_SLOWHZ)
#define IPFLOW_HASHBITS		6	/* should not be a multiple of 8 */
#define	IPFLOW_HASHSIZE		(1 << IPFLOW_HASHBITS)
#define	IPFLOW_MAX		256

#define IPFLOW_RTENTRY_ISDOWN(rt) \
	(((rt)->rt_flags & RTF_UP) == 0 || ((rt)->rt_ifp->if_flags & IFF_UP) == 0)

#define ipflow_inuse		ipflow_inuse_pcpu[mycpuid]
#define ipflows			ipflows_pcpu[mycpuid]

static LIST_HEAD(ipflowhead, ipflow) ipflows_pcpu[MAXCPU][IPFLOW_HASHSIZE];
static int		ipflow_inuse_pcpu[MAXCPU];
static struct netmsg	ipflow_timo_netmsgs[MAXCPU];
static int		ipflow_active = 0;

SYSCTL_NODE(_net_inet_ip, OID_AUTO, ipflow, CTLFLAG_RW, 0, "ip flow");
SYSCTL_INT(_net_inet_ip, IPCTL_FASTFORWARDING, fastforwarding, CTLFLAG_RW,
	   &ipflow_active, 0, "Enable flow-based IP forwarding");

static MALLOC_DEFINE(M_IPFLOW, "ip_flow", "IP flow");

static unsigned
ipflow_hash(struct in_addr dst, struct in_addr src, unsigned tos)
{
	unsigned hash = tos;
	int idx;

	for (idx = 0; idx < 32; idx += IPFLOW_HASHBITS)
		hash += (dst.s_addr >> (32 - idx)) + (src.s_addr >> idx);
	return hash & (IPFLOW_HASHSIZE-1);
}

static struct ipflow *
ipflow_lookup(const struct ip *ip)
{
	unsigned hash;
	struct ipflow *ipf;

	hash = ipflow_hash(ip->ip_dst, ip->ip_src, ip->ip_tos);

	crit_enter();
	ipf = LIST_FIRST(&ipflows[hash]);
	while (ipf != NULL) {
		if (ip->ip_dst.s_addr == ipf->ipf_dst.s_addr &&
		    ip->ip_src.s_addr == ipf->ipf_src.s_addr &&
		    ip->ip_tos == ipf->ipf_tos)
			break;
		ipf = LIST_NEXT(ipf, ipf_next);
	}
	crit_exit();

	return ipf;
}

int
ipflow_fastforward(struct mbuf *m, lwkt_serialize_t serializer)
{
	struct ip *ip;
	struct ipflow *ipf;
	struct rtentry *rt;
	struct sockaddr *dst;
	struct ifnet *ifp;
	int error;

	/*
	 * Are we forwarding packets?  Big enough for an IP packet?
	 */
	if (!ipforwarding || !ipflow_active || m->m_len < sizeof(struct ip))
		return 0;

	/*
	 * IP header with no option and valid version and length
	 */
	ip = mtod(m, struct ip *);
	if (ip->ip_v != IPVERSION || ip->ip_hl != (sizeof(struct ip) >> 2) ||
	    ntohs(ip->ip_len) > m->m_pkthdr.len)
		return 0;

	/*
	 * Find a flow.
	 */
	ipf = ipflow_lookup(ip);
	if (ipf == NULL)
		return 0;

	/*
	 * Route and interface still up?
	 */
	rt = ipf->ipf_ro.ro_rt;
	if (IPFLOW_RTENTRY_ISDOWN(rt))
		return 0;
	ifp = rt->rt_ifp;

	/*
	 * Packet size OK?  TTL?
	 */
	if (m->m_pkthdr.len > ifp->if_mtu || ip->ip_ttl <= IPTTLDEC)
		return 0;

	/*
	 * Everything checks out and so we can forward this packet.
	 * Modify the TTL and incrementally change the checksum.
	 */
	ip->ip_ttl -= IPTTLDEC;
	if (ip->ip_sum >= htons(0xffff - (IPTTLDEC << 8)))
		ip->ip_sum += htons(IPTTLDEC << 8) + 1;
	else
		ip->ip_sum += htons(IPTTLDEC << 8);

	/*
	 * Send the packet on its way.  All we can get back is ENOBUFS
	 */
	ipf->ipf_uses++;
	ipf->ipf_timer = IPFLOW_TIMER;

	if (rt->rt_flags & RTF_GATEWAY)
		dst = rt->rt_gateway;
	else
		dst = &ipf->ipf_ro.ro_dst;

	if (serializer)
		lwkt_serialize_exit(serializer);

	error = ifp->if_output(ifp, m, dst, rt);
	if (error) {
		if (error == ENOBUFS)
			ipf->ipf_dropped++;
		else
			ipf->ipf_errors++;
	}

	if (serializer)
		lwkt_serialize_enter(serializer);
	return 1;
}

static void
ipflow_addstats(struct ipflow *ipf)
{
	ipf->ipf_ro.ro_rt->rt_use += ipf->ipf_uses;
	ipstat.ips_cantforward += ipf->ipf_errors + ipf->ipf_dropped;
	ipstat.ips_forward += ipf->ipf_uses;
	ipstat.ips_fastforward += ipf->ipf_uses;
}

static void
ipflow_free(struct ipflow *ipf)
{
	/*
	 * Remove the flow from the hash table (at elevated IPL).
	 * Once it's off the list, we can deal with it at normal
	 * network IPL.
	 */
	crit_enter();
	LIST_REMOVE(ipf, ipf_next);

	KKASSERT(ipflow_inuse > 0);
	ipflow_inuse--;
	crit_exit();

	ipflow_addstats(ipf);
	RTFREE(ipf->ipf_ro.ro_rt);
	kfree(ipf, M_IPFLOW);
}

static struct ipflow *
ipflow_reap(void)
{
	struct ipflow *ipf, *maybe_ipf = NULL;
	int idx;

	crit_enter();
	for (idx = 0; idx < IPFLOW_HASHSIZE; idx++) {
		ipf = LIST_FIRST(&ipflows[idx]);
		while (ipf != NULL) {
			/*
			 * If this no longer points to a valid route
			 * reclaim it.
			 */
			if ((ipf->ipf_ro.ro_rt->rt_flags & RTF_UP) == 0)
				goto done;

			/*
			 * choose the one that's been least recently used
			 * or has had the least uses in the last 1.5
			 * intervals.
			 */
			if (maybe_ipf == NULL ||
			    ipf->ipf_timer < maybe_ipf->ipf_timer ||
			    (ipf->ipf_timer == maybe_ipf->ipf_timer &&
			     ipf->ipf_last_uses + ipf->ipf_uses <
			     maybe_ipf->ipf_last_uses + maybe_ipf->ipf_uses))
				maybe_ipf = ipf;
			ipf = LIST_NEXT(ipf, ipf_next);
		}
	}
	ipf = maybe_ipf;
done:
	/*
	 * Remove the entry from the flow table.
	 */
	LIST_REMOVE(ipf, ipf_next);
	crit_exit();

	ipflow_addstats(ipf);
	RTFREE(ipf->ipf_ro.ro_rt);
	return ipf;
}

static void
ipflow_timo_dispatch(struct netmsg *nmsg)
{
	struct ipflow *ipf;
	int idx;

	crit_enter();
	lwkt_replymsg(&nmsg->nm_lmsg, 0);	/* reply ASAP */

	for (idx = 0; idx < IPFLOW_HASHSIZE; idx++) {
		ipf = LIST_FIRST(&ipflows[idx]);
		while (ipf != NULL) {
			struct ipflow *next_ipf = LIST_NEXT(ipf, ipf_next);

			if (--ipf->ipf_timer == 0) {
				ipflow_free(ipf);
			} else {
				ipf->ipf_last_uses = ipf->ipf_uses;
				ipf->ipf_ro.ro_rt->rt_use += ipf->ipf_uses;
				ipstat.ips_forward += ipf->ipf_uses;
				ipstat.ips_fastforward += ipf->ipf_uses;
				ipf->ipf_uses = 0;
			}
			ipf = next_ipf;
		}
	}
	crit_exit();
}

static void
ipflow_timo_ipi(void *arg __unused)
{
	struct lwkt_msg *msg = &ipflow_timo_netmsgs[mycpuid].nm_lmsg;

	crit_enter();
	if (msg->ms_flags & MSGF_DONE)
		lwkt_sendmsg(cpu_portfn(mycpuid), msg);
	crit_exit();
}

void
ipflow_slowtimo(void)
{
#ifdef SMP
	lwkt_send_ipiq_mask(smp_active_mask, ipflow_timo_ipi, NULL);
#else
	ipflow_timo_ipi(NULL);
#endif
}

static void
ipflow_create_oncpu(const struct route *ro, struct mbuf *m)
{
	const struct ip *const ip = mtod(m, struct ip *);
	struct ipflow *ipf;
	unsigned hash;

	/*
	 * See if an existing flow struct exists.  If so remove it from it's
	 * list and free the old route.  If not, try to malloc a new one
	 * (if we aren't at our limit).
	 */
	ipf = ipflow_lookup(ip);
	if (ipf == NULL) {
		if (ipflow_inuse == IPFLOW_MAX) {
			ipf = ipflow_reap();
		} else {
			ipf = kmalloc(sizeof(*ipf), M_IPFLOW,
				      M_INTWAIT | M_NULLOK);
			if (ipf == NULL)
				return;
			ipflow_inuse++;
		}
		bzero(ipf, sizeof(*ipf));
	} else if (IPFLOW_RTENTRY_ISDOWN(ipf->ipf_ro.ro_rt)) {
		crit_enter();
		LIST_REMOVE(ipf, ipf_next);
		crit_exit();

		ipflow_addstats(ipf);
		RTFREE(ipf->ipf_ro.ro_rt);
		ipf->ipf_uses = ipf->ipf_last_uses = 0;
		ipf->ipf_errors = ipf->ipf_dropped = 0;
	} else {
		/*
		 * The route entry cached in ipf is still up,
		 * this could happen while the ipf installation
		 * is in transition state.
		 * XXX should not happen on UP box
		 */
		return;
	}

	/*
	 * Fill in the updated information.
	 */
	ipf->ipf_ro = *ro;
	ro->ro_rt->rt_refcnt++;
	ipf->ipf_dst = ip->ip_dst;
	ipf->ipf_src = ip->ip_src;
	ipf->ipf_tos = ip->ip_tos;
	ipf->ipf_timer = IPFLOW_TIMER;

	/*
	 * Insert into the approriate bucket of the flow table.
	 */
	hash = ipflow_hash(ip->ip_dst, ip->ip_src, ip->ip_tos);
	crit_enter();
	LIST_INSERT_HEAD(&ipflows[hash], ipf, ipf_next);
	crit_exit();
}

#ifdef SMP

static void
ipflow_create_dispatch(struct netmsg *nmsg)
{
	struct netmsg_packet *nmp = (struct netmsg_packet *)nmsg;
	struct sockaddr_in *sin;
	struct route ro;
	int nextcpu;

	bzero(&ro, sizeof(ro));
	sin = (struct sockaddr_in *)&ro.ro_dst;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = (in_addr_t)nmsg->nm_lmsg.u.ms_result32;

	rtalloc_ign(&ro, RTF_PRCLONING);
	if (ro.ro_rt != NULL) {
		ipflow_create_oncpu(&ro, nmp->nm_packet);
		RTFREE(ro.ro_rt);
	}

	nextcpu = mycpuid + 1;
	if (nextcpu < ncpus)
		lwkt_forwardmsg(cpu_portfn(nextcpu), &nmsg->nm_lmsg);
	else
		m_freem(nmp->nm_packet);
}

#endif	/* SMP */

void
ipflow_create(const struct route *ro, struct mbuf *m)
{
	const struct ip *const ip = mtod(m, struct ip *);
#ifdef SMP
	struct netmsg_packet *nmp;
	struct netmsg *nmsg;
	int nextcpu;
#endif

	/*
	 * Don't create cache entries for ICMP messages.
	 */
	if (!ipflow_active || ip->ip_p == IPPROTO_ICMP) {
		m_freem(m);
		return;
	}

#ifdef SMP
	nmp = &m->m_hdr.mh_netmsg;
	nmsg = &nmp->nm_netmsg;

	netmsg_init(nmsg, &netisr_apanic_rport, 0, ipflow_create_dispatch);
	nmp->nm_packet = m;
	nmsg->nm_lmsg.u.ms_result32 =
		((const struct sockaddr_in *)&ro->ro_dst)->sin_addr.s_addr;

	if (mycpuid == 0) {
		ipflow_create_oncpu(ro, m);
		nextcpu = 1;
	} else {
		nextcpu = 0;
	}
	if (nextcpu < ncpus)
		lwkt_sendmsg(cpu_portfn(nextcpu), &nmsg->nm_lmsg);
	else
		m_freem(m);
#else
	ipflow_create_oncpu(ro, m);
	m_freem(m);
#endif
}

static void
ipflow_init(void)
{
	char oid_name[32];
	int i;

	for (i = 0; i < ncpus; ++i) {
		netmsg_init(&ipflow_timo_netmsgs[i], &netisr_adone_rport, 0,
			    ipflow_timo_dispatch);

		ksnprintf(oid_name, sizeof(oid_name), "inuse%d", i);

		SYSCTL_ADD_INT(NULL,
		SYSCTL_STATIC_CHILDREN(_net_inet_ip_ipflow),
		OID_AUTO, oid_name, CTLFLAG_RD, &ipflow_inuse_pcpu[i], 0,
		"# of ip flow being used");
	}
}
SYSINIT(arp, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY, ipflow_init, 0);
