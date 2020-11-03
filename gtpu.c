/*
    This is gtpu kernel module
    Version 0.1
    Copyright (C) 2010 Grzegorz Pawelski <grzegorz.pawelski@nsn.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#ifndef __OPTIMIZE__
#define __OPTIMIZE__
#endif


#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/types.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/ip6_route.h>
#include <net/ip6_fib.h>
#include <net/xfrm.h>
#include <linux/spinlock.h>

#include <linux/inet.h>
#include <net/ipip.h>

#include <linux/inet_lro.h>

#include <linux/moduleparam.h>
#include <linux/version.h>


#define IPUDPGTP_HDR_LEN 36

#define SETTEID 0x89f1
#define SETSRC  0x89f2
#define SETDST  0x89f3
#define SETSAEPRFX  0x89f4
#define SETSAEIP    0x89f5
#define SETSAETEID  0x89f6
#define SETTOS  0x89f7


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GTP Module");
MODULE_AUTHOR("GP");


static int mode=0;
module_param(mode, int, 0000);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#ifdef NET_SKBUFF_DATA_USES_OFFSET
#define SKB_IPHDR(skb) ((struct iphdr*)(skb->head+skb->network_header))
#else
#define SKB_IPHDR(skb) ((struct iphdr*)skb->network_header)
#endif
#else
#define SKB_IPHDR(skb) skb->nh.iph
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
static inline void skb_dst_set(struct sk_buff *skb, struct dst_entry *dst)
{
   skb->dst = dst;
}

static inline struct dst_entry *skb_dst(const struct sk_buff *skb)
{
   return skb->dst;
}
#endif


u32 sae_teids[256];
u8 sae_current_ip;
u32 sae_prfx;

struct net_device *gtp_dev;
struct nf_hook_ops hook;

typedef struct gtp_dev_priv {
   u32 teid;
   u32 src;
   u32 dst;
   u8 tos;
   struct net_device_stats stats;
} gtp_dev_priv;

struct gtpuhdr {
   u8 flags;
   u8 mtype;
   u16 length;
   u32 teid;
};


static void gtp_uninit(struct net_device *dev)
{
   printk(KERN_INFO "GTP UNINIT!\n");  
   dev_put(dev);
}


static int
gtp_xmit(struct sk_buff *skb, struct net_device *dev) 
{
   int pkt_len = skb->len;
   struct iphdr  *old_iph = SKB_IPHDR(skb);
   u8     tos=13;
   u16    df=0x40;
   struct rtable *rt;
   struct net_device *tdev;
   struct iphdr  *iph;
   int    max_headroom;
   struct gtp_dev_priv *privat;
   privat = netdev_priv(dev);
   u32 teid = privat->teid;
   struct udphdr *udph;
   void *iph_in = skb->data;
   u16 in_len = ntohs( ((struct iphdr *)iph_in)->tot_len );

   struct flowi fl = 
   { .oif = 0,
     .nl_u = 
             { .ip4_u =
	                { .daddr = privat->dst,
	                  .saddr = privat->src,
		          .tos = RT_TOS(tos) 
                        } 
             },
       .proto = IPPROTO_UDP 
   };

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
   struct net *nt = dev_net(dev); 
   if (ip_route_output_key(nt, &rt, &fl)) goto error;
#else
   if (ip_route_output_key(&rt, &fl)) goto error; 
#endif
   
   tdev = rt->u.dst.dev;                                                     
   max_headroom = LL_RESERVED_SPACE(tdev) + IPUDPGTP_HDR_LEN;

   if (skb_headroom(skb) < max_headroom || skb_cloned(skb) || skb_shared(skb)) 
   {
      struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
      if (!new_skb) {
         ip_rt_put(rt);
	 dev_kfree_skb(skb);
	 return 0;
      }
      if (skb->sk) skb_set_owner_w(new_skb, skb->sk);
      dev_kfree_skb(skb);
      skb = new_skb;
      old_iph = SKB_IPHDR(skb);
   }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
   skb->transport_header = skb->network_header;
   skb_push(skb, IPUDPGTP_HDR_LEN);
   skb_reset_network_header(skb);
#else
   skb->h.raw = skb->nh.raw;
   skb->nh.raw = skb_push(skb, IPUDPGTP_HDR_LEN);
#endif

   memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
   dst_release(skb_dst(skb));
   skb_dst_set(skb, &rt->u.dst);

   iph 			=	(struct iphdr*)skb->data;
   iph->version		=	4;
   iph->ihl		=	sizeof(struct iphdr) >> 2;
   iph->frag_off	=	df;
   iph->protocol	=	IPPROTO_UDP;
   iph->tos		=	privat->tos;
   iph->daddr		=	rt->rt_dst;
   iph->saddr		=	rt->rt_src;
   iph->ttl = 0xff;

   udph 		= (struct udphdr*)(skb->data + 20);
   udph->source	        = htons(2152);
   udph->dest		= htons(2152);
   udph->len 		= htons(in_len + 16);
   udph->check		= 0;

   u_char header[8] = { 0x30, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
   u16 gtp_len = in_len;
   header[2] = (gtp_len >> 8) & 0xff;
   header[3] = gtp_len & 0xff;

   header[4] = (teid >> 24) & 0xff;
   header[5] = (teid >> 16) & 0xff;
   header[6] = (teid >> 8) & 0xff;
   header[7] = teid & 0xff;

   memcpy(skb->data + 28, header, 8);

   nf_reset(skb);
                                         
   int err;                                                                                                                                                                         
   skb->ip_summed = CHECKSUM_NONE;                                 
   iph->tot_len = htons(skb->len);                             
   ip_select_ident(iph, &rt->u.dst, NULL);                       
   ip_send_check(iph);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
   err = NF_HOOK(PF_INET, NF_INET_LOCAL_OUT, skb, NULL, rt->u.dst.dev, dst_output); 
#else
   err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev, dst_output); 
#endif
                                                                                                                  
   if (err == NET_XMIT_SUCCESS || err == NET_XMIT_CN) 
   {          
      privat->stats.tx_bytes += pkt_len;                             
      privat->stats.tx_packets++;                                    
   } else 
   {                                                    
      privat->stats.tx_errors++;                                     
      privat->stats.tx_aborted_errors++;                             
   }                                                               

   return 0;
error:
   dev_kfree_skb(skb);
   return 0;
}


static struct net_device_stats *gtp_get_stats(struct net_device *dev)
{
   struct gtp_dev_priv *privat;
   privat = netdev_priv(dev);
   return &privat->stats;
}


static int
gtp_ioctl (struct net_device *dev, struct ifreq *ifr, int cmd)
{
   struct gtp_dev_priv *privat;
   privat = netdev_priv(dev);

   switch (cmd) {
      case SETTEID:
         privat->teid = ifr->ifr_ifru.ifru_ivalue;
         break;
      case SETSRC:
         privat->src = ifr->ifr_ifru.ifru_ivalue;
         break;
      case SETDST:
         privat->dst = ifr->ifr_ifru.ifru_ivalue;
         break;
      case SETSAEPRFX:
         sae_prfx = ifr->ifr_ifru.ifru_ivalue & 0x00ffffff;
         break;
      case SETSAEIP:
         sae_current_ip = ifr->ifr_ifru.ifru_ivalue;
         break;
      case SETSAETEID:
         sae_teids[sae_current_ip] = ifr->ifr_ifru.ifru_ivalue;
         break;
      case SETTOS:
         privat->tos = (u8)ifr->ifr_ifru.ifru_ivalue;
         break;

   }
   return 0;
}


static int gtp_change_mtu(struct net_device *dev, int new_mtu)
{
   return 0;
}


static int gtp_dev_init(struct net_device *dev)
{
   dev_hold(dev);
   return 0;
}


static int gtp_open(struct net_device *dev)
{
   return 0;
}


static int gtp_close(struct net_device *dev)
{
   return 0;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
static struct net_device_ops gtp_netdev_ops = 
{
   .ndo_uninit		= gtp_uninit,
   .ndo_start_xmit	= gtp_xmit,
   .ndo_get_stats	= gtp_get_stats,
   .ndo_do_ioctl	= gtp_ioctl,
   .ndo_change_mtu	= gtp_change_mtu,
   .ndo_init		= gtp_dev_init,
   .ndo_open		= gtp_open,
   .ndo_stop		= gtp_close,
};
#endif


static void
gtp_setup(struct net_device *dev)
{
   dev->destructor 	= free_netdev;                 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
   dev->netdev_ops = &gtp_netdev_ops;
#else
   dev->uninit		= gtp_uninit;
   dev->hard_start_xmit	= gtp_xmit;
   dev->get_stats	= gtp_get_stats;
   dev->do_ioctl	= gtp_ioctl;
   dev->change_mtu	= gtp_change_mtu;
   dev->init		= gtp_dev_init;
   dev->open		= gtp_open;
   dev->stop		= gtp_close;
#endif
   dev->type		= ARPHRD_VOID;
   dev->hard_header_len = LL_MAX_HEADER + IPUDPGTP_HDR_LEN;
   dev->mtu		= ETH_DATA_LEN - IPUDPGTP_HDR_LEN;
   dev->flags		= IFF_NOARP |IFF_POINTOPOINT;
   dev->iflink		= 0;
   dev->addr_len	= 4;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
unsigned int
gtp_rcv(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
			  const struct net_device *out, int (*okfn)(struct sk_buff*))
#else
unsigned int
gtp_rcv(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in,
			  const struct net_device *out, int (*okfn)(struct sk_buff*)) 
#endif
{
   struct gtp_dev_priv *privat;
   privat = netdev_priv(gtp_dev);

   struct iphdr * iph;
   struct udphdr * udph;

   struct gtpuhdr * gtpuh;

   struct sk_buff *sock_buff;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
   sock_buff = skb;
#else
   sock_buff = *skb;
#endif
   iph = (struct iphdr *)sock_buff->data;
   if (iph->protocol != IPPROTO_UDP) return NF_ACCEPT;

   udph = (struct udphdr *)(sock_buff->data + (iph->ihl*4));
   gtpuh = (struct gtpuhdr *)(sock_buff->data + (iph->ihl*4) + 8);

   if ((udph->dest == htons(2152)) && !(iph->frag_off & htons(IP_MF)))
   {
      if (gtpuh->mtype == 0xff)
      {
         if (1)
         {    
            struct iphdr *ip;
	    struct sk_buff *new_skb;
	    new_skb = skb_clone(sock_buff, GFP_ATOMIC);
	    secpath_reset(new_skb);	
	    skb_pull(new_skb, IPUDPGTP_HDR_LEN);
	    ip = (struct iphdr *)new_skb->data;
	    if (ip->version == 4) 
            {
               int pkt_len = new_skb->len;
	       new_skb->protocol = htons(ETH_P_IP);
	       new_skb->pkt_type = PACKET_HOST;
               if (mode==1) new_skb->dev = gtp_dev;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
               skb_dst_drop(new_skb);
#else
               dst_release(skb_dst(new_skb));
#endif
	       nf_reset(new_skb);
	       netif_rx(new_skb);   
               privat->stats.rx_bytes += pkt_len;                             
               privat->stats.rx_packets++;    
            }
	    else 
            {
               dev_kfree_skb(new_skb); 
            }
         }
      }
      else if (gtpuh->mtype == 0x01) return NF_ACCEPT;
      return NF_DROP;
   }
   return NF_ACCEPT;    
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
unsigned int
sae_gw(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
			  const struct net_device *out, int (*okfn)(struct sk_buff*)) 
#else
unsigned int
sae_gw(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in,
			  const struct net_device *out, int (*okfn)(struct sk_buff*)) 
#endif
{
   struct iphdr * iph;
   struct sk_buff *skb1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
   skb1 = skb;
#else
   skb1 = *skb;
#endif
   iph = (struct iphdr *)skb1->data;
   struct gtp_dev_priv *privat;
   privat = netdev_priv(gtp_dev);

   if ((iph->daddr & 0x00ffffff) == sae_prfx)
   {
      privat->teid = sae_teids[iph->daddr >> 24];
      if (privat->teid != 0) 
      {
	 struct sk_buff *new_skb;
	 new_skb = skb_clone(skb1, GFP_ATOMIC);
	 secpath_reset(new_skb); 
         gtp_xmit(new_skb, gtp_dev);
      }                                                     
      return NF_DROP;
   }
   return gtp_rcv(hooknum, skb, in, out, 0); 
}


static int __init gtp_init(void)
{
   printk(KERN_INFO "GTPU INIT!\n");
   gtp_dev = alloc_netdev(sizeof(struct gtp_dev_priv), "gtp0", gtp_setup);
   if (gtp_dev == NULL) printk(KERN_INFO "GTPU ALLOC NULL!\n");                                                             
   if (register_netdev(gtp_dev)) {printk(KERN_INFO "GTPU REGISTER ERROR!\n");};

   if (mode==0) hook.hook = sae_gw;
   else hook.hook = gtp_rcv;

   hook.pf	= PF_INET;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
   hook.hooknum	= NF_INET_PRE_ROUTING;
#else
   hook.hooknum	= NF_IP_PRE_ROUTING;
#endif
 
   hook.priority	= NF_IP_PRI_FIRST;
   nf_register_hook(&hook);
   
   int i; 
   for (i = 0; i<=255; i++) sae_teids[i] = 0;   
   sae_current_ip = 0; 
   sae_prfx = 0x0;

   printk(KERN_INFO "GTPU MODE: %i!\n", mode);

   return 0;
}


static void __exit gtp_exit(void)
{
   printk(KERN_INFO "GTPU EXIT!.\n");
   unregister_netdev(gtp_dev);
   nf_unregister_hook(&hook);
}

module_init(gtp_init);
module_exit(gtp_exit);




