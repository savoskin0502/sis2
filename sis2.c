#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Savoskin Roman, Biryukova Alexandra, Amambayeva Meruert");
MODULE_DESCRIPTION("SIS2: Linux kernel module program to capture all network packets");

struct packet_type packet;
static struct nf_hook_ops *nfho = NULL;
int recieve_packet (struct sk_buff *skb, struct net_device *dev, 
                    struct packet_type *pt, struct net_device *orig_dev) {
    printk(KERN_INFO "RAM : New packet captured.\n");

    switch (skb->pkt_type) {
    case PACKET_HOST: printk(KERN_INFO "RAM : PACKET to us"); break;
    case PACKET_BROADCAST: printk(KERN_INFO "RAM : PACKET to all"); break;
    case PACKET_MULTICAST: printk(KERN_INFO "RAM : PACKET to group"); break;
    case PACKET_OTHERHOST: printk(KERN_INFO "RAM : PACKET to someone else"); break;
    case PACKET_OUTGOING: printk(KERN_INFO "RAM : PACKET outgoing"); break;
    case PACKET_LOOPBACK: printk(KERN_INFO "RAM : PACKET LOOPBACK"); break;
    case PACKET_FASTROUTE: printk(KERN_INFO "RAM : PACKET FASTROUTE"); break;
    case PACKET_KERNEL: printk(KERN_INFO "RAM : PACKET to kernel space"); break;
    }

    printk(KERN_CONT " Device: %s ; 0x%.4X ; 0x%.4X \n", skb->dev->name, 
                  ntohs(skb->protocol), ip_hdr(skb)->protocol);

    kfree_skb (skb);
    return 0;
}


static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *udph;
	if (!skb){
        printk(KERN_INFO "here");
        return NF_ACCEPT;
    }

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (ntohs(udph->dest) == 53) {
            printk(KERN_INFO "RAM : UDP rejected");
			return NF_ACCEPT;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
        printk(KERN_INFO "RAM : TCP accepted");
		return NF_ACCEPT;
	}
	return NF_DROP;
}

static int __init ram_init(void) {
    packet.type = htons(ETH_P_IP);
    packet.dev = dev_get_by_name (&init_net, "enp0s3");
    packet.func = recieve_packet;
    dev_add_pack (&packet);
    printk(KERN_INFO "RAM : Module insertion completed successfully!\n");

    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    nfho->hook = (nf_hookfn*)hfunc;
    nfho->hooknum = NF_INET_PRE_ROUTING;
    nfho->pf = PF_INET;
    nfho->priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, nfho);

    
    return 0;
}

static void __exit ram_cleanup(void) {
    dev_remove_pack(&packet);

    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);

    printk(KERN_INFO "RAM : Cleaning up module....\n");

}

module_init(ram_init);
module_exit(ram_cleanup);
