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
#include <linux/time.h>
/***
 * SIMPLE SNIFFER THAT CAN HELP TO ANALYZE AND CONTROL PACKETS IN THE NETWORK
 * The work of the program consists of several parts:
 *     1. Settings for the packets that we will accept
 *     2. Channel type determination
 *     3. Packets filtering
***/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Savoskin Roman, Biryukova Alexandra, Amambayeva Meruert");
MODULE_DESCRIPTION("SIS2: Linux kernel module program to capture all network packets");

struct packet_type packet;

static struct timespec t;
static struct nf_hook_ops *nfho = NULL;

static struct iphdr *iph;
char source[16], dest[16], protocolIp[16];

static unsigned int protocol_num = 0;
module_param(protocol_num, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

void print_addresses(void){
    snprintf(source, 16, "%pI4", &iph->saddr);
    snprintf(dest, 16, "%pI4", &iph->daddr);
    printk("@RAM ID: %d\n", iph->id);
    printk("@RAM SOURCE: %s\n", source);
    printk("@RAM DESTINATION: %s\n", dest);
}

void print_time(void) {
    getnstimeofday(&t);
	printk("@RAM TIME: %.2lu:%.2lu:%2lu\n",
                   (t.tv_sec / 3600 + 6) % (24),
                   (t.tv_sec / 60) % (60),
                    t.tv_sec % 60);
}
/**
 * Packet sockets are used to sending and receiving raw packets at the device driver
 * Here we control all incoming packets of protocol that were passed, in our case these are 
 * Internet protocol packets. All information with definition can be found by paths
 * /usr/include/linux/if_packet.h/ and /usr/include/linux/in.h/
**/
int recieve_packet (struct sk_buff *skb, struct net_device *dev, 
                    struct packet_type *pt, struct net_device *orig_dev) {
    printk("\n\n------------------NEW PACKET RECIEVED------------------");
    print_time();
    switch (skb->pkt_type) {
    case PACKET_HOST: printk(KERN_INFO "@RAM TYPE: to us"); break;
    case PACKET_BROADCAST: printk(KERN_INFO "@RAM TYPE: to all"); break;
    case PACKET_MULTICAST: printk(KERN_INFO "@RAM TYPE: to group"); break;
    case PACKET_OTHERHOST: printk(KERN_INFO "@RAM TYPE: to someone else"); break;
    case PACKET_OUTGOING: printk(KERN_INFO "@RAM TYPE: outgoing"); break;
    case PACKET_LOOPBACK: printk(KERN_INFO "@RAM TYPE: LOOPBACK"); break;
    case PACKET_FASTROUTE: printk(KERN_INFO "@RAM TYPE: FASTROUTE"); break;
    case PACKET_KERNEL: printk(KERN_INFO "@RAM TYPE: to kernel space"); break;
    }
    iph = ip_hdr(skb);
    print_addresses();
    kfree_skb (skb);
    return 0;
}
/**
 * In hfunc function we set our pointer on the packet ip header
 * and after that can access all the information about the packet.
 * Few examples of such information: destination and reciver IP, source information
 * We don't provide user space handling via return NF_QUEUE, instead,  all control 
 * is delivered to kernel space. Using NF_DROP we drop the packet and free the resources.
 * We accept the packet by NF_ACCEPT, thus all protocols that were passed 
 * to the module will dropped
 * By struct ip_hdr->protocol we get information about protocol that was used
 * for this packet
 * If ip_hdr->protocol==protocol_num then packet should be dropped and accepted otherwise.
**/
static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	if (!skb) { 
        return NF_ACCEPT; 
    }
    printk("\n\n------------------PACKET IS FILTERED------------------");
	iph = ip_hdr(skb);
    snprintf(protocolIp, 16, "%pI4", &iph->protocol);
    print_addresses();
	printk("@RAM PROTOCOL %s", protocolIp);
    
    if (protocol_num == (iph->protocol)){
        switch (iph->protocol)
        {               
            case IPPROTO_ICMP: printk("@RAM ICMP DROPPED"); return NF_DROP; break;
            case IPPROTO_IGMP: printk("@RAM IGMP DROPPED"); return NF_DROP; break;
            case IPPROTO_IPIP: printk("@RAM IPIP DROPPED"); return NF_DROP; break;
            case IPPROTO_TCP: printk("@RAM TCP DROPPED"); return NF_DROP; break;
            case IPPROTO_EGP: printk("@RAM EGP DROPPED"); return NF_DROP; break;
            case IPPROTO_PUP: printk("@RAM PUP DROPPED"); return NF_DROP; break;
            case IPPROTO_UDP: printk("@RAM UDP DROPPED"); return NF_DROP; break;
            case IPPROTO_IDP: printk("@RAM IDP DROPPED"); return NF_DROP; break;
            case IPPROTO_TP: printk("@RAM TP DROPPED"); return NF_DROP; break;
            case IPPROTO_DCCP: printk("@RAM DCCP DROPPED"); return NF_DROP; break;
            case IPPROTO_IPV6: printk("@RAM IPV6 DROPPED"); return NF_DROP; break;
            case IPPROTO_RSVP: printk("@RAM RSVP DROPPsED"); return NF_DROP; break;
            case IPPROTO_GRE: printk("@RAM GRE DROPPED"); return NF_DROP; break;
            case IPPROTO_ESP: printk("@RAM ESP DROPPED"); return NF_DROP; break;
            case IPPROTO_AH: printk("@RAM AH DROPPED"); return NF_DROP; break;
            case IPPROTO_MTP: printk("@RAM MTP DROPPED"); return NF_DROP; break;
            case IPPROTO_BEETPH: printk("@RAM BEETPH DROPPED"); return NF_DROP; break;
            case IPPROTO_ENCAP: printk("@RAM ENCAP DROPPED"); return NF_DROP; break;
            case IPPROTO_PIM: printk("@RAM PIM DROPPED"); return NF_DROP; break;
            case IPPROTO_COMP: printk("@RAM COMP DROPPED"); return NF_DROP; break;
            case IPPROTO_SCTP: printk("@RAM SCTP DROPPED"); return NF_DROP; break;
            case IPPROTO_UDPLITE: printk("@RAM UDPLITE DROPPED"); return NF_DROP; break;
            case IPPROTO_MPLS: printk("@RAM MPLS DROPPED"); return NF_DROP; break;
            case IPPROTO_RAW: printk("@RAM RAW DROPPED"); return NF_DROP; break;
            default:
                break;
        }
    }else {
        switch (iph->protocol)
        {               
            case IPPROTO_ICMP: printk("@RAM ICMP ACCEPTED"); break;
            case IPPROTO_IGMP: printk("@RAM IGMP ACCEPTED"); break;
            case IPPROTO_IPIP: printk("@RAM IPIP ACCEPTED"); break;
            case IPPROTO_TCP: printk("@RAM TCP ACCEPTED"); break;
            case IPPROTO_EGP: printk("@RAM EGP ACCEPTED");  break;
            case IPPROTO_PUP: printk("@RAM PUP ACCEPTED");  break;
            case IPPROTO_UDP: printk("@RAM UDP ACCEPTED"); break;
            case IPPROTO_IDP: printk("@RAM IDP ACCEPTED"); break;
            case IPPROTO_TP: printk("@RAM TP ACCEPTED"); break;
            case IPPROTO_DCCP: printk("@RAM DCCP ACCEPTED"); break;
            case IPPROTO_IPV6: printk("@RAM IPV6 ACCEPTED");  break;
            case IPPROTO_RSVP: printk("@RAM RSVP ACCEPTED"); break;
            case IPPROTO_GRE: printk("@RAM GRE ACCEPTED"); break;
            case IPPROTO_ESP: printk("@RAM ESP ACCEPTED");  break;
            case IPPROTO_AH: printk("@RAM AH ACCEPTED"); break;
            case IPPROTO_MTP: printk("@RAM MTP ACCEPTED"); break;
            case IPPROTO_BEETPH: printk("@RAM BEETPH ACCEPTED"); break;
            case IPPROTO_ENCAP: printk("@RAM ENCAP ACCEPTED"); break;
            case IPPROTO_PIM: printk("@RAM PIM ACCEPTED"); break;
            case IPPROTO_COMP: printk("@RAM COMP ACCEPTED"); break;
            case IPPROTO_SCTP: printk("@RAM SCTP ACCEPTED"); break;
            case IPPROTO_UDPLITE: printk("@RAM UDPLITE ACCEPTED"); break;
            case IPPROTO_MPLS: printk("@RAM MPLS ACCEPTED"); break;
            case IPPROTO_RAW: printk("@RAM RAW ACCEPTED"); break;
            default:
                break;
        }

    }

	return NF_ACCEPT;
}

static int __init ram_init(void) {
    // We define which type of protocols will received
    // In our case ETH_P_IP means that we will receive all Internet protocol packets
    packet.type = htons(ETH_P_IP);
    packet.dev = dev_get_by_name (&init_net, "enp0s3");
    packet.func = recieve_packet;
    dev_add_pack (&packet);
    printk(KERN_INFO "@RAM Module insertion completed successfully!\n");
    // we register the filter in the input path before routing. To register a filter we specify
    // that will work with ipv4 via PF_INET; to register more that one hook in the same place via NF_IP_PRI_FIRST
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
    printk(KERN_INFO "@RAM Cleaning up module....\n");
}

module_init(ram_init);
module_exit(ram_cleanup);
