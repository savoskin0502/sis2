#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Savoskin Roman, Biryukova Alexandra, Amambayeva Meruert");
MODULE_DESCRIPTION("SIS2: Linux kernel module program to capture all network packets");

struct packet_type packet;

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

static int __init ram_init(void) {
    packet.type = htons(ETH_P_IP);
    packet.dev = dev_get_by_name (&init_net, "enp0s3");
    packet.func = recieve_packet;
    dev_add_pack (&packet);
    printk(KERN_INFO "RAM : Module insertion completed successfully!\n");
    return 0;
}

static void __exit ram_cleanup(void) {
    dev_remove_pack(&packet);
    printk(KERN_INFO "RAM : Cleaning up module....\n");
}

module_init(ram_init);
module_exit(ram_cleanup);
