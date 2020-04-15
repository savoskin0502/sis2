# SIS 2 Project

# Capturing network packets

## Team members:
	[Biryukova Alexandra] (https://github.com/AlexandraBiryukova)
	[Savoskin Roman] (https://github.com/savoskin0502)
	[Amambayeva Meruert] (https://github.com/hellomeruert)
	
	
### Goal of the project: 
create a simple sniffer that can help to analyze and control packets in the network

### Description: 
we want to create a module that will present all packets in the socket buffer structure form, that is using to store all information about packets, like header, ip, destination information etc. For all packets in the network we will fi lter them by protocol type and decide which ones we will accept and which ones to discard. At the same time, for all received packets we will determine for whom they were intended. Were they directed to us or for all machines in the network(broadcast), or may be some looped back packets.
In our work we will control at least two type of protocols(UDP, TCP) and six packet types. There are:
1. Packets that was directed to us
2. Broadcast packets - intended for reception by all network participants
3. Multicast packets - addressed to a group of destination computers simultaneously
4. Unicast packets for sending to a peer - host to host sending
5. Outgoing packets - originate at the machine
6. Any looped back broadcast or unicast packets
