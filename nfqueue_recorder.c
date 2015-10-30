/*! netfilterilter_queue.c
 *
 \brief test file
 \author julien vehent
 \date 20111203
 \code gcc -Wall -o nfqueue_recorder nfqueue_recorder.c -lnetfilter_queue -lpcap
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <time.h>
#include <getopt.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#define BUFSIZE 2048
// pcap file descriptor
pcap_dumper_t *p_output;
int use_pcap = 0;

static void print_pkt4(struct iphdr *iph)
{
    // Computing IP address translation from 32 bits words to 4*8bits decimal
    /* NOTE ON THE LENGTHS
    all lengths used in headers are specified in 32bits words
    thus, to print the size in bytes, we need to multiply this value by 4
    */

    // display IP HEADERS : ip.h line 45
    // ntohs convert short unsigned int, ntohl do the same for long unsigned int
    fprintf(stdout, "IP{v=%u; ihl=%u; tos=%u; tot_len=%u; id=%u; ttl=%u; protocol=%u; "
        ,iph->version
        ,iph->ihl*4
        ,iph->tos
        ,ntohs(iph->tot_len)
        ,ntohs(iph->id)
        ,iph->ttl
        ,iph->protocol);

    char *saddr = inet_ntoa(*(struct in_addr *)&iph->saddr);
    fprintf(stdout,"saddr=%s; ",saddr);

    char *daddr = inet_ntoa(*(struct in_addr *)&iph->daddr);
    fprintf(stdout,"daddr=%s}\n",daddr);

}

static void print_pkt6(struct ip6_hdr *ip6h)
{
    fprintf(stdout, "IP{v=%x; tc=%x; fl=%x; pl_len=%x; next_hdr=%x; hop_limit=%x; "
	    ,ip6h->ip6_vfc >>4
	    ,ip6h->ip6_flow >> 20
	    ,ntohl(ip6h->ip6_flow & 0x000fffff)
	    ,ntohs(ip6h->ip6_plen)
	    ,ip6h->ip6_nxt
	    ,ip6h->ip6_hlim);	
	
    char addr6[INET6_ADDRSTRLEN]; 
    // TODO: Replace later with protocol independent struct/function
    // inet_ntop need to be replaced
    inet_ntop(AF_INET6, &ip6h->ip6_src, addr6, sizeof(addr6));
    fprintf(stdout, "saddr=%s; ", addr6);
   
    inet_ntop(AF_INET6, &ip6h->ip6_dst, addr6, sizeof(addr6));
    fprintf(stdout, "daddr=%s;}\n", addr6);    


}

#define PREROUTING 0
#define POSTROUTING 4
#define OUTPUT 3
#define INPUT 1
#define FORWARD 2

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *nf_packet;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph){
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u ",
            ntohs(ph->hw_protocol), ph->hook);

    
        switch (ph->hook) 
        {
            case INPUT:
                printf("(INPUT), ");
            break;
            case PREROUTING:
                printf("(PREROUTING), ");
            break;
            case FORWARD:
                printf("(FORWARD), ");
            break;
            case OUTPUT:
                printf("(OUTPUT), ");
            break;     
            case POSTROUTING:
                printf("(POSTROUTING), ");
            break;  
            default:
                printf("UNKNOWN!"); 
            break;   
        }           
    
        printf("id=%u ", id); 
    
    }
    

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);

    ret = nfq_get_payload(tb, &nf_packet);
    if ((ret >= 0)){
        printf("payload_len=%d bytes", ret);
            fputc('\n', stdout);
        }

    // parse the packet headers
    struct iphdr *iph = ((struct iphdr *) nf_packet);

    // Check if IP Header version is 4 or 6 (IPv4 or IPV6)
    if (iph->version == 6)
    {
	    // Since it is IPv6 packet, we cast it to ip6_hdr struct, and pass
	    // pass to print_pkt6 function.
	    struct ip6_hdr *ip6h = ((struct ip6_hdr *) nf_packet); 

        // Print the IPv6 Header Fields
	    print_pkt6(ip6h); 
   
	    
	    // Check for ICMPv6 packet (Next Header = 58)
        if (ip6h->ip6_nxt == IPPROTO_ICMPV6)
        {
//            fprintf(stdout, "sizeof struct icmp6_hdr = %lu\n", sizeof(struct icmp6_hdr)); 
            // Cast the icmpv6 header after "shifting" the initial pointer to point to the 
            // beginning of icmp6 header by offseting it by the size of ip6 header :-) 
            struct icmp6_hdr *icmp6h = ((struct icmp6_hdr *) (&nf_packet[sizeof(struct ip6_hdr)])) ;

/*	        char *buf = malloc(64); 
	        memcpy(buf, &nf_packet[40], 64);
	        
	        struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)buf; 

            fprintf(stdout, "ICMPv6{type=0x%x; code=0x%x; checksum=0x%x;}\n"
	            ,icmp6h->icmp6_type
	            ,icmp6h->icmp6_code
	            ,ntohs(icmp6h->icmp6_cksum));       
*/	            
	        // STAGE 2: Cast the ICMPv6 packets into its individual struct:
	        // nd_router_solicit, nd_router_advert, nd_neighbor_solicit .. 
	        // defined in netinet/icmp6.h
            char *targetAddr = malloc(INET6_ADDRSTRLEN * sizeof(char));
            struct nd_neighbor_advert   *na;
            struct nd_neighbor_solicit  *ns; 
            struct nd_router_advert     *ra; 
            struct nd_router_solicit    *rs;
            	                	        
	        switch (icmp6h->icmp6_type)
	        {
	            case ND_NEIGHBOR_ADVERT:
	                na = 
	                    ((struct nd_neighbor_advert *)(&nf_packet[sizeof(struct ip6_hdr)])) ;

                    fprintf(stdout, "ICMPv6 HEADER{type=%u (NA); code=%u; checksum=0x%x; "
	                    ,na->nd_na_hdr.icmp6_type
	                    ,na->nd_na_hdr.icmp6_code
	                    ,ntohs(na->nd_na_hdr.icmp6_cksum));  
	                
                    memset(targetAddr, 0, INET6_ADDRSTRLEN * sizeof(char)); 
	                inet_ntop(AF_INET6, &na->nd_na_target, targetAddr, INET6_ADDRSTRLEN); 
	                
	                fprintf(stdout, "target address=%s;}\n", targetAddr);                 
	            
	            break;           
                
                case ND_ROUTER_SOLICIT:
	                rs = 
	                    ((struct nd_router_solicit *)(&nf_packet[sizeof(struct ip6_hdr)])) ;

                    fprintf(stdout, "ICMPv6 HEADER{type=%u (RS); code=%u; checksum=0x%x;}\n"
	                    ,rs->nd_rs_type
	                    ,rs->nd_rs_code
	                    ,ntohs(rs->nd_rs_cksum));  

                    fprintf(stdout, "ICMPv6 OPTION{reserved=%u;}\n"
	                    ,ntohl(rs->nd_rs_reserved));	                    
                 
                break;
                
                case ND_ROUTER_ADVERT:
	                ra = 
	                    ((struct nd_router_advert *)(&nf_packet[sizeof(struct ip6_hdr)])) ;

                    fprintf(stdout, "ICMPv6 HEADER{type=%u (RA); code=%u; checksum=0x%x;}\n"
	                    ,ra->nd_ra_type
	                    ,ra->nd_ra_code
	                    ,ntohs(ra->nd_ra_cksum));  

                    fprintf(stdout, "ICMPv6 OPTION{hoplimit=%u; managed=%u; other flag=%u; MHA Flag=%u; "
	                    ,ra->nd_ra_curhoplimit
	                    ,ra->nd_ra_flags_reserved >> 7
	                    ,(ra->nd_ra_flags_reserved >> 6) & 1
	                    ,(ra->nd_ra_flags_reserved >> 5) & 1);	                    
	                    
                    fprintf(stdout, "lifetime=%u; reachable=%u ms; retransmit=%u ms; }\n"
	                    ,ntohs(ra->nd_ra_router_lifetime)
	                    ,ntohl(ra->nd_ra_reachable)
	                    ,ntohl(ra->nd_ra_retransmit));                      
                   
                break;
                
                case ND_NEIGHBOR_SOLICIT:
	                ns = 
	                    ((struct nd_neighbor_solicit *)(&nf_packet[sizeof(struct ip6_hdr)])) ;

                    fprintf(stdout, "ICMPv6{type=%u (NS); code=0x%x; checksum=0x%x; "
	                    ,ns->nd_ns_hdr.icmp6_type
	                    ,ns->nd_ns_hdr.icmp6_code
	                    ,ntohs(ns->nd_ns_hdr.icmp6_cksum));  
	                
	                memset(targetAddr, 0, INET6_ADDRSTRLEN * sizeof(char)); 
	                inet_ntop(AF_INET6, &ns->nd_ns_target, targetAddr, INET6_ADDRSTRLEN); 
	                
	                fprintf(stdout, "target address=%s;}\n", targetAddr);                  
                break;
                
                case ND_REDIRECT:
                break;
      
	        }
	        
	        free(targetAddr); 	       	             
                
        }    
    }

    else if (iph->version == 4)
    {
	    // We already cast to iphdr earlier, so just pass the data to 
	    // print_pkt function. 
	    print_pkt4(iph); 
    }
    else
	    fprintf(stdout, "UNKNOWN IP VERSIONI\n"); 

   return id; 

}

static inline void print_tcphdr4(struct iphdr *iph, struct tcphdr *tcp)
{

    // if protocol is tcp
    if (iph->protocol == 6){
        // extract tcp header from packet
        /* Calculate the size of the IP Header. iph->ihl contains the number of 32 bit
        words that represent the header size. Therfore to get the number of bytes
        multiple this number by 4 */
//        struct tcphdr *tcp = ((struct tcphdr *) (nf_packet + (iph->ihl << 2)));
    
        /* Calculate the size of the TCP Header. tcp->doff contains the number of 32 bit
        words that represent the header size. Therfore to get the number of bytes
        multiple this number by 4 */
        //int tcphdr_size = (tcp->doff << 2); 

        /* to print the TCP headers, we access the structure defined in tcp.h line 89
        and convert values from hexadecimal to ascii */
        fprintf(stdout, "TCP{sport=%u; dport=%u; seq=%u; ack_seq=%u; flags=u%ua%up%ur%us%uf%u; window=%u; urg=%u}\n",
            ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq)
            ,tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin, ntohs(tcp->window), tcp->urg_ptr);
    }

    // if protocol is udp
/*    if(iph->protocol == 17){
        struct udphdr *udp = ((struct udphdr *) (nf_packet + (iph->ihl << 2)));
        fprintf(stdout,"UDP{sport=%u; dport=%u; len=%u}\n",
            ntohs(udp->source), ntohs(udp->dest), udp->len);
    }
*/
    fprintf(stdout,"\n");

}



static u_int32_t record_pkt (struct nfq_data *tb){

    /*! create pcap specific header
     */
    struct pcap_pkthdr phdr;

    /*! init capture time
     */
    static struct timeval t;
    memset (&t, 0, sizeof(struct timeval));
    gettimeofday(&t, NULL);
    phdr.ts.tv_sec = t.tv_sec;
    phdr.ts.tv_usec = t.tv_usec;

    /*! populate pcap struct with packet headers
     */
    unsigned char *nf_packet;
    phdr.caplen = nfq_get_payload(tb,&nf_packet);
    phdr.len = phdr.caplen;

    /*! dump packet data to the file */
    pcap_dump((u_char *)p_output, &phdr, (const u_char *)nf_packet);

    return 0;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    if(use_pcap == 1)
        record_pkt(nfa);

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


/* ************************************* 
 *
 * Section: TRUST-ND related functions 
 * Sub-Section: Trust Option Validation
 *
 * ************************************* */ 



/* ************************************* 
 *
 * Section: TRUST-ND related functions 
 * Sub-Section: Trust Option Generation
 *
 * ************************************* */ 

// TRUST-ND Option's Nonce Field
static inline int TrustND_generateNonce()
{
    // Generate Nonce field using SHA1 PRNG
    // Java version: 
/* 
	   // Create a secure random number generator
	   SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");

	   // Get 512 random bits
	   byte[] bytes = new byte[512/8];
	   sr.nextBytes(bytes);

	   // Create secure number generators with the seed
	   int seedByteCount = 5;
	   byte[] seed = sr.generateSeed(seedByteCount);
	   sr.setSeed(seed);
	  
	   return Math.abs(sr.nextInt());

*/
    return 1; 
}

static inline int TrustND_generateTimestamp(char *ts)
{
    // Calculate Timestamp and populate buffer pointed by ts
	/**  SAMPLE FROM ORIGINAL TRUST-ND IMPLEMENTATION IN JAVA
	 * Class to generate timestamps with microsecond precision
	 * For example: MicroTimestamp.INSTANCE.get() = "19:13:45.267128"
	  
	public enum MicroTimestamp 
	{  INSTANCE ;

	   private long              startDate ;
	   private long              startNanoseconds ;
	   private SimpleDateFormat  dateFormat ;

	   private MicroTimestamp()
	   {  this.startDate = System.currentTimeMillis() ;
	      this.startNanoseconds = System.nanoTime() ;
	      this.dateFormat = new SimpleDateFormat("HH:mm:ss:SSS") ;
	   }

	   public String get()
	   {  long microSeconds = (System.nanoTime() - this.startNanoseconds) / 1000 ;
	      long date = this.startDate + (microSeconds/1000) ;
	      return this.dateFormat.format(date) + String.format("%03d", microSeconds % 1000) ;
	   }
	}
	END SAMPLE */
	
    return 1;    
}


static inline int TrustND_generateMAD(char *mad)
{
    // Java version 
    /*
String computeMAD(byte [] byteRaw, int offset, int len)
	{
		String MAD = ""; 	

		MessageDigest md = MessageDigest.getInstance("SHA-1");
	
        byte[] sha1hash = new byte[20]; 
        md.update(byteRaw, offset, len);
        sha1hash = md.digest();
        
        final char[] hexArray = "0123456789ABCDEF".toCharArray();       
        char[] hexChars = new char[sha1hash.length * 2];
        
        for ( int j = 0; j < sha1hash.length; j++ ) {
        	int v = sha1hash[j] & 0xFF;
        	hexChars[j * 2] = hexArray[v >>> 4];
        	hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }	
            
//     	System.out.println("hexa length " +hexChars.length +" valid sha-1? "+ new String(hexChars).matches("[a-fA-F0-9]{40}"));
            
        MAD="";
        int a = 1;
        for (int n = 0; n < hexChars.length; n++)
        {
        	if(a <= 2)
        	{
        		MAD = MAD + hexChars[n];
        		a++;
        	} 
        	else 
        	{
        		MAD = MAD + " " + hexChars[n];
        		a=2;
        	}
        }

        System.out.println("computed MAD: " + MAD + ".");		


	    return MAD;
    }   
    
    JAVA VERSION ENDS */ 


    return 1; 
}


int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    int argument;
    char buf[BUFSIZE];
    char *pcap_destination;
    pcap_t *pd;

    /*! process arguments
     */
    while ( -1 != (argument = getopt (argc, argv, "o:h")))
    {
        switch (argument)
        {
            case 'o' :
                pcap_destination = (char *) malloc(strlen(optarg) * sizeof(char));
                memcpy(pcap_destination,optarg,strlen(optarg));
                fprintf(stdout,"pcap recording into %s\n",pcap_destination);
                use_pcap = 1;
                break;
            case 'h':
                fprintf(stdout,"nfqueue_recorder: record/display traffic passing through a netfilter queue\n\n"
                    "-h: this help\n"
                    "-o <file> : record in pcap <file>\n"
                    "\nroute traffic to it using the NFQUEUE target\n"
                    "\tiptables -I INPUT -p tcp --dport 443 -j NFQUEUE\n"
                    "\tiptables -I FORWARD -j NFQUEUE\n"
                    "\nex: ./nfqueue_recorder -o traffic.pcap\n");
                return 0;
            default:
                fprintf(stdout,"use -h for help\n");
                return -1;
        }
    }

    /*! open dump file
    * using DLT_RAW because iptables does not give us datalink layer
    */
    if(use_pcap == 1){
        fprintf(stdout,"opening pcap file at %s\n",pcap_destination);
        pd = pcap_open_dead(DLT_RAW, BUFSIZE);
        p_output = pcap_dump_open(pd,pcap_destination);
        if (!p_output){
            fprintf(stderr, "error while opening pcap file\n");
            exit(1);
        }
    }

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    nh = nfq_nfnlh(h);
    fd = nfnl_fd(nh);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        printf("-- New packet received --\n");

        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
