#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>           /* Definition of AT_* constants */

#define IP_MAXPACKET 65535
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <netinet/ip6.h>      // struct ip6_hdr
#include <linux/icmpv6.h>
#include <linux/ipv6.h>

#define IP6_HDRLEN 40         // IPv6 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data

#define RD_GWL_TIMEOUT 20

#define STATE_OLD 0
#define STATE_NEW 1

// work mode
#define SET_PRIO_LOW  0
#define SET_PRIO_HIGH 1
#define SET_RA_DROP   3

// globale may be set by parameters
static int cmpMode   = 1;
static char *batIf   = "bat0";
static char *mainIf  = "br-client"; // not used now!
static int work_Mode = SET_RA_DROP;

typedef struct gwl_s {
	struct gwl_s *next;
	int  mark;
	int  tq;
	int  has6;
	int  state;
	char mac[20];
} gwl_t;

static gwl_t *gwl_root = NULL;
static gwl_t *best = NULL;

static void getMac(char **line, char *mac)
{
	char *s = *line;
	while(*s != ' ')
	{
		*mac = *s;
		mac++;
		s++;
	}
	*mac='\0';
	while ( *s == ' ' ) s++;
	*line = s;
}

static int getTq(char **line)
{
	char *s = *line;
	int tq = 0;
	while ( ! isdigit(*s) ) s++; 
	tq = atoi(s);
	while (*s != ' ') s++;
	while (*s == ' ') s++;
	*line = s;
	return tq;
}

static int getMark(char **line)
{
	char *s = *line;
	int mark=0;
	if ( *s != ' ' )
	{
		mark=1;
		s++;
		if ( *s != ' ') s++;
	}
	while ( *s == ' ' ) s++;
	*line = s;
	return mark;
}

static void insertReplaceGw(gwl_t *gwl)
{
	gwl_t *act = gwl_root;
	if ( gwl_root == NULL )
	{
		gwl_root = calloc(1,sizeof(gwl_t));
		memcpy(gwl_root, gwl, sizeof(gwl_t));
#ifdef DEBUG
	printf("Set Root entry %s\n",gwl->mac);
#endif
	}
	else
	{
		while ( act )
		{
			if ( strcmp(act->mac, gwl->mac) == 0 )
			{
				act->tq = gwl->tq;
				act->mark = gwl->mark;
				act->state = gwl->state;
#ifdef DEBUG
				printf("Modify entry %s\n",act->mac);
#endif
				break;
			}
			else if ( act->next == NULL )
			{
				act->next = calloc(1,sizeof(gwl_t));
				memcpy(act->next, gwl, sizeof(gwl_t));
#ifdef DEBUG
				printf("Append entry %s\n",act->mac);
#endif
			}
			act = act->next;
		}
	}
}

static void cleanGwL()
{
	gwl_t *act = gwl_root;
	gwl_t *next= NULL;
	while ( act )
	{
		next = act->next;
		if ( act->state == STATE_OLD)
		{
			if ( act == best )
			{
				best = NULL;
			}
			next = act->next;
			if ( act == gwl_root )
			{
				gwl_root = next;
			}
#ifdef DEBUG
		printf("Delete entry %s\n",act->mac);
#endif
			free(act);
			act = next;
		}
		else
		{
			act = act->next;
		}
	}
}

static void setStateOld()
{
	gwl_t *act = gwl_root;
	while ( act )
	{
		act->state = STATE_OLD;
		act = act->next;
	}
}

void readGwL()
{
	FILE *f  = NULL;
	size_t size = 0;
	ssize_t ssize = 0;
	gwl_t gwl = { NULL };
	char *s;
	char *line = NULL;
	int use_netns = 0;
	char path[1024];
	snprintf(path, sizeof(path),"/sys/kernel/debug/batman_adv/%s/gateways",batIf);
	use_netns = access(path, R_OK);

#ifdef DEBUG
	printf("Read Gateway List\n");
#endif
	setStateOld();
	if ( use_netns )
	{
        	f = popen("/sbin/batctl gwl", "r");
	}
	else
	{
		f = fopen(path, "r");
	}
	if ( f )
	{
		if ( use_netns )
			ssize = getline(&line,&size,f);
		ssize = getline(&line,&size,f);
		while ( (ssize = getline(&line,&size,f)) > 0 )
		{
			memset(&gwl, 0, sizeof(gwl_t));
			gwl.state = STATE_NEW;
			s = line;
			gwl.mark = getMark(&s);
			getMac(&s, gwl.mac);
			gwl.tq = getTq(&s);
			insertReplaceGw(&gwl);
		}
		if ( line )
		{
			free(line);
		}
		if ( use_netns )
			pclose(f);
		else
			fclose(f);
	}
	else
	{
		fprintf(stderr,"Failed to call batctl\n");
	}
	cleanGwL();
	
}

static int macCmp(void *s, char *t)
{
	int r;
	if ( cmpMode == 0 )
		r = strncmp(s,t,11) == 0 && strncmp(s+15,t+15,2) == 0;
	else
		r = strncmp(s,t,15) == 0;
	return r;
}

#if 0
static void freeGwL()
{
	gwl_t *act = gwl_root->next;
	while ( gwl_root )
	{
		act = gwl_root->next;
		free(gwl_root);
		gwl_root = act;
	}
}
#endif

static int checkForGw(char *mac)
{
	gwl_t *act = gwl_root;
	int r = 0;
	if ( gwl_root == NULL )
	{
		r = 1;
	}
	while ( act )
	{
		if ( macCmp(act->mac,mac) )
		{
			if ( act->mark )
			{
				best = act;
				r=1;
				break;
			}
		}
		act = act->next;
	}
#ifdef DEBUG
	printf("Result Check %s -> %d \n", mac ,r);
#endif
	return r;
}

// RA struct
struct ipv6_hdr {
	uint32_t src[4];
	uint32_t dst[4];
	uint32_t len;
	uint8_t  zero[3];
	uint8_t nxth;
};

struct opt_hdr             /* Neighbor discovery option header */
{
    uint8_t  nd_opt_type;
    uint8_t  nd_opt_len;        /* in units of 8 octets */
    /* followed by option specific data */
};

struct opt_route
{
	uint8_t prefix_len;
	uint8_t	reserved1:3,
		router_pref:2,
		reserved2:3;	
};
  
// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}


static int handler(struct nfq_q_handle *myQueue, struct nfgenmsg *msg, struct nfq_data *pkt,   void *cbData) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *header;
    struct nfqnl_msg_packet_hw *source;
    int pl=0;
    unsigned char *pktData;
    struct ipv6_hdr *ipv6hdr;
    struct ip6_hdr *iphdr;
    struct icmp6hdr *icmp6;
    struct opt_hdr *opt;
    struct opt_route *route;
    uint8_t *opt_end;
    char mac[20];
    uint8_t buf[IP_MAXPACKET];

    if( (header = nfq_get_msg_packet_hdr(pkt)) )
        id = ntohl(header->packet_id);

    source = nfq_get_packet_hw(pkt);
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		source->hw_addr[0],
		source->hw_addr[1],
		source->hw_addr[2],
		source->hw_addr[3],
		source->hw_addr[4],
		source->hw_addr[5]);
#ifdef DEBUG
	printf("ID[ %d ]: mac %s\n",id,mac);
#endif

    int len = nfq_get_payload(pkt, &pktData);

    iphdr=(struct ip6_hdr*) pktData;
    pl = len-sizeof(struct ip6_hdr);
    icmp6=(struct icmp6hdr *)(pktData+sizeof(struct ip6_hdr));

    if ( icmp6->icmp6_type != 134 )
	 return nfq_set_verdict(myQueue, id, NF_ACCEPT, len, pktData);

    // Check if the ra is from best gateway
    int check = checkForGw(mac);
    if ( work_Mode == SET_RA_DROP )
    {    
	if ( check )
	{
#ifdef DEBUG
	    printf("ID[ %d ]: mac %s ACCEPT\n",id,mac);
#endif
	    return nfq_set_verdict(myQueue, id, NF_ACCEPT, len, pktData);
	}
	else
	{
#ifdef DEBUG
	    printf("ID[ %d ]: mac %s DROP\n",id,mac);
#endif
	    return nfq_set_verdict(myQueue, id, NF_DROP, len, pktData);
	}
    }
    else if ( work_Mode == SET_PRIO_LOW )
    {
	// LOWER_PRIO
	if ( check )
	    return nfq_set_verdict(myQueue, id, NF_ACCEPT, len, pktData);
    }

    if ( !check ) // set prio high
    {
    	return nfq_set_verdict(myQueue, id, NF_ACCEPT, len, pktData);
    }

    /* Modify paket */
    if (work_Mode == SET_PRIO_LOW )
	icmp6->icmp6_router_pref = ICMPV6_ROUTER_PREF_LOW;
    else
	icmp6->icmp6_router_pref = ICMPV6_ROUTER_PREF_HIGH;

    icmp6->icmp6_cksum=0;
    /* and route options if any */
    opt = (struct opt_hdr*)((uint8_t*) icmp6 + 16);
    opt_end = (uint8_t*) pktData + len;
    while ( (uint8_t*)opt < opt_end )
    {
	if ( opt->nd_opt_type == 24 )
	{
	    route = (struct opt_route*)(opt+1);
	    if (work_Mode == SET_PRIO_LOW )
		route->router_pref = ICMPV6_ROUTER_PREF_LOW;
	    else
		route->router_pref = ICMPV6_ROUTER_PREF_HIGH;
	}
	opt = (struct opt_hdr*)((uint8_t*)opt + ((uint16_t)opt->nd_opt_len << 3));
    }
    

    /* Prepare buf for checksum calculation */
    /* fill pseudo header */

    ipv6hdr = (struct ipv6_hdr*)&buf; 
    memcpy(ipv6hdr->src, &iphdr->ip6_src, sizeof(iphdr->ip6_src));
    memcpy(ipv6hdr->dst, &iphdr->ip6_dst, sizeof(iphdr->ip6_dst));
    ipv6hdr->len = htonl(pl);
    ipv6hdr->zero[0] = 0;
    ipv6hdr->zero[1] = 0;
    ipv6hdr->zero[2] = 0;
    ipv6hdr->nxth= 58;;

    /* copy icmp6 part to buffer */
    
    memcpy(buf+ sizeof(struct ipv6hdr),icmp6, pl);

   /* put checksum to buffer */
   icmp6->icmp6_cksum=checksum((uint16_t*)&buf, len);

    /* accept  modified paket */
    return nfq_set_verdict(myQueue, id, NF_ACCEPT, len, pktData);
}

int main(int argc, char **argv) {
    struct nfq_handle *nfqHandle;
    struct nfq_q_handle *myQueue;
    struct nfnl_handle *netlinkHandle;
    time_t ot, nt;
    int fd, res;
    char buf[4096];
    int c;
    
    while ( (c = getopt(argc, argv,  "m:c:b:i:")) > 0 )
    {
    	switch(c)
	{
	    case 'm':
	    {
		switch(*optarg)
		{
		    // set RA priority to Low / high or drop RA 
		    case 'l': work_Mode = SET_PRIO_LOW; break;
		    case 'h': work_Mode = SET_PRIO_HIGH;break;
		    case 'd': work_Mode = SET_RA_DROP;  break;
		}
	    }
	    break;
	    case 'c':
	    {
	        // set compare mode for MAC to 5 bytes or byte 0-3 and 5
		switch(*optarg)
		{
		    case '4': cmpMode = 0; break;
		    case '5': cmpMode = 1; break;
		}
	    }
	    break;
	    case 'b':batIf = optarg; break;
	    case 'i': mainIf = optarg; break;
	    default:
		return 1;
	}
    }
    // queue connection
    if (!(nfqHandle = nfq_open())) {
        perror("Error in nfq_open()");
        return(-1);
    }

    // bind this handler
    if (nfq_bind_pf(nfqHandle, AF_INET6) < 0) {
        perror("Error in nfq_bind_pf()");
        return(1);
    }

    // define a handler
    if (!(myQueue = nfq_create_queue(nfqHandle, 0, &handler, NULL))) {
        perror("Error in nfq_create_queue()");
        return(1);
    }

    // turn on packet copy mode
    if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("Could not set packet copy mode");
        return(1);
    }

    netlinkHandle = nfq_nfnlh(nfqHandle);
    fd = nfnl_fd(netlinkHandle);

    readGwL();
    ot = time(NULL);

    while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0)
    {
    	nt = time(NULL);
#ifdef DEBUG
    	printf("Ra received\n");
#endif
	if ( ot + RD_GWL_TIMEOUT < nt )
	{
		readGwL();
		ot = nt;
	}
        nfq_handle_packet(nfqHandle, buf, res);
    }

    nfq_destroy_queue(myQueue);
    nfq_close(nfqHandle);

    return 0;
}
