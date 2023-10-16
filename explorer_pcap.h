
#define PF_MAGIC 0xA1B2C3D4

typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;

struct _PFHeader //패킷 파일 헤더
{
	uint magic;//0xA1B2C3D4
	ushort major;
	ushort minor;
	uint gmt_to_local;
	uint timestamp;
	uint max_caplen;
	uint linktype;
};
typedef struct _PFHeader PFHeader; 

struct _PACKETHEADER //패킷 헤더
{
	uint captime;//second
	uint caputime;//u second
	uint caplen;
	uint packlen;
};
typedef struct _PACKETHEADER PackHeader;

typedef struct  _EtherHeader EtherHeader;
struct  _EtherHeader
{
	uchar dst_mac[6];
	uchar src_mac[6];
	ushort l3type;
};

typedef struct _IPv4Header IPv4Header;
struct _IPv4Header
{    
    uchar hlen : 4;
    uchar version : 4;
    uchar tos;
    ushort tlen;
    ushort id;
    ushort fl_off;
#define DONT_FRAG(x) (x&0x40)
#define MORE_FRAG(x) (x&0x20)
#define FRAG_OFF(x) ntohs(x&0xFF1F)
    uchar ttl;
    uchar protocol;
    ushort checksum;
    uint srcaddr;
    uint dstaddr;
};

typedef struct _TCPHeader TCPHeader;
struct _TCPHeader
{
    ushort src_port;
    ushort dst_port;
    uint seqno;
    uint ackno;
    
    uchar reserved : 4;
    uchar hdlen : 4;
    
    uchar fin : 1;
    uchar syn : 1;
    uchar rst : 1;
    uchar psh : 1;
    uchar ack : 1;
    uchar urg : 1;
    uchar reserv : 2;
    
    ushort winsize;
    ushort checksum;
    ushort upoint;
};
