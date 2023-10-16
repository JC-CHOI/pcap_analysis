#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "explorer_pcap.h"
#include <arpa/inet.h> // ntohs() , + gcc -lsocket

int ParsePCapFile(FILE *fp, PFHeader *pfh);
void PrintIPaddr(IPv4Header *iph);
void ViewPCapFile(PFHeader *pfh);

char buffer[0x100000];

int main(int argc, char *argv[])
{	
	if( argc < 2)
	{
		fprintf(stderr, "Usage : <program name> <file name> \n");
		exit(1);
	}
	
	FILE *fp = fopen(argv[1], "rb");
	if (fp == 0)
	{
		perror("file open fail ");
		return 0;
	}

	PFHeader pfh = { 0, };
	if (ParsePCapFile(fp, &pfh) == 0)
	{
		printf(" not PCAP file\n");
		fclose(fp);
		return 0;
	}
    
    // main file analysis routine
    PackHeader ph = { 0 };
	int pno=0;
    short payload_len=0;
	while (fread(&ph,sizeof(PackHeader),1,fp)==1)
	{
		pno++;
        printf("\033[31m %d\033[0m th packet, Length : \033[31m%d\033[0m\n",pno,ph.caplen);
		fread(buffer, sizeof(uchar), ph.caplen, fp);

        EtherHeader *eh = (EtherHeader *)buffer;
        uint len = ph.caplen;
        // something to do on Layer 2
        if( ntohs(eh->l3type) != 0x0800) // L3_IPv4
        {
            fprintf(stderr,"not support this type only for IPv4\n");
            continue;
        }
        uchar *next = buffer + sizeof(EtherHeader);
        len = len - sizeof(EtherHeader);
        
        IPv4Header *iph = (IPv4Header *)next;
        // Layer 3
        if( iph->protocol != 0x06) // 1byte 0x06 = TCP
        {
            fprintf(stderr, "not support this protocol only for TCP\n");
            continue;
        }
        payload_len = ntohs(iph->tlen);
        PrintIPaddr(iph);

        next = next + (iph->hlen * 4);
        len = len - (iph->hlen * 4);
        payload_len -= (iph->hlen * 4);

        TCPHeader* th = (TCPHeader*)next;
        // Layer 4
        printf("port \t: %u\t\t --->", ntohs(th->src_port));
        printf("\t%u\n", ntohs(th->dst_port));
        
        next = next + (th->hdlen * 4);
        len = len - (th->hdlen * 4);
        payload_len -= (th->hdlen * 4);

        // Layer 5 , TCP payload
        if( payload_len > 0)
        {
            printf("payload length : %d bytes \n",payload_len);
            next[payload_len] = '\0';
            printf("%s\n",(char *)next);
        }
        
	}
}

int ParsePCapFile(FILE *fp, PFHeader *pfh)
{
	fread(pfh, sizeof(PFHeader), 1, fp);
	if (pfh->magic != PF_MAGIC)
	{
		return 0;
	}
	ViewPCapFile(pfh);
	return 1;
}
void ViewPCapFile(PFHeader *pfh)
{
	printf("=========== PCAP File 헤더 정보 ============\n");
	printf("\t 버전:%d.%d\n", pfh->major, pfh->minor);
	printf("\t최대 캡쳐 길이:%d bytes\n", pfh->max_caplen);
}
void PrintIPaddr(IPv4Header *iph)
{
    uchar *up = (uchar *)&(iph->srcaddr);
    printf("ip addr : ");
    for (int i = 0; i < 4; i++)
    {
        printf("%d.", up[i]);
    }
    up = (uchar *)&(iph->dstaddr);
    printf("\t---> \t");
    for (int i = 0; i < 4; i++)
    {
        printf("%d.", up[i]);
    }
    printf("\n");
}