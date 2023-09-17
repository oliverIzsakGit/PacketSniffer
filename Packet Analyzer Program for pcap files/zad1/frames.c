#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#define ethertypes "}\n\0"
#define i3eeeSAPS "{\n\0"
#define IPv4p "+\n\0"
#define TCPp "-\n\0"
#define UDPp "(\n\0"
#define ICMPp "%\n\0"
#define IPv6p "#\n\0"
#define ARPp "!\n\0"
#define SNAPp "$\n\0"
#define EHL 14 // ETHERNET HEADER LENGTH

struct ethernet {
    u_char dmac[6];
    u_char smac[6];
    u_short EtherType;
};

struct IE3
{
    u_char dsap;
    u_char ssap;
    u_char ie3Control;
    u_char ie3Vendor[3];
    u_short ie3EtherType;

};

struct arp {
    u_short hwType;
    u_short protType;
    u_char hwAddrLen;
    u_char protAddrLen;
    u_short operation;
    u_char srcHwAddr[6];
    u_char srcAddr[4];
    u_char tarHwAddr[6];
    u_char destAddr[4];
};
struct icmp {
    u_char type;
    u_char code;
    u_short checksum;
};


struct ip {
    u_char versionAndIHL;
    u_char TypeOfService;
    u_short TotalLength;
    u_short id;
    u_short offset;
    u_char timeToLive;
    u_char protocol;
    u_short checksum;
    u_char srcAddr[4];
    u_char destAddr[4];
};

struct ip6 {
    u_char versionTrafficFlow[4];
    u_short payloadLength;
    u_char NextHeader;
    u_char HopLimit;
    u_char srcAddr[16];
    u_char destAddr[16];

};

struct tcp {
    u_short srcPort;
    u_short destPort;
    u_int32_t sequenceNo;
    u_int32_t ackNo;
    u_short offsetReservedFlag;
    u_short window;
    u_short checksum;
    u_short urgentPointer;
};
struct HTTPList {
    u_short frameNo;
    struct tcp* current;
    struct tcp* next;
};

struct udp {
    u_short  srcPort;
    u_short  destPort;
    u_short  length;
    u_short  checksum;
};





int getFrameType(u_short type, u_char* payload) { // returns an int representing an ethertype.
    
    
    
    if ( type >= 1536)  //ethernet II ether types have a decimal value above 1536
    {
        return 1;

    }
    else {
        struct IE3* e3;
        e3 = (struct IE3*)(payload + EHL); 
       
        if ((e3->dsap) == 255 && (e3->ssap)==255)         //ieee novell raw
        {
           
           
            return 2;
        }
        else if ((e3->dsap) == 170 && (e3->ssap)==170)      // SNAP
        {
            
            return 3;
        }
        else   return 4; // LLC

    }
    return 0;

}
char* getProtocol(u_short number, FILE* protocols, char* sign) // returns the protocol in string format from the protocol.txt file.
{
    rewind(protocols);
    if (protocols == NULL)
    {
        printf("Error: could not open file ");
        return 1;
    }
    
    char* type[255];
    int m = 0;
    int n = 0;
    char* prot;

    while (fgets(type, 255, protocols)) {

        if (strcmp(type, sign) == 0)
        {

            m++;
            fgets(type, 255, protocols);
            
        }
        if (m == 1)
        {
            prot = strtok(type, "=");
            if (atoi(prot) == number)
            {
                

                prot = strtok(NULL, "=");
                char *prott = malloc(strlen(prot) + 1);
               
                strcpy(prott, prot);
                
                
                return prott;
            }

        }
        


    }


}

u_short bitSwap(u_short etherType)
{

    u_short m;

    m = (etherType << 8) | (etherType >> 8);

    return m;






}
void printout(int packetAmount,int plength,int mlength,u_short type, u_char* payload,struct ethernet* header,char* typeName,struct ip* ipv4,FILE* protocols,FILE* output,char* format)
{
 
    
    printf("%s  - frame_number: %u\n",format, packetAmount);
    fprintf(output, "%s - frame_number: %u\n",format, packetAmount);
printf("%s    len_frame_pcap: %u\n",format, plength);
fprintf(output,"%s   len_frame_pcap: %u\n",format, plength);

printf("%s    len_frame_medium: %u\n", format, mlength);
fprintf(output,"%s   len_frame_medium: %u\n", format, mlength);

int etype = getFrameType(type, payload);
if (etype == 1)
{
    printf("%s    frame_type: ETHERNET II\n", format );
    fprintf(output,"%s   frame_type: ETHERNET II\n", format );
}
else if (etype == 2) {
   
    printf("%s    frame_type: IEEE 802.3 Raw\n", format);
    fprintf(output,"%s   frame_type: IEEE 802.3 Raw\n", format);
}
else if (etype == 3) {
    printf("%s    frame_type: IEEE 802.3 LLC & SNAP\n",format);
    fprintf(output,"%s   frame_type: IEEE 802.3 LLC & SNAP\n", format);

}
else if (etype == 4) {
    
    printf("%s    frame_type: IEEE 802.3 LLC\n", format);
    fprintf(output,"%s   frame_type: IEEE 802.3 LLC\n", format);
    
    

}
else { printf("Error with Frame type");
fprintf(output,"Error with Frame type");
}
printf("%s    src_mac: ",format );
fprintf(output, "%s   src_mac: ", format );
for (int i = 0; i < 6; i++) {
    if (i == 5) {
        printf("%.2x", header->smac[i]);
        fprintf(output, "%.2x", header->smac[i]);
    }else {printf("%.2x:", header->smac[i]);
    fprintf(output, "%.2x:", header->smac[i]);}
    
    

}

printf("\n");
printf("%s    dst_mac: ", format );
fprintf(output, "\n");
fprintf(output, "%s   dst_mac: ", format);
for (int i = 0; i < 6; i++) {
    if (i == 5) {
        printf("%.2x", header->dmac[i]);
        fprintf(output, "%.2x", header->dmac[i]);
    }
    else {
        printf("%.2x:", header->dmac[i]);
        fprintf(output, "%.2x:", header->dmac[i]);
    }
  
}
printf("\n");
fprintf(output, "\n");
if (etype == 4) {
    struct IE3* ie = (struct IE3*)(payload + EHL);
    char* prot = getProtocol(ie->ssap, protocols, (char*)i3eeeSAPS);
    if (prot != NULL) {
        printf("%s    sap: %s", format, prot);
        fprintf(output, "%s   sap: %s", format, prot);

    }
    
}
if (etype == 3)
{
    struct IE3* ie = (struct IE3*)(payload + EHL);
    
    char* prot = getProtocol(bitSwap(ie->ie3EtherType), protocols, (char*)i3eeeSAPS);
   
    if (prot != NULL) {
        
        printf("%s    pid: %s", format, prot);
        fprintf(output, "%s   pid: %s", format, prot);
    }
    }
   
if (etype == 1) {
    if (strcmp(typeName, "Unknown")) {
        printf("%s    ether_type: %s", format, typeName);
        fprintf(output, "%s   ether_type: %s", format, typeName);
    }
}

if ( etype == 1 && typeName !=NULL ) {
    if (strcmp(typeName,"IPv4\n\0") == 0) {
        printf("%s    src_ip: %d.%d.%d.%d\n", format, ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);
        fprintf(output,"%s   src_ip: %d.%d.%d.%d\n", format, ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);
        printf("%s    dst_ip: %d.%d.%d.%d\n", format, ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);
        fprintf(output,"%s   dst_ip: %d.%d.%d.%d\n", format, ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);
      
        char* prot = getProtocol(ipv4->protocol, protocols, (char*)IPv4p);
        if (prot != NULL) {
            printf("%s    protocol: %s", format, prot);
            fprintf(output, "%s   protocol: %s", format, prot);

        }
    }
      else if (strcmp(typeName, "IPv6\n\0") == 0) {
        struct ip6* ipv6 = (struct ip*)(payload + EHL);
        /* //for some reason this is not needed
        
        printf("Source ip address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", ipv6->srcAddr[0], ipv6->srcAddr[1], ipv6->srcAddr[2], ipv6->srcAddr[3], ipv6->srcAddr[4], ipv6->srcAddr[5], ipv6->srcAddr[6], ipv6->srcAddr[7], ipv6->srcAddr[8], ipv6->srcAddr[9], ipv6->srcAddr[10], ipv6->srcAddr[11], ipv6->srcAddr[12], ipv6->srcAddr[13], ipv6->srcAddr[14], ipv6->srcAddr[15]);
        fprintf(output, " Source ip address :%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", ipv6->srcAddr[0], ipv6->srcAddr[1], ipv6->srcAddr[2], ipv6->srcAddr[3], ipv6->srcAddr[4], ipv6->srcAddr[5], ipv6->srcAddr[6], ipv6->srcAddr[7], ipv6->srcAddr[8], ipv6->srcAddr[9], ipv6->srcAddr[10], ipv6->srcAddr[11], ipv6->srcAddr[12], ipv6->srcAddr[13], ipv6->srcAddr[14], ipv6->srcAddr[15]);
        printf("Source ip address:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", ipv6->destAddr[0], ipv6->destAddr[1], ipv6->destAddr[2], ipv6->destAddr[3], ipv6->destAddr[4], ipv6->destAddr[5], ipv6->destAddr[6], ipv6->destAddr[7], ipv6->destAddr[8], ipv6->destAddr[9], ipv6->destAddr[10], ipv6->destAddr[11], ipv6->destAddr[12], ipv6->destAddr[13], ipv6->destAddr[14], ipv6->destAddr[15]);
        fprintf(output, "Source ip address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", ipv6->destAddr[0], ipv6->destAddr[1], ipv6->destAddr[2], ipv6->destAddr[3], ipv6->destAddr[4], ipv6->destAddr[5], ipv6->destAddr[6], ipv6->destAddr[7], ipv6->destAddr[8], ipv6->destAddr[9], ipv6->destAddr[10], ipv6->destAddr[11], ipv6->destAddr[12], ipv6->destAddr[13], ipv6->destAddr[14], ipv6->destAddr[15]);
    */
        char* prot = getProtocol(bitSwap(bitSwap(ipv6->NextHeader)), protocols, (char*)IPv6p);
        if (prot != NULL) {
            printf("%s   app_protocol: %s", format, prot);
            fprintf(output, "%s   app_protocol: %s", format, prot);
        }
    }
      else if (strcmp(typeName, "ARP\n\0") == 0)
    {
        struct arp* ar = (struct arp*)(payload + EHL);
        
        char* prot = getProtocol(bitSwap(ar->operation), protocols, (char*)ARPp);
        

      
        printf("%s    arp_opcode: %s", format, prot);
       
        fprintf(output, "%s   arp_opcode: %s", format, prot);
        printf("%s    src_ip: %d.%d.%d.%d\n", format, ar->srcAddr[0], ar->srcAddr[1], ar->srcAddr[2], ar->srcAddr[3]);
        fprintf(output, "%s   src_ip: %d.%d.%d.%d\n", format, ar->srcAddr[0], ar->srcAddr[1], ar->srcAddr[2], ar->srcAddr[3]);
        printf("%s    dst_ip: %d.%d.%d.%d\n", format, ar->destAddr[0], ar->destAddr[1], ar->destAddr[2], ar->destAddr[3]);
        fprintf(output, "%s   dst_ip: %d.%d.%d.%d\n", format, ar->destAddr[0], ar->destAddr[1], ar->destAddr[2], ar->destAddr[3]);

        

        
    }
   
}


}


struct ipAddresses
{
    u_char srcIp[4];
    u_char destIp[4];
    int frames[500];
    int num;
    char isEnded;
    struct ipAdresses* next;
};
u_short calculateICMP(u_char val)
{
    u_char m = val;
    int k = m % 16;

    u_short b = k * 4;


    return b;
}
struct ipAddresses* getList(u_char* packet,struct ipAddresses* pairs,int packetCount,int choice,struct ipAddresses* current,char end)
{
    
    if (choice == 10)
    {
        struct arp* http = (struct arp*)(packet + EHL);




        if (pairs->num == 0) {

            pairs->srcIp[0] = http->srcAddr[0];
            pairs->srcIp[1] = http->srcAddr[1];
            pairs->srcIp[2] = http->srcAddr[2];
            pairs->srcIp[3] = http->srcAddr[3];

            pairs->destIp[0] = http->destAddr[0];
            pairs->destIp[1] = http->destAddr[1];
            pairs->destIp[2] = http->destAddr[2];
            pairs->destIp[3] = http->destAddr[3];


            pairs->frames[0] = packetCount;
            
            pairs->num = 1;
            pairs->next = NULL;
            pairs->isEnded =end;
           
            return pairs;
        }

        current = pairs;
        struct ipAddresses* last = current; // this remembers the last node

        while (current != NULL)
        {   //  first search the linked list whtether is already contains this ip
            if (
                (
                (
                    ((current->srcIp[0] == http->srcAddr[0]) &&
                        (current->srcIp[1] == http->srcAddr[1]) &&
                        (current->srcIp[2] == http->srcAddr[2]) &&
                        (current->srcIp[3] == http->srcAddr[3])
                        )
                    &&
                    ((current->destIp[0] == http->destAddr[0]) &&
                        (current->destIp[1] == http->destAddr[1]) &&
                        (current->destIp[2] == http->destAddr[2]) &&
                        (current->destIp[3] == http->destAddr[3])))
                ||
                (
                    (
                        (current->srcIp[0] == http->destAddr[0]) && (current->srcIp[1] == http->destAddr[1]) && (current->srcIp[2] == http->destAddr[2]) && (current->srcIp[3] == http->destAddr[3])
                        )
                    &&
                    (
                        (current->destIp[0] == http->srcAddr[0]) && (current->destIp[1] == http->srcAddr[1]) && (current->destIp[2] == http->srcAddr[2]) && (current->destIp[3] == http->srcAddr[3])
                        )
                    )) && current->isEnded ==0


                )

            { // if it contains then we increment the numbeR there., put the van counter to 1. and break from the loop.
                current->num++;
                
                    current->frames[(current->num) - 1] = packetCount;
                
                    if (end == 1 && (current->isEnded==0 && current->num==2))
                {
                    current->isEnded = 1;
                    
                }
                return pairs;

            } 
            last = current;
            current = current->next;  // then put into the current the next one.
        } // if there was no match with the other ips then we take the last node and put it into the current, 
        current = last;
        { // this happens when we are adding a 2nd  node to the linked list.
            struct ipAddresses* current2 = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
            for (int i = 0; i < 500; i++)
            {
                current2->frames[i] = -1;
            }

            current2->srcIp[0] = http->srcAddr[0];
            current2->srcIp[1] = http->srcAddr[1];
            current2->srcIp[2] = http->srcAddr[2];
            current2->srcIp[3] = http->srcAddr[3];

            current2->destIp[0] = http->destAddr[0];
            current2->destIp[1] = http->destAddr[1];
            current2->destIp[2] = http->destAddr[2];
            current2->destIp[3] = http->destAddr[3];

            current2->num = 1;
            current2->frames[0] = packetCount;
            current2->next = NULL;
            current2->isEnded = end;
           current->next = current2; // adding the  node to the end of the list

        }

    }





else {





 struct ip* http = (struct ip*)(packet + EHL); 

if (pairs->num == 0) {

    pairs->srcIp[0] = http->srcAddr[0];
    pairs->srcIp[1] = http->srcAddr[1];
    pairs->srcIp[2] = http->srcAddr[2];
    pairs->srcIp[3] = http->srcAddr[3];

    pairs->destIp[0] = http->destAddr[0];
    pairs->destIp[1] = http->destAddr[1];
    pairs->destIp[2] = http->destAddr[2];
    pairs->destIp[3] = http->destAddr[3];


    pairs->frames[0] = packetCount;
  
    pairs->num = 1;
    pairs->next = NULL;
    pairs->isEnded = end;
    return pairs; 
}

current = pairs;
struct ipAddresses* last = current; // this remembers the last node

while (current != NULL)
{   //  first search the linked list whtether is already contains this ip
   // printf("Current is currently %d \n", current->isEnded);
    if ((

        (
            ((current->srcIp[0] == http->srcAddr[0]) &&
                (current->srcIp[1] == http->srcAddr[1]) &&
                (current->srcIp[2] == http->srcAddr[2]) &&
                (current->srcIp[3] == http->srcAddr[3])
                )
            &&
            ((current->destIp[0] == http->destAddr[0]) &&
                (current->destIp[1] == http->destAddr[1]) &&
                (current->destIp[2] == http->destAddr[2]) &&
                (current->destIp[3] == http->destAddr[3])))
        ||
        (
            (
                (current->srcIp[0] == http->destAddr[0]) && (current->srcIp[1] == http->destAddr[1]) && (current->srcIp[2] == http->destAddr[2]) && (current->srcIp[3] == http->destAddr[3])
                )
            &&
            (
                (current->destIp[0] == http->srcAddr[0]) && (current->destIp[1] == http->srcAddr[1]) && (current->destIp[2] == http->srcAddr[2]) && (current->destIp[3] == http->srcAddr[3])
                )
            )) && current->isEnded == 0


        )

    { 
        current->num++;
  
            current->frames[(current->num) - 1] = packetCount;
         
       
        if (end == 1)
        {
            current->isEnded = 1;
         
           
        }
      
       
        // printf("frame : %d , Same node being incremented:  %d.%d.%d.%d - %d.%d.%d.%d - frame : %d  \n",packetCount, current->srcIp[0], current->srcIp[1], current->srcIp[2], current->srcIp[3], current->destIp[0], current->destIp[1], current->destIp[2], current->destIp[3], current->frames[current->num-1]);

        return pairs;

    } // if we do not find it, then we put the current node into the last variable.
    last = current;
    current = current->next;  // then put into the current the next one.
} // if there was no match with the other ips then we take the last node and put it into the current, 
current = last;
 // this happens when we are adding a 2nd  node to the linked list.
    struct ipAddresses* current2 = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    for (int i = 0; i < 500; i++)
    {
        current2->frames[i] = -1;
    }

    current2->srcIp[0] = http->srcAddr[0];
    current2->srcIp[1] = http->srcAddr[1];
    current2->srcIp[2] = http->srcAddr[2];
    current2->srcIp[3] = http->srcAddr[3];

    current2->destIp[0] = http->destAddr[0];
    current2->destIp[1] = http->destAddr[1];
    current2->destIp[2] = http->destAddr[2];
    current2->destIp[3] = http->destAddr[3];

    current2->num = 1;
    current2->frames[0] = packetCount;
    current2->next = NULL;
    current2->isEnded = end;
  
    current->next = current2; // adding the  node to the end of the list



return pairs;
}
        
    
    return pairs;
}





void ICMPCommunication(int returnValue, pcap_t* pcap_file, struct pcap_pkthdr* header, u_char* packet, int packetCount, struct ipAddresses* pairs, FILE* protocol, FILE* output, int k,char* file,int complete)
{
    int i = 0;// for packets
   
   
    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    while (returnValue = pcap_next_ex(pcap_file, &header, &packet) >= 0)
    {
        u_short type;
        int pcaplen = (header->caplen) + 4;

        if (pcaplen < 64)
        {
            pcaplen = 64;
        }
        u_short m;
        struct ethernet* ethHead;
        ethHead = (struct Ethernet*)(packet);
        char* etypeName = "  ";
        type = bitSwap(ethHead->EtherType);
        current = pairs;
      
        if (current == NULL || current->frames[0] == -1)
        {
            printf("No results\n"); return;
        }



        if (current!=NULL && packetCount == current->frames[i]) {
            if ((current->isEnded == 1 && complete == 1) || (current->isEnded == 0 && complete == 0)) {
                
                etypeName = getProtocol(type, protocol, (char*)ethertypes);

                struct ip* ipv4 = (struct ip*)(packet + EHL);
                char* format = "    ";
                if (i == 0) {
                    printf("    number_comm: %d\n", k);

                    fprintf(output, "  - number_comm: %d\n", k);
                    printf("    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);

                    fprintf(output, "    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);
                    printf("     dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);

                    fprintf(output, "    dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);
                    printf("    packets:\n");
                    fprintf(output, "    packets:\n");

                }
                u_char m = (ipv4->versionAndIHL);
                u_short sol = calculateICMP(m);
                struct icmp* por = (struct icmp*)(packet + EHL + sol);

                char* pro = getProtocol((u_short)(por->type), protocol, (char*)ICMPp);


                printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, ipv4, protocol, output, format);
                if (pro == NULL)
                {
                    pro = "Fragmented\n";
                }



                printf("        Type: %s", pro);


                fprintf(output, "       type: %s", pro);
                u_short code = bitSwap(por->code);
                if (code < 31) {
                    printf("       Code: %hu\n", code);
                    fprintf(output, "       code: %hu\n", code);
                }
                else {
                    printf("       code: -\n");
                    fprintf(output, "       code: -\n");
                }


                printf("        hexa_frame: |");
                fprintf(output, "       hexa_frame: |");

                for (u_int l = 0; (l < header->caplen); l++)
                {


                    if ((l % 16) == 0)
                    {
                        printf("\n\t     ");
                        fprintf(output, "\n\t     ");

                    }


                    printf("%.2x ", packet[l]);
                    fprintf(output, "%.2x ", packet[l]);

                }
                printf("\n\n");
                fprintf(output, "\n\n");

                i++;
                
                if (i == 500 || current->frames[i] == -1)
                {

                    

                    break;
                }
            }
            else { k--; }

          
        }
        packetCount++;

    
        

    }
    if (current->next != NULL)
    {
        pairs = current->next;
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
       
        ICMPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output,k, file, complete);
    }
}

void ARPCommunication(int returnValue, pcap_t* pcap_file, struct pcap_pkthdr* header, u_char* packet, int packetCount, struct ipAddresses* pairs, FILE* protocol, FILE* output,int k, char* file,int complete)
{
    //
            
    
    int i = 0;// for packets
    
    
    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    current = pairs;
   

    while (returnValue = pcap_next_ex(pcap_file, &header, &packet) >= 0) // opening pcap file
    {
        u_short type;
        int pcaplen = (header->caplen) + 4;            // calculating frame length provided by pcap 

        if (pcaplen < 64)
        {
            pcaplen = 64;
        }
        u_short m;
        struct ethernet* ethHead;
        ethHead = (struct Ethernet*)(packet);
        char* etypeName = "  ";
        type = bitSwap(ethHead->EtherType);
       



       
           
                
        
                  
        if (packetCount == current->frames[i]) {
            if ((current->isEnded == 1 && complete==1 ) || (current->isEnded==0 && complete==0)) {

                etypeName = getProtocol(type, protocol, (char*)ethertypes);

                if (etypeName == NULL) {

                    etypeName = "Not ARP";
                }
                if (strcmp(etypeName, "ARP\n\0") == 0) {



                    struct arp* arp = (struct arp*)(packet + EHL);




                    char* operation = getProtocol(bitSwap(arp->operation), protocol, (char*)ARPp);
                    
                   
                    if (i == 0) {
                        printf("    number_comm: %d\n", k);

                        fprintf(output, "  - number_comm: %d\n", k);
                        printf("     src_comm:: %d.%d.%d.%d\n", arp->srcAddr[0], arp->srcAddr[1], arp->srcAddr[2], arp->srcAddr[3]);

                        fprintf(output, "    src_comm:: %d.%d.%d.%d\n", arp->srcAddr[0], arp->srcAddr[1], arp->srcAddr[2], arp->srcAddr[3]);
                        printf("      dst_comm: %d.%d.%d.%d\n", arp->destAddr[0], arp->destAddr[1], arp->destAddr[2], arp->destAddr[3]);

                        fprintf(output, "    dst_comm: %d.%d.%d.%d\n", arp->destAddr[0], arp->destAddr[1], arp->destAddr[2], arp->destAddr[3]);
                        printf("    packets:\n");
                        fprintf(output, "    packets:\n");

                    }


                    char* format = "     ";
                    etypeName = getProtocol(type, protocol, (char*)ethertypes);
                    printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, NULL, protocol, output, format);

                    printf("         hexa_frame: |");
                    fprintf(output, "        hexa_frame: |");
                   
                    for (u_int l = 0; (l < header->caplen); l++)
                    {


                        if ((l % 16) == 0)
                        {
                            printf("\n\t   ");
                            fprintf(output, "\n\t      ");

                        }


                        printf("%.2x ", packet[l]);
                        fprintf(output, "%.2x ", packet[l]);

                    }



                    printf("\n\n");
                    fprintf(output, "\n\n");

                    i++;
                    if ( current->frames[i] == -1)
                    {

                        

                        break;
                    }
                }
            }
            else { k--; }
        }
         
                    packetCount++; 


        

    }
    if (current->next != NULL)
    {
        pairs = current->next;
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        k++;
        ARPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,complete);
    }
}

void TFTPCommunication(int returnValue, pcap_t* pcap_file, struct pcap_pkthdr* header, u_char* packet, int packetCount, struct ipAddresses* pairs, FILE* protocol, FILE* output, int k, char* file,int complete)
{
   

    int i = 0;// for packets

    
    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    current = pairs;
    if (current == NULL || current->frames[0] == -1)
    {
        printf("No results\n"); return;
    }
    while (returnValue = pcap_next_ex(pcap_file, &header, &packet) >= 0) // opening pcap file
    {
        u_short type;
        int pcaplen = (header->caplen) + 4;            // calculating frame length provided by pcap 

        if (pcaplen < 64)
        {
            pcaplen = 64;
        }
        u_short m;
        struct ethernet* ethHead;
        ethHead = (struct Ethernet*)(packet);
        char* etypeName = "  ";
        type = bitSwap(ethHead->EtherType);
        
        

        if (packetCount == current->frames[i]) {
            if ((current->isEnded == 1 && complete == 1) || (current->isEnded == 0 && complete == 0)) {
                struct ip* ipv4 = (struct ip*)(packet + EHL);
                etypeName = getProtocol(type, protocol, (char*)ethertypes);
                if (i == 0) {
                    printf("    number_comm: %d\n", k);

                    fprintf(output, "  - number_comm: %d\n", k);
                    printf("    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);

                    fprintf(output, "    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);
                    printf("     dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);

                    fprintf(output, "    dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);
                    printf("    packets:\n");
                    fprintf(output, "    packets:\n");

                }
                
                etypeName = getProtocol(type, protocol, (char*)ethertypes);
                char* format = "    ";
                printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, ipv4, protocol, output, format);

                struct udp* ud = (struct udp*)(packet + EHL + 20);

                
              
                
                printf("        src_port: %hu\n", bitSwap(ud->srcPort));
                printf("        dst_port: %hu\n", bitSwap(ud->destPort));
                printf("        app_protocol: TFTP");

                fprintf(output, "       src_port: %hu\n", bitSwap(ud->srcPort));
                fprintf(output, "       dst_port: %hu\n", bitSwap(ud->destPort));
                fprintf(output, "       app_protocol: TFTP\n");

               
                printf("         hexa_frame: |");
                fprintf(output, "       hexa_frame: |");

                for (u_int l = 0; (l < header->caplen); l++)
                {


                    if ((l % 16) == 0)
                    {
                        printf("\n\t   ");
                        fprintf(output, "\n\t     ");

                    }


                    printf("%.2x ", packet[l]);
                    fprintf(output, "%.2x ", packet[l]);

                }



                printf("\n\n");
                fprintf(output, "\n\n");

                i++;
                if ( current->frames[i] == -1)
                {

                    

                    break;
                }
            }
            else { k--; }
        }

        packetCount++;




    }
    if (current->next != NULL)
    {
        pairs = current->next;
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        k++;
        TFTPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,complete);
    }
}


void TELNETCommunication(int returnValue, pcap_t* pcap_file, struct pcap_pkthdr* header, u_char* packet, int packetCount, struct ipAddresses* pairs, FILE* protocol, FILE* output, int k, char* file,int complete)
{

    int i = 0;// for packets


    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    current = pairs;
    if (current == NULL || current->frames[0] == -1)
    {
        printf("No results\n"); return;
    }
    while (returnValue = pcap_next_ex(pcap_file, &header, &packet) >= 0) // opening pcap file
    {
        u_short type;
        int pcaplen = (header->caplen) + 4;            // calculating frame length provided by pcap 

        if (pcaplen < 64)
        {
            pcaplen = 64;
        }
        u_short m;
        struct ethernet* ethHead;
        ethHead = (struct Ethernet*)(packet);
        char* etypeName = "  ";
        type = bitSwap(ethHead->EtherType);


        if (packetCount == current->frames[i]) {
            if ((current->isEnded == 1 && complete == 1) || (current->isEnded == 0 && complete == 0)) {
                struct ip* ipv4 = (struct ip*)(packet + EHL);
                etypeName = getProtocol(type, protocol, (char*)ethertypes);
                if (i == 0) {
                    printf("    number_comm: %d\n", k);

                    fprintf(output, "  - number_comm: %d\n", k);
                    printf("    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);

                    fprintf(output, "    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);
                    printf("     dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);

                    fprintf(output, "    dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);
                    printf("    packets:\n");
                    fprintf(output, "    packets:\n");

                }

               
                char* format = "     ";
                etypeName = getProtocol(type, protocol, (char*)ethertypes);
                printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, ipv4, protocol, output, format);

                struct tcp* tcp = (struct tcp*)(packet + EHL + 20);

                char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);

                printf("        src_port: %hu\n", bitSwap(tcp->srcPort));
                printf("        dst_port: %hu\n", bitSwap(tcp->destPort));
                printf("        app_protocol: TELNET");

                fprintf(output, "        src_port: %hu\n", bitSwap(tcp->srcPort));
                fprintf(output, "        dst_port: %hu\n", bitSwap(tcp->destPort));
                fprintf(output, "        app_protocol: TELNET\n");

                u_char* g = (u_char*)(packet + EHL + 33);
                unsigned char p = *g;
                int bits[8];
                /*
                printf("Flags:\n");
                fprintf(output, "Flags:\n");
                for (int i = 0; i != 8; i++) {
                    bits[i] = (p & (1 << i)) != 0;

                    printf("%u", bits[i]);
                    fprintf(output, "%u", bits[i]);

                }
                printf(" - ");
                fprintf(output, " - ");
                if (bits[4] == 1)
                {
                    printf("ACK,");
                    fprintf(output, "ACK,");
                }
                if (bits[3] == 1)
                {
                    printf("PUSH,");

                    fprintf(output, "PUSH,");
                }
                if (bits[2] == 1)
                {
                    printf("RESET,");
                    fprintf(output, "RESET,");
                }
                if (bits[1] == 1)
                {
                    printf("SYN,");
                    fprintf(output, "SYN,");
                }
                if (bits[0] == 1)
                {
                    printf("FIN,");
                    fprintf(output, "FIN,");
                }
                printf("\n");
                fprintf(output, "\n");
                */

                printf("         hexa_frame: |");
                fprintf(output, "        hexa_frame: |");
                
                for (u_int l = 0; (l < header->caplen); l++)
                {


                    if ((l % 16) == 0)
                    {
                        printf("\n\t   ");
                        fprintf(output, "\n\t      ");

                    }


                    printf("%.2x ", packet[l]);
                    fprintf(output, "%.2x ", packet[l]);

                }



                printf("\n\n");
                fprintf(output, "\n\n");

                i++;
                if (current->frames[i] == -1)
                {

                    

                    break;
                }
            }
                    else { k--; }

        }
        packetCount++;




    }
    if (current->next != NULL)
    {
        pairs = current->next;
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        k++;
        TELNETCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,complete);
    }
}

void SSHCommunication(int returnValue, pcap_t* pcap_file, struct pcap_pkthdr* header, u_char* packet, int packetCount, struct ipAddresses* pairs, FILE* protocol, FILE* output, u_short k, char* file,int complete)
{

    int i = 0;// for packets


    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    current = pairs;
    if (current == NULL || current->frames[0] == -1)
    {
        printf("No results\n"); return;
    }
    while (returnValue = pcap_next_ex(pcap_file, &header, &packet) >= 0) // opening pcap file
    {
        u_short type;
        int pcaplen = (header->caplen) + 4;            // calculating frame length provided by pcap 

        if (pcaplen < 64)
        {
            pcaplen = 64;
        }
        u_short m;
        struct ethernet* ethHead;
        ethHead = (struct Ethernet*)(packet);
        char* etypeName = "  ";
        type = bitSwap(ethHead->EtherType);


        if (packetCount == current->frames[i]) {
            if ((current->isEnded == 1 && complete == 1) || (current->isEnded == 0 && complete == 0)) {
                etypeName = getProtocol(type, protocol, (char*)ethertypes);

                char* format = "     ";

                struct ip* ipv4 = (struct ip*)(packet + EHL);
                etypeName = getProtocol(type, protocol, (char*)ethertypes);
                if (i == 0) {
                    printf("    number_comm: %d\n", k);

                    fprintf(output, "  - number_comm: %d\n", k);
                    printf("    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);

                    fprintf(output, "    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);
                    printf("     dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);

                    fprintf(output, "    dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);
                    printf("    packets:\n");
                    fprintf(output, "    packets:\n");

                }
                printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, ipv4, protocol, output, format);

                struct tcp* tcp = (struct tcp*)(packet + EHL + 20);

                char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);


                printf("         src_port: %hu\n", bitSwap(tcp->srcPort));
                printf("         dst_port: %hu\n", bitSwap(tcp->destPort));
                printf("         app_protocol: SSH");

                fprintf(output, "        src_port: %hu\n", bitSwap(tcp->srcPort));
                fprintf(output, "        dst_port: %hu\n", bitSwap(tcp->destPort));
                fprintf(output, "        app_protocol: SSH\n");
                u_char* g = (u_char*)(packet + EHL + 33);
                unsigned char p = *g;
                int bits[8];
                /*
                printf("Flags:\n");
                fprintf(output, "Flags:\n");
                for (int i = 0; i != 8; i++) {
                    bits[i] = (p & (1 << i)) != 0;

                    printf("%u", bits[i]);
                    fprintf(output, "%u", bits[i]);

                }
                printf(" - ");
                fprintf(output, " - ");
                if (bits[4] == 1)
                {
                    printf("ACK,");
                    fprintf(output, "ACK,");
                }
                if (bits[3] == 1)
                {
                    printf("PUSH,");

                    fprintf(output, "PUSH,");
                }
                if (bits[2] == 1)
                {
                    printf("RESET,");
                    fprintf(output, "RESET,");
                }
                if (bits[1] == 1)
                {
                    printf("SYN,");
                    fprintf(output, "SYN,");
                }
                if (bits[0] == 1)
                {
                    printf("FIN,");
                    fprintf(output, "FIN,");
                }
                */
               
            

                printf("         hexa_frame: |");
                fprintf(output, "        hexa_frame: |");

                for (u_int l = 0; (l < header->caplen); l++)
                {


                    if ((l % 16) == 0)
                    {
                        printf("\n\t   ");
                        fprintf(output, "\n\t      ");

                    }


                    printf("%.2x ", packet[l]);
                    fprintf(output, "%.2x ", packet[l]);

                }




                printf("\n\n");
                fprintf(output, "\n\n");

                i++;
                if (current->frames[i] == -1)
                {

                    k++;

                    break;
                }
            }
            else { k++; }

        }
        packetCount++;




    }
    if (current->next != NULL)
    {
        pairs = current->next;
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        k++;
        SSHCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,complete);
    }
}


void HTTPCommunication(int returnValue, pcap_t* pcap_file, struct pcap_pkthdr* header, u_char* packet, int packetCount, struct ipAddresses* pairs, FILE* protocol, FILE* output, u_short k, char* file,int complete)
{

    int i = 0;// for packets


    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    current = pairs;
    if (current == NULL || current->frames[0] == -1)
    {
        printf("No results\n"); return;
    }
    while (returnValue = pcap_next_ex(pcap_file, &header, &packet) >= 0) // opening pcap file
    {
        u_short type;
        int pcaplen = (header->caplen) + 4;            // calculating frame length provided by pcap 

        if (pcaplen < 64)
        {
            pcaplen = 64;
        }
        u_short m;
        struct ethernet* ethHead;
        ethHead = (struct Ethernet*)(packet);
        char* etypeName = "  ";
        type = bitSwap(ethHead->EtherType);


        if (packetCount == current->frames[i]) {
            if ((current->isEnded == 1 && complete == 1) || (current->isEnded == 0 && complete == 0)) {
                etypeName = getProtocol(type, protocol, (char*)ethertypes);


                struct ip* ipv4= (struct ip*)(packet + EHL);
                etypeName = getProtocol(type, protocol, (char*)ethertypes);
                char* format = "     ";
                if (i == 0) {
                    printf("    number_comm: %d\n", k);

                    fprintf(output, "  - number_comm: %d\n", k);
                    printf("    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);

                    fprintf(output, "    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);
                    printf("     dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);

                    fprintf(output, "    dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);
                    printf("    packets:\n");
                    fprintf(output, "    packets:\n");

                }

               

                printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, ipv4, protocol, output, format);

                struct tcp* tcp = (struct tcp*)(packet + EHL + 20);

                char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);


                printf("        src_port: %hu\n", bitSwap(tcp->srcPort));
                printf("        dst_port: %hu\n", bitSwap(tcp->destPort));
                printf("        app_protocol: HTTP");

                fprintf(output, "        src_port: %hu\n", bitSwap(tcp->srcPort));
                fprintf(output, "        dst_port: %hu\n", bitSwap(tcp->destPort));
                fprintf(output, "        app_protocol: HTTP\n");
                u_char* g = (u_char*)(packet + EHL + 33);
                unsigned char p = *g;
                int bits[8];
                /*
                printf("Flags:\n");
                fprintf(output, "Flags:\n");
                for (int i = 0; i != 8; i++) {
                    bits[i] = (p & (1 << i)) != 0;

                    printf("%u", bits[i]);
                    fprintf(output, "%u", bits[i]);

                }
                printf(" - ");
                fprintf(output, " - ");
                if (bits[4] == 1)
                {
                    printf("ACK,");
                    fprintf(output, "ACK,");
                }
                if (bits[3] == 1)
                {
                    printf("PUSH,");

                    fprintf(output, "PUSH,");
                }
                if (bits[2] == 1)
                {
                    printf("RESET,");
                    fprintf(output, "RESET,");
                }
                if (bits[1] == 1)
                {
                    printf("SYN,");
                    fprintf(output, "SYN,");
                }
                if (bits[0] == 1)
                {
                    printf("FIN,");
                    fprintf(output, "FIN,");
                }
                */
                printf("         hexa_frame: |");
                fprintf(output, "        hexa_frame: |");

                for (u_int l = 0; (l < header->caplen); l++)
                {


                    if ((l % 16) == 0)
                    {
                        printf("\n\t   ");
                        fprintf(output, "\n\t      ");

                    }


                    printf("%.2x ", packet[l]);
                    fprintf(output, "%.2x ", packet[l]);

                }



                printf("\n\n");
                fprintf(output, "\n\n");

                i++;
                if (current->frames[i] == -1)
                {

                    

                    break;
                }
            }
            else { k++; }
        }

        packetCount++;




    }
    if (current->next != NULL)
    {
        pairs = current->next;
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        k++;
        HTTPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,complete);
    }

}


void HTTPSCommunication(int returnValue, pcap_t* pcap_file, struct pcap_pkthdr* header, u_char* packet, int packetCount, struct ipAddresses* pairs, FILE* protocol, FILE* output, u_short k, char* file,int complete)
{

    int i = 0;// for packets


    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    current = pairs;
    if (current == NULL || current->frames[0] == -1)
    {
        printf("No results\n"); return;
    }
    while (returnValue = pcap_next_ex(pcap_file, &header, &packet) >= 0) // opening pcap file
    {
        u_short type;
        int pcaplen = (header->caplen) + 4;            // calculating frame length provided by pcap 

        if (pcaplen < 64)
        {
            pcaplen = 64;
        }
        u_short m;
        struct ethernet* ethHead;
        ethHead = (struct Ethernet*)(packet);
        char* etypeName = "  ";
        type = bitSwap(ethHead->EtherType);


        if (packetCount == current->frames[i]) {
            if ((current->isEnded == 1 && complete == 1) || (current->isEnded == 0 && complete == 0)) {

                etypeName = getProtocol(type, protocol, (char*)ethertypes);

                struct ip* ipv4 = (struct ip*)(packet + EHL);
                etypeName = getProtocol(type, protocol, (char*)ethertypes);
                char* format = "     ";
                if (i == 0) {
                    printf("    number_comm: %d\n", k);

                    fprintf(output, "  - number_comm: %d\n", k);
                    printf("    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);

                    fprintf(output, "    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);
                    printf("     dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);

                    fprintf(output, "    dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);
                    printf("    packets:\n");
                    fprintf(output, "    packets:\n");

                }

                printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, ipv4, protocol, output, format);

                struct tcp* tcp = (struct tcp*)(packet + EHL + 20);

                char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);


                printf("        src_port: %hu\n", bitSwap(tcp->srcPort));
                printf("        dst_port: %hu\n", bitSwap(tcp->destPort));
                printf("        app_protocol: HTTPS");

                fprintf(output, "        src_port: %hu\n", bitSwap(tcp->srcPort));
                fprintf(output, "        dst_port: %hu\n", bitSwap(tcp->destPort));
                fprintf(output, "        app_protocol: HTTPS\n");



                u_char* g = (u_char*)(packet + EHL + 33);
                unsigned char p = *g;
                int bits[8];
                /*
                printf("Flags:\n");
                fprintf(output, "Flags:\n");
                for (int i = 0; i != 8; i++) {
                    bits[i] = (p & (1 << i)) != 0;

                    printf("%u", bits[i]);
                    fprintf(output, "%u", bits[i]);

                }
                printf(" - ");
                fprintf(output, " - ");
                if (bits[4] == 1)
                {
                    printf("ACK,");
                    fprintf(output, "ACK,");
                }
                if (bits[3] == 1)
                {
                    printf("PUSH,");

                    fprintf(output, "PUSH,");
                }
                if (bits[2] == 1)
                {
                    printf("RESET,");
                    fprintf(output, "RESET,");
                }
                if (bits[1] == 1)
                {
                    printf("SYN,");
                    fprintf(output, "SYN,");
                }
                if (bits[0] == 1)
                {
                    printf("FIN,");
                    fprintf(output, "FIN,");
                }*/


                printf("         hexa_frame: |");
                fprintf(output, "        hexa_frame: |");

                for (u_int l = 0; (l < header->caplen); l++)
                {


                    if ((l % 16) == 0)
                    {
                        printf("\n\t   ");
                        fprintf(output, "\n\t      ");

                    }


                    printf("%.2x ", packet[l]);
                    fprintf(output, "%.2x ", packet[l]);

                }



                printf("\n\n");
                fprintf(output, "\n\n");

                i++;
                if (current->frames[i] == -1)
                {



                    break;
                }
            }
            else { k++; }
        }

        packetCount++;




    }
    if (current->next != NULL)
    {
        pairs = current->next;
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        k++;
        HTTPSCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output,  k, file,complete);
    }
}


void FTPDATACommunication(int returnValue, pcap_t* pcap_file, struct pcap_pkthdr* header, u_char* packet, int packetCount, struct ipAddresses* pairs, FILE* protocol, FILE* output, u_short k, char* file,int complete)
{

    int i = 0;// for packets


    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    current = pairs;
    if (current == NULL || current->frames[0] == -1)
    {
        printf("No results\n"); return;
    }
    while (returnValue = pcap_next_ex(pcap_file, &header, &packet) >= 0) // opening pcap file
    {
        u_short type;
        int pcaplen = (header->caplen) + 4;            // calculating frame length provided by pcap 

        if (pcaplen < 64)
        {
            pcaplen = 64;
        }
        u_short m;
        struct ethernet* ethHead;
        ethHead = (struct Ethernet*)(packet);
        char* etypeName = "  ";
        type = bitSwap(ethHead->EtherType);


        if (packetCount == current->frames[i]) {
            if ((current->isEnded == 1 && complete == 1) || (current->isEnded == 0 && complete == 0)) {
                etypeName = getProtocol(type, protocol, (char*)ethertypes);


                struct ip* ipv4 = (struct ip*)(packet + EHL);
                char* format = "     ";
                etypeName = getProtocol(type, protocol, (char*)ethertypes);
                if (i == 0) {
                    printf("    number_comm: %d\n", k);

                    fprintf(output, "  - number_comm: %d\n", k);
                    printf("    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);

                    fprintf(output, "    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);
                    printf("     dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);

                    fprintf(output, "    dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);
                    printf("    packets:\n");
                    fprintf(output, "    packets:\n");

                }

                printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, ipv4, protocol, output, format);

                struct tcp* tcp = (struct tcp*)(packet + EHL + 20);

                char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);


                printf("        src_port: %hu\n", bitSwap(tcp->srcPort));
                printf("        dst_port: %hu\n", bitSwap(tcp->destPort));
                printf("        app_protocol: FTP-DATA");

                fprintf(output, "        src_port: %hu\n", bitSwap(tcp->srcPort));
                fprintf(output, "        dst_port: %hu\n", bitSwap(tcp->destPort));
                fprintf(output, "        app_protocol: FTP-DATA\n");



                u_char* g = (u_char*)(packet + EHL + 33);
                unsigned char p = *g;
                int bits[8];/*
                printf("Flags:\n");
                fprintf(output, "Flags:\n");
                for (int i = 0; i != 8; i++) {
                    bits[i] = (p & (1 << i)) != 0;

                    printf("%u", bits[i]);
                    fprintf(output, "%u", bits[i]);

                }
                printf(" - ");
                fprintf(output, " - ");
                if (bits[4] == 1)
                {
                    printf("ACK,");
                    fprintf(output, "ACK,");
                }
                if (bits[3] == 1)
                {
                    printf("PUSH,");

                    fprintf(output, "PUSH,");
                }
                if (bits[2] == 1)
                {
                    printf("RESET,");
                    fprintf(output, "RESET,");
                }
                if (bits[1] == 1)
                {
                    printf("SYN,");
                    fprintf(output, "SYN,");
                }
                if (bits[0] == 1)
                {
                    printf("FIN,");
                    fprintf(output, "FIN,");
                }*/


                printf("         hexa_frame: |");
                fprintf(output, "        hexa_frame: |");

                for (u_int l = 0; (l < header->caplen); l++)
                {


                    if ((l % 16) == 0)
                    {
                        printf("\n\t   ");
                        fprintf(output, "\n\t      ");

                    }


                    printf("%.2x ", packet[l]);
                    fprintf(output, "%.2x ", packet[l]);

                }



                printf("\n\n");
                fprintf(output, "\n\n");

                i++;
                if (current->frames[i] == -1)
                {

                    

                    break;
                }
            }
            else { k++; }
        }

        packetCount++;




    }
    if (current->next != NULL)
    {
        pairs = current->next;
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        k++;
        FTPDATACommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output,  k, file,complete);
    }
}

void FTPControlCommunication(int returnValue, pcap_t* pcap_file, struct pcap_pkthdr* header, u_char* packet, int packetCount, struct ipAddresses* pairs, FILE* protocol, FILE* output, u_short k, char* file,int complete)
{

    int i = 0;// for packets


    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    current = pairs;
    if (current == NULL || current->frames[0] == -1)
    {
        printf("No results\n"); return;
    }
    while (returnValue = pcap_next_ex(pcap_file, &header, &packet) >= 0) // opening pcap file
    {
        u_short type;
        int pcaplen = (header->caplen) + 4;            // calculating frame length provided by pcap 

        if (pcaplen < 64)
        {
            pcaplen = 64;
        }
        u_short m;
        struct ethernet* ethHead;
        ethHead = (struct Ethernet*)(packet);
        char* etypeName = "  ";
        type = bitSwap(ethHead->EtherType);


        if (packetCount == current->frames[i]) {
            if ((current->isEnded == 1 && complete == 1) || (current->isEnded == 0 && complete == 0)) {
                etypeName = getProtocol(type, protocol, (char*)ethertypes);


                struct ip* ipv4 = (struct ip*)(packet + EHL);
                char* format = "     ";
                etypeName = getProtocol(type, protocol, (char*)ethertypes);
                if (i == 0) {
                    printf("    number_comm: %d\n", k);

                    fprintf(output, "  - number_comm: %d\n", k);
                    printf("    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);

                    fprintf(output, "    src_comm:: %d.%d.%d.%d\n", ipv4->srcAddr[0], ipv4->srcAddr[1], ipv4->srcAddr[2], ipv4->srcAddr[3]);
                    printf("     dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);

                    fprintf(output, "    dst_comm: %d.%d.%d.%d\n", ipv4->destAddr[0], ipv4->destAddr[1], ipv4->destAddr[2], ipv4->destAddr[3]);
                    printf("    packets:\n");
                    fprintf(output, "    packets:\n");

                }
                printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, ipv4, protocol, output, format);

                struct tcp* tcp = (struct tcp*)(packet + EHL + 20);

                char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);



                printf("        src_port: %hu\n", bitSwap(tcp->srcPort));
                printf("        dst_port: %hu\n", bitSwap(tcp->destPort));
                printf("        app_protocol: HTTP");

                fprintf(output, "        src_port: %hu\n", bitSwap(tcp->srcPort));
                fprintf(output, "        dst_port: %hu\n", bitSwap(tcp->destPort));
                fprintf(output, "        app_protocol: HTTP\n");


                u_char* g = (u_char*)(packet + EHL + 33);
                unsigned char p = *g;
                int bits[8];
                /*
                printf("Flags:\n");
                fprintf(output, "Flags:\n");
                for (int i = 0; i != 8; i++) {
                    bits[i] = (p & (1 << i)) != 0;

                    printf("%u", bits[i]);
                    fprintf(output, "%u", bits[i]);

                }
                printf(" - ");
                fprintf(output, " - ");
                if (bits[4] == 1)
                {
                    printf("ACK,");
                    fprintf(output, "ACK,");
                }
                if (bits[3] == 1)
                {
                    printf("PUSH,");

                    fprintf(output, "PUSH,");
                }
                if (bits[2] == 1)
                {
                    printf("RESET,");
                    fprintf(output, "RESET,");
                }
                if (bits[1] == 1)
                {
                    printf("SYN,");
                    fprintf(output, "SYN,");
                }
                if (bits[0] == 1)
                {
                    printf("FIN,");
                    fprintf(output, "FIN,");
                }*/
               

                printf("         hexa_frame: |");
                fprintf(output, "        hexa_frame: |");

                for (u_int l = 0; (l < header->caplen); l++)
                {


                    if ((l % 16) == 0)
                    {
                        printf("\n\t   ");
                        fprintf(output, "\n\t      ");

                    }


                    printf("%.2x ", packet[l]);
                    fprintf(output, "%.2x ", packet[l]);

                }



                printf("\n\n");
                fprintf(output, "\n\n");

                i++;
                if (current->frames[i] == -1)
                {



                    break;
                }
            }
            else { k++; }

        }
        packetCount++;




    }
    if (current->next != NULL)
    {
        pairs = current->next;
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        k++;
        FTPControlCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output,  k, file,complete);
    }
}

// arp 
// ipv4- 1. udp - 2.tcp -                                          3.icmp 
//        tftp      ssh,https,http,telnet,ftp-control,ftp-data, 

int main()
{

   
HelloThere:;
    char numb[5] = { "" };
    int choice;
    int choice2;
    int choice3;
    printf("Choose a file by typing one of the numbers representing the type of the file \n1 - Eth\n2 - trace\n3 - other\n");
    scanf("%d", &choice2);
    FILE* output = fopen("Output.yaml", "w"); //C:/Users/29313/PycharmProjects/Analyzer/examples/
    FILE* protocol = fopen("protocol.txt", "r");

    if (output == NULL) {
        printf("Cannot open output ");

    }
    else if (protocol == NULL)
    {
        printf("Cannot open protocol");
    }
    printf("\n%d\n", choice2);
    printf("Choose the number of the file :");
    scanf("%d", &choice3);
    printf("\n%d\n", choice3);
    printf("These are the tasks that you can choose from - press the correponding button !\nTask 1-3(Everything) - button 1\nTask 4a(HTTP) - button 2\nTask 4b(HTTPS) - button 3\nTask 4c(Telnet) - button 7\nTask 4d(SSH) - button 6\nTask 4e(FTP-Control) - button 5\nTask 4f(FTP-Data) - button 4\nTask 4g(TFTP) - button 9\nTask 4h(ICMP) - button 8\nTask 4i(ARP) - button 10\n");
    scanf("%d", &choice);


    if (choice2 == 0 || choice3 == 0 || choice == 0)
    {
        return;
    }
    char* file = (char*)malloc(200);

    strcpy(file, "vzorky_pcap_na_analyzu//"); //C://Users//29313//source//repos//vzorky_pcap_na_analyzu//

    char* file4 = (char*)malloc(8);
    strcpy(file4, ".pcap");



    char* a = (char*)malloc(20);
    strcpy(a, "");

    if (choice2 == 1)
    {
        a = strcpy(a, "eth-");
      
    }
    else if (choice2 == 2)
    {
        a = strcpy(a, "trace-");
        
    }
    else if (choice2 == 3)
    {
        a = strcpy(a, "trace_ip_nad_20_B");
      
    }
    else {
        printf("Wrong file ! "); goto HelloThere;
    }
    if (choice == 3)
    {
        numb[5] = "";
    }


    file = strcat(file, a);
   
  
    char snum[5];
    sprintf(snum, "%d", choice3);
    strcat(file, snum);
    
    strcat(file, file4);

    
   
    
    printf("name: PKS2022/23\n");
    printf("pcap_name: %s%d%s\n", a,choice3, ".pcap");
    
    fprintf(output, "name: PKS2022/23\n");
    fprintf(output, "pcap_name: %s%d%s\n", a, choice3, ".pcap");
    if (choice == 1) {
        printf("packets:\n");
        fprintf(output, "packets:\n");
    }
    else
    {
        char* h="ForDifferentProtocols";
        if (choice == 2)
        {
            h = "HTTP";

        }
        else if (choice == 3) {
            h = "HTTPS";
        }
        else if (choice == 4) {
            h = "FTP-DATA";
        }
        else if (choice == 5) {
            h = "FTP-CONTROL";
        }
        else if (choice == 6) {
            h = "SSH";
        }
        else if (choice == 7) {
            h = "TELNET";
        }
        else if (choice == 8) {
            h = "ICMP";
        }
        else if (choice == 9) {
            h = "TFTP";
        }
        else if (choice == 10) {
            h = "ARP";
        }
        printf("filter_name: %s\n",h);
        fprintf(output, "filter_name: %s\n",h);
    }
    

    char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
    pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
    struct pcap_pkthdr* header; 
    const u_char* packet;
    int packetCount = 1;
    int returnValue;
    struct ipAddresses* pairs = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
    struct ipAddresses* clientServer = (struct ipAddresses*)malloc(sizeof(struct ipAddresses));
    for (int i = 0; i < 500; i++)
    {
        pairs->frames[i] = -1;
    }
    struct ipAddresses* ipList = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));  // linked list
    u_short s = 0; // counter for a special situation in the linked list
    u_short s2 = 0;
    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses)); // linked list
   
    int r = 0;
    ipList->num = 0;
    pairs->num = 0;
    clientServer->num = 0;
    u_short type;
    
   
    while (returnValue = pcap_next_ex(pcap_file, &header, &packet) >= 0) // opening pcap file
    {
       
        int pcaplen = (header->caplen) + 4;            // calculating frame length provided by pcap 

        if (pcaplen < 64)
        {
            pcaplen = 64;
        }
        u_short m;
        struct ethernet* ethHead;
        ethHead = (struct Ethernet*)(packet);                    
        char* etypeName="  ";
         type= bitSwap(ethHead->EtherType);  // swapping the bits to get the correct value of the ethertype in decimal.
        
         if (choice == 1) {
             etypeName = getProtocol(type, protocol, (char*)ethertypes);
             struct ip* ipv4;
             if (etypeName == NULL) { etypeName = ""; }
             
                 ipv4 = (struct ip*)(packet + EHL);                        // putting the packet into the ipv4 header, since in this task ipv4 will be used mostly.
             
             


             if (getFrameType(type, packet) == 1) // this filters the packets that are ethernet II
             {



                 etypeName = getProtocol(type, protocol, (char*)ethertypes); // this returns the name of the ether type.
                 if (etypeName == NULL) { etypeName = "Unknown\n"; }
                 if (strcmp(etypeName, "IPv4\n\0") == 0) {                     // here I check if it is ipv4, if yes then it will be analyzed more throughoutly.
                     if (ipList->num == 0) // this happens the first time a node is added to the linked list.
                     {
                         ipList->srcIp[0] = ipv4->srcAddr[0];
                         ipList->srcIp[1] = ipv4->srcAddr[1];
                         ipList->srcIp[2] = ipv4->srcAddr[2];
                         ipList->srcIp[3] = ipv4->srcAddr[3];

                         ipList->num++;
                         ipList->next = NULL;


                     }
                     current = ipList;
                     struct ipAddresses* last = current; // this remembers the last node
                     int van = 0; // this is just a counter 
                     while (current != NULL)
                     {   //  first search the linked list whtether is already contains this ip
                         if (current->srcIp[0] == ipv4->srcAddr[0] && current->srcIp[1] == ipv4->srcAddr[1] &&
                             current->srcIp[2] == ipv4->srcAddr[2] &&
                             current->srcIp[3] == ipv4->srcAddr[3])
                         { // if it contains then we increment the numbeR there., put the van counter to 1. and break from the loop.

                             current->num++;
                             if (s2 == 0) { current->num = 1; s2 = 1; }//after the head node is added(ipList),here its number gets incremented once again, so thats why we decrement it.
                             van = 1;
                             break;
                         } // if we do not find it, then we put the current node into the last variable.
                         last = current;
                         current = current->next;  // then put into the current the next one.
                     } // if there was no match with the other ips then we take the last node and put it into the current, 
                     current = last;
                     if (van == 0) { // this happens when we are adding a 2nd  node to the linked list.
                         struct ipAddresses* current2 = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));

                         current2->srcIp[0] = ipv4->srcAddr[0];
                         current2->srcIp[1] = ipv4->srcAddr[1];
                         current2->srcIp[2] = ipv4->srcAddr[2];
                         current2->srcIp[3] = ipv4->srcAddr[3];

                         current2->num = 1;
                         current2->next = NULL;

                         current->next = current2; // adding the  node to the end of the list
                         if (s == 0) //s another counter, this happens only only once, when we add a node a 2nd time.
                         {

                             ipList = current;  // we add the updated linked list to the original one
                             s = 1;
                         }
                     }


                 }
                 



             }
             else if (getFrameType(type, packet) == 3) // the other one that has an ethertype is ie3 llc snap
             {
                 struct IE3* e3;
                 e3 = (struct IE3*)(packet + EHL);
                 u_short e3type = bitSwap(e3->ie3EtherType);
                 etypeName = getProtocol(e3type, protocol, (char*)i3eeeSAPS);
                 if (etypeName == NULL) {
                     etypeName = getProtocol(e3type, protocol, (char*)ethertypes);
                 }



             } // else if for other ethertypes if it needs to be added
             if (etypeName == NULL)
             {
                 etypeName = "Undefined"; // the protocol.txt file can be uncomplete that means it might not contain some ethertype so in this situation it says undefined.
             }

             //checking for udp,tcp ports.
             char* format = "";
            
             printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, ipv4, protocol, output,format); // printing out all the information.
             char* protz = getProtocol(ipv4->protocol, protocol, (char*)IPv4p);
             if (protz == NULL) { protz = ""; }
            
             //arpcheck

             if ((strcmp(protz, "UDP\n\0") == 0 || strcmp(protz, "TCP\n\0") == 0))
             {

                 etypeName = getProtocol(type, protocol, (char*)ethertypes);


                 if (strcmp(etypeName, "ARP") == 0 || strcmp(etypeName, "ARP\0") == 0 || strcmp(etypeName, "ARP\0\n") == 0 || strcmp(etypeName, "ARP\n") == 0) 
                 {


                 }
                 
                   
          
                 else

                 {
                     protz = getProtocol(ipv4->protocol, protocol, (char*)IPv4p);

                     struct tcp* ports = (struct tcp*)(packet + EHL + 20);
                     char* portProt = NULL;


                     if ((strcmp(protz, "UDP\n\0")) == 0)
                     {
                         portProt = getProtocol(bitSwap(ports->srcPort), protocol, (char*)UDPp);

                         if (portProt == NULL)
                         {
                             portProt = getProtocol(bitSwap(ports->destPort), protocol, (char*)UDPp);

                         }
                     }
                     else if (strcmp(protz, "TCP\n\0") == 0)
                     {

                         portProt = getProtocol(bitSwap(ports->srcPort), protocol, (char*)TCPp);
                         if (portProt == NULL)
                         {
                             portProt = getProtocol(bitSwap(ports->destPort), protocol, (char*)TCPp);

                         }

                     }
                   
                     
                     printf("    src_port: %hu\n", bitSwap(ports->srcPort));
                     printf("    dst_port: %hu\n", bitSwap(ports->destPort));
                     printf("    app_protocol: %s", portProt);
                
                     fprintf(output, "   src_port: %hu\n", bitSwap(ports->srcPort));
                     fprintf(output, "   dst_port: %hu\n", bitSwap(ports->destPort));
                   
                     if (portProt != NULL) { fprintf(output, "   app_protocol: %s", portProt); }



                 }
             }
             if ((strcmp(protz, "ICMP\n\0") == 0 || strcmp(protz, "ICMP\n") == 0 || strcmp(protz, "ICMP\0") == 0 || strcmp(protz, "ICMP") == 0)&&(strcmp(etypeName,"IPv4\n\0")==0)) {

                 if (strcmp(etypeName, "ARP") == 0 || strcmp(etypeName, "ARP\0") == 0 || strcmp(etypeName, "ARP\0\n") == 0 || strcmp(etypeName, "ARP\n") == 0) {}

                 else
                 {


                     u_char m = (ipv4->versionAndIHL);

                     u_short sol = calculateICMP(m);
                     struct icmp* por = (struct icmp*)(packet + EHL + sol);
                     char * kk =getProtocol((u_short)(por->type), protocol, (char*)ICMPp);
                     if (kk != NULL) {
                         printf("   icmp_type: %s\n", getProtocol((u_short)(por->type), protocol, (char*)ICMPp));


                         fprintf(output, "   icmp_type: %s\n", getProtocol((u_short)(por->type), protocol, (char*)ICMPp));
                     }


                 }
             }

             
             printf("   hexa_frame: |");
             fprintf(output,"   hexa_frame: |");
             u_int h = 0;
             for (u_int i = 0; (i < header->caplen-1); i++)
             {


                 if ((i % 16) == 0)
                 {
                     printf("\n      ");
                     fprintf(output, "\n      ");
                 }

                 if ((i % 16) == 15 && i!=1)
                 {
                     printf("%.02X", packet[i]);
                     fprintf(output, "%.02X", packet[i]);
                 }
                 else {
                     printf("%.02X ", packet[i]);
                     fprintf(output, "%.02X ", packet[i]);
                 }
                 h++;
             }
             if (h%16==0) {
                 printf("\n      ");
                 fprintf(output, "\n      ");
             }
             printf("%.02X", packet[h]);
             fprintf(output, "%.02X", packet[h]);



             printf("\n\n");
             fprintf(output, "\n\n");

         }
         if (choice == 11)

         {
            
             if (getFrameType(type, packet) == 1) // the other one that has an ethertype is ie3 llc snap
             {
                

                 etypeName = getProtocol(type, protocol, (char*)ethertypes);
                
                 if (etypeName == NULL)
                 {
                     etypeName = "";
                 }
                 if (strcmp(etypeName,"LLDP\n\0") == 0)
                 {
                     
                     
                     char* format = "    ";
                     printout(packetCount, header->len, pcaplen, type, packet, ethHead, etypeName, NULL, protocol, output,format);
                     for (u_int i = 0; (i < header->caplen); i++)
                     {


                         if ((i % 16) == 0)
                         {
                             printf("\n");
                             fprintf(output, "\n");
                         }


                         printf("%.2x ", packet[i]);
                         fprintf(output, "%.2x ", packet[i]);

                     }



                     printf("\n\n");
                     fprintf(output, "\n\n");






                 }
             }
             
         }
        if (choice != 1)
        {
          
            if (getFrameType(type, packet) == 1)
            {struct ip* ipv = (struct ip*)(packet + EHL);
                etypeName = getProtocol(type, protocol, (char*)ethertypes); // this returns the name of the ether type.
               
                if (etypeName == NULL) { etypeName = "undefined\n"; }
                
                if (strcmp(etypeName, "IPv4\n\0") == 0 && choice !=10) {
                    
                    char* protz = getProtocol(ipv->protocol, protocol, (char*)IPv4p);
                 
                    if (protz == NULL) { protz = "undefined\n"; }
                    if((strcmp(protz, "TCP\n\0") == 0)){
                        
                        struct tcp* tcp = (struct tcp*)(packet + EHL + 20);
                        char* sport = getProtocol(bitSwap(tcp->srcPort), protocol, (char*)TCPp);
                       

                        if (sport == NULL) { sport = "undefined\n"; }
                       
                        if (strcmp(sport,"HTTP\n\0") ==0 && choice==2)
                        {
                            u_short end = 0;
                            u_char* g = (u_char*)(packet + EHL + 33);

                            if (r == 1 && *g == 17)
                            {
                                r = 2; 
                            }
                            if ((*g == 1 || *g == 17) && r == 0)
                            {
                                r = 1;
                            }
                            if (*g == 4 || *g == 20 || *g == 12)
                            {
                                end = 1;
                            }

                            if (r == 2 && *g == 16)
                            {
                                end = 1;
                                r = 0;
                               
                            }
                            pairs = getList(packet, pairs, packetCount, choice, current,end);
                            
                            
                        }
                        else if(strcmp(sport, "HTTP\n\0") != 0 && choice ==2)
                        {
                            char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);
                            if (dport == NULL) { dport = "undefined"; }

                            if (strcmp(dport, "HTTP\n\0") == 0) {
                               
                                u_short end = 0;
                                u_char* g = (u_char*)(packet + EHL + 33);

                                
                                if (r == 1 && *g == 17)
                                {
                                    r = 2;
                                }
                                if ((*g == 1 || *g == 17) && r == 0)
                                {
                                    r = 1;  
                                }
                                if (*g == 4 || *g == 20 || *g == 12)
                                {
                                    end = 1;
                                }

                                if (r == 2 && *g == 16)
                                {
                                    end = 1;
                                    r = 0;
                                   
                                }
                            pairs = getList(packet, pairs, packetCount, choice, current,end);
                           
                            
                            }
                        }
                        else if (strcmp(sport, "HTTPS\n\0") == 0 && choice == 3)
                        {
                            u_short end = 0;
                            u_char* g = (u_char*)(packet + EHL + 33);

                       
                            if (r == 1 && *g == 17)
                            {
                                r = 2; 
                            }
                            if ((*g == 1 || *g == 17) && r == 0)
                            {
                                r = 1;
                            }
                            if (*g == 4 || *g == 20 || *g == 12)
                            {
                                end = 1;
                            }

                            if (r == 2 && *g == 16)
                            {
                                end = 1;
                                r = 0;
                             
                            }
                            pairs = getList(packet, pairs, packetCount, choice, current,end);

                            
                        }
                        else if (strcmp(sport, "HTTPS\n\0") != 0 && choice == 3)
                        {
                            char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);
                            if (dport == NULL) { dport = "undefined"; }

                            if (strcmp(dport, "HTTPS\n\0") == 0) {
                                u_short end = 0;
                                u_char* g = (u_char*)(packet + EHL + 33);

                               
                                if (r == 1 && *g == 17)
                                {
                                    r = 2;
                                }
                                if ((*g == 1 || *g == 17) && r == 0)
                                {
                                    r = 1;  
                                }
                                if (*g == 4 || *g == 20 || *g == 12)
                                {
                                    end = 1;
                                }

                                if (r == 2 && *g == 16)
                                {
                                    end = 1;
                                    r = 0;
                                    
                                }
                                pairs = getList(packet, pairs, packetCount, choice, current,end);
                               
                                
                            }
                        }
                        else if (strcmp(sport, "FTP DATA\n\0") == 0 && choice == 4)
                        {

                            u_short end = 0;
                            u_char* g = (u_char*)(packet + EHL + 33);

                           
                            if (r == 1 && *g == 17)
                            {
                                r = 2; 
                            }
                            if ((*g == 1 || *g == 17) && r == 0)
                            {
                                r = 1; 
                            }
                            if (*g == 4 || *g == 20 || *g == 12)
                            {
                                end = 1;
                            }

                            if (r == 2 && *g == 16)
                            {
                                end = 1;
                                r = 0;
                              
                            }
                            pairs = getList(packet, pairs, packetCount, choice, current,end);

                            
                        }
                        else if (strcmp(sport, "FTP DATA\n\0") != 0 && choice == 4)
                        {
                            char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);
                            if (dport == NULL) { dport = "undefined"; }

                            if (strcmp(dport, "FTP DATA\n\0") == 0) {

                                u_short end = 0;
                                u_char* g = (u_char*)(packet + EHL + 33);

                                
                                if (r == 1 && *g == 17)
                                {
                                    r = 2;
                                }
                                if ((*g == 1 || *g == 17) && r == 0)
                                {
                                    r = 1;  
                                }
                                if (*g == 4 || *g == 20 || *g == 12)
                                {
                                    end = 1;
                                }

                                if (r == 2 && *g == 16)
                                {
                                    end = 1;
                                    r = 0;
                                    
                                }
                                pairs = getList(packet, pairs, packetCount, choice, current,end);
                                
                                
                            }
                        }
                        else if (strcmp(sport, "FTP CONTROL\n\0") == 0 && choice == 5)
                        {
                            u_short end = 0;
                            u_char* g = (u_char*)(packet + EHL + 33);

                          
                            if (r == 1 && *g == 17)
                            {
                                r = 2; 
                            }
                            if ((*g == 1 || *g == 17) && r == 0)
                            {
                                r = 1; 
                            }
                            if (*g == 4 || *g == 20 || *g == 12)
                            {
                                end = 1;
                            }

                            if (r == 2 && *g == 16)
                            {
                                end = 1;
                                r = 0;
                               
                            }
                            pairs = getList(packet, pairs, packetCount, choice, current,end);

                            
                        }
                        else if (strcmp(sport, "FTP CONTROL\n\0") != 0 && choice == 5)
                        {
                            char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);
                            if (dport == NULL) { dport = "undefined"; }

                            if (strcmp(dport, "FTP CONTROL\n\0") == 0) {

                                u_short end = 0;
                                u_char* g = (u_char*)(packet + EHL + 33);

                               
                                if (r == 1 && *g == 17)
                                {
                                    r = 2; 
                                }
                                if ((*g == 1 || *g == 17) && r == 0)
                                {
                                    r = 1; 
                                }
                                if (*g == 4 || *g == 20 || *g == 12)
                                {
                                    end = 1;
                                }

                                if (r == 2 && *g == 16)
                                {
                                    end = 1;
                                    r = 0;
                                   
                                }
                                pairs = getList(packet, pairs, packetCount, choice, current,end);
                                
                                
                            }
                        }
                       
                        else if (strcmp(sport, "SSH\n\0") == 0 && choice == 6)
                        {

                            u_short end = 0;
                            u_char* g = (u_char*)(packet + EHL + 33);

                           
                            if (r == 1 && *g == 17)
                            {
                                r = 2;
                            }
                            if ((*g == 1 || *g == 17) && r == 0)
                            {
                                r = 1; 
                            }
                            if (*g == 4 || *g == 20 || *g == 12)
                            {
                                end = 1;
                            }

                            if (r == 2 && *g == 16)
                            {
                                end = 1;
                                r = 0;
                             
                            }

                            pairs = getList(packet, pairs, packetCount, choice, current,end);

                            
                        }
                        else if (strcmp(sport, "SSH\n\0") != 0 && choice == 6)
                        {
                            char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);
                            if (dport == NULL) { dport = "undefined"; }

                            if (strcmp(dport, "SSH\n\0") == 0) {
                                u_short end = 0;
                                u_char* g = (u_char*)(packet + EHL + 33);

                               
                                if (r == 1 && *g == 17)
                                {
                                    r = 2; 
                                }
                                if ((*g == 1 || *g == 17) && r == 0)
                                {
                                    r = 1; 
                                }
                                if (*g == 4 || *g == 20 || *g == 12)
                                {
                                    end = 1;
                                }

                                if (r == 2 && *g == 16)
                                {
                                    end = 1;
                                    r = 0;
                                   
                                }

                                pairs = getList(packet, pairs, packetCount, choice, current,end);
                             
                                
                            }
                        }
                        else if (strcmp(sport, "TELNET\n\0") == 0 && choice == 7)
                        {

                           
                            u_short end = 0;
                            u_char* g = (u_char*)(packet + EHL + 33);
                            
                            
                            if (r == 1 && *g == 17)
                            {
                                r = 2; 
                            }
                            if ((*g == 1 || *g == 17)&& r==0)
                            {
                                r = 1; 
                            }
                            if (*g==4 || *g==20 || *g==12)
                            {
                                end = 1;
                            }
                           
                            if(r==2 && *g==16)
                            {
                                end = 1;
                                r = 0;
                               
                            }
                            
                            pairs = getList(packet, pairs, packetCount, choice, current,end);

                            
                        }
                        else if (strcmp(sport, "TELNET\n\0") != 0 && choice == 7)
                        {
                            char* dport = getProtocol(bitSwap(tcp->destPort), protocol, (char*)TCPp);
                            if (dport == NULL) { dport = "undefined"; }

                            if (strcmp(dport, "TELNET\n\0") == 0) {
                                

                                u_short end = 0;
                                u_char* g = (u_char*)(packet + EHL + 33);
                                
                                
                                if (r == 1 && *g == 17)
                                {
                                    r = 2; 
                                }
                                if ((*g == 1 || *g == 17) && r == 0)
                                {
                                    r = 1; 
                                }
                                if (*g == 4 || *g == 20 || *g == 12)
                                {
                                    end = 1;
                                }

                                if (r == 2 && *g == 16)
                                {
                                    end = 1;
                                    r = 0;
                                    
                                }
                                

                                pairs = getList(packet, pairs, packetCount, choice, current,end);
                                
                                
                            }
                        }
                        
                        
                    }
                    else if ((strcmp(protz, "ICMP\n\0") == 0) &&  choice==8)
                    {

                    
                    
                        struct icmp* icp = (struct icmp*)(packet + EHL + 20);
                     
                        struct ip* ip4 = (struct ip*)(packet + EHL);
                       
                       
                        u_char m = (ip4->versionAndIHL);

                        u_short sol = calculateICMP(m);
                        struct icmp* por = (struct icmp*)(packet + EHL + sol);
                        int end = 0;
                        char* gg = getProtocol((u_short)(por->type), protocol, (char*)ICMPp);
                       
                        if (gg == NULL)
                        {
                            gg = "Fragmented";
                        }
                        if (strcmp(gg, "Echo Reply\n\0") == 0)
                        {
                            end = 1;
                        }
                        char* sport = getProtocol((unsigned short)icp->type, protocol, (char*)ICMPp);

                            if (sport == NULL) { sport = "undefined"; }
                            pairs = getList(packet, pairs, packetCount, choice, current,end);
                           
                            
                       
                        
                    }
                    else  if ((strcmp(protz, "UDP\n\0") == 0) && choice == 9)
                    {
                    struct ipAddresses* current = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
                    struct ipAddresses* last = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));
                        struct ip* ip = (struct ip*)(packet + EHL);
                        
                        struct udp* ud = (struct udp*)(packet + EHL + 20);

                        char* dport = getProtocol(bitSwap(ud->destPort), protocol, (char*)UDPp);
                       
                        if (dport == NULL) { dport = "undefined\n"; }
                      
                        
                        if ((strcmp(dport, "TFTP\n\0") == 0) && choice == 9)
                        {
                           
                            
                          
                            
                            // 
                            if (clientServer->num == 0) { // if the number is 0, then the linked list is empty, so we put in the first tftp packet
                                clientServer->srcIp[0] = ip->srcAddr[0];
                                clientServer->srcIp[1] = ip->srcAddr[1];
                                clientServer->srcIp[2] = ip->srcAddr[2];
                                clientServer->srcIp[3] = ip->srcAddr[3];

                                clientServer->destIp[0] = ip->destAddr[0];
                                clientServer->destIp[1] = ip->destAddr[1];
                                clientServer->destIp[2] = ip->destAddr[2];
                                clientServer->destIp[3] = ip->destAddr[3];
                                clientServer->num = 1;               // we put the number on 1.
                                clientServer->frames[0] = bitSwap(ud->srcPort);
                                clientServer->frames[1] = bitSwap(ud->destPort);
                                
                                clientServer->next = NULL;
                                
                            }
                            else {                    // if the list already has a first node, then we check if this ip to ip pair is already in?
                                current = clientServer;
                                
                                u_short counter = 0;
                                while (current != NULL)
                                {
                                    last = current;
                                    if (((((current->srcIp[0] == ip->srcAddr[0]) && (current->srcIp[1] == ip->srcAddr[1]) &&
                                        (current->srcIp[2] == ip->srcAddr[2]) &&
                                        (current->srcIp[3] == ip->srcAddr[3])) &&
                                        ((current->destIp[0] == ip->destAddr[0]) &&
                                            (current->destIp[1] == ip->destAddr[1]) &&
                                            (current->destIp[2] == ip->destAddr[2]) &&
                                            (current->destIp[3] == ip->destAddr[3])))
                                        ||
                                        (((current->srcIp[0] == ip->destAddr[0]) && (current->srcIp[1] == ip->destAddr[1]) && (current->srcIp[2] == ip->destAddr[2]) && (current->srcIp[3] == ip->destAddr[3])
                                            ) && ((current->destIp[0] == ip->srcAddr[0]) && (current->destIp[1] == ip->srcAddr[1]) && (current->destIp[2] == ip->srcAddr[2]) && (current->destIp[3] == ip->srcAddr[3])
                                                )))
                                        )
                                    {
                                        counter++; break;

                                    }
                                    current = current->next;
                                } 
                               
                                if (counter == 0 || current->num==2)
                                {
                                    
                                    current = last;

                                    struct ipAddresses* current2 = (struct  ipAddresses*)malloc(sizeof(struct ipAddresses));

                                    current2->srcIp[0] = ip->srcAddr[0];
                                    current2->srcIp[1] = ip->srcAddr[1];
                                    current2->srcIp[2] = ip->srcAddr[2];
                                    current2->srcIp[3] = ip->srcAddr[3];

                                    current2->destIp[0] = ip->destAddr[0];
                                    current2->destIp[1] = ip->destAddr[1];
                                    current2->destIp[2] = ip->destAddr[2];
                                    current2->destIp[3] = ip->destAddr[3];

                                    current2->num = 1;
                                    current2->frames[0] = bitSwap(ud->srcPort);
                                    current2->frames[1] = bitSwap(ud->destPort);
                                
                                    current2->next = NULL;

                                    current->next = current2;
                                  
                                }
                               

                               
                                
                            }
                            pairs = getList(packet, pairs, packetCount, choice, current, 0);

                           

                           
                        }
                        else if(clientServer->num!=0)
                        {
                            last = clientServer;
                            current=last;
                            
                            while (current !=NULL)
                            {
                                if (((((current->srcIp[0] == ip->srcAddr[0]) && (current->srcIp[1] == ip->srcAddr[1]) &&
                                    (current->srcIp[2] == ip->srcAddr[2]) &&
                                    (current->srcIp[3] == ip->srcAddr[3])) &&
                                    ((current->destIp[0] == ip->destAddr[0]) &&
                                        (current->destIp[1] == ip->destAddr[1]) &&
                                        (current->destIp[2] == ip->destAddr[2]) &&
                                        (current->destIp[3] == ip->destAddr[3])))
                                    ||
                                    (((current->srcIp[0] == ip->destAddr[0]) && (current->srcIp[1] == ip->destAddr[1]) && (current->srcIp[2] == ip->destAddr[2]) && (current->srcIp[3] == ip->destAddr[3])
                                        ) && ((current->destIp[0] == ip->srcAddr[0]) && (current->destIp[1] == ip->srcAddr[1]) && (current->destIp[2] == ip->srcAddr[2]) && (current->destIp[3] == ip->srcAddr[3])
                                            ))) 
                                    ) 
                                {
                                    
                                    u_short end = 0;
                                    u_char* g = (u_char*)(packet + EHL + 29);
                                    
                                    if (*g == 5)
                                    {
                                 
                                        end = 1;
                                        current->num = 2;
                                       
                                    }
                                    
                                    pairs = getList(packet, pairs, packetCount, choice, current,end);
                                    
                                    
                                    break;
                                }
                                
                                current = current->next;
                            }
                            clientServer = last;
                        }
                      

                    }
                }
                 else if (strcmp(etypeName, "ARP\n\0") == 0 && choice==10)
               {
               struct arp* ar = (struct arp*)(packet + EHL);

               
               if (bitSwap(ar->operation) == 2) {
                   pairs = getList(packet, pairs, packetCount, choice, current, 1);
               }
               else if (bitSwap(ar->operation) == 1)
               {
                   pairs = getList(packet, pairs, packetCount, choice, current, 0);
               }
               
             
             
              
                
                
               }
               
            }
           
           
                
            
        }
         packetCount++;
      
      
       
    }
    if (choice == 1) {
        printf("ipv4_senders:\n");
        fprintf(output,"ipv4_senders:\n");
        int max = 0;
        int ipMax[200];
        u_char multimax = 0;
        u_char track = 0;
        while (ipList != NULL) {
            fprintf(output, "  - node: %d.%d.%d.%d   \n    number_of_sent_packets: %d\n\n", ipList->srcIp[0], ipList->srcIp[1], ipList->srcIp[2], ipList->srcIp[3], ipList->num);
            printf("  - node:%d.%d.%d.%d\n     number_of_sent_packets: %d\n\n", ipList->srcIp[0], ipList->srcIp[1], ipList->srcIp[2], ipList->srcIp[3], ipList->num);
            
            if (ipList->num > max || ipList->num==max) {
                
                multimax++;
                max = ipList->num;
                ipMax[track] = ipList->srcIp[0];
                track++;

                ipMax[track] = ipList->srcIp[1];
                track++;
                ipMax[track] = ipList->srcIp[2];
                track++;
                ipMax[track] = ipList->srcIp[3];
                track++;
                ipMax[track] = ipList->num;
                track++;
                
            }
            ipList = ipList->next;
            
        } 
        track--;
        fprintf(output, "max_send_packets_by:\n");
        
        for (u_char j = 0; j <= multimax; j++)
        { 
            printf("max=%d | valInIp=%d | track=%d | multimax=%d | iPmax=%d  | realIpmax=%d | others: %d- %d - %d\n",max, ipMax[(track - j) - (j * 4)],track,multimax, (track - j) - (j * 4),ipMax[9], ipMax[8], ipMax[7], ipMax[6]);
            if (max == ipMax[(track - j) - (j * 4)]) {
                
                fprintf(output, "  - %d.%d.%d.%d\n", ipMax[(track - j) - (4 + (j * 4))], ipMax[(track - j) - (3 + (j * 4))], ipMax[(track - j) - (2 + (j * 4))], ipMax[(track - j) - (1 + (j * 4))]);
            }
            else { break; }
        }
        fclose(output);
    }
 
    if (choice == 8)
    {
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header=NULL;
        const u_char* packet=NULL;
        int packetCount = 1;
        int returnValue=NULL;
        int k = 1;
        printf("complete_comms:\n");
        fprintf(output, "complete_comms:\n");
        ICMPCommunication(returnValue, pcap_file, header, packet, packetCount,pairs,protocol,output,k,file,1);
        pcap_close(pcap_file);
        errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        header = NULL;
        packet = NULL;
        packetCount = 1;
        returnValue = NULL;
        k = 1;
        
        printf("partial_comms:\n");
        fprintf(output, "partial_comms:\n");
        ICMPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k,file,0);
        fclose(output);
    }

    if (choice == 10)
    {
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        int k = 1;
       
            printf("complete_comms:\n");
            fprintf(output, "complete_comms:\n");
        
        
           
        
        ARPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file, 1);
        pcap_close(pcap_file);
        errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        header = NULL;
        packet = NULL;
        packetCount = 1;
        returnValue = NULL;
        
        printf("partial_comms:\n");
        fprintf(output, "partial_comms:\n");
        ARPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, 1, file, 0);
        fclose(output);

    }
    if (choice == 9)
    {
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        u_short k = 1;
       
        
        TFTPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,1);
        pcap_close(pcap_file);
        errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        header = NULL;
        packet = NULL;
        packetCount = 1;
        returnValue = NULL;
        

        
        TFTPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output,  1, file,0);
        fclose(output);
    }
    if (choice == 7)
    {
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        u_short k = 1;
        
        printf("complete_comms:\n");
        fprintf(output, "complete_comms:\n");
        TELNETCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,1);
        pcap_close(pcap_file);
        errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        header = NULL;
        packet = NULL;
        packetCount = 1;
        returnValue = NULL;
       
        printf("partial_comms:\n");
        fprintf(output, "partial_comms:\n");
        TELNETCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output,  1, file,0);
        fclose(output);
    }
    if (choice == 6)
    {
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        u_short k = 1;
        
        printf("complete_comms:\n");
        fprintf(output, "complete_comms:\n");
        SSHCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,1);
        pcap_close(pcap_file);
        errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        header = NULL;
        packet = NULL;
        packetCount = 1;
        returnValue = NULL;
        k = 1;
        printf("partial_comms:\n");
        fprintf(output, "partial_comms:\n");
        SSHCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output,  k, file,0);
        fclose(output);
    }
    if (choice == 5)
    {
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        u_short k = 1;
        
        printf("complete_comms:\n");
        fprintf(output, "complete_comms:\n");
        FTPControlCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output,  k, file,1);
        pcap_close(pcap_file);
        errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        header = NULL;
        packet = NULL;
        packetCount = 1;
        returnValue = NULL;
        k = 1;
        printf("partial_comms:\n");
        fprintf(output, "partial_comms:\n");
        FTPControlCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output,  k, file,0);
        fclose(output);
    }
    if (choice == 4)
    {
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        u_short k = 1;
        
        printf("complete_comms:\n");
        fprintf(output, "complete_comms:\n");
        FTPDATACommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output,  k, file,1);
        pcap_close(pcap_file);
        errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        header = NULL;
        packet = NULL;
        packetCount = 1;
        returnValue = NULL;
        k = 1;

        printf("partial_comms:\n");
        fprintf(output, "partial_comms:\n");
        FTPDATACommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,0);
        fclose(output);
    }
    if (choice == 3)
    {
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        u_short k = 1;
        
        printf("complete_comms:\n");
        fprintf(output, "complete_comms:\n");
        HTTPSCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,1);
        pcap_close(pcap_file);
        errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        header = NULL;
        packet = NULL;
        packetCount = 1;
        returnValue = NULL;
        k = 1;
        printf("partial_comms:\n");
        fprintf(output, "partial_comms:\n");
        HTTPSCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,0);
        fclose(output);
    }
    if (choice == 2)
    {
        pcap_close(pcap_file);
        char* errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_t* pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        struct pcap_pkthdr* header = NULL;
        const u_char* packet = NULL;
        int packetCount = 1;
        int returnValue = NULL;
        u_short k = 1;
        
        printf("complete_comms:\n");
        fprintf(output, "complete_comms:\n");
        HTTPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,1);
        pcap_close(pcap_file);
        errbuff[PCAP_ERRBUF_SIZE];//open PCAP FILE                     //these are all responsible
        pcap_file = pcap_open_offline(file, errbuff);             // for opening and reading pcap files
        header = NULL;
        packet = NULL;
        packetCount = 1;
        returnValue = NULL;
        k = 1;
        printf("partial_comms:\n");
        fprintf(output, "partial_comms:\n");
        HTTPCommunication(returnValue, pcap_file, header, packet, packetCount, pairs, protocol, output, k, file,0);

        fclose(output);
    }



    

    goto HelloThere;

	return 0;
    
} 