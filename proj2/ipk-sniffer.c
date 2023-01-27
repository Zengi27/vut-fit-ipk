/**********************
*
*   VUT FIT
*   IPK - projekt 2 (sniffer)
*   Autor: Jan Homola (xhomol27)
*   Zaciatok: 19.4.2021
*
***********************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <string.h>
#include <unistd.h>     // spracovanie arg
#include <getopt.h>     // spracovanie arg
#include <ifaddrs.h>    // najdenie rozhrani

#include <netinet/if_ether.h> // potrebne pre puzitie pripania vsetkych socketov
#include <netinet/in.h>       // htons()
#include <sys/socket.h> 
#include <netinet/ip.h>       // ziskanie ip hlavicky protokolu
#include <net/ethernet.h>     // enthernet hlavicka

#include <arpa/inet.h>      // inet_ntoa
#include <netinet/tcp.h>    // tcp hlavicka
#include <netinet/udp.h>    // udp hlavicka
#include <netinet/ip_icmp.h>// icmp hlavicka
#include <netpacket/packet.h>   // sockaddr_ll

#include <net/if.h>             // na funkciu if_nametoindex()

#include <netinet/ip6.h>        // hlavicka ipv6


#include <time.h>
#include <sys/time.h>

#include <ctype.h>          // funckia isprinte


#define line_len 16
#define half_line_len 8


// Funkcia vypise vsetky dostupne rozhrania 
int print_all_interface()
{   
    struct ifaddrs *interface_addrs;
    if (getifaddrs(&interface_addrs) < 0)
    {
        printf("Chyba vo funkcii getifaddrs \n");
        return 1;
    }
    struct ifaddrs *intf_addr = interface_addrs;

    for (intf_addr; intf_addr; intf_addr = intf_addr->ifa_next)
    {
        int family = intf_addr->ifa_addr->sa_family;
        if (family == AF_PACKET)
        {
            char *intf_name = intf_addr->ifa_name;
            printf("%s \n", intf_name);
        }
    }
    freeifaddrs(interface_addrs);
    return 0;
}

// Funkcia na ziskanie source adresy
char* get_src(struct iphdr *ip_header)
{
    struct sockaddr_in ip_source;

    // tato cast kodu bola prevzata a upravena z : https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/?fbclid=IwAR12w0bPmT67iIGi2aRu9ByfNb1AsHAt0fj8GzbOMhI361oAsgpTjBMXIQ0
    memset(&ip_source, 0, sizeof(ip_source));
    ip_source.sin_addr.s_addr = ip_header->saddr;
    // koniec prevzatej casti

    return inet_ntoa(ip_source.sin_addr);
}



// Funkcia na ziskanie destination adresy
char* get_dst(struct iphdr *ip_header)
{
    struct sockaddr_in ip_destination;

    // tato cast kodu bola prevzata a upravena z : https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/?fbclid=IwAR12w0bPmT67iIGi2aRu9ByfNb1AsHAt0fj8GzbOMhI361oAsgpTjBMXIQ0
    memset(&ip_destination, 0, sizeof(ip_destination));
    ip_destination.sin_addr.s_addr = ip_header->daddr;
    // koniec prevzatej casti

    return inet_ntoa(ip_destination.sin_addr);
}


// Funkcia na ziskanie casu 
void get_time()
{
    time_t my_time = time(NULL);
    struct tm *t = localtime(&my_time);

    struct timeval curret;

    gettimeofday(&curret, NULL);

    int mili_s = curret.tv_usec / 1000;
    int t_zone_hours = t->tm_gmtoff / 3600;
    int t_zone_min = t->tm_gmtoff % 3600;

    printf("%d", 1900 + t->tm_year);
    printf("-");
    printf("%d", t->tm_mon);
    printf("-");
    printf("%d", t->tm_mday);
    printf("T");
    printf("%d", t->tm_hour);
    printf(":");
    printf("%d", t->tm_min);
    printf(":");
    printf("%d", t->tm_sec);
    printf(".");
    printf("%d", mili_s);

    printf("%+03d", t_zone_hours);        
    printf(":");
    printf("%02d", t_zone_min);
}


// Funkcia ktora vypise data 
void print_data(int lenght, unsigned char* buffer)
{
    for (int i = 0; i < lenght; i++)
    {
        // vypisanie cisla riadka
        if (i % line_len == 0)
            printf("\n0x%04d: ", i/16 * 10);      
        
        
        // ak je to osme cislo tak dve medzeri pre prehladnost
        if (i % half_line_len == 0)
            printf("  %02x", buffer[i]);
        else
            printf(" %02x", buffer[i]);

       

        // ak je to posledne cislo riadku vypisanie znakov
        if (i + 1 < lenght)
        {   if ((i + 1) % line_len == 0)
            {
                printf("    ");
                int j = i - line_len + 1;   // zaciatok riadka
                for (j ; j < i + 1; j++)
                {
                    if (j % half_line_len == 0)// medzera v strede pre prehladnost
                        printf(" ");
                    
                    if (isprint(buffer[j]))             // ak sa znak da vypisat
                        printf("%c", buffer[j]);
                    else                                // ak sa znak neda vypisat      
                        printf(".");
                }
            }
        }

        // vypisanie zvysku dat 
        if (i + 1 == lenght)                    // ak v nasledujucom cykle je koniec dat
        {
            printf("    ");
            int cnt_rest = lenght % 16;         // pocet zvysku dat na vypisanie
            int missing_value = 16 - cnt_rest;  // kolko znakov sa nevypisalo 
            
            int j = i - cnt_rest + 1;           // ziskanie zaciatku riadka

            // korekcia medzier (spravny padding)
            for (int k = 0; k < missing_value; k++)
                printf("   ");
            // ak je pocet znakov mensi nez polovica tak este jedna medzera na korekciu
            if (cnt_rest <= 8)
                printf(" ");

            // vypisanie jednotlivych znakov
            for (j ; j < i + 1; j++)
            {
                if (j % half_line_len == 0)         // medzera v strede pre prehladnost
                        printf(" ");
                    
                if (isprint(buffer[j]))             // ak sa znak da vypisat
                        printf("%c", buffer[j]);
                else                                // ak sa znak neda vypisat      
                        printf(".");
            }
        }
    }
}

// Funkcia na vypisanie TCP paketu aj s hlavickou Ethernetu
void tcp_packet_print_data(int lenght,unsigned char* buffer, struct iphdr *ip_header)
{
    unsigned int lenght_of_header = ip_header->ihl*4;   // ziskanie ip hlavicky v bajtoch
    
    // ziskanie tcp hlavicky
    struct tcphdr *tcp_header = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + lenght_of_header); 

    printf("------------------------------------------ TCP ------------------------------------------\n");
    get_time();
    printf(" %s ", get_src(ip_header));
    printf(": %d ", ntohs(tcp_header->source));
    printf("> %s ", get_dst(ip_header));
    printf(": %d", ntohs(tcp_header->dest));
    printf(", length %d bytes\n", lenght);
    print_data(lenght, buffer);
    printf("\n");
    printf("-----------------------------------------------------------------------------------------\n");
    printf("\n");
}

// Funkcia na vypisanie TCP paketu aj s hlavickou Ethernetu (IPv6)
void tcp_packet_print_data_IPv6(int lenght, unsigned char* buffer, struct ip6_hdr *ipv6_header, struct tcphdr *tcp_header)
{
    // tato cast kodu bola prevzata a modifikovana z :
    // link: http://long.ccaba.upc.edu/long/045Guidelines/eva/ipv6.html
    char ipv6_src[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_header->ip6_src, ipv6_src, sizeof(ipv6_src));
    char ipv6_dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_header->ip6_dst, ipv6_dst, sizeof(ipv6_dst));
    // koniec prevzatej casti

    printf("------------------------------------------ TCP ------------------------------------------\n");
    get_time();
    printf(" %s ", ipv6_src);
    printf(": %d ", ntohs(tcp_header->source));
    printf("> %s ", ipv6_dst);
    printf(": %d", ntohs(tcp_header->dest));
    printf(", length %d bytes\n", lenght);
    print_data(lenght, buffer);
    printf("\n");
    printf("-----------------------------------------------------------------------------------------\n");
    printf("\n");
}

// Funkcia na vypisanie UDP packetu aj s hlavickou Ethernetu
void udp_packet_print_data(int lenght,unsigned char* buffer, struct iphdr *ip_header)
{
    unsigned int lenght_of_header = ip_header->ihl*4;   // ziskanie ip hlavicky v bajtoch

    // ziskanie udp hlavicky
    struct udphdr *udp_header = (struct udphdr *) (buffer + sizeof(struct ethhdr) + lenght_of_header); 

    printf("------------------------------------------ UDP ------------------------------------------\n");
    get_time();
    printf(" %s ", get_src(ip_header));
    printf(": %d ", ntohs(udp_header->source));
    printf("> %s ", get_dst(ip_header));
    printf(": %d", ntohs(udp_header->dest));
    printf(", length %d bytes\n", lenght);
    print_data(lenght, buffer);
    printf("\n");
    printf("-----------------------------------------------------------------------------------------\n");
    printf("\n");
}

// Funkcia na vypisanie UDP packetu aj s hlavickou Ethernetu (IPv6)
void udp_packet_print_data_IPv6(int lenght, unsigned char* buffer, struct ip6_hdr *ipv6_header, struct udphdr *udp_header)
{
    // tato cast kodu bola prevzata a modifikovana z :
    // link: http://long.ccaba.upc.edu/long/045Guidelines/eva/ipv6.html
    char ipv6_src[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_header->ip6_src, ipv6_src, sizeof(ipv6_src));
    char ipv6_dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_header->ip6_dst, ipv6_dst, sizeof(ipv6_dst));
    // koniec prevzatej casti

    printf("------------------------------------------ UDP ------------------------------------------\n");
    get_time();
    printf(" %s ", ipv6_src);
    printf(": %d ", ntohs(udp_header->source));
    printf("> %s ", ipv6_dst);
    printf(": %d", ntohs(udp_header->dest));
    printf(", length %d bytes\n", lenght);
    print_data(lenght, buffer);
    printf("\n");
    printf("-----------------------------------------------------------------------------------------\n");
    printf("\n");
}

// Funkcia na vypisanie ICMP packetu aj s hlavickou Ethernetu
void icmp_packet_print_data(int lenght,unsigned char* buffer, struct iphdr *ip_header)
{
    printf("------------------------------------------ ICMP ------------------------------------------\n");
    get_time();
    printf(" %s ", get_src(ip_header));
    printf("> %s ", get_dst(ip_header));
    printf(", length %d bytes\n", lenght);
    print_data(lenght, buffer);
    printf("\n");
    printf("-----------------------------------------------------------------------------------------\n");
    printf("\n");
}

// Funkcia na vypisanie ICMP packetu aj s hlavickou Ethernetu (IPv6)
void icmp_packet_print_data_IPv6(int lenght,unsigned char* buffer, struct ip6_hdr *ipv6_header)
{
    // tato cast kodu bola prevzata a modifikovana z :
    // link: http://long.ccaba.upc.edu/long/045Guidelines/eva/ipv6.html
    char ipv6_src[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_header->ip6_src, ipv6_src, sizeof(ipv6_src));
    char ipv6_dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6_header->ip6_dst, ipv6_dst, sizeof(ipv6_dst));
    // koniec prevzatej casti


    printf("------------------------------------------ ICMP ------------------------------------------\n");
    get_time();
    printf(" %s ", ipv6_src);
    printf("> %s ", ipv6_dst);
    printf(", length %d bytes\n", lenght);
    print_data(lenght, buffer);
    printf("\n");
    printf("-----------------------------------------------------------------------------------------\n");
    printf("\n");
}

// Funkcia na vypisanie ARP packetu a jeho Ethernet hlavicku
void arp_packet_print_data(int lenght,unsigned char* buffer, struct ethhdr *eth_header)
{
    printf("------------------------------------------ ARP ------------------------------------------\n");
    get_time();

    // Ethernet src
    printf(" %02x:%02x:%02x:", eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2]);
    printf("%02x:%02x:%02x ", eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);
    
    // Ethernet dst
    printf("> %02x:%02x:%02x:", eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2]);
    printf("%02x:%02x:%02x", eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);
    
    printf(", length %d bytes\n", lenght);
    print_data(lenght, buffer);
    printf("\n");
    printf("-----------------------------------------------------------------------------------------\n");
    printf("\n");

}

int main(int argc, char *argv[])
{
    int o;
    static int arp_only = 0;
    static int icmp_only = 0;

    char interface[256];
    int port_number = 0;
    int packet_number = 1;

    bool B_interface = false;
    int tcp_only = 0;
    int udp_only = 0;


    // spracovanie vstupnych argumentov
    static struct option long_options[] = 
    {
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, &arp_only, 1},
        {"icmp", no_argument, &icmp_only, 1},
        {"interface", optional_argument, 0, 'i'},
    };

    while((o = getopt_long(argc, argv, ":i:hp:tun:", long_options, NULL)) != -1)
    {
        switch(o)
        {
            case 'h' :
                printf("Program na sniffovanie paketov \n");
                return 0;
                break;
            case 'i' :
                if (optarg != NULL)
                {
                    strcpy(interface, optarg); 
                    B_interface = true;
                }
                break;

            case 'p' :
                port_number = atoi(optarg);
                break;

            case 't' :
                tcp_only = 1;
                break;

            case 'u' :
                udp_only = 1;
                break;

            case 'n' :
                packet_number = atoi(optarg);
                break;
           
            
        }
    }

    if (B_interface == false)
    {
        int return_value = print_all_interface();
        return return_value;
    }
    
    // prijatie vsetkych socketov 
    int socket_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    int counter = 0;
    while(counter != packet_number)
    {
        struct sockaddr socketadress;
        struct sockaddr_ll addr;
        int saddr_size = sizeof (socketadress);

        int size_of_data;
        unsigned char *buffer = (unsigned char *) malloc(65536);
        

        size_of_data = recvfrom(socket_raw, buffer, 65536, 0, &socketadress, (socklen_t*)&saddr_size);

        // tato cast kodu bola prevzata a modifokovana z 
        // link : https://stackoverflow.com/questions/26908439/c-program-to-receive-and-send-the-same-packets-out-over-another-interface
        // Autor : anon_16
        // Datum : Nov 17, 2014
        addr.sll_protocol = htons(ETH_P_ALL);
        addr.sll_family = AF_PACKET;
        addr.sll_ifindex = if_nametoindex(interface);        
        if (bind(socket_raw, (struct sockaddr *) &addr, sizeof(addr)) == -1)
        {
            close(socket_raw);
            return 1;
        }
        // koniec prevzatej casti

        // ziskanie ethernet hlavicky
        struct ethhdr *ethernet_header = (struct ethhdr *)(buffer);
        uint16_t eth_protocol = ntohs(ethernet_header->h_proto);

        // ziskanie hlavicky (IP vrstva)
        struct iphdr *ip_header = (struct iphdr*) (buffer + sizeof(struct ethhdr));  // posunutie za eth hlavicku
        uint8_t ip_protocol = ip_header->protocol;

        if (eth_protocol == 0x0800)     // eth protokol IPv4
        {
            if (ip_protocol == 1)      // protokol ICMP
            {
                // kontrola ci sa ma dany protokol vypisat
                if ((tcp_only == 0 && udp_only == 0 && arp_only == 0) || icmp_only == 1)
                {
                    icmp_packet_print_data(size_of_data, buffer, ip_header);
                    counter++;
                }
            }
            else if (ip_protocol == 6)  // protokol TCP
            {
                // kontrola ci ma dany protokol vypisat
                if ((icmp_only == 0 && udp_only == 0 && arp_only == 0) || tcp_only == 1)
                {   
                    if (port_number != 0)           //kontrola ci bol zadani prepinac
                    {
                        unsigned int lenght_of_header = ip_header->ihl*4;   // ziskanie ip hlavicky v bajtoch
                        // ziskanie tcp hlavicky
                        struct tcphdr *tcp_header = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + lenght_of_header);
                        uint16_t tmp_port_src = ntohs(tcp_header->source);
                        uint16_t tmp_port_dst = ntohs(tcp_header->dest);
                        if (tmp_port_src != port_number && tmp_port_dst != port_number) // ak to nie je pozadovany port hlada dalej
                            continue;
                    }
                    tcp_packet_print_data(size_of_data, buffer, ip_header);
                    counter++;
                }
            }
            
            else if (ip_protocol == 17) // protokol UDP
            {
                // kontrola ci ma dany protokol vypisat
                if ((icmp_only == 0 && tcp_only == 0 && arp_only == 0) || udp_only == 1)
                {
                    if (port_number != 0)
                    {
                        unsigned int lenght_of_header = ip_header->ihl*4;   // ziskanie ip hlavicky v bajtoch
                        // ziskanie udp hlavicky
                        struct udphdr *udp_header = (struct udphdr *) (buffer + sizeof(struct ethhdr) + lenght_of_header); 
                        u_int16_t tmp_port_src = ntohs(udp_header->source);
                        u_int16_t tmp_port_dst = ntohs(udp_header->dest);
                        if (tmp_port_src != port_number && tmp_port_dst != port_number) // ak to nie je pozadovany port hlada dalej
                            continue;    
                    }
                    udp_packet_print_data(size_of_data, buffer, ip_header);
                    counter++;
                }
            }

        }
        else if (eth_protocol == 0x0806)                        // eth protokol ARP
        {
            if ((icmp_only == 0 && tcp_only == 0 && udp_only == 0) || arp_only == 1)
            {
                arp_packet_print_data(size_of_data, buffer, ethernet_header);
                counter++;
            }
        }
        else if (eth_protocol == 0x86DD)                        // eth protokol IPv6
        {
            struct ip6_hdr *ipv6_header = (struct ip6_hdr*) (buffer + sizeof(struct ethhdr));
            u_int8_t ipv6_protocol = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;


            if (ipv6_protocol == 1)         // ICMP protokol
            {
                // kontrola ci sa ma dany protokol vypisat
                if ((tcp_only == 0 && udp_only == 0 && arp_only == 0) || icmp_only == 1)
                {
                    icmp_packet_print_data(size_of_data, buffer, ip_header);
                    counter++;
                }
            }
            else if (ipv6_protocol == 6)    // TCP protokol
            {
                // kontrola ci ma dany protokol vypisat
                if ((icmp_only == 0 && udp_only == 0 && arp_only == 0) || tcp_only == 1)
                {   
                    unsigned int lenght_of_header = 40;   // vzdy 40
                    // ziskanie tcp hlavicky
                    struct tcphdr *tcp_header = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + lenght_of_header);
                    
                    if (port_number != 0)           //kontrola ci bol zadani prepinac
                    {
                        uint16_t tmp_port_src = ntohs(tcp_header->source);
                        uint16_t tmp_port_dst = ntohs(tcp_header->dest);
                        if (tmp_port_src != port_number && tmp_port_dst != port_number) // ak to nie je pozadovany port hlada dalej
                            continue;
                    }
                    tcp_packet_print_data_IPv6(size_of_data, buffer, ipv6_header, tcp_header);
                    counter++;
                }
            }
            else if (ipv6_protocol == 17)   // UDP protokol
            {
                // kontrola ci ma dany protokol vypisat
                if ((icmp_only == 0 && tcp_only == 0 && arp_only == 0) || udp_only == 1)
                {
                    unsigned int lenght_of_header = ip_header->ihl*4;   // ziskanie ip hlavicky v bajtoch
                    // ziskanie udp hlavicky
                    struct udphdr *udp_header = (struct udphdr *) (buffer + sizeof(struct ethhdr) + lenght_of_header);
                    if (port_number != 0)
                    {     
                        u_int16_t tmp_port_src = ntohs(udp_header->source);
                        u_int16_t tmp_port_dst = ntohs(udp_header->dest);
                        if (tmp_port_src != port_number && tmp_port_dst != port_number) // ak to nie je pozadovany port hlada dalej
                            continue;    
                    }
                    udp_packet_print_data_IPv6(size_of_data, buffer, ipv6_header, udp_header);
                    counter++;
                }
            }
        }
        free(buffer);
    }
    close(socket_raw);
    
}