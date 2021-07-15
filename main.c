#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h> /* Explicitly used for IPv6 max packet payload */
#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <ctype.h>

/*
 *  Prerequisites:
 *  - A device node capable of tx/rx to userspace 
 *    e.g. /dev/net/tun, /dev/net/tap
 *    => Creating such a device node is described 
 *       in the README.md 
 *  - The `tun` kernel module must be loaded either
 *    manually via `modprobe tun` or kernel auto module loader
 *    e.g. appending tun to /etc/modules
 *  - Referencing:
 *    www.kernel.org/doc/Documentation/networking/tuntap.txt
 */

// GLOBAL
unsigned int keep_run = 1;
// Screen dimensions in rows & columns
typedef struct screen_dimensions screen_dimensions_t;
struct screen_dimensions
{
    int cols;
    int rows;
};

// Expected IP Packet Format:
// -- Flags [2 bytes]
// -- Proto [2 bytes]
// -- Raw Protocol (IP, IPv6, etc) frame
static const uint8_t IP_META_SZ = 4;
typedef struct packet packet;
struct packet {
    uint16_t flags;
    uint16_t proto;
    uint8_t  ip_payload[ETH_MAX_MTU];
}__attribute__((packed));

// Gracefully exit the programming, destructing while 1
void exit_graceful(int sig);
// Allocate a TUN interface with name dev
int tun_alloc(char* dev);
// Set the interface flags for dev
int set_iff_up_with(char* dev, int flags);
// Find rows/columns of the current screen
int find_screen_dimensions(screen_dimensions_t* current_screen);
// Parse packet
void pretty_print_packet(packet ip_packet);

int main(int argc, char* argv[])
{
    // Trap ctrl-C
    signal(SIGINT, exit_graceful);
    // Device name
    char dev[IFNAMSIZ];
    strcpy(&dev[0], "tun0");
    // Allocate the network device
    int tun_fd;
    if ((tun_fd = tun_alloc(dev)) < 0)
    {
        fprintf(stderr, "TUN allocation has failed... Exiting...\n");
        exit(-1);
    }
    // Set TUN0 up with flags set to:
    // IFF_PROMISC  -- receive all packets
    // IFF_ALLMULTI -- receive all multicast packets
    // IFF_DYNAMIC  -- dialup device with changing address
    if (-1 == set_iff_up_with(dev, IFF_PROMISC | IFF_ALLMULTI | IFF_DYNAMIC))
    {
        fprintf(stderr, "Could not set interface \"%s\" up with flags: "
                        " IFF_PROMISC, IFF_ALLMULTI, IFF_DYNAMIC. Permissions?\n",
                dev);
        exit(-1);
    }

    // Set stdout to fully unbuffered, many ways to do this
    setvbuf(stdout, NULL, _IONBF, 0);
    
    // Find screen dimensions
    screen_dimensions_t my_screen;
    if(-1 == find_screen_dimensions(&my_screen))
    {
        fprintf(stderr, "Failed to get screen dimensions.\n");
        exit(-1);
    }

    // Print statements indicating row & tun device name
    printf("Screen dimensions to be: %i x %i\n", my_screen.rows,
            my_screen.cols);
    printf("Network device \"%s\" successfully allocated.\n", dev);
    
    // Poll timeout
    static const unsigned int poll_timeoutms = 100;
    // Character spinner
    const char* spinner = "-\\|/"; 
    unsigned int spin_ind = 0;
    /* TODO: 
     * -- IP Frame decode 
     * -- Tun0 set as default gateway (set as promiscious so sees all packets anyways?)
     *  */
    // While 1 on global, simple sig int trap to break this 
    while (keep_run)
    {
        /* Timeout setup for select call */
        // See if stdout is ready to be written
        int select_retval;
        // Timeout specification
        struct timeval tv, cp; /* cp (copy) is used for printing */
        tv.tv_sec  = 0;
        tv.tv_usec = 25; /* Waiting only up to 1000 us, or 1 ms*/
        cp = tv;
        // Stdout file descriptor is the only fd we are watching
        fd_set out_fd;
        FD_ZERO(&out_fd); 
        FD_SET(STDOUT_FILENO, &out_fd);
        // Avoid hammering stdout, watch and see if stdout is ready 
        if (select_retval = select(STDOUT_FILENO + 1, NULL, &out_fd, NULL, &tv))
        {
            // Print that we are polling network device soon
            printf("Polling network device %s...", dev);
            printf("%c\r", spinner[spin_ind]);
            spin_ind = (spin_ind + 1) % (sizeof(spinner)/sizeof(spinner[0]));
        }
        // Poll the network device fd
        struct pollfd net_p[1];
        memset(&net_p, 0, sizeof(net_p));
        net_p[0].events = POLLIN | POLLNVAL | POLLHUP | POLLERR | POLLPRI;
        net_p[0].fd     = tun_fd;
        int fd_to_serve;
        // If there is a fd to service
        if ((fd_to_serve = poll(&net_p[0], 1, poll_timeoutms)) > 0)
        {
            // In the revent show a real event
            if (net_p[0].revents != POLLNVAL | POLLHUP | POLLERR | POLLPRI)
            {
                // Print new line
                printf("\n\n");
                // IP Packet Buffer
                packet ip_packet;
                // Blocking read on successful poll
                ssize_t bts = read(tun_fd, &ip_packet, sizeof(ip_packet));
                // 0 indicates EOF
                if (0 >= bts)
                {
                    fprintf(stderr, "%s%s\n", 
                            bts == 0 ? "Unexpected results, EOF?? Exiting..." :
                                       "Unexpected error: ", 
                            bts == 0 ? "" : strerror(errno));
                    keep_run = 0;
                    errno = 0;
                }
                else
                {
                    // Packet Header printing 
                    printf("IP Packet received [length %u]...\n");
                    printf("Flags: %02x %02x Protocol: %02x %02x\n", ip_packet.flags >> 8, ip_packet.flags & 0xFF,
                                                                     ip_packet.proto >> 8, ip_packet.flags & 0xFF);
                    // Pretty print packet details
                    pretty_print_packet(ip_packet);
                    // Footer printing
                    for (size_t i = 0; i < my_screen.cols; i++)
                    {
                        printf("=");
                    }
                    printf("\n\n");
                }
            }
        }
    }
    // Exiting now...
    close(tun_fd);
    return 0;
}


void exit_graceful(int signum)
{
    keep_run = 0;
    printf("Recieved interrupt, exiting gracefully now...\n");
}

// char* dev should be the name of the device with format "tun%d"
int tun_alloc(char* dev)
{
    /// LOCALS ///
    struct ifreq ifr;
    int fd, err;

    // Open /dev/net/tun
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {   
        // On failure print error and return
        fprintf(stderr, "The device node \"/dev/net/tun\" does not exist or do we " 
                        "not have permissions. Errno: %s\n", strerror(errno));
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));

    // Set request flags to IFF_TUN
    ifr.ifr_flags = IFF_TUN;
    if ( *dev )
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    else
    {
        fprintf(stderr, "Device name is bad! %s\n", dev);
    }
    // Ioctl call, pass the request structure for fd
    if ( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0)
    {
        fprintf(stderr,"IOCTL call failed! Errno: %s\n", strerror(errno));
        errno = 0;
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

int set_iff_up_with(char* dev, int flags)
{
    // The return value for this function, 
    // -1 = failure, 0 = success
    int retval = 0;
    // Socket fd on tun0
    int socket_fd;
    // Create a dgram socket to set socket flags to flags
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        // Printf call logging socket allocation failure
        fprintf(stderr, "Socket allocation failed [%s]... Exiting...\n",
                strerror(errno));
        // Set to error
        retval = socket_fd;
        errno = 0;
    }
    // Success, make ioctl req
    else
    {
        // Set request flags to bring the interface up
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_UP | flags;
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
        // Make the request
        if (ioctl(socket_fd, SIOCSIFFLAGS, (void *)&ifr) < 0)
        {
            fprintf(stderr, "Socket allocation failed [%s]... Exiting...\n",
                    strerror(errno));
            // Set to error
            retval = socket_fd;
            errno = 0;
        }
        // Success, close socket fd
        {
            // Close socket fd
            close(socket_fd);
        }
    }
    return retval;
}

int find_screen_dimensions(screen_dimensions_t* current_screen)
{
    // Return value of the function
    // 0 indicating success, -1 otherwise
    int retval = 0;
    // Get the screen dimensions
    FILE* stream;
    int fd;
    // Buffer to hold piped output, memset?
    char buf[15];
    if (NULL == current_screen)
    {
        fprintf(stderr, "Passed argument is null pointer!\n");
        retval = -1;
    }
    // Call into stty size returning rows/cols
    else if (NULL != (stream = popen("stty size", "r")))
    {
        // Get file descriptor from stream (could use fread here, simply
        // feel like sticking with read(2) when possible) 
        if (-1 != (fd = fileno(stream)))
        {
            // Retval set to return from read here
            if (-1 == (retval = read(fd, &buf[0], sizeof(buf)/sizeof(buf[0]))))
            {
                fprintf(stderr, "Reading from process \"stty size\" FAILED. Returned:"
                                " %s", strerror(errno));
                errno = 0;
            }
            // Always close stream & fd
            pclose(stream);
            close(fd);
        }
        else
        {
            // Print and set return value, closing any open file streams/descriptors
            fprintf(stderr, "Failed to get file descriptor from stream! Returned :%s\n",
                            strerror(errno));
            retval = -1;
            errno = 0;
            pclose(stream);
        }
    }
    else
    {
        // Print and set return value, closing any open file streams/descriptors
        fprintf(stderr, "Failed to open process \"stty size\". Returned %s\n",
                        strerror(errno));
        retval = -1;
        errno = 0;
    }
    // Parse out the rows & columns here if success
    if (retval)
    {
        // Buffer used to hold digit characters only
        char digit_only[sizeof(buf)/sizeof(buf[0])];
        // Character position in string
        int char_pos = 0;
        // Length of piped output
        int piped_length = strlen(&buf[0]);
        // Retval carries the number of characters read from read(2)
        // NOTE: We are guaranteeing that we land character position on
        //       space character position + 1
        while ((char_pos < retval) && isdigit(buf[char_pos++]));
        // Find rows
        memset(&digit_only[0], 0, sizeof(digit_only)/sizeof(digit_only[0]));
        strncpy(&digit_only[0], &buf[0], char_pos - 1);
        if ( -1 == (current_screen->rows = atoi(digit_only)))
        {
            fprintf(stderr, "Atoi failed on \"%s\". Returned %s\n", 
                    digit_only, strerror(errno));
            retval = -1;
            errno = 0;
            current_screen->rows = 0;
        }
        // First conversion success, validity check on length of cols
        else if ((&buf[0] + char_pos + 1) < &buf[piped_length - 1])
        {
            // Find cols
            memset(&digit_only[0], 0, sizeof(digit_only)/sizeof(digit_only[0]));
            strncpy(&digit_only[0], &buf[0] + char_pos, piped_length - char_pos + 1);
            if (-1 == (current_screen->cols = atoi(digit_only)))
            {
                fprintf(stderr, "Atoi failed on \"%s\". Returned %s\n", 
                        digit_only, strerror(errno));
                retval = -1;
                errno = 0;
                current_screen->rows = 0;
                current_screen->cols = 0;
            }
        }
        // Unexpected, string out of range
        else
        {
            fprintf(stderr, "The character position for the columns value is out of "
                            "range! Expected to be within \"%i\" was \"%i\". Returned: "
                            "%s", 
                    piped_length, char_pos + 1, strerror(errno));
            retval = -1;
            errno = 0;
            current_screen->rows = 0;
        }
    }
    return retval;
}

/* Pretty printing packet *
 * IPv4 : TODO
 */
void pretty_print_packet(packet ip_packet)
{
    // Print buffer and a running character count
    char print_buffer[8192]; size_t cnt = 0;
    // Low nibble of first byte of either a IPv4 or IPv6 payload is the 
    // version
    uint8_t version = (ip_packet.ip_payload[0] & 0xF0) >> 4;
    static const uint8_t IPV6_VERSION = 6;
    static const uint8_t IPV4_VERSION = 4;
    cnt += sprintf(print_buffer, "IP Version: %s [0x%02x] ", 
                   version == IPV6_VERSION ? "IPv6" : "IPv4", version);

    // Bit mapped structure
    static const uint8_t IPV6_ADDRESS_SIZE = 16;
    typedef struct i6_pckt_hdr 
    {
        uint8_t  version       :4;
        uint16_t  traffic_class:8;
        uint32_t flow_label    :20;
        uint16_t payload_length;
        uint8_t  next_header;
        uint8_t  hop_limit;
        uint8_t  source_address[IPV6_ADDRESS_SIZE];
        uint8_t  destination_address[IPV6_ADDRESS_SIZE];
    }__attribute__((packed)) i6_pckt_hdr_t;
    // IPv6 parsing
    if (IPV6_VERSION == version)
    {
        // Memcpy into bit mapped IPv6 packet header structure above
        i6_pckt_hdr_t ipv6_header;
        memcpy(&ipv6_header, &ip_packet.ip_payload, sizeof(ipv6_header));
        cnt += sprintf(print_buffer + cnt, "vs. [0x%01x]\n", ipv6_header.version); 
        // Traffic class parsing
        uint8_t traffic_class = (ip_packet.ip_payload[0] & 0x0F << 4) | (ip_packet.ip_payload[1] & 0xF0);
        cnt += sprintf(print_buffer + cnt, "Differentiated Services Field: [0x%02x %s] vs. " 
                                           "[0x%02x %s] \n", 
                                            (traffic_class & 0xFC) >> 2, 
                                            (traffic_class & 0xFC >> 2) & 0x03 == 0x03 ? 
                                            "local/experimental use" : "",
                                            (ipv6_header.traffic_class & 0xFC) >> 2, 
                                            (ipv6_header.traffic_class & 0xFC >> 2) & 0x03 == 0x03? 
                                            "local/experimental use" : ""
                                            ); 
        cnt += sprintf(print_buffer + cnt, "Explicit Congestion Notification: [0x%01x] vs. " 
                                           "[0x%01x]\n", 
                                           traffic_class & 0x03,
                                           ipv6_header.traffic_class & 0x03); 
        // Flow label
        uint32_t flow_label = (ip_packet.ip_payload[1] & 0x0F) << 20 |\
                              (ip_packet.ip_payload[2])        << 8  |\
                              (ip_packet.ip_payload[3]);
        cnt += sprintf(print_buffer + cnt, "Flow Label: [0x%06x] vs. [0x%06x]\n", 
                                           flow_label, ipv6_header.flow_label);
        // Payload Length
        uint16_t payload_length = ip_packet.ip_payload[4] << 8|\
                                  ip_packet.ip_payload[5];
        cnt += sprintf(print_buffer + cnt, "Payload Length: [%u] vs. [%u]\n", 
                                           payload_length, ipv6_header.payload_length);
        // Next Header
        uint8_t next_header = ip_packet.ip_payload[6];
        cnt += sprintf(print_buffer + cnt, "Next Header: [0x%02x] vs. [0x%02x]\n", 
                                           next_header, ipv6_header.next_header);
        // Hop Limit
        uint8_t hop_limit = ip_packet.ip_payload[7];
        cnt += sprintf(print_buffer + cnt, "Hop Limit: [0x%02x] vs. [0x%02x]\n", 
                                           hop_limit, ipv6_header.hop_limit);
        // Source Address
        struct in6_addr ipv6;
        char ipaddr[INET_ADDRSTRLEN];
        memcpy(&ipv6, &ip_packet.ip_payload[8], 16);
        if (NULL == inet_ntop(AF_INET6, &ipv6, &ipaddr[0], INET6_ADDRSTRLEN))
        {
            fprintf(stderr, "Error: %s\n", strerror(errno));
        }
        cnt += sprintf(print_buffer + cnt, "Source IPv6: %s", ipaddr);
        memset(&ipaddr[0], 0, strlen(ipaddr));
        memcpy(&ipv6, &ipv6_header.source_address, IPV6_ADDRESS_SIZE);
        if (NULL == inet_ntop(AF_INET6, &ipv6, &ipaddr[0], INET6_ADDRSTRLEN))
        {
            fprintf(stderr, "Error: %s\n", strerror(errno));
        }
        cnt += sprintf(print_buffer + cnt, " vs. %s\n", ipaddr);
        // Destination 
        struct in6_addr dest_ipv6;
        memset(&ipaddr[0], 0, strlen(ipaddr));
        memcpy(&dest_ipv6, &ip_packet.ip_payload[24], 16);
        if (NULL == inet_ntop(AF_INET6, &dest_ipv6, &ipaddr[0], INET6_ADDRSTRLEN))
        {
            fprintf(stderr, "Error: %s\n", strerror(errno));
        }
        cnt += sprintf(print_buffer + cnt, "Destination IPv6: %s", ipaddr);
        memset(&ipaddr[0], 0, strlen(ipaddr));
        memcpy(&dest_ipv6, &ipv6_header.destination_address, 16);
        if (NULL == inet_ntop(AF_INET6, &dest_ipv6, &ipaddr[0], INET6_ADDRSTRLEN))
        {
            fprintf(stderr, "Error: %s\n", strerror(errno));
        }
        cnt += sprintf(print_buffer + cnt, " vs. %s\n", ipaddr);
    }
    else
    {
        // Packet Contents printing
        cnt += sprintf(print_buffer + cnt, "Raw IPv4 Packet:\n");
        for (size_t i = 0; i < sizeof(ip_packet.ip_payload); ++i)
        {
            cnt += sprintf(print_buffer + cnt, "%02x ", ip_packet.ip_payload[i]);
        }
        cnt += sprintf(print_buffer + cnt, "\n");
    }
    printf("%s", print_buffer);
    // Packet Contents printing
    printf("Raw Packet:\n");
    for (size_t i = 0; i < sizeof(ip_packet.ip_payload); ++i)
    {
        printf("%02x ", ip_packet.ip_payload[i]);
    }
    printf("\n");
}

