#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    /* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <glog/logging.h> //google log header
#include <regex> //seach host
using namespace std;
/* returns packet id */
string getHostAddr(char*_data)
{
    string data(_data);
    smatch result;
    regex pattern("Host: .*");

    if (regex_search(data, result, pattern)) {
        return result[1];
    }
    cout<<"no search"<<endl;
    return "";

}
void glog(int option, string err)
{
    google::InitGoogleLogging("netfilter");
    google::SetLogDestination(google::GLOG_INFO, "./errlog");
    LOG(INFO) << "this is info logging";
    LOG(WARNING)<<err;
    VLOG(option) << "I'm printed when you run the program with --v=1 or higher";
    //VLOG(option) << "I'm printed when you run the program with --v=2 or higher";
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    nfqnl_msg_packet_hdr *ph; //packet header
    nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    u_char *data; //tcp packet data
    ph = nfq_get_msg_packet_hdr(tb); //data parse function
    if(ph)
    {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }
    hwph = nfq_get_packet_hw(tb);//print hw_addr
    if (hwph)
    {
        int i, hlen = ntohs(hwph->hw_addrlen);
        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }
    mark = nfq_get_nfmark(tb);
    if (mark)
        cout<<"mark="<<hex<<mark;
    
    ifi = nfq_get_indev(tb);
    if (ifi)
        cout<<"indev="<<hex<<ifi;
    
    ifi = nfq_get_outdev(tb);
    if (ifi)
        cout<<"outdev="<<hex<<ifi;
    ifi = nfq_get_physindev(tb);
    if (ifi)
        cout<<"physindev="<<hex<<ifi;
    
    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        cout<<"physoutdev="<<hex<<ifi;
    
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {
        cout<<"payload_len="<<ret<<endl;
        for(int i = 0 ; i <= ret ; i++)
            cout<<data[i];
        cout<<endl;
        //data is tcp data

    }
    fputc('\n', stdout);
    
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    cout<<"entering callback\n";
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

//this is callback function
void dump(unsigned char*buf, size_t len)
{
    size_t i;
    
    for (i = 0; i < len; i++) {
        printf("%02x ", *buf++);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
    fflush(stdout);
}
void queue_setting()
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    cout<<"opening library handle\n";
    
    h = nfq_open(); // return struct nfq_handle
    if (!h) {
        glog(1,"error during nfq_open()\n");
        exit(1);
    }
    
    cout<<"unbinding existing nf_queue handler for AF_INET (if any)\n";
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        glog(1,"error during nfq_unbind_pf()\n");
        exit(1);
    }
    
    cout<<"binding nfnetlink_queue as nf_queue handler for AF_INET\n";
    if (nfq_bind_pf(h, AF_INET) < 0) {
        glog(1,"error during nfq_bind_pf()\n");
        exit(1);
    }
    
    cout<<"binding this socket to queue '0'\n";
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        glog(1,"error during nfq_create_queue()\n");
        exit(1);
    }
    
    cout<<"setting copy_packet mode\n";
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        glog(1,"can't set packet_copy mode\n");
        exit(1);
    }
    
    fd = nfq_fd(h);
    
    while(1)
    {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
        {
            cout<<"pkt received\n"<<endl;
            dump((unsigned char*)buf, rv); //print binary array
            nfq_handle_packet(h, buf, rv); //handle a packet received from the nfqueue subsystem
            continue;
        }
        
        /* if your application is too slow to digest the packets that
       * are sent from kernel-space, the socket buffer that we use
       * to enqueue packets may fill up returning ENOBUFS. Depending
       * on your application, this error may be ignored. Please, see
       * the doxygen documentation of this library on how to improve
       * this situation.
       */

        if (rv < 0 && errno == ENOBUFS)
        {
            cout<<"losing pacekt!!\n";
            continue;
        }
        perror("recv failed");
        glog(1,"recv failed\n");
        break;
    }
    
    cout<<"unbinding from queue 0\n";
    nfq_destroy_queue(qh);
    
    cout<<"closing library handle\n";
    nfq_close(h);
    
    exit(0);
}

int main(int argc, char **argv)
{
    queue_setting();
}
