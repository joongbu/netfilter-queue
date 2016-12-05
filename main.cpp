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
#include <set>
#include <thread>
using namespace std;
//map<string,int> site;
typedef set<string> d_type;
d_type d_url;
void glog(int option, string err)
{
    google::InitGoogleLogging("netfilter");
    google::SetLogDestination(google::GLOG_INFO, "./errlog");
    LOG(INFO) << "this is info logging";
    LOG(WARNING)<<err;
    VLOG(option) << "I'm printed when you run the program with --v=1 or higher";
    //VLOG(option) << "I'm printed when you run the program with --v=2 or higher";
}
void drop_url()
{
    string url;
    cout<<"input url : ";
    cin>>url;
    d_type::iterator it = d_url.find(url);
    if(it == d_url.end())
    {
    d_url.insert(url);
    cout<<"success input"<<endl;
    }

}

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

/* returns packet id */
string getHostAddr(struct nfq_data *tb)
{
    u_char *_data;
    char *tcp_data;
    tcp_data = (char *)malloc(1500);
    nfq_get_payload(tb, &_data);
    tcp_data  = (char *)(_data + 20 + 32);
    string data(tcp_data);
    smatch result;
    regex pattern("Host: (.*)");
    if (regex_search(data, result, pattern)) {
        return result[1];
    }
        return "";
}

static u_int32_t print_pkt(struct nfq_data *tb)
{
    int id = 0;
    nfqnl_msg_packet_hdr *ph; //packet header
    int ret;
    u_char *data; //tcp packet data
    ph = nfq_get_msg_packet_hdr(tb); //data parse function
    if(ph)
    id = ntohl(ph->packet_id);
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
    {

        string url;
        cout<<"payload_len="<<dec<<ret<<endl;
        //dump((unsigned char*)data,ret);
        url = getHostAddr(tb);
        if(!url.empty())
        cout<<"site :"<<url<<endl;

    }
    fputc('\n', stdout);
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    d_type::iterator it = d_url.find(getHostAddr(nfa));
    cout<<"entering callback\n";
    if(it != d_url.end())
    return nfq_set_verdict(qh, id, NF_DROP, 0 , NULL);  //packet Drop setting

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); //packet determind
}

//this is callback function

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
    //drop_url();
    queue_setting();
}
