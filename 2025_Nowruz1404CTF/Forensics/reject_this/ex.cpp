#include <pcap.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("reject_this.pcapng", errbuf);
    if (!handle)
        return 1;
    
    std::vector<u_char> data_buffer;
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    while (pcap_next_ex(handle, &header, &packet) == 1) {
        const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + 14);
        const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(packet + 14 + (ip_header->ip_hl * 4));
        
        if (header->len != 54) continue;
        if (ip_header->ip_p != IPPROTO_TCP) continue;
        if (!(tcp_header->syn)) continue;
        
        uint32_t raw_seq = tcp_header->th_seq;
        const u_char* seq_bytes = reinterpret_cast<const u_char*>(&raw_seq);
        
        data_buffer.insert(data_buffer.end(), seq_bytes, seq_bytes + 4);
    }

    pcap_close(handle);

    std::ofstream output_file("flag.png", std::ios::binary);
    if (!output_file) 
        return 1;
    
    output_file.write(reinterpret_cast<const char*>(data_buffer.data()), data_buffer.size());
    output_file.close();
    
    return 0;
}
