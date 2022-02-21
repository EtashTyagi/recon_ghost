#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/socket.h>
#include <net/netfilter/nf_conntrack.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Etash Tyagi");
MODULE_DESCRIPTION("Simple LKM firewall to circumvent and log nmap recon techniques.");

/**
 *        Module:   recon_ghost
 *        Desc:     Simple LKM firewall to circumvent and log nmap and other recon techniques.
 *
 *        help:
 *          compile:        Run '[sudo] make' to compile the module.
 *          run:            After compiling run '[sudo] make run' to run.
 *          stop:           To stop a running module run '[sudo] make stop'.
 *          logs:           To view syslogs run '[sudo] make syslog [REGEX=...]'.
 *                          edit REGEX for specifity, currently it shows all recognized scans.
 *        powers:
 *          1. TCP_ACK:     This is triggered when TCP packet containing [ACK], is received
 *                          but the connection is not ESTABLISED resistant to payloads and
 *                          additional headers. nmap -sA and -sW shows all filtered.
 *          2. TCP_XMAS:    This is triggered when TCP packet containing [FIN, PSH, URG]
 *                          is received. Prevents TCP RFC loophole exploitation (see 5.).
 *                          Resistant to payloads. nmap -sX shows open|filtered for all.
 *          3. TCP_FIN:     This is triggerred when TCP packet containing [FIN] is received
 *                          Prevents TCP RFC loophole exploitation (see 5.). Resistant
 *                          to payloads. nmap -sF shows open|filtered for all.
 *          4. TCP_NULL:    Triggered when TCP packet containing no flags is received.
 *                          Prevents TCP RFC loophole exploitation (see 5.). Resistant
 *                          to payloads. nmap -sN shows open|filtered for all.
 *          5. TCP_RFC_O    Triggered when TCP packet does not contain atleast one of
 *                          SYN, RST or ACK, and not 2-4. By default linux replies
 *                          RST to closed ports, while ignores open. Here, we drop all.
 *          6. TCP_SYN:     Triggered either when a 3-way tcp connection is ended by client
 *                          using rst or when server sends RST. when server sends [RST], 
 *                          it is replaced by a fake [ACK, SYN] so that the attacker thinks 
 *                          that the port is open. Resistant to payloads. nmap 
 *                          (default and -sS) shows open for all ports.
 *                          LOG works for even -sT and manual scans on un open ports.
 *        note:
 *                This module requires conntrack to be enabled. This is on by default on
 *                some kernels, but I have used iptables to enable it on run (kind of dumb,
 *                will figure out alternative later.). The rule is deleted when the module
 *                stopped using '[sudo] make stop'
 */

enum scan_type {
    NONE,           // Safe packet
    TCP_ACK,        // {DROP & LOG}
    TCP_XMAS,       // {DROP & LOG}
    TCP_FIN,        // {DROP & LOG}
    TCP_NULL,       // {DROP & LOG}
    TCP_RFC_O,      // {DROP & LOG}
    TCP_SYN,        // {LOG & PRETEND_OPEN}
};

/* Main Incoming Firewall Logic */
enum scan_type find_scan_type_in(struct sk_buff *skb) {
    /* variable declaration */
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct nf_conn *ct;
    enum ip_conntrack_info ctinfo;
    u_int32_t seq, ack;

    iph = ip_hdr(skb);  // Get ip header

    if (iph->protocol == IPPROTO_TCP) {     // TCP
        ct = nf_ct_get(skb, &ctinfo);       // Get Conntrack
        tcph = tcp_hdr(skb);                // Get tcp header
        if (ct == NULL) {                   // Invalid connection
            if (!tcph->ack && !tcph->rst && !tcph->syn) {       // TCP RFC exploit

                /* 2. XMAS */
                if (tcph->fin && tcph->psh && tcph->urg) {
                    printk(KERN_INFO "TCP_XMAS:  src: %pI4\t;\tdport: %u\n",
                                &iph->saddr, ntohs(tcph->dest));
                    return TCP_XMAS;
                }

                /* 3. FIN */
                if (tcph->fin && !tcph->psh && !tcph->urg) {
                    printk(KERN_INFO "TCP_FIN:   src: %pI4\t;\tdport: %u\n",
                                &iph->saddr, ntohs(tcph->dest));
                    return TCP_FIN;
                }

                /* 4. NULL */
                if (!tcph->fin && !tcph->psh && !tcph->urg) { // NULL
                    printk(KERN_INFO "TCP_NULL:  src: %pI4\t;\tdport: %u\n",
                                &iph->saddr, ntohs(tcph->dest));
                    return TCP_NULL;
                }

                /* 5. TCP RFC Others */
                printk(KERN_INFO "TCP_RFC_O: src: %pI4\t;\tdport: %u\n",
                            &iph->saddr, ntohs(tcph->dest));
                return TCP_RFC_O;
            }
            return NONE;    // Unknown problem in connection, don't mark as scan
        }

        seq = ct->proto.tcp.last_seq;   // last packet sequence
        ack = ct->proto.tcp.last_ack;   // last ack sequence

        /* 1. ACK without connection */
        if (ctinfo == IP_CT_NEW && tcph->ack) {
            printk(KERN_INFO "TCP_ACK:   src: %pI4\t;\tdport: %u\n",
                        &iph->saddr, ntohs(tcph->dest));
            return TCP_ACK;
        }

        /* 6. SYN when port is actually open, seq and ack of prev packets is 0
              when reset during 3-way handshake by client. */
        if (ctinfo == IP_CT_ESTABLISHED && tcph->rst && ack == 0 && seq == 0) {
            printk(KERN_INFO "TCP_SYN:   src: %pI4\t;\tdport: %u\n",
                        &iph->saddr, ntohs(tcph->dest));
            return TCP_SYN;
        }
    }
    return NONE; /* Safe packet according to rules */
}

/* netfilter hook for incoming connections */
static unsigned int hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    enum scan_type st;

    if (!skb) return NF_ACCEPT;                // IDK
    st = find_scan_type_in(skb);               // find scan type from above rules

    if (st == NONE) return NF_ACCEPT;          // If safe packet accept

    if (st == TCP_FIN || st == TCP_NULL || st == TCP_XMAS || st == TCP_RFC_O || st == TCP_ACK)
        return NF_DROP;                        // If ack or RFC exploit drop

    return NF_ACCEPT;                          // For non safe, non dropping
}

/* Main Outgoing Firewall Logic */
enum scan_type find_scan_type_out(struct sk_buff *skb) {
    /* variable declaration */
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct nf_conn *ct;
    enum ip_conntrack_info ctinfo;
    u_int32_t seq, ack;
    iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_TCP) {     // TCP
        ct = nf_ct_get(skb, &ctinfo);   // Get conntrack
        if (ct == NULL) return NONE;    // Bad connection

        tcph = tcp_hdr(skb);            // Get tcp header
        seq = ct->proto.tcp.last_seq;   // Previous packet seq
        ack = ct->proto.tcp.last_ack;   // Previous packet ack

        /* 6. SYN when port is closed, seq and ack of prev packet is 0
               when the server sends RST in 3-way handshake. */
        if (seq == 0 && ack == 0 && tcph->rst) {
            printk(KERN_INFO "TCP_SYN:   src: %pI4\t;\tdport: %u\n",
                        &iph->saddr, ntohs(tcph->source));
            printk(KERN_INFO "[info] TCP_SYN: Pretending To Be Open\n");

            tcph->rst = 0;
            tcph->syn = 1;
            tcph->ack = 1;
            return TCP_SYN;
        }
    }
    return NONE; // Safe packet according to rules
}

/* netfilter hook for outgoing connections */
static unsigned int hook_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    enum scan_type st;

    if (!skb) return NF_ACCEPT;             // IDK
    st = find_scan_type_out(skb);           // find scan type according to above rules

    if (st == NONE) return NF_ACCEPT;       // Accept if not a scan packet
    if (st == TCP_SYN) return NF_ACCEPT;    // Accept if TCP_SYN (all open)
    return NF_ACCEPT;                       // Accept for others
}

// Register Netfilter hooks when module initialized
static struct nf_hook_ops *nfho_in = NULL;
static struct nf_hook_ops *nfho_out = NULL;
static int __init test_init(void) {
    nfho_in = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    nfho_out = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

    nfho_in->hook = (nf_hookfn *) hook_in;          // inbcomming netfilter
    nfho_in->hooknum = NF_INET_LOCAL_IN;            // ingress packet
    nfho_in->pf = PF_INET;                          // IPv4
    nfho_in->priority = NF_IP_PRI_CONNTRACK + 150;  // To Allow conntrack
    nf_register_net_hook(&init_net, nfho_in);       // Register


    nfho_out->hook = (nf_hookfn *) hook_out;        // outgoing netfilter
    nfho_out->hooknum = NF_INET_LOCAL_OUT;          // Egress packet
    nfho_out->pf = PF_INET;                         // IPv4
    nfho_out->priority = NF_IP_PRI_CONNTRACK + 150; // To Allow conntrack
    nf_register_net_hook(&init_net, nfho_out);      // Register
    return 0;
}

// Unregister Netfilter hooks on module exit
static void __exit test_exit(void) {
    nf_unregister_net_hook(&init_net, nfho_in);
    kfree(nfho_in);

    nf_unregister_net_hook(&init_net, nfho_out);
    kfree(nfho_out);
}

module_init(test_init);
module_exit(test_exit);

