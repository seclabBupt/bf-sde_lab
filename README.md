# simple_l3
```shell
第一个shell:设置tofino target接口
cd bf-sde-9.2.0/p4_doc_internal-master
. tools/set_sde.bash
. ../run_tofino_model.sh -p simple_l3

第二个shell:启动交换机配置P4
cd bf-sde-9.2.0/p4_doc_internal-master
. tools/set_sde.bash
. ../run_switchd.sh -p simple_l3

ptf测试缺库

第三个shell:通过bf-runtime（bfshell）添加匹配表
cd bf-sde-9.2.0/p4_doc_internal-master
. tools/set_sde.bash
. ../run_bfshell.sh -b ba-102-labs/01-simple_l3/bfrt_python/setup.py [-i]

第四/五个shell：验证收发
cd bf-sde-9.2.0/p4_doc_internal-master
sudo python ba-102-labs/01-simple_l3/pkt/send.py 192.168.1.1 veth0
sudo python ba-102-labs/01-simple_l3/pkt/recv.py veth1
```

疑问：为什么只能veth0/1之间收发（交换机端口没开？），而且它们本身就是一对veth，没用到交换机。

```shell
root@localhost:~/bf-sde-9.2.0/p4_doc_internal-master# . ../run_tofino_model.sh -p simple_l3
Using SDE /root/bf-sde-9.2.0
Using SDE_INSTALL /root/bf-sde-9.2.0/install
Model using test directory:
Model using port info file: None
Using PATH /root/bf-sde-9.2.0/install/bin:/root/bf-sde-9.2.0/install/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Using LD_LIBRARY_PATH /usr/local/lib:/root/bf-sde-9.2.0/install/lib:
Opening p4 target config file '/root/bf-sde-9.2.0/install/share/p4/targets/tofino/simple_l3.conf' ...
Loaded p4 target config file
 No of Chips is 1
Chip part revision number is 1
Chip 0 SKU: defaulting to BFN77110
Chip 0 SKU setting: sku 0 pipe mode 0
Chip 0 Physical pipes enabled bitmap 0xf
Adding interface veth0 as port 0
Adding interface veth2 as port 1
Adding interface veth4 as port 2
Adding interface veth6 as port 3
Adding interface veth8 as port 4
Adding interface veth10 as port 5
Adding interface veth12 as port 6
Adding interface veth14 as port 7
Adding interface veth16 as port 8
Adding interface veth18 as port 9
Adding interface veth20 as port 10
Adding interface veth22 as port 11
Adding interface veth24 as port 12
Adding interface veth26 as port 13
Adding interface veth28 as port 14
Adding interface veth30 as port 15
Adding interface veth32 as port 16
Adding interface veth250 as port 64
Simulation target: Asic Model
Using TCP port range: 8001-8004
Listen socket created
bind done on port 8001. Listening..
Waiting for incoming connections...
CLI listening on port 8000
```

疑问：Adding interface veth0 as port 0是指在port0上添加veth0吗？

```shell
bf-sde> pm
bf-sde.pm> show -a
```

疑问：端口没开？开了也不行，而且为啥没有port0？这里的port和上面的port是一个概念吗？匹配表里的port是指哪一种概念？

```python
#setup.py
from ipaddress import ip_address

p4 = bfrt.simple_l3.pipe

# This function can clear all the tables and later on other fixed objects
# once bfrt support is added.
def clear_all(verbose=True, batching=True):
    global p4
    global bfrt

    def _clear(table, verbose=False, batching=False):
        if verbose:
            print("Clearing table {:<40} ... ".
                  format(table['full_name']), end='', flush=True)
        try:
            entries = table['node'].get(regex=True, print_ents=False)
            try:
                if batching:
                    bfrt.batch_begin()
                for entry in entries:
                    entry.remove()
            except Exception as e:
                print("Problem clearing table {}: {}".format(
                    table['name'], e.sts))
            finally:
                if batching:
                    bfrt.batch_end()
        except Exception as e:
            if e.sts == 6:
                if verbose:
                    print('(Empty) ', end='')
        finally:
            if verbose:
                print('Done')

        # Optionally reset the default action, but not all tables
        # have that
        try:
            table['node'].reset_default()
        except:
            pass

    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members


    # Clear Match Tables
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)

    # Clear Selectors
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['SELECTOR']:
            _clear(table, verbose=verbose, batching=batching)

    # Clear Action Profiles
    for table in p4.info(return_info=True, print_info=False):
        if table['type'] in ['ACTION_PROFILE']:
            _clear(table, verbose=verbose, batching=batching)

#clear_all()

ipv4_host = p4.Ingress.ipv4_host
ipv4_host.add_with_send(dst_addr=ip_address('192.168.1.1'),   port=1)
ipv4_host.add_with_send(dst_addr=ip_address('192.168.1.2'),   port=2)
ipv4_host.add_with_drop(dst_addr=ip_address('192.168.1.3'))
ipv4_host.add_with_send(dst_addr=ip_address('192.168.1.254'), port=64)

ipv4_lpm =  p4.Ingress.ipv4_lpm
ipv4_lpm.add_with_send(
    dst_addr=ip_address('192.168.1.0'), dst_addr_p_length=24, port=1)
ipv4_lpm.add_with_drop(
    dst_addr=ip_address('192.168.0.0'), dst_addr_p_length=16)
ipv4_lpm.add_with_send(
    dst_addr=ip_address('0.0.0.0'),     dst_addr_p_length=0,  port=64)

bfrt.complete_operations()

# Final programming
print("""
******************* PROGAMMING RESULTS *****************
""")
print ("Table ipv4_host:")
ipv4_host.dump(table=True)
print ("Table ipv4_lpm:")
ipv4_lpm.dump(table=True)
```

```python
#send.py
#!/usr/bin/python

import os
import sys

if os.getuid() !=0:
    print """
ERROR: This script requires root privileges.
       Use 'sudo' to run it.
"""
    quit()

from scapy.all import *

try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "192.168.1.2"

try:
    iface = sys.argv[2]
except:
    iface="veth0"

print "Sending IP packet to", ip_dst
p = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
     IP(src="10.11.12.13", dst=ip_dst)/
     UDP(sport=7,dport=7)/
     "This is a test")
sendp(p, iface=iface)
```

```python
#recv.py
#!/usr/bin/python

import os
import sys

if os.getuid() !=0:
    print """
ERROR: This script requires root privileges.
       Use 'sudo' to run it.
"""
    quit()

from scapy.all import *
try:
    iface=sys.argv[1]
except:
    iface="veth1"

print "Sniffing on ", iface
print "Press Ctrl-C to stop..."
sniff(iface=iface, prn=lambda p: p.show())
```

```shell
11: veth1@veth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 10240 qdisc noqueue state UP group default qlen 1000
    link/ether da:46:1b:12:4d:fc brd ff:ff:ff:ff:ff:ff
```

```p4
/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

/* Table Sizes */
const int IPV4_HOST_SIZE = 65536;

#ifdef USE_ALPM
const int IPV4_LPM_SIZE  = 400*1024;
#else
const int IPV4_LPM_SIZE  = 12288;
#endif

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_TPID:  parse_vlan_tag;
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
#ifdef BYPASS_EGRESS
        ig_tm_md.bypass_egress = 1;
#endif
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    table ipv4_host {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            send; drop;
#ifdef ONE_STAGE
            @defaultonly NoAction;
#endif /* ONE_STAGE */
        }

#ifdef ONE_STAGE
        const default_action = NoAction();
#endif /* ONE_STAGE */

        size = IPV4_HOST_SIZE;
    }

#if defined(USE_ALPM)
    @alpm(1)
    @alpm_partitions(2048)
#endif
    table ipv4_lpm {
        key     = { hdr.ipv4.dst_addr : lpm; }
        actions = { send; drop; }

        default_action = send(64);
        size           = IPV4_LPM_SIZE;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if (!ipv4_host.apply().hit) {
                ipv4_lpm.apply();
            }
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
```

