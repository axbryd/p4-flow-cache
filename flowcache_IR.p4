#include <v1model.p4>
#include <core.p4>

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define PROTO_UDP 0x11
#define UDP_PORT_VXLAN 4789


header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header vlan_t {
    bit<3> pri;
    bit<1> cfi;
    bit<12> vid;
    bit<16> next_proto;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header vxlan_t {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

//Custom metadata definition
struct local_metadata_t {
    bit<8> ip_proto;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<16> udp_length;
    bit<8> state;
    bit<32> in_flight_cnt; 
    bit<24> vxlan_vni;
    bool update_flow_ctx;
    bit<4> use_flow_key;
    bit<32> outer_ip_dst;
    bit<32> outer_ip_src;
    bit<16> outer_udp_src;
}

struct parsed_headers_t {
    ethernet_t ethernet;
    vlan_t vlan;
    ipv4_t ipv4;
    udp_t udp;
    vxlan_t vxlan;
    ethernet_t inner_ethernet;
    ipv4_t inner_ipv4;
}

parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
    state start {
        transition select(standard_metadata.ingress_port) {
            default: parse_ethernet;
        }
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_VLAN: parse_vlan;
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(hdr.vlan);

        transition select(hdr.vlan.next_proto) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        local_metadata.ip_proto = hdr.ipv4.protocol;
        local_metadata.udp_length = hdr.ipv4.total_len - 16w20;

        transition select(hdr.ipv4.protocol) {
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;

        transition select (hdr.udp.dst_port) {
            UDP_PORT_VXLAN: parse_vxlan;
            default: accept;
        }
    }

    state parse_vxlan {
        packet.extract(hdr.vxlan);

        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
    	packet.extract(hdr.inner_ethernet);

    	transition select(hdr.inner_ethernet.ether_type) {
    		ETHERTYPE_IPV4: parse_inner_ipv4;
    		default: accept;
    	}
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);

        transition accept;
    }
}

#define DC_NETWORK_PORT 0
#define OTR_0_PORT 1
#define NEW 0
#define LEARNT 1

control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    table stage_0 {
    	key = {
    		hdr.vlan.vid[7:0] : exact; 
    		hdr.inner_ipv4.dst_addr : exact;
    	}
    	actions = {
    		NoAction();
    	}
    	default_action = NoAction();
    }

    action decap_and_fwd_to_bm_server(bit<9> output_port, bit<12> vid) {
        hdr.ethernet = hdr.inner_ethernet;

        hdr.vlan.setValid();
        hdr.vlan.pri = 0; 
        hdr.vlan.cfi = 0;
        hdr.vlan.vid = vid;
        hdr.vlan.next_proto = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_VLAN;

        hdr.udp.setInvalid();
        hdr.vxlan.setInvalid();

        hdr.ipv4.setInvalid();

        standard_metadata.egress_spec = output_port;
    }

    action encap_to_dc_network(bit<24> vxlan_vni, 
    						   bit<32> src_ip_addr, 
    						   bit<32> dst_ip_addr, 
    						   bit<16> udp_src_port) {

    	hdr.inner_ethernet.setValid();
    	hdr.inner_ipv4.setValid();
    	hdr.vxlan.setValid();
    	hdr.vlan.setInvalid();

		hdr.inner_ethernet = hdr.ethernet;
        hdr.inner_ipv4 = hdr.ipv4;

        hdr.ethernet.setValid();

        hdr.ethernet.src_addr = 0xbeefbeefbeef;
        hdr.ethernet.dst_addr = 0xdeaddeaddead;
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;

        hdr.inner_ethernet.ether_type = ETHERTYPE_IPV4;

        hdr.ipv4.setValid();
        hdr.ipv4.version = hdr.inner_ipv4.version;
        hdr.ipv4.ihl = hdr.inner_ipv4.ihl;
        hdr.ipv4.dscp = 0;
        hdr.ipv4.ecn = 0;
        hdr.ipv4.total_len = hdr.inner_ipv4.total_len +
        					 14 + 20 + 8 + 8;
        hdr.ipv4.identification = 0x1513;
        hdr.ipv4.flags = 0;
        hdr.ipv4.frag_offset = 0;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = PROTO_UDP;
        hdr.ipv4.dst_addr = dst_ip_addr;
        hdr.ipv4.src_addr = src_ip_addr;
        hdr.ipv4.hdr_checksum = 0;

        local_metadata.udp_length = hdr.ipv4.total_len - 16w20;

        hdr.udp.setValid();

        hdr.udp.src_port = udp_src_port;
        hdr.udp.dst_port = UDP_PORT_VXLAN;
        hdr.udp.len = hdr.ipv4.total_len - 20;
        hdr.udp.checksum = 0;

        hdr.vxlan.flags = 0b00001000;
        hdr.vxlan.reserved = 0;
        hdr.vxlan.vni = vxlan_vni;
        hdr.vxlan.reserved2 = 0;
    }

    action fwd_to_otr() {
        standard_metadata.egress_spec = OTR_0_PORT;
    }

    table from_dc_network {
        key = {hdr.ipv4.dst_addr: exact;}
        actions = {
            decap_and_fwd_to_bm_server;
            NoAction;
        }
        default_action = NoAction;
    }

    apply {
        if (standard_metadata.ingress_port == DC_NETWORK_PORT) {
            from_dc_network.apply();
        } else {
            // flow key creation
            if (standard_metadata.ingress_port == OTR_0_PORT) {
                local_metadata.use_flow_key = 0;
            } else {
                local_metadata.use_flow_key = 1;
            }
            stage_0.apply();

            if (local_metadata.state == NEW) {
            	// fk = {vxlan.reserved2, inner_ipv4.dst_addr}
	            if (standard_metadata.ingress_port == OTR_0_PORT) {
	            	//learn
		            local_metadata.vxlan_vni = hdr.vxlan.vni;

		            local_metadata.outer_ip_dst = hdr.ipv4.dst_addr;
		            // TODO: maybe the source address is unique? can we store it in a global reg?
		            local_metadata.outer_ip_src = hdr.ipv4.src_addr;
		            // TODO: maybe also udp source is always the same?
		            local_metadata.outer_udp_src = hdr.udp.src_port;

		            standard_metadata.egress_spec = DC_NETWORK_PORT;

		            local_metadata.state = LEARNT;

		            if (local_metadata.in_flight_cnt != 0) {
		            	local_metadata.in_flight_cnt = 
		            		local_metadata.in_flight_cnt - 1;
		            }
	        	} else { // fk: {vlan.vdi, ipv4.dst_addr}
	        		fwd_to_otr();
	        		local_metadata.in_flight_cnt = local_metadata.in_flight_cnt + 1;
	        	}
        	} else if (local_metadata.state == LEARNT) {
        		// fk = {vxlan.reserved2, inner_ipv4.dst_addr}
				if (standard_metadata.ingress_port == OTR_0_PORT) {
		            local_metadata.in_flight_cnt = 
		            		local_metadata.in_flight_cnt - 1;
		            standard_metadata.egress_spec = DC_NETWORK_PORT;
	        	} else {  // fk: {vlan.vdi, ipv4.dst_addr}
	        		if (local_metadata.in_flight_cnt == 0) {
		                encap_to_dc_network(local_metadata.vxlan_vni,
		                					local_metadata.outer_ip_src,
		                					local_metadata.outer_ip_dst,
		                					local_metadata.outer_udp_src);
		            } else {
		                fwd_to_otr();
		                local_metadata.in_flight_cnt = 
		                		local_metadata.in_flight_cnt + 1;
		            }
	        	}
        	}
        	
        	local_metadata.update_flow_ctx = true;
        }
    }
}


control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {}
}

control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
    }
}


control VerifyChecksumImpl(inout parsed_headers_t hdr,
                           inout local_metadata_t meta) 
    { apply {} }

control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t meta) 
{ 
	apply {
		update_checksum(hdr.ipv4.isValid(), 
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                16w0,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            }, 
            hdr.ipv4.hdr_checksum, 
            HashAlgorithm.csum16
        );

        update_checksum_with_payload(hdr.udp.isValid(), 
            {   
                hdr.ipv4.src_addr, 
                hdr.ipv4.dst_addr, 
                8w0, 
                hdr.ipv4.protocol, 
                meta.udp_length, 
                hdr.udp.src_port, 
                hdr.udp.dst_port 
            }, 
            hdr.udp.checksum, 
            HashAlgorithm.csum16);
    }
}


V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
