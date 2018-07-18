#include "config.h"

#include <epan/packet.h>
#include <stdint.h>

#define COPE_PACKET_TYPE 0x7123
#define COPE_START_FLAG 0x01
#define COPE_END_FLAG        0x02
#define COPE_PRIORITY_FLAG   0x04

#define CONTROL_PKT_TYPE 0
#define NATIVE_PKT_TYPE 3
#define ENCODED_PKT_TYPE 4

static const char* packet_types[] = {"Control", "Report", "ACK", "Native", "Encoded"};

struct EncodedHeader {
    uint64_t pkt_id;
    uint8_t nexthop[6];
};

struct ReportHeader {
    uint8_t src_ip[4];
    uint32_t last_pkt;
    uint8_t bit_map;
};

struct ACKHeader {
    uint8_t neighbour[6];
    uint32_t last_ack;
    uint8_t ack_map;
};

struct COPE_header {
    uint16_t encoded_num;
    struct EncodedHeader *encoded_pkts;
    uint16_t report_num;
    struct ReportHeader *reports;
    uint16_t ack_num;
    uint32_t local_pkt_seq_num;
    struct ACKHeader * acks;
    uint16_t checksum;      
};

static int proto_cope = -1;
static dissector_handle_t ipv4_handle = -1;
static gint ett_cope = -1;
static gint ett_encoded_packets = -1;

static int hf_enc_num = -1;
static int hf_enc_spacer = -1;
static int hf_pkt_id = -1;
static int hf_nexthop = -1;

static int hf_report_num = -1;
static int hf_src_ip = -1;
static int hf_last_pkt = -1;
static int hf_bit_map = -1;

static int hf_ack_num = -1;
static int hf_local_pkt_seq_num = -1;
static int hf_neighbour = -1;
static int hf_last_ack = -1;
static int hf_ack_map = -1;
static int hf_checksum = -1;

// static int hf_cope_flags = -1;
// static int hf_cope_startflag = -1;
// static int hf_cope_endflag = -1;
// static int hf_cope_priorityflag = -1;

// static int hf_cope_sequenceno = -1;
// static int hf_cope_initialip = -1;

// static const value_string packettypenames[] = {
//     { 1, "Initialise" },
//     { 2, "Terminate" },
//     { 3, "Data" },
//     { 0, NULL }
// };

static int
dissect_cope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    tvbuff_t *next_tvb;
    guint16 enc_num = -1;
    guint16 report_num = -1;
    guint16 ack_num = -1;
    proto_item *ti, *tf;
    proto_tree *report_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "COPE");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    ti = proto_tree_add_item(tree, proto_cope, tvb, 0, -1, ENC_NA);

    proto_tree *cope_tree = proto_item_add_subtree(ti, ett_cope);
    enc_num = tvb_get_guint16(tvb, 0, ENC_BIG_ENDIAN);
    // printf("enc_num %d\n", enc_num);
    proto_tree_add_item(cope_tree, hf_enc_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    int i = 0;
    for (i = 0; i < enc_num; i++) {
        // printf("Looping");
        tf = proto_tree_add_item(cope_tree, hf_enc_spacer, tvb, offset, -1, ENC_NA);
        proto_item_set_text(tf, "Enc Pkt %d", i+1);
        report_tree = proto_item_add_subtree(tf, ett_encoded_packets);
        proto_tree_add_item(report_tree, hf_pkt_id, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(report_tree, hf_nexthop, tvb, offset, 6, ENC_BIG_ENDIAN);
        offset += 6;
    }

    report_num = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(cope_tree, hf_report_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    for (i = 0; i < report_num; i++) {
        // printf("Looping");
        tf = proto_tree_add_item(cope_tree, hf_enc_spacer, tvb, offset, -1, ENC_NA);
        proto_item_set_text(tf, "Report %d", i+1);
        report_tree = proto_item_add_subtree(tf, ett_encoded_packets);
        proto_tree_add_item(report_tree, hf_src_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(report_tree, hf_last_pkt, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(report_tree, hf_bit_map, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    ack_num = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(cope_tree, hf_ack_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(cope_tree, hf_local_pkt_seq_num, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    for (i = 0; i < ack_num; i++) {
        // printf("Looping");
        tf = proto_tree_add_item(cope_tree, hf_enc_spacer, tvb, offset, -1, ENC_NA);
        proto_item_set_text(tf, "ACK %d", i+1);
        report_tree = proto_item_add_subtree(tf, ett_encoded_packets);
        proto_tree_add_item(report_tree, hf_neighbour, tvb, offset, 6, ENC_BIG_ENDIAN);
        offset += 6;
        proto_tree_add_item(report_tree, hf_last_ack, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(report_tree, hf_ack_map, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    proto_tree_add_item(cope_tree, hf_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;    

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    // Set display details
    int packet_type = -1;
    if (enc_num == 0) {
        packet_type = CONTROL_PKT_TYPE;
    }
    else if (enc_num == 1) {
        packet_type = NATIVE_PKT_TYPE;
    }
    else if (enc_num >= 2) {
        packet_type = ENCODED_PKT_TYPE;
    }
    
    proto_item_set_text(ti, "COPE %s: Enc Num %d, Report Num %d, ACK Num %d", packet_types[packet_type], enc_num, report_num, ack_num);

    if (enc_num > 0) {
        call_dissector(ipv4_handle, next_tvb, pinfo, tree);
    }
    else {
        call_data_dissector(next_tvb, pinfo, tree);   
    }

    return tvb_captured_length(tvb);
}


void
proto_register_cope(void)
{
    static hf_register_info hf[] = {
        { &hf_enc_num,
            { "COPE Enc Num", "cope.enc_num",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_enc_spacer,
            { "Enc Pkt ", "cope.enc_spacer",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pkt_id,
            { "Enc Pkt ID", "cope.encoded.pkt_id",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nexthop,
            { "Enc Nexthop", "cope.encoded.nexthop",
            FT_ETHER, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_report_num,
            { "COPE Report Num", "cope.report_num",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_src_ip,
            { "Report Src ip", "cope.report.src_ip",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_last_pkt,
            { "Report last packet", "cope.report.last_pkt",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bit_map,
            { "Report bit map", "cope.report.bit_map",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ack_num,
            { "COPE ACK Num", "cope.ack_num",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_local_pkt_seq_num,
            { "COPE Local pkt seq num", "cope.local_pkt_seq_num",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_neighbour,
            { "ACK Neighbour", "cope.ack.neighbour",
            FT_ETHER, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_last_ack,
            { "ACK Last ACK", "cope.ack.last_ack",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ack_map,
            { "ACK map", "cope.ack.ack_map",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_checksum,
            { "COPE Checksum", "cope.checksum",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        }
        // { &hf_cope_flags,
        //     { "COPE PDU Flags", "cope.flags",
        //     FT_UINT8, BASE_HEX,
        //     NULL, 0x0,
        //     NULL, HFILL }
        // },
        // { &hf_cope_sequenceno,
        //     { "COPE PDU Sequence Number", "cope.seqn",
        //     FT_UINT16, BASE_DEC,
        //     NULL, 0x0,
        //     NULL, HFILL }
        // },
        // { &hf_cope_startflag,
        //     { "COPE PDU Start Flags", "cope.flags.start",
        //     FT_BOOLEAN, 8,
        //     NULL, COPE_START_FLAG,
        //     NULL, HFILL }
        // },
        // { &hf_cope_endflag,
        //     { "COPE PDU End Flags", "cope.flags.end",
        //     FT_BOOLEAN, 8,
        //     NULL, COPE_END_FLAG,
        //     NULL, HFILL }
        // },
        // { &hf_cope_priorityflag,
        //     { "COPE PDU Priority Flags", "cope.flags.priority",
        //     FT_BOOLEAN, 8,
        //     NULL, COPE_PRIORITY_FLAG,
        //     NULL, HFILL }
        // },
        // { &hf_cope_initialip,
        //     { "COPE PDU Initial IP", "cope.initialip",
        //     FT_IPv4, BASE_NONE,
        //     NULL, 0x0,
        //     NULL, HFILL }
        // }
        // { &hf_cope_pdu_type,
        //     { "COPE Enc Num", "cope.enc_num",
        //     FT_UINT16, BASE_DEC,
        //     NULL, 0x0,
        //     NULL, HFILL }
        // },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_cope,
        &ett_encoded_packets
    };

    proto_cope = proto_register_protocol (
        "COPE Protocol", /* name       */
        "COPE",      /* short name */
        "cope"       /* abbrev     */
        );

    proto_register_field_array(proto_cope, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cope(void)
{
    static dissector_handle_t cope_handle;

    cope_handle = create_dissector_handle(dissect_cope, proto_cope);
    dissector_add_uint("ethertype", COPE_PACKET_TYPE, cope_handle);

    ipv4_handle = find_dissector_add_dependency("ip", proto_cope);
}
