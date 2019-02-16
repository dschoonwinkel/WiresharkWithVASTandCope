/* packet-vast.c
 *
 * Updated routines for vast protocol packet dissection
 * By Mark C. <markc@dgtech.com>
 * Copyright (C) 2018 DG Technologies, Inc. (Dearborn Group, Inc.) USA
 *
 * Routines for vast protocol packet disassembly
 * By Steve Limkemann <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <stdio.h>


#define VAST_PORT 1037
#define VAST_START_FLAG 0x01
#define VAST_END_FLAG 0x02
#define VAST_PRIORITY_FLAG 0x04

#define VAST_START_BITS 0x0A
#define VAST_END_BITS 0x05

static int proto_vast = -1;

static int hf_vast_header = -1;
static gint ett_vast = -1;

static int hf_vast_from = -1;
static int hf_vast_size = -1;
static int hf_vast_msgtype = -1;
static int hf_vast_msggroup = -1;
static int hf_vast_priority = -1;
static int hf_vast_reliable = -1;
static int hf_vast_num_targets = -1;
// static int hf_target_spacer = -1;
static gint ett_targets = -1;
static int hf_vast_target = -1;
static int hf_vast_data = -1;


// static int hf_vast_flags = -1;
// static int hf_vast_startflag = -1;
// static int hf_vast_endflag = -1;
// static int hf_vast_priorityflag = -1;

static const value_string HEADER_MSGTYPE[] = 
{
    {0, "ID_REQUEST"},     // requesting a new ID & public IP detection
    {1, "ID_ASSIGN"},          // assigning a new ID
    {2, "HANDSHAKE"},          // handshake message (notify my hostID)
    {3, "REGULAR"}             // regular message 
};


//Define in VAST.h
static const value_string MSG_TYPE_STRINGS[] = {
    {0, "VON_DISCONNECT"}, // VON's disconnect
    {1, "VON_QUERY"},          // VON's query, to find an acceptor that can take in a joining node
    {2, "VON_HELLO"},          // VON's hello, to let a newly learned node to be mutually aware
    {3, "VON_HELLO_R"},        // VON's hello response
    {4, "VON_EN"},             // VON's enclosing neighbor inquiry (to see if my knowledge of EN is complete)
    {5, "VON_MOVE"},           // VON's move, to notify AOI neighbors of new/current position
    {6, "VON_MOVE_F"},         // VON's move, full notification on AOI
    {7, "VON_MOVE_B"},         // VON's move for boundary neighbors
    {8, "VON_MOVE_FB"},        // VON's move for boundary neighbors with full notification on AOI
    {9, "VON_BYE"},            // VON's disconnecting a remote node
    {10, "VON_NODE"},           // notification of new nodes 

    // internal message # must begin with VON_MAX_MSG as VONpeer is used and share the MessageQueue        
    {30, "MATCHER_CANDIDATE"},               // notify gateway of willingness to be origin matcher
    {31, "MATCHER_INIT"},                   // call up a candidate origin matcher to start up a new world
    {32, "MATCHER_ALIVE"},                  // keepalive messages from matchers to gateway
    {33, "MATCHER_WORLD_INFO"},             // notify a matcher of its world_id
    {34, "NOTIFY_MATCHER"},                 // current matcher notifying client of new current matcher
    {35, "NOTIFY_CLOSEST"},                 // current matcher notifying client of closest alternative matcher
    {36, "JOIN"},                           // client request to gateway for joining a world (find first "origin matcher")
    {37, "LEAVE"},                          // departure of a client
    {38, "PUBLISH"},                        // publish a message         
    {39, "SUBSCRIBE"},                      // send subscription
    {40, "SUBSCRIBE_R"},                    // to reply whether a node has successfully subscribed (VON node joined)        
    {41, "SUBSCRIBE_TRANSFER"},             // transfer a subscription to a neighbor matcher
    {42, "SUBSCRIBE_UPDATE"},               // update of a subscription to neighboring matchers
    {43, "MOVE"},                           // position update to normal nodes
    {44, "MOVE_F"},                         // full update for an AOI region        
    {45, "NEIGHBOR"},                       // send back a list of known neighbors
    {46, "NEIGHBOR_REQUEST"},               // request full info for an unknown neighbor
    {47, "SEND"},                           // send a particular message to certain targets        
    {48, "ORIGIN_MESSAGE"},                 // messsage to origin matcher
    {49, "MESSAGE"},                        // deliver a message to a node
    {50, "SUBSCRIBE_NOTIFY"},               // client notifying a relay of its subscription
    {51, "STAT"},                           // sending statistics for gateway to record
    {52, "SYNC_CLOCK"},                     // synchronize logical clock with gateway

    // Relay-specific messages
    {53, "REQUEST"},                // request for relays
    {54, "RELAY"},                  // notifying an existing relay        
    {55, "PING"},                   // query to measure latency
    {56, "PONG"},                   // reponse to PING
    {57, "PONG_2"},                 // reponse to PONG
    {58, "RELAY_QUERY"},            // find closest relay
    {59, "RELAY_QUERY_R"},          // response to closest relay query
    {60, "RELAY_JOIN"},             // attach to the physically closest relay
    {61, "RELAY_JOIN_R"}           // response to JOIN request
};

unsigned int extract_startbits(unsigned int header_int) {
    unsigned int bitmask = 0x0000000f;
    unsigned int startbits = header_int & bitmask;

    return startbits;
}

unsigned int extract_msgtype(unsigned int header_int) {
    unsigned int bitmask = 0x00000030;
    unsigned msgtype = header_int & bitmask;
    msgtype = msgtype >> 4;

    return msgtype;
}

unsigned int extract_packet_size(unsigned int header_int) {
    unsigned int bitmask = 0x0fffffC0;
    header_int = header_int & bitmask;
    header_int = header_int >> 6;

    return header_int;
}

unsigned int extract_endbits(unsigned int header_int) {
    unsigned int bitmask = 0xf0000000;
    unsigned int endbits = header_int & bitmask;
    endbits = endbits >> 28;

    return endbits;
}

static gboolean test_vast(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{

    guint32 header_int = -1;

    if (tvb_captured_length(tvb) < 4)
        return FALSE;

    header_int = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);

    if (extract_startbits(header_int) != VAST_START_BITS)
        return FALSE;

    if (extract_endbits(header_int) != VAST_END_BITS)
        return FALSE;

    return TRUE;

}

static gboolean
dissect_vast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    gint offset = 0;
    gint starting_offset = 0;
    tvbuff_t *next_tvb;
    guint8 num_targets = -1;
    guint32 header_int = -1;
    guint32 header_startbits = -1;
    guint32 header_msgtype = -1;
    guint32 header_packet_size = -1;
    guint32 header_endbits = -1;
    guint32 data_size = -1;
    guint32 data_length_left = -1;
    proto_item *ti, *theader;
    proto_tree *targets_tree;

    // static const int* bits[] = {
    //     &hf_vast_startflag,
    //     &hf_vast_endflag,
    //     &hf_vast_priorityflag
    // };

    // If this is not a VAST packet, stop dissecting
    if (!test_vast(pinfo, tvb, offset, data))
        return FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VAST");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    for (int i = 0; tvb_reported_length_remaining(tvb, offset) > 4; i++) {

        starting_offset = offset;

        ti = proto_tree_add_item(tree, proto_vast, tvb, 0, -1, ENC_NA);

        proto_tree *vast_tree = proto_item_add_subtree(ti, ett_vast);

        header_int = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
        // printf("Header int %u\n", header_int);
        header_startbits = extract_startbits(header_int);
        header_msgtype = extract_msgtype(header_int);
        header_packet_size = extract_packet_size(header_int);
        header_endbits = extract_endbits(header_int);
        // printf("Header packet size %u\n", header_packet_size);

        theader = proto_tree_add_item(vast_tree, hf_vast_header, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_item_set_text(theader, "Header startbits %X, msgtype %s, size %d, endbits %X", 
            header_startbits, val_to_str(header_msgtype, HEADER_MSGTYPE, "Unknown"), header_packet_size, header_endbits);

        proto_tree_add_item(vast_tree, hf_vast_from, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item_ret_uint(vast_tree, hf_vast_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &data_size);
        offset += 4;
        proto_tree_add_item(vast_tree, hf_vast_msgtype, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(vast_tree, hf_vast_msggroup, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(vast_tree, hf_vast_priority, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(vast_tree, hf_vast_reliable, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        num_targets = tvb_get_guint8(tvb, offset);
        // printf("num_targets %d\n", num_targets);
        proto_tree_add_item(vast_tree, hf_vast_num_targets, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        targets_tree = proto_item_add_subtree(ti, ett_targets);

        int j = 0;
        for (j = 0; j < num_targets; j++) {
            proto_tree_add_item(targets_tree, hf_vast_target, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
        }    

        //Header size is not part of header_packet_size and should therefore be removed -4 bytes from offset
        data_length_left = starting_offset + header_packet_size - (offset - 4);
        // printf("bytes left: %d\n", data_length_left);
        if (data_length_left > 0) {
            proto_tree_add_item(vast_tree, hf_vast_data, tvb, offset, data_length_left, ENC_NA);
        }

        if (data_length_left != data_size) {
            printf("Something strange is happening: data_length_left: %d ; data_size: %d\n", data_length_left, data_size);
        }

        //Account for the header size += 4 bytes
        offset = starting_offset + header_packet_size + 4;
    }

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}



void
proto_register_vast(void)
{
    static hf_register_info hf[] = {
        { &hf_vast_header,
            { "VAST Header", "vast.header",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vast_from,
            { "VAST from", "vast.from",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vast_size,
            { "VAST data size", "vast.size",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vast_msgtype,
            { "VAST msgtype", "vast.msgtype",
            FT_UINT16, BASE_DEC,
            VALS(MSG_TYPE_STRINGS), 0x0,
            NULL, HFILL }
        },
        { &hf_vast_msggroup,
            { "VAST msggroup", "vast.msggroup",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vast_priority,
            { "VAST priority", "vast.priority",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vast_reliable,
            { "VAST reliable", "vast.reliable",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_vast_num_targets,
            { "VAST num targets", "vast.num_targets",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vast_target,
            { "VAST target", "vast.target",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vast_data,
            { "VAST data", "vast.data",
            FT_BYTES, SEP_SPACE,
            NULL, 0x0,
            NULL, HFILL }
        },


    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_vast,
        &ett_targets
    };

    proto_vast = proto_register_protocol (
        "VAST Protocol", /* name       */
        "VAST",      /* short name */
        "vast"       /* abbrev     */
        );

    proto_register_field_array(proto_vast, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vast(void)
{
    static dissector_handle_t vast_handle;

    
    heur_dissector_add("tcp", dissect_vast, "VAST over TCP",
     "VAST_tcp", proto_vast, HEURISTIC_ENABLE);
    heur_dissector_add("udp", dissect_vast, "VAST over UDP",
     "VAST_udp", proto_vast, HEURISTIC_ENABLE);

    // vast_handle = create_dissector_handle(dissect_vast, proto_vast);
    // dissector_add_uint("udp.port", VAST_PORT, vast_handle);
    // dissector_add_uint("tcp.port", VAST_PORT, vast_handle);
}


// 