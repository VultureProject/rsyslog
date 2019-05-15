/* extract_impcap.h
 *
 * This header contains the definition of structures and functions
 * to get Impcap data
 *
 * File begun on 2018-12-5
 *
 * Created by:
 *  - François Bernard (francois.bernard@isen.yncrea.fr)
 *  - Théo Bertin (theo.bertin@isen.yncrea.fr)
 *  - Tianyu Geng (tianyu.geng@isen.yncrea.fr)
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef EXTRACT_IMPCAP_H
#define EXTRACT_IMPCAP_H

#define IMPCAP_METADATA "!impcap"
#define IMPCAP_DATA     "!data"

#include <stdint.h>
#include <json.h>
#include "rsyslog.h"
#include "packets.h"
#include "rsconf.h"

#define SMB_PORT1 139
#define SMB_PORT2 445
#define SMB_PORTS (SMB_PORT1 || SMB_PORT2)
#define HTTP_PORT 80
#define FTP_PORT 21
#define FTP_PORT_DATA 20

typedef struct TCPHdr_ {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    char *flags;
} TCPHdr;

#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_IPV6  0X86DD

typedef struct IPV4Hdr_ {
    char *src;
    char *dst;
    uint8_t hLen;
    uint8_t ttl;
    uint16_t proto;
#define TCP_PROTO 6
} IPV4Hdr;

typedef struct IPV6Hdr_ {
    char *src;
    char *dst;
    uint8_t ttl;
} IPV6Hdr;

typedef struct SMBHdr_ {
    uint32_t version;
    uint32_t ntStatus;
    uint16_t opcode;
    char *flags;
    uint64_t seqNumber;
    uint32_t procID;
    uint32_t treeID;
    uint64_t userID;
} SMBHdr;

struct Packet_ *getImpcapData(smsg_t *);
char *ImpcapDataDecode(char *, uint32_t );
TCPHdr *getTcpHeader(struct json_object *);
IPV4Hdr *getIpv4Header(struct json_object *);
IPV6Hdr *getIpv6Header(struct json_object *);
SMBHdr *getSmbHeader(struct json_object *);


#endif /* EXTRACT_IMPCAP_H */
