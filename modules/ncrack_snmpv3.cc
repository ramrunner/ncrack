/***************************************************************************
 * ncrack_snmpv3.cc -- ncrack module for SNMPv3 (user enumeration)
 * Created by dsp
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2019 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed Nmap technology into proprietary      *
 * software, we sell alternative licenses (contact sales@nmap.com).        *
 * Dozens of software vendors already license Nmap technology such as      *
 * host discovery, port scanning, OS detection, version detection, and     *
 * the Nmap Scripting Engine.                                              *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, the Nmap Project grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * The Nmap Project has permission to redistribute Npcap, a packet         *
 * capturing driver and library for the Microsoft Windows platform.        *
 * Npcap is a separate work with it's own license rather than this Nmap    *
 * license.  Since the Npcap license does not permit redistribution        *
 * without special permission, our Nmap Windows binary packages which      *
 * contain Npcap may not be redistributed without special permission.      *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, we are happy to help.  As mentioned above, we also *
 * offer an alternative license to integrate Nmap into proprietary         *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing support and updates.  They also fund the continued         *
 * development of Nmap.  Please email sales@nmap.com for further           *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify            *
 * otherwise) that you are offering the Nmap Project the unlimited,        *
 * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
 * will always be available Open Source, but this is important because     *
 * the inability to relicense code has caused devastating problems for     *
 * other Free Software projects (such as KDE and NASM).  We also           *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/

#include "ncrack.h"
#include "nsock.h"
#include "Service.h"
#include "modules.h"

#define SNMP_TIMEOUT 20000
#define SNMP_MAXMSG 1500

#define T_BOOLEAN	0x01
#define T_INTEGER	0x02
#define T_BIT_STRING	0x03
#define T_OCTET_STRING	0x04
#define T_DISPLAYSTRING	0x04
#define T_NULL	0x05
#define T_OBJECT_IDENTIFIER	0x06
#define T_SEQUENCE	0x30
#define T_IP_ADDRESS	0x40
#define T_COUNTER32	0x41
#define T_GAUGE32	0x42
#define T_TIME_TICKS	0x43
#define T_OPAQUE	0x44
#define T_NSAP_ADDRESS	0x45
#define T_COUNTER64	0x46
#define T_UINTEGER32	0x47

#define MSGID_MAX 832 
#define MSGID_MIN 432


extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);
static void snmpv3_free(Connection *con);

static int snmpv3_loop_read(nsock_pool nsp, Connection *con);

/* In SNMPV3_INIT we send a get-request message.
 * In SNMPV3_INIT_REPLY we receive a response that reveals the msgAuthoritativeEngineID
 * In SNMPV3_USERNAME we send a message using the above id and a test username
 * In SNMPV3_USERNAME_REPLY we receive a response indicating if the username exists.
 */
enum states { SNMPV3_INIT, SNMPV3_INIT_REPLY, SNMPV3_USERNAME, SNMPV3_USERNAME_REPLY };

typedef struct type_len {
	uint8_t t;
	uint8_t l;
} __attribute__((__packed__)) type_len;

typedef struct snmp_version {
	type_len tl;
	uint8_t v;
} __attribute__((__packed__)) m_vers;

typedef struct snmp_globaldata {
	type_len tl;
	struct msg_id {
		type_len tl;
		uint32_t id;
	} __attribute__((__packed__)) m_id;
} __attribute__((__packed__)) m_globaldata;

/*
 * attempting to map snmpv3 message format from 
 * https://www.rfc-editor.org/rfc/rfc3412#page-19
 */
typedef struct snmp_v3_msg {
	type_len tl;
	m_vers v;
	m_globaldata g;
	/* security parameter bytes */
	/* PDU bytes */
} __attribute__((__packed__)) m_v3;


typedef struct snmp_get_data {
	u_char data[64];

	snmp_get_data(uint32_t seq) {
		uint32_t seqbytes = htonl(seq);
		u_char staticmsg[65] = "\x30\x3e\x02\x01\x03\x30\x11\x02\x04\x40\xa3\x72\x4e\x02\x03\x00" \
"\xff\xe3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\x00\x02\x01" \
"\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00\x30\x14\x04\x00\x04\x00" \
"\xa0\x0e\x02\x04\x33\x7b\x1b\x53\x02\x01\x00\x02\x01\x00\x30\x00";
		memcpy(data, staticmsg, 64);
		memcpy(data+28, &seqbytes, 4);
	}
} snmp_get_data;

typedef struct snmp_username_msg {
	u_char data[1024];
	uint8_t len = 0;
	snmp_username_msg(uint32_t msgid) {
		uint32_t id = htonl(msgid);
		// since this message is > 127 bytes the ASN.1 encodes the len
		// in 2 bytes. the first being 0x81 and the second the actual length (138).
		u_char staticmsg[139] = "\x30\x81\x87\x02\x01\x03\x30\x11\x02\x04\x40\xa3\x72\x4d\x02\x03" \
"\x00\xff\xe3\x04\x01\x07\x02\x01\x03\x04\x3b\x30\x39\x04\x11\x80" \
"\x00\x1f\x88\x80\x75\x7e\x6d\x15\xe8\x39\x39\x63\x00\x00\x00\x00" \
"\x02\x01\x06\x02\x02\x01\x98\x04\x05\x77\x72\x6f\x6e\x67\x04\x0c" \
"\x9b\x31\xb5\xe0\x0c\xae\x22\x26\xc8\xa1\x9d\xa7\x04\x08\x5e\xb2" \
"\x82\xcb\x7c\xe1\x64\x5e\x04\x32\x87\xa2\x55\x98\x2e\xd6\xc8\x9a" \
"\xab\xa2\x4b\xab\x91\x65\x03\xdd\xc1\x4b\xff\xab\x07\x40\xfa\xdb" \
"\xa4\x40\x49\x0f\xca\xeb\x99\x46\x34\x3f\x75\xe9\x24\x97\x57\xdf" \
"\x18\xea\x34\x54\x55\x84\x39\xf7\xe6\x86";
		memcpy(data, staticmsg, 10); /* up to the message id */
		len += 10;
		memcpy(data+10, &id, 4);
		len += 4;
		memcpy(data+14, staticmsg+14, 15); /* up to the security parameters */
		len += 15;
		/* the static message is produced by the username "wrong" len 5. so for a null
		 * username the type_lengths at the beginning of the security parameter should
		 * be both reduced by 5
		 */
		memcpy(data+29, staticmsg+29, 138-29); /* XXX: just copy the rest for now */
		len += 138-29;
	}
} snmp_username_msg;


static int
snmpv3_loop_read(nsock_pool nsp, Connection *con)
{
	m_v3 *p;
	type_len *tl;

	/* if there are less than 4 bytes we can't figure out a 
	 * type length. so we try to read again
	 */
	if (con->inbuf == NULL || con->inbuf->get_len() < 4) {
		nsock_read(nsp, con->niod, ncrack_read_handler, SNMP_TIMEOUT, con);
		return -1;
	}

	tl = (type_len *) ((char *)con->inbuf->get_dataptr());

	/* read up to len bytes*/
	if (con->inbuf->get_len() < tl->l) {
		nsock_read(nsp, con->niod, ncrack_read_handler, SNMP_TIMEOUT, con);
		return -1;
	}

	p = (m_v3 *)((char *)con->inbuf->get_dataptr());
	if (p->v.v != 0x3) /* not an snmp v3 message */
		return -2;

	return 0;
}

typedef struct crack_state {
	u_char eng_id[17]; /* RFC specifies it to 17 bytes */
	uint32_t cur_msg_id; /* stored as int, need to htonl before serializing */
	bool eng_id_set;
} crack_state;

// we need to allocate a buffer that will hold the security parameters
// for subsequent requests. This will be set by the first init_reply message
// this module provides a free function that will be called upon the modules
// exit (see Connection.h->ops_free)
void
ncrack_snmpv3(nsock_pool nsp, Connection *con)
{
	
	con->ops_free = &snmpv3_free;
	crack_state *cs = (crack_state *)con->misc_info;
	if (cs == NULL) { /* we need to allocate a sec_params struct */
		con->misc_info = (crack_state *) safe_zalloc(sizeof(crack_state));
		cs->eng_id_set = false;
		cs->cur_msg_id = (uint32_t)(rand() + MSGID_MIN);
	}
	nsock_iod nsi = con->niod;
	Service *serv = con->service;
	m_v3 *reply;
	uint32_t mid; // message id should be the same on the reply packet
	snmp_get_data gd = snmp_get_data(cs->cur_msg_id);
	type_len *sec_p;
	/* the maximum offset we can address according to the message type_len*/
	uint32_t max_offset = 0; 
	snmp_username_msg umsg = snmp_username_msg(cs->cur_msg_id);

	switch (con->state) {
		case SNMPV3_INIT:
			con->state = SNMPV3_INIT_REPLY;
			printf("at 1\n");
			delete con->inbuf;
			con->inbuf = NULL;

			if (con->outbuf)
				delete con->outbuf;
			con->outbuf = new Buf();

			con->outbuf->append(gd.data, sizeof(gd.data));

			nsock_write(nsp, nsi, ncrack_write_handler, SNMP_TIMEOUT, con,
					(const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
			break;
		case SNMPV3_INIT_REPLY:
			printf("at 2\n");
			if (snmpv3_loop_read(nsp, con) < 0)
				break;
			reply = (m_v3 *)con->inbuf->get_dataptr();
			max_offset = reply->tl.l - 2;
			// check that this is a reply to the previous message id.
			mid = reply->g.m_id.id;
			if (mid != cs->cur_msg_id) {
				printf("wrong message id in reply:%ud\n", mid);
				break;
			}
			con->state = SNMPV3_USERNAME;
			
			if (!cs->eng_id_set) { /* we need to populate  the engine id */
				/* extract the security parameters that contain the engine id . 
				 * this is a OCTET_STRING sequence after the globaldata. from the start it is:
				 * [tl][m_vers][m_globaldata][security_parameters]
				 * so this starts at  reply->g.l + 7 (7 -> 2 tl packet + 2 tl version + 1 version + 2 tl globaldata)
				 */
				sec_p = (type_len *)(((unsigned char *)con->inbuf->get_dataptr()) + (reply->g.tl.l + 7));
				if (sec_p->t != T_OCTET_STRING || sec_p->l > max_offset - 5 - reply->g.tl.l) {
					printf("length in security parameters type_len is beyond message offset\n");
					break;
				} 
				memcpy(cs->eng_id, sec_p+6, 17); /* engine id is always 17 bytes */
				cs->eng_id_set = true;
			}
			/* we need to increase the msg id */
			if (cs->cur_msg_id >= MSGID_MAX)
				cs->cur_msg_id = MSGID_MIN-1;
			cs->cur_msg_id += 1;


			break;

		case SNMPV3_USERNAME:
			printf("at 3\n");
			con->state = SNMPV3_USERNAME_REPLY;
			delete con->inbuf;
			con->inbuf = NULL;

			if (con->outbuf)
				delete con->outbuf;
			con->outbuf = new Buf();
			con->outbuf->append(umsg.data, umsg.len);

			nsock_write(nsp, nsi, ncrack_write_handler, SNMP_TIMEOUT, con,
					(const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
			break;

		case SNMPV3_USERNAME_REPLY:
			printf("at 4\n");
			if (snmpv3_loop_read(nsp, con) < 0)
				break;
			reply = (m_v3 *)con->inbuf->get_dataptr();
			max_offset = reply->tl.l - 2;
			// check that this is a reply to the previous message id.
			mid = reply->g.m_id.id;
			if (mid != cs->cur_msg_id) {
				printf("wrong message id in reply:%ud\n", mid);
				break;
			}
			printf("well i got a reply yo");
			con->state = SNMPV3_INIT;
			delete con->inbuf;
			con->inbuf = NULL;
			return ncrack_module_end(nsp, con);

		default:
			printf("done!\n");
			return;
	}
}

static void
snmpv3_free(Connection *con)
{
	crack_state *p = NULL;
	if (con->misc_info == NULL)
		return;
	p = (crack_state *)con->misc_info;
	free(p);
}
