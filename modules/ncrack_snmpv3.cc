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

#define START_MSGID 0xb33f

extern void ncrack_read_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_write_handler(nsock_pool nsp, nsock_event nse, void *mydata);
extern void ncrack_module_end(nsock_pool nsp, void *mydata);

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

typedef struct snmp_msg_header {
	type_len tl;
	struct snmp_version {
		type_len tl;
		uint8_t v;
		snmp_version() {
			tl.t = T_INTEGER;
			tl.l = 0x1; /* only one byte integer for version */
			v = 0x3; /* snmp v3 */
		}
	} __attribute__((__packed__)) m_vers;

	struct snmp_globaldata {
		type_len tl;
		struct msg_id {
			type_len tl;
			uint32_t id;

			msg_id() {
				tl.t = T_SEQUENCE;
				tl.l = 0x4;
				id = START_MSGID;
			}
		} __attribute__((__packed__)) m_id;

		struct msg_max_sz {
			type_len tl;
			uint8_t sz[3];

			msg_max_sz() {
				u_char staticsz[3] = {0x00, 0xff, 0xe3}; /* 65507 */
				tl.t = T_INTEGER;
				tl.l = 0x3;
				memcpy(sz, staticsz, 3);
			}
		} __attribute__((__packed__)) m_maxsz;

		struct msg_flags {
			type_len tl;
			u_char flag;

			msg_flags() {
				tl.t = T_OCTET_STRING;
				tl.l = 0x1;
				flag = 0x4; /* 100, Reportable set, Encrypted not set, Authenticatable not set */
			}
		} __attribute__((__packed__)) m_flags;

		struct msg_security_model {
			type_len tl;
			u_char model;

			msg_security_model() {
				tl.t = T_INTEGER;
				tl.l = 0x1;
				model = 0x3; /* USM */
			}
		} __attribute__((__packed__)) m_secmod;
	} __attribute__((__packed__)) m_globaldata;

	snmp_msg_header(uint8_t sz) {
		tl.t = T_SEQUENCE;
		tl.l = sz; /* need to be set before transmission */
	}
} __attribute__((__packed__)) snmp_msg_header;

typedef struct snmp_get_data() {
	snmp_header h;
	u_char data[40];

	snmp_get_data(uint32 seq) {
		h = snmp_msg_header(62);
		u_char staticmsg[40] = "\x30\x3e\x02\x01\x03\x30\x11\x02\x04\x40\xa3\x72\x4e\x02\x03\x00" \
"\xff\xe3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\x00\x02\x01" \
"\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00\x30\x14\x04\x00\x04\x00" \
"\xa0\x0e\x02\x04\x33\x7b\x1b\x53\x02\x01\x00\x02\x01\x00\x30\x00";
		memcpy(data, staticmsg, 40);
		memcpy(data+28, htonl(seq), 4);
	}
} __attribute__((__packed__)) snmp_get_data;


static int
snmpv3_loop_read(nsock_pool nsp, Connection *con)
{
	snmp_msg_header *p;
	typelen *tl;

	/* if there are less than 4 bytes we can't figure out a 
	 * type length. so we try to read again
	 */
	if (con->inbuf == NULL || con->inbuf->get_len() < 4) {
		nsock_read(nsp, con->niod, ncrack_read_handler, SNMP_TIMEOUT, con);
		return -1;
	}

	tl = (typelen *) ((char *)con->inbuf->get_dataptr());

	/* read up to len bytes*/
	if (con->inbuf->get_len() < tl->l) {
		nsock_read(nsp, con->niod, ncrack_read_handler, SNMP_TIMEOUT, con);
		return -1;
	}

	p = (struct snmp_msg_header *)((char *)con->inbuf->get_dataptr());
	if (p->m_vers.v != 0x3) /* not an snmp v3 message */
		return -2;

	/* XXX more sanity check */
	return 0;
}

void
ncrack_snmpv3(nsock_pool nsp, Connection *con)
{
	nsock_iod = con->niod;
	Service *serv = con->service;
	snmp_msg_header *reply;
	uint32_t rid; // reply id

	switch (con->state) {
		case SNMPV3_INIT:
			con->state = SNMPV3_INIT_REPLY;
			delete con->inbuf;
			con->inbuf = NULL;

			if (con->outbuf)
				delete con->outbuf;
			con->outbuf = new Buf();

			snmp_get_data gd = snmp_get_data(8888);
			con->outbuf->append(&gd, sizeof(snmp_get_data));

			nsock_write(nsp, nsi, ncrack_write_handler, SNMP_TIMEOUT, con,
					(const char *)con->outbuf->get_dataptr(), con->outbuf->get_len());
			break;
		case SNMPV3_INIT_REPLY:
			if (snmpv3_loop_read(nsp, con) < 0)
				break;
			reply = (snmp_msg_header *)con->inbuf->get_dataptr();
			// check that this is a reply to the previous message id.
			rid = reply->m_globaldata->m_id->id;
			if (rid != 8888) {
				printf("wrong message id in reply:%ud \n", rid);
				break;
			}
			// extract the engine id.

			
		default:
			printf("done!\n");
			return 

	}
}
