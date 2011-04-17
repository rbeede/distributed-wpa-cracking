/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004-2009, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: cowpatty.c 264 2009-07-03 15:15:50Z jwright $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * coWPAtty is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * wpa_supplicant by Jouni Malinen.  This tool would have been MUCH more
 * difficult for me if not for this code.  Thanks Jouni.
 */

/*
 * Right off the bat, this code isn't very useful.  The PBKDF2 function makes
 * 4096 SHA-1 passes for each passphrase, which takes quite a bit of time.  On
 * my Pentium II development system, I'm getting ~2.5 passphrases/second.
 * I've done my best to optimize the PBKDF2 function, but it's still pretty
 * slow.
 */

#define PROGNAME "cowpatty"
#define VER "CU5673"
#define MAXPASSPHRASE 256
#define DOT1X_LLCTYPE "\x88\x8e"
#define MAX_PKT_LEN 4096
#define MAX_STR_LEN 1024
#define MAX_LOG_STR 8192

#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <getopt.h>
#include <unistd.h>
#include <pcap.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "cowpatty.h"
#include "common.h"
#include "utils.h"
#include "sha1.h"
#include "md5.h"
#include "radiotap.h"

#define LOADED 1
#define RUNNING 2
#define FINISHED 3
#define KILLED 4
#define NOTLOADED 5

/* Globals */
pcap_t *p = NULL;
unsigned char *packet;
struct pcap_pkthdr *h;
char errbuf[PCAP_ERRBUF_SIZE];
int sig = 0;			/* Used for handling signals */
char *words;
/* temporary storage for the password from the hash record, instead of
   malloc/free for each entry. */
char password_buf[65];
unsigned long wordstested = 0;

struct ssid_table {
        char *ssid;
        unsigned char *buffer;
};
int status = NOTLOADED;
char rainbow_table_path[MAX_STR_LEN];
int port_num;
int log_fd;
int node_count;
int node_rank;
int start_offset;
int end_offset;
int num_ssid;
struct ssid_table **rainbow_table;

struct job {
    char jobid[MAX_STR_LEN];
    char capture_path[MAX_STR_LEN];
    char output_path[MAX_STR_LEN];
    char ssid[MAX_STR_LEN];
    pthread_t thread;
};
struct job currJob;

/* Prototypes */
void wpa_pmk_to_ptk(u8 * pmk, u8 * addr1, u8 * addr2,
		    u8 * nonce1, u8 * nonce2, u8 * ptk, size_t ptk_len);
void hexdump(unsigned char *data, int len);
void usage(char *message);
void testopts(struct user_opt *opt);
void cleanup();
void parseopts(struct user_opt *opt, int argc, char **argv);
void closepcap(struct capture_data *capdata);
void handle_dot1x(struct crack_data *cdata, struct capture_data *capdata,
		  struct user_opt *opt);
void dump_all_fields(struct crack_data cdata, struct user_opt *opt);
void printstats(struct timeval start, struct timeval end,
		unsigned long int wordcount);
int nextdictword(char *word, FILE * fp);
int nexthashrec(FILE * fp, struct hashdb_rec *rec);
void fatal(const char *msg);

/*
 * Writes a log message to a file.  A timestamp is written along with the 
 * message.  The file should be previously opened in append mode.
 *  fd     - file descriptor of file to write to
 *  format - format string
 */
int logMessage(int fd, const char* format, ...) {

    int ret;                   // return value
    char msg[MAX_LOG_STR];     // message to log
    char total[MAX_LOG_STR];   // total buffer to output
    va_list args;              // arguments from formatted string

    // clear memory
    memset(msg,0,MAX_LOG_STR);
    memset(total,0,MAX_LOG_STR);

    // turn parameters into a character string
    va_start(args,format);
    vsnprintf(msg,MAX_LOG_STR,format,args);
    va_end(args);

	
	// Get the current time so we can output it in the log as a nicely formatted one :)
	time_t rawtime;
	time (&rawtime);
	struct tm * ptm;
	ptm = gmtime (&rawtime);  // No messing with time zones and daylight savings time
	
	char currTimeFormatted[27];  // sizeof(currTimeFormatted) works on this since it isn't a pointer to a malloc
	// format comes out with 0 padded numbers and looks like:  "YYYY-mm-dd HH:MM:SS +0000\t" or "YYYY-mm-dd HH:MM:SS -0000\t"
	//	where +/-0000 is the time zone offset and \t means a single tab character
	strftime(currTimeFormatted, sizeof(currTimeFormatted), "%Y-%m-%d %H:%M:%S %z\t", ptm);  // %z is a GNU extension
	strncat(total, currTimeFormatted, 26);  // add the formatted date to the line
	
	strncat(total, msg, MAX_LOG_STR - 26);  // minus 26 for characters in date/time
	
	
    // write buffer and flush
    ret = write(fd, total, strlen(total));
    if (ret<0) return -1;
    ret = fsync(fd);
    if (ret<0) return -1;

    return 0;
}

void fatal(const char *msg) {
    perror(msg);
    exit(1);
}

void usage(char *message)
{

	if (strlen(message) > 0) {
		printf("%s: %s\n", PROGNAME, message);
	}

	printf("\nUsage: %s [options]\n", PROGNAME);
	printf("\n"
	       "\t-f \tDictionary file\n"
	       "\t-d \tHash file (genpmk)\n"
	       "\t-r \tPacket capture file\n"
	       "\t-s \tNetwork SSID (enclose in quotes if SSID includes spaces)\n"
	       "\t-2 \tUse frames 1 and 2 or 2 and 3 for key attack (nonstrict mode)\n"
           "\t-c \tCheck for valid 4-way frames, does not crack\n"
	       "\t-h \tPrint this help information and exit\n"
	       "\t-v \tPrint verbose information (more -v for more verbosity)\n"
	       "\t-V \tPrint program version and exit\n" "\n");
}

void cleanup()
{
	/* lame-o-meter++ */
	sig = 1;
}

void wpa_pmk_to_ptk(u8 * pmk, u8 * addr1, u8 * addr2,
		    u8 * nonce1, u8 * nonce2, u8 * ptk, size_t ptk_len)
{
	u8 data[2 * ETH_ALEN + 2 * 32];

	memset(&data, 0, sizeof(data));

	/* PTK = PRF-X(PMK, "Pairwise key expansion",
	 *             Min(AA, SA) || Max(AA, SA) ||
	 *             Min(ANonce, SNonce) || Max(ANonce, SNonce)) */

	if (memcmp(addr1, addr2, ETH_ALEN) < 0) {
		memcpy(data, addr1, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr2, ETH_ALEN);
	} else {
		memcpy(data, addr2, ETH_ALEN);
		memcpy(data + ETH_ALEN, addr1, ETH_ALEN);
	}

	if (memcmp(nonce1, nonce2, 32) < 0) {
		memcpy(data + 2 * ETH_ALEN, nonce1, 32);
		memcpy(data + 2 * ETH_ALEN + 32, nonce2, 32);
	} else {
		memcpy(data + 2 * ETH_ALEN, nonce2, 32);
		memcpy(data + 2 * ETH_ALEN + 32, nonce1, 32);
	}

	sha1_prf(pmk, 32, "Pairwise key expansion", data, sizeof(data),
		 ptk, ptk_len);
}

void hexdump(unsigned char *data, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02x ", data[i]);
	}
}

void parseopts(struct user_opt *opt, int argc, char **argv)
{

	int c;

	while ((c = getopt(argc, argv, "f:r:s:d:c2nhvV")) != EOF) {
		switch (c) {
		case 'f':
			strncpy(opt->dictfile, optarg, sizeof(opt->dictfile));
			break;
		case 'r':
			strncpy(opt->pcapfile, optarg, sizeof(opt->pcapfile));
			break;
		case 's':
			strncpy(opt->ssid, optarg, sizeof(opt->ssid));
			break;
		case 'd':
			strncpy(opt->hashfile, optarg, sizeof(opt->hashfile));
			break;
		case 'n':
		case '2':
			opt->nonstrict++;
			break;
		case 'c':
			opt->checkonly++;
			break;
		case 'h':
			usage("");
			exit(0);
			break;
		case 'v':
			opt->verbose++;
			break;
		case 'V':
			printf
				("$Id: cowpatty.c 264 2009-07-03 15:15:50Z jwright $\n");
			exit(0);
			break;
		default:
			usage("");
			exit(-1);
		}
	}
}

void testopts(struct user_opt *opt)
{
	struct stat teststat;

    /* Test for a pcap file */
	if (IsBlank(opt->pcapfile)) {
		usage("Must supply a pcap file with -r");
		exit(-1);
	}

    if (opt->checkonly == 1) {
        /* Special case where we only need pcap file */
        return;
    }

	/* test for required parameters */
	if (IsBlank(opt->dictfile) && IsBlank(opt->hashfile)) {
		usage("Must supply a list of passphrases in a file with -f "
		      "or a hash file\n\t  with -d.  "
		      "Use \"-f -\" to accept words on stdin.");
		exit(-1);
	}

	if (IsBlank(opt->ssid)) {
		usage("Must supply the SSID for the network with -s");
		exit(-1);
	}

	/* Test that the files specified exist and are greater than 0 bytes */
	if (!IsBlank(opt->hashfile) && strncmp(opt->hashfile, "-", 1) != 0) {
		if (stat(opt->hashfile, &teststat)) {
			usage("Could not stat hashfile.  Check file path.");
			exit(-1);
		} else if (teststat.st_size == 0) {
			usage("Empty hashfile (0 bytes).  Check file contents.");
			exit(-1);
		}
	}

	if (!IsBlank(opt->dictfile) && strncmp(opt->dictfile, "-", 1) != 0) {
		if (stat(opt->dictfile, &teststat)) {
			usage
			    ("Could not stat the dictionary file.  Check file path.");
			exit(-1);
		} else if (teststat.st_size == 0) {
			usage
			    ("Empty dictionary file (0 bytes).  Check file contents.");
			exit(-1);
		}
	}

	if (stat(opt->pcapfile, &teststat) && strncmp(opt->hashfile, "-", 1) != 0) {
		usage("Could not stat the pcap file.  Check file path.");
		exit(-1);
	} else if (teststat.st_size == 0) {
		usage("Empty pcap file (0 bytes).  Check file contents.");
		exit(-1);
	}
}

int openpcap(struct capture_data *capdata)
{

	/* Assume for now it's a libpcap file */
	p = pcap_open_offline(capdata->pcapfilename, errbuf);
	if (p == NULL) {
		perror("Unable to open capture file");
		return (-1);
	}

	/* Determine link type */
	capdata->pcaptype = pcap_datalink(p);

	/* Determine offset to EAP frame based on link type */
	switch (capdata->pcaptype) {
	case DLT_NULL:
	case DLT_EN10MB:
	case DLT_IEEE802_11:
	case DLT_PRISM_HEADER:
	case DLT_IEEE802_11_RADIO:
		break;
	default:
		/* Unknown/unsupported pcap type */
		return (1);
	}

	return (0);
}

void closepcap(struct capture_data *capdata)
{

	/* Assume it's a libpcap file for now */
	pcap_close(p);
}

/* Populates global *packet, returns status */
int getpacket(struct capture_data *capdata)
{
	/* Assume it's a libpcap file for now */
	int ret;
	struct ieee80211_radiotap_header *rtaphdr;
	int rtaphdrlen=0;
	struct dot11hdr *dot11 = NULL;

	/* Loop on pcap_next_ex until we get a packet we want, return from
	 * this while loop.  This is kinda hack.
	 */
	while ((ret = pcap_next_ex(p, &h, (const u_char **)&packet)) 
			&& ret > 0) {

		/* Determine offset to EAP frame based on link type */
		switch (capdata->pcaptype) {
		case DLT_NULL:
		case DLT_EN10MB:
			/* Standard ethernet header */
			capdata->dot1x_offset = 14;
			capdata->l2type_offset = 12;
			capdata->dstmac_offset = 0;
			capdata->srcmac_offset = 6;
			return(ret);
			break;

		case DLT_IEEE802_11:
			/* If this is not a data packet, get the next frame */
			dot11 = (struct dot11hdr *)packet;
			if (dot11->u1.fc.type != DOT11_FC_TYPE_DATA) {
				continue;
			}

			capdata->dstmac_offset = 4;
			capdata->srcmac_offset = 10;

			/* differentiate QoS data and non-QoS data frames */
			if (dot11->u1.fc.subtype == DOT11_FC_SUBTYPE_QOSDATA) {
				/* 26 bytes 802.11 header, 8 for 802.2 header */
				capdata->dot1x_offset = 34;
				capdata->l2type_offset = 32;
			} else if (dot11->u1.fc.subtype == DOT11_FC_SUBTYPE_DATA) {
				/* 24 bytes 802.11 header, 8 for 802.2 header */
				capdata->dot1x_offset = 32;
				capdata->l2type_offset = 30;
			} else {
				/* Not a data frame we support */
				continue;
			}
			return(ret);
			break;

		case DLT_PRISM_HEADER:
			/* 802.11 frames with AVS header, AVS header is 144
			 * bytes */
			 
			/* If this is not a data packet, get the next frame */
			dot11 = ((struct dot11hdr *)(packet+144));
			if (dot11->u1.fc.type != DOT11_FC_TYPE_DATA) {
				continue;
			}
			capdata->dstmac_offset = 4 + 144;
			capdata->srcmac_offset = 10 + 144;

			/* differentiate QoS data and non-QoS data frames */
			if (dot11->u1.fc.subtype == DOT11_FC_SUBTYPE_QOSDATA) {
				capdata->dot1x_offset = 34 + 144;
				capdata->l2type_offset = 32 + 144;
			} else if (dot11->u1.fc.subtype == DOT11_FC_SUBTYPE_DATA) {
				capdata->dot1x_offset = 32 + 144;
				capdata->l2type_offset = 30 + 144;
			} else {
				/* Not a data frame we support */
				continue;
			}
			return(ret);
			break;

		case DLT_IEEE802_11_RADIO:
			/* Radiotap header, need to calculate offset to payload
			   on a per-packet basis.
			*/
			rtaphdr = (struct ieee80211_radiotap_header *)packet;
			/* rtap is LE */
			rtaphdrlen = le16_to_cpu(rtaphdr->it_len); 
	
			/* Sanity check on header length, 10 bytes is min 
			   802.11 len */
			if (rtaphdrlen > (h->len - 10)) {
				return -2; /* Bad radiotap data */
			}
	
			capdata->dstmac_offset = 4 + rtaphdrlen;
			capdata->srcmac_offset = 10 + rtaphdrlen;

			dot11 = ((struct dot11hdr *)(packet+rtaphdrlen));
			/* differentiate QoS data and non-QoS data frames */
			if (dot11->u1.fc.subtype == DOT11_FC_SUBTYPE_QOSDATA) {
				capdata->dot1x_offset = 34 + rtaphdrlen;
				capdata->l2type_offset = 32 + rtaphdrlen;
			} else if (dot11->u1.fc.subtype ==
					DOT11_FC_SUBTYPE_DATA) {
				capdata->dot1x_offset = 32 + rtaphdrlen;
				capdata->l2type_offset = 30 + rtaphdrlen;
			} else {
				/* Not a data frame we support */
				continue;
			}
			return(ret);
			break;

		default:
			/* Unknown/unsupported pcap type */
			return (1);
		}
	}

	return (ret);
}

void handle_dot1x(struct crack_data *cdata, struct capture_data *capdata,
		  struct user_opt *opt)
{
	struct ieee8021x *dot1xhdr;
	struct wpa_eapol_key *eapolkeyhdr;
	int eapolkeyoffset;
	int key_info, index;

	/* We're going after the last three frames in the 4-way handshake.
	   In the last frame of the TKIP exchange, the authenticator nonce is
	   omitted.  In cases where there is a unicast and a multicast key 
	   distributed, frame 4 will include the authenticator nonce.  In some
	   cases however, there is no multicast key distribution, so frame 4 has
	   no authenticator nonce.  For this reason, we need to capture information
	   from the 2nd, 3rd and 4th frames to accommodate cases where there is no
	   multicast key delivery.  Suckage.
	 */

	dot1xhdr = (struct ieee8021x *)&packet[capdata->dot1x_offset];
	eapolkeyoffset = capdata->dot1x_offset + sizeof(struct ieee8021x);
	eapolkeyhdr = (struct wpa_eapol_key *)&packet[eapolkeyoffset];

	/* Bitwise fields in the key_info field of the EAPOL-Key header */
	key_info = be_to_host16(eapolkeyhdr->key_info);
	cdata->ver = key_info & WPA_KEY_INFO_TYPE_MASK;
	index = key_info & WPA_KEY_INFO_KEY_INDEX_MASK;

	if (opt->nonstrict == 0) {

	        /* Check for EAPOL version 1, type EAPOL-Key */
        	if (dot1xhdr->version != 1 || dot1xhdr->type != 3) {
                	return;
        	}

	} else {

		/* Check for type EAPOL-Key */
		if (dot1xhdr->type != 3) {
			return;
		}

	}
	if (cdata->ver != WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 &&
		cdata->ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		return;
	}

	if (cdata->ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
		/* Check for WPA key, and pairwise key type */
		if (eapolkeyhdr->type != 254 || 
				(key_info & WPA_KEY_INFO_KEY_TYPE) == 0) {
			return;
		}
	} else if (cdata->ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		if (eapolkeyhdr->type != 2 ||
				(key_info & WPA_KEY_INFO_KEY_TYPE) == 0) {
			return;
		}
	}

	if (opt->nonstrict == 0) {

		/* Check for frame 2 of the 4-way handshake */
		if ((key_info & WPA_KEY_INFO_MIC)
			&& (key_info & WPA_KEY_INFO_ACK) == 0
			&& (key_info & WPA_KEY_INFO_INSTALL) == 0
			&& eapolkeyhdr->key_data_length > 0) {

			/* All we need from this frame is the authenticator nonce */
			memcpy(cdata->snonce, eapolkeyhdr->key_nonce,
			       sizeof(cdata->snonce));
			cdata->snonceset = 1;

		/* Check for frame 3 of the 4-way handshake */
		} else if ((key_info & WPA_KEY_INFO_MIC)
			  && (key_info & WPA_KEY_INFO_INSTALL)
			  && (key_info & WPA_KEY_INFO_ACK)) {

			memcpy(cdata->spa, &packet[capdata->dstmac_offset],
			       sizeof(cdata->spa));
			memcpy(cdata->aa, &packet[capdata->srcmac_offset],
			       sizeof(cdata->aa));
			memcpy(cdata->anonce, eapolkeyhdr->key_nonce,
			       sizeof(cdata->anonce));
			cdata->aaset = 1;
			cdata->spaset = 1;
			cdata->anonceset = 1;
			/* We save the replay counter value in the 3rd frame to match
			   against the 4th frame of the four-way handshake */
			memcpy(cdata->replay_counter,
			       eapolkeyhdr->replay_counter, 8);

		/* Check for frame 4 of the four-way handshake */
		} else if ((key_info & WPA_KEY_INFO_MIC)
			  && (key_info & WPA_KEY_INFO_ACK) == 0
			  && (key_info & WPA_KEY_INFO_INSTALL) == 0
			  && (memcmp (cdata->replay_counter,
			      eapolkeyhdr->replay_counter, 8) == 0)) {

			memcpy(cdata->keymic, eapolkeyhdr->key_mic,
			       sizeof(cdata->keymic));
			memcpy(cdata->eapolframe, &packet[capdata->dot1x_offset],
			       sizeof(cdata->eapolframe));
			cdata->keymicset = 1;
			cdata->eapolframeset = 1;
		}
	} else {

		/* Check for frame 1 of the 4-way handshake */
		if ((key_info & WPA_KEY_INFO_MIC) == 0 
		   && (key_info & WPA_KEY_INFO_ACK)
		   && (key_info & WPA_KEY_INFO_INSTALL) == 0 ) {
	                /* All we need from this frame is the authenticator nonce */
			memcpy(cdata->anonce, eapolkeyhdr->key_nonce,
				sizeof(cdata->anonce));
			cdata->anonceset = 1;
 
		/* Check for frame 2 of the 4-way handshake */
		} else if ((key_info & WPA_KEY_INFO_MIC)
			  && (key_info & WPA_KEY_INFO_INSTALL) == 0
			  && (key_info & WPA_KEY_INFO_ACK) == 0
			  && eapolkeyhdr->key_data_length > 0) {

			cdata->eapolframe_size = ( packet[capdata->dot1x_offset + 2] << 8 )
					+   packet[capdata->dot1x_offset + 3] + 4;

			memcpy(cdata->spa, &packet[capdata->dstmac_offset],
				sizeof(cdata->spa));
			cdata->spaset = 1;

			memcpy(cdata->aa, &packet[capdata->srcmac_offset],
				sizeof(cdata->aa));
			cdata->aaset = 1;

			memcpy(cdata->snonce, eapolkeyhdr->key_nonce,
				 sizeof(cdata->snonce));
			cdata->snonceset = 1;

			memcpy(cdata->keymic, eapolkeyhdr->key_mic,
				sizeof(cdata->keymic));
			cdata->keymicset = 1;

			memcpy(cdata->eapolframe, &packet[capdata->dot1x_offset],
				cdata->eapolframe_size);
			cdata->eapolframeset = 1;


        /* Check for frame 3 of the 4-way handshake */
		}  else if ((key_info & WPA_KEY_INFO_MIC)
			  	&& (key_info & WPA_KEY_INFO_ACK)
	   			&& (key_info & WPA_KEY_INFO_INSTALL)) {
			/* All we need from this frame is the authenticator nonce */
			memcpy(cdata->anonce, eapolkeyhdr->key_nonce,
			sizeof(cdata->anonce));
			cdata->anonceset = 1;
		}
	}
}

void dump_all_fields(struct crack_data cdata, struct user_opt *opt)
{

	printf("AA is:");
	lamont_hdump(cdata.aa, 6);
	printf("\n");

	printf("SPA is:");
	lamont_hdump(cdata.spa, 6);
	printf("\n");

	printf("snonce is:");
	lamont_hdump(cdata.snonce, 32);
	printf("\n");

	printf("anonce is:");
	lamont_hdump(cdata.anonce, 32);
	printf("\n");

	printf("keymic is:");
	lamont_hdump(cdata.keymic, 16);
	printf("\n");

	printf("eapolframe is:");
	if (opt->nonstrict == 0) {
		lamont_hdump(cdata.eapolframe, 99);
	} else {
		lamont_hdump(cdata.eapolframe, 125);
	}

	printf("\n");

}

void printstats(struct timeval start, struct timeval end,
		unsigned long int wordcount)
{

	float elapsed = 0;

	if (end.tv_usec < start.tv_usec) {
		end.tv_sec -= 1;
		end.tv_usec += 1000000;
	}
	end.tv_sec -= start.tv_sec;
	end.tv_usec -= start.tv_usec;
	elapsed = end.tv_sec + end.tv_usec / 1000000.0;

	printf("\n%lu passphrases tested in %.2f seconds:  %.2f passphrases/"
	       "second\n", wordcount, elapsed, wordcount / elapsed);
}

int nexthashrec(FILE * fp, struct hashdb_rec *rec) {
    
    int recordlength, wordlen;
    
    if (fread(&rec->rec_size, sizeof(rec->rec_size), 1, fp) != 1) {	
	perror("fread");
	return -1;
    }
    
    recordlength = abs(rec->rec_size);
    wordlen = recordlength - (sizeof(rec->pmk) + sizeof(rec->rec_size));
    
    if (wordlen > 63 || wordlen < 8) {
	fprintf(stderr, "Invalid word length: %d\n", wordlen);
	return -1;
    }
    
    /* hackity, hack, hack, hack */
    rec->word = password_buf;
    
    if (fread(rec->word, wordlen, 1, fp) != 1) {
	perror("fread");
	return -1;
    }
    
    if (fread(rec->pmk, sizeof(rec->pmk), 1, fp) != 1) {
	perror("fread");
	return -1;
    }
    
    return recordlength;
}

int nexthashrec_dist(unsigned char* rt,int i,struct hashdb_rec *rec) {
    
    int recordlength, wordlen;
    int len = i;

    //TODO: check errors
    //TODO: change fprintfs to logMessages
    memcpy(&rec->rec_size, rt+len, sizeof(rec->rec_size));
    len += sizeof(rec->rec_size);
    //read(fd, &rec->rec_size, sizeof(rec->rec_size));
    /*if (fread(&rec->rec_size, sizeof(rec->rec_size), 1, fp) != 1) {	
	perror("fread");
	return -1;
	}*/
    
    recordlength = abs(rec->rec_size);
    wordlen = recordlength - (sizeof(rec->pmk) + sizeof(rec->rec_size));
    
    if (wordlen > 63 || wordlen < 8) {
	logMessage(log_fd, "Invalid word length: %d\n", wordlen);
	return -1;
    }
    
    /* hackity, hack, hack, hack */
    rec->word = password_buf;
    
    memcpy(rec->word, rt+len, wordlen);
    len += wordlen;
    //read(fd, rec->word, wordlen);
    /*if (fread(rec->word, wordlen, 1, fp) != 1) {
	perror("fread");
	return -1;
	}*/
    
    memcpy(rec->pmk, rt+len, sizeof(rec->pmk));
    //read(fd, rec->pmk, sizeof(rec->pmk));
    /*if (fread(rec->pmk, sizeof(rec->pmk), 1, fp) != 1) {
	perror("fread");
	return -1;
	}*/
    
    return recordlength;
}

int nextdictword(char *word, FILE * fp)
{

	if (fgets(word, MAXPASSLEN + 1, fp) == NULL) {
		return (-1);
	}

	/* Remove newline */
	word[strlen(word) - 1] = '\0';

	if (feof(fp)) {
		return (-1);
	}

	return (strlen(word));
}

void hmac_hash(int ver, u8 *key, int hashlen, u8 *buf, int buflen, u8 *mic)
{
	u8 hash[SHA1_MAC_LEN];

	if (ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
		hmac_md5(key, hashlen, buf, buflen, mic);
	} else if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		hmac_sha1(key, hashlen, buf, buflen, hash, NOCACHED);
		memcpy(mic, hash, MD5_DIGEST_LENGTH); /* only 16 bytes, not 20 */
	}
}

int hashfile_attack(struct user_opt *opt, char *passphrase, 
		    struct crack_data *cdata) {
	
    FILE *fp;
    int reclen, wordlen;
    u8 pmk[32];
    u8 ptk[64];
    u8 keymic[16];
    struct wpa_ptk *ptkset;
    struct hashdb_rec rec;
    struct hashdb_head hf_head;
    char headerssid[33];
    
    /* Open the hash file */
    if (*opt->hashfile == '-') {
	printf("Using STDIN for hashfile contents.\n");
	fp = stdin;
    } else {
	fp = fopen(opt->hashfile, "rb");
	if (fp == NULL) {
	    perror("fopen");
	    return(-1);
	}
    }
    
    /* Read the record header contents */
    if (fread(&hf_head, sizeof(hf_head), 1, fp) != 1) {
	perror("fread");
	return(-1);
    }
    
    /* Ensure selected SSID matches what's stored in the header record */
    if (memcmp(hf_head.ssid, opt->ssid, hf_head.ssidlen) != 0) {
	
	memcpy(&headerssid, hf_head.ssid, hf_head.ssidlen);
	headerssid[hf_head.ssidlen] = 0; /* NULL terminate string */
	
	fprintf(stderr, "\nSSID in hashfile (\"%s\") does not match "
		"SSID specified on the \n"
		"command line (\"%s\").  You cannot "
		"mix and match SSID's for this\nattack.\n\n",
		headerssid, opt->ssid);
	return(-1);
    }
    
    
    while (feof(fp) == 0 && sig == 0) {
	
	/* Populate the hashdb_rec with the next record */
	reclen = nexthashrec(fp, &rec);
	
	/* nexthashrec returns the length of the record, test to ensure
	   passphrase is greater than 8 characters */
	wordlen = rec.rec_size - 
	    (sizeof(rec.pmk) + sizeof(rec.rec_size));
	if (wordlen < 8) {
	    printf("Found a record that was too short, this "
		   "shouldn't happen in practice!\n");
	    return(-1);
	}
	
	/* Populate passphrase with the record contents */
	memcpy(passphrase, rec.word, wordlen);
	
	/* NULL terminate passphrase string */
	passphrase[wordlen] = 0;
	
	if (opt->verbose > 1) {
	    printf("Testing passphrase: %s\n", passphrase);
	}
	
	/* Increment the words tested counter */
	wordstested++;
	
	/* Status display */
	if ((wordstested % 10000) == 0) {
	    printf("key no. %ld: %s\n", wordstested, passphrase);
	    fflush(stdout);
	}
	
	if (opt->verbose > 1) {
	    printf("Calculating PTK for \"%s\".\n", passphrase);
	}
	
	if (opt->verbose > 2) {
	    printf("PMK is");
	    lamont_hdump(pmk, sizeof(pmk));
	}
	
	if (opt->verbose > 1) {
	    printf("Calculating PTK with collected data and "
		   "PMK.\n");
	}
	
	wpa_pmk_to_ptk(rec.pmk, cdata->aa, cdata->spa, cdata->anonce,
		       cdata->snonce, ptk, sizeof(ptk));
	
	if (opt->verbose > 2) {
	    printf("Calculated PTK for \"%s\" is", passphrase);
	    lamont_hdump(ptk, sizeof(ptk));
	}
	
	ptkset = (struct wpa_ptk *)ptk;
	
	if (opt->verbose > 1) {
	    printf("Calculating hmac-MD5 Key MIC for this "
		   "frame.\n");
	}
	
	if (opt->nonstrict == 0) {
	    hmac_hash(cdata->ver, ptkset->mic_key, 16, cdata->eapolframe,
		      sizeof(cdata->eapolframe), keymic);
	} else {
	    hmac_hash(cdata->ver, ptkset->mic_key, 16, cdata->eapolframe,
		      cdata->eapolframe_size, keymic);
	}
	
	if (opt->verbose > 2) {
	    printf("Calculated MIC with \"%s\" is", passphrase);
	    lamont_hdump(keymic, sizeof(keymic));
	}
	
	if (memcmp(&cdata->keymic, &keymic, sizeof(keymic)) == 0) {
	    return 0;
	} else {
	    continue;
	}
    }
    
    return 1;
}

int dictfile_attack(struct user_opt *opt, char *passphrase, 
	struct crack_data *cdata)
{
	
	FILE *fp;
	int fret;
	u8 pmk[32];
	u8 ptk[64];
	u8 keymic[16];
	struct wpa_ptk *ptkset;

	/* Open the dictionary file */
	if (*opt->dictfile == '-') {
		printf("Using STDIN for words.\n");
		fp = stdin;
	} else {
		fp = fopen(opt->dictfile, "r");
		if (fp == NULL) {
			perror("fopen");
			exit(-1);
		}
	}


	while (feof(fp) == 0 && sig == 0) {

		/* Populate "passphrase" with the next word */
		fret = nextdictword(passphrase, fp);
		if (fret < 0) {
			break;
		}

		if (opt->verbose > 1) {
			printf("Testing passphrase: %s\n", passphrase);
		}

		/*
		 * Test length of word.  IEEE 802.11i indicates the passphrase
		 * must be at least 8 characters in length, and no more than 63 
		 * characters in length. 
		 */
		if (fret < 8 || fret > 63) {
			if (opt->verbose) {
				printf("Invalid passphrase length: %s (%u).\n",
				       passphrase, (unsigned int) strlen(passphrase));
			}
			continue;
		} else {
			/* This word is good, increment the words tested
			counter */
			wordstested++;
		}

		/* Status display */
		if ((wordstested % 1000) == 0) {
			printf("key no. %ld: %s\n", wordstested, passphrase);
			fflush(stdout);
		}

		if (opt->verbose > 1) {
			printf("Calculating PMK for \"%s\".\n", passphrase);
		}
		
		pbkdf2_sha1(passphrase, opt->ssid, strlen(opt->ssid), 4096,
			    pmk, sizeof(pmk), USECACHED);

		if (opt->verbose > 2) {
			printf("PMK is");
			lamont_hdump(pmk, sizeof(pmk));
		}

		if (opt->verbose > 1) {
			printf("Calculating PTK with collected data and "
			       "PMK.\n");
		}

		wpa_pmk_to_ptk(pmk, cdata->aa, cdata->spa, cdata->anonce,
			       cdata->snonce, ptk, sizeof(ptk));

		if (opt->verbose > 2) {
			printf("Calculated PTK for \"%s\" is", passphrase);
			lamont_hdump(ptk, sizeof(ptk));
		}

		ptkset = (struct wpa_ptk *)ptk;

		if (opt->verbose > 1) {
			printf("Calculating hmac-MD5 Key MIC for this "
			       "frame.\n");
		}

		if (opt->nonstrict == 0) {
			hmac_hash(cdata->ver, ptkset->mic_key, 16, cdata->eapolframe,
				sizeof(cdata->eapolframe), keymic);
		} else {
			hmac_hash(cdata->ver, ptkset->mic_key, 16, cdata->eapolframe,
				cdata->eapolframe_size, keymic);
                }

		if (opt->verbose > 2) {
			printf("Calculated MIC with \"%s\" is", passphrase);
			lamont_hdump(keymic, sizeof(keymic));
		}

		if (memcmp(&cdata->keymic, &keymic, sizeof(keymic)) == 0) {
			return 0;
		} else {
			continue;
		}
	}

	return 1;
}

int hashfile_attack_dist(struct user_opt *opt, char *passphrase, 
			 struct crack_data *cdata,unsigned char* raint) {
	
    int reclen, wordlen, i;
    u8 pmk[32];
    u8 ptk[64];
    u8 keymic[16];
    struct wpa_ptk *ptkset;
    struct hashdb_rec rec;
    
    while (i<(end_offset-start_offset+1)) {
	
	// Populate the hashdb_rec with the next record
	reclen = nexthashrec_dist(raint, i, &rec);
	i += reclen;
	
	// nexthashrec returns the length of the record, test to ensure
	//   passphrase is greater than 8 characters
	wordlen = rec.rec_size - 
	    (sizeof(rec.pmk) + sizeof(rec.rec_size));
	if (wordlen < 8) {
	    logMessage(log_fd, "Found a record that was too short, this "
		   "shouldn't happen in practice!\n");
	    return -1;
	}
	
	// Populate passphrase with the record contents
	memcpy(passphrase, rec.word, wordlen);
	
	// NULL terminate passphrase string
	passphrase[wordlen] = 0;
	
	if (opt->verbose > 1) 
	    logMessage(log_fd,"Testing passphrase: %s\n", passphrase);
	
	// Increment the words tested counter
	wordstested++;
	
	// Status display
	if ((wordstested % 10000) == 0)
	    logMessage(log_fd, "key no. %ld: %s\n", wordstested, passphrase);
	
	if (opt->verbose > 1)
	    logMessage(log_fd, "Calculating PTK for \"%s\".\n", passphrase);
	
	//TODO: fix verbosity > 2 (lamont_hdump will print to stdout)
	if (opt->verbose > 2) {
	    printf("PMK is");
	    lamont_hdump(pmk, sizeof(pmk));
	}
	
	if (opt->verbose > 1)
	    logMessage(log_fd,"Calculating PTK with collected data and "
		       "PMK.\n");
	
	wpa_pmk_to_ptk(rec.pmk, cdata->aa, cdata->spa, cdata->anonce,
		       cdata->snonce, ptk, sizeof(ptk));
	
	if (opt->verbose > 2) {
	    printf("Calculated PTK for \"%s\" is", passphrase);
	    lamont_hdump(ptk, sizeof(ptk));
	}
	
	ptkset = (struct wpa_ptk *)ptk;
	
	if (opt->verbose > 1) 
	    logMessage(log_fd,"Calculating hmac-MD5 Key MIC for this "
		       "frame.\n");
	
	if (opt->nonstrict == 0) {
	    hmac_hash(cdata->ver, ptkset->mic_key, 16, cdata->eapolframe,
		      sizeof(cdata->eapolframe), keymic);
	} else {
	    hmac_hash(cdata->ver, ptkset->mic_key, 16, cdata->eapolframe,
		      cdata->eapolframe_size, keymic);
	}
	
	if (opt->verbose > 2) {
	    printf("Calculated MIC with \"%s\" is", passphrase);
	    lamont_hdump(keymic, sizeof(keymic));
	}
	
	if (memcmp(&cdata->keymic, &keymic, sizeof(keymic)) == 0) {
	    return 0;
	} else {
	    continue;
	}
    }
    
    return 1;
}

int sendPacket(int sockfd,char* type,char* status,char* jobid) {

    char buffer[MAX_STR_LEN],packet[MAX_PKT_LEN];
    memset(buffer,0,MAX_STR_LEN);
    memset(packet,0,MAX_PKT_LEN);

    if (type==NULL) return -1;
    int len = strlen(type)+1;
    if (len>MAX_STR_LEN) return -1;

    memcpy(packet,type,len);
    packet[len++] = (char)31;

    if (status!=NULL) {
	if (strlen(status)+1>MAX_STR_LEN) return -1;
	memcpy(&packet[len],status,strlen(status)+1);
	len += strlen(status)+1;
	packet[len++] = (char)31;
	
	if (jobid!=NULL) {
	    if (strlen(jobid)+1>MAX_STR_LEN) return -1;
	    memcpy(&packet[len],jobid,strlen(jobid)+1);
	    len += strlen(jobid)+1;
	    packet[len++] = (char)31;
	}
    }
    packet[len] = '\4';

    int n = write(sockfd, packet, MAX_STR_LEN);
    
    return n;

}

void* getCracking(void* arg) {

    //TODO: manage errors and exits differently (communicate)

    struct user_opt opt;
    struct crack_data cdata;
    struct capture_data capdata;
    struct wpa_eapol_key *eapkeypacket;
    u8 eapolkey_nomic[99];
    struct timeval start, end;
    int ret;
    char passphrase[MAXPASSLEN + 1];

    // clear structs
    memset(&opt,            0, sizeof(struct user_opt));
    memset(&capdata,        0, sizeof(struct capture_data));
    memset(&cdata,          0, sizeof(struct crack_data));
    memset(&eapolkey_nomic, 0, sizeof(eapolkey_nomic));
    
    // Populate capdata struct
    //TODO: check on these sizes
    strncpy(capdata.pcapfilename, currJob.capture_path,
            sizeof(capdata.pcapfilename));
    if (openpcap(&capdata) != 0) {
	logMessage(log_fd,"Unsupported or unrecognized pcap file.\n");
	return NULL;
    }

    //TODO: opt.verbose,opt.checkonly, opt.nonstrict will default to 0
    // for testing purposes
    opt.verbose = 2;
    
    /* populates global *packet */
    while (getpacket(&capdata) > 0) {
	if (opt.verbose > 2) {
	    lamont_hdump(packet, h->len);
	}
	/* test packet for data that we are looking for */
	if (memcmp(&packet[capdata.l2type_offset], DOT1X_LLCTYPE, 2) ==
	    0 && (h->len >
		  capdata.l2type_offset + sizeof(struct wpa_eapol_key))) {
	    /* It's a dot1x frame, process it */
	    handle_dot1x(&cdata, &capdata, &opt);
	    if (cdata.aaset && cdata.spaset && cdata.snonceset &&
		cdata.anonceset && cdata.keymicset
		&& cdata.eapolframeset) {
		/* We've collected everything we need. */
		break;
	    }
	}
    }
    
    closepcap(&capdata);
    
    if (!(cdata.aaset && cdata.spaset && cdata.snonceset &&
	  cdata.anonceset && cdata.keymicset && cdata.eapolframeset)) {
	logMessage(log_fd,"End of pcap capture file, incomplete four-way "
		   "handshake exchange.  Try using a different capture.\n");
	return NULL;
    } else {
	if (cdata.ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
	    logMessage(log_fd, "Collected all necessary data to mount crack"
		   " against WPA2/PSK passphrase.\n");
	} else if (cdata.ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
	    logMessage(log_fd, "Collected all necessary data to mount crack"
		   " against WPA/PSK passphrase.\n");
	}
    }
    
    /*
    if (opt.verbose > 1) dump_all_fields(cdata, &opt);
    
    if (opt.checkonly) {
	// Don't attack the PSK, just return non-error return code
	return 0;
    }
    */
    
    /* Zero mic and length data for hmac-md5 calculation */
    eapkeypacket =
	(struct wpa_eapol_key *)&cdata.eapolframe[EAPDOT1XOFFSET];
    memset(&eapkeypacket->key_mic, 0, sizeof(eapkeypacket->key_mic));
    if (opt.nonstrict == 0) {
	eapkeypacket->key_data_length = 0;
    }
    
    //printf("Starting dictionary attack.  Please be patient.\n");
    //fflush(stdout);

    gettimeofday(&start, 0);
    
    int i;
    struct ssid_table *ssid_entry;
    for (i=0; i<num_ssid; i++) {
            ssid_entry = rainbow_table[i];
            if(!strcmp(ssid_entry->ssid,currJob.ssid))
                break;
    }
    if(i>=num_ssid)
    {
        exit(-1);
    }
    
	ret = hashfile_attack_dist(&opt,passphrase,&cdata,ssid_entry->buffer);
	if (ret==0) {
	    logMessage(log_fd,"SOLUTION FOUND: %s\n",passphrase);
	}
    gettimeofday(&end, 0);
    if (ret!=0) {
	logMessage(log_fd,"NO SOLUTION\n");
    }
    
    status = FINISHED;
    pthread_exit(NULL);
}

int processConnection(int master_socket_fd) {

    int len;                   // number of bytes read from packet
    char buffer[MAX_PKT_LEN];  // packet buffer

    // clear packet buffer
    memset(buffer, 0, MAX_PKT_LEN);

    // read packet
    len = read(master_socket_fd, buffer, MAX_PKT_LEN);
    if (len < 0) {
	logMessage(log_fd,"Error while reading from socket\n");
	return -1;
    }

    int i;            // for loop counter
    int sub_i=0;      // index into sub buffer
    int sub_count=0;  // number of sub buffers

    char message[MAX_STR_LEN];      // command/query message from master
    char jobid[MAX_STR_LEN];        // job ID being queried
    char capture_path[MAX_STR_LEN]; // path to capture file (if applicable)
    char output_path[MAX_STR_LEN];  // path to output directory (if applicable)
    char ssid[MAX_STR_LEN];         // SSID

    // clear buffers
    memset(message,      0, MAX_STR_LEN);
    memset(jobid,        0, MAX_STR_LEN);
    memset(capture_path, 0, MAX_STR_LEN);
    memset(output_path,  0, MAX_STR_LEN);
    memset(ssid,         0, MAX_STR_LEN);
    
    // parse packet
    for (i=0; i<len; i++) {
		if (buffer[i] == (char) 4) {
			logMessage(log_fd,"RECEIVED: %s %s %s %s %s\n",
				   message, jobid, capture_path, output_path, ssid);
			break;
		} else if (buffer[i] == (char) 31) {
			sub_i = 0;
			sub_count++;
		} else {
			switch (sub_count) {
			case 0: message[sub_i]      = buffer[i]; break;
			case 1: jobid[sub_i]        = buffer[i]; break;
			case 2: capture_path[sub_i] = buffer[i]; break;
			case 3: output_path[sub_i]  = buffer[i]; break;
			case 4: ssid[sub_i]         = buffer[i]; break;
			default: break;
			}
			sub_i++;
		}
    }

    if (strcmp(message,"START")==0) {
	// check if a job is running
	if (status==RUNNING) {
	    sendPacket(master_socket_fd,"ERROR",
		       "Another job is still running",NULL);
	    return 0;
	}
	// clear memory
	memset(&currJob,              0,sizeof(struct job));
	memcpy(&currJob.jobid,        &jobid, MAX_STR_LEN);
	memcpy(&currJob.capture_path, &capture_path, MAX_STR_LEN);
	memcpy(&currJob.output_path,  &output_path, MAX_STR_LEN);
	memcpy(&currJob.ssid,         &ssid, MAX_STR_LEN);
	
	// start worker thread
	int ret = pthread_create(&currJob.thread,NULL,getCracking,NULL);
	if (ret<0) {
	    sendPacket(master_socket_fd,"ERROR",
		       "Unable to create thread to perform work",NULL);
	    return 0;
	}
	logMessage(log_fd,"Job started\n");
	// job started successfully
	status = RUNNING;
	sendPacket(master_socket_fd,"STATUS","SUCCESS_START",jobid);
    } else if (strcmp(message,"STATUS")==0) {
	switch(status) {
	case LOADED:
	    sendPacket(master_socket_fd,"STATUS","LOADED",NULL);
	    break;
	case RUNNING:
	    sendPacket(master_socket_fd,"STATUS","RUNNING",jobid);
	    break;
	case FINISHED:
	    sendPacket(master_socket_fd,"STATUS","FINISHED",jobid);
	    break;
	case KILLED:
	    sendPacket(master_socket_fd,"STATUS","KILLED",jobid);
	    break;
	default: 
	    sendPacket(master_socket_fd,"ERROR","Unknown status", NULL);
	    break;
	}
    } else if (strcmp(message,"KILLJOB")==0) {
	int ret = pthread_cancel(currJob.thread);
	if (ret == 0) {
	    status = KILLED;
	    sendPacket(master_socket_fd,"STATUS","KILLED",jobid);
	} else if (errno == ESRCH) {
	    //TODO: this may mean that the job finished already
	    sendPacket(master_socket_fd,"ERROR","No such job exists",NULL);
	} else {
	    sendPacket(master_socket_fd,"ERROR",
		       "Kill command failed for unknown reason",NULL);
	}
    }

    return 0;
}

void* listenForPacket(void* arg1) {

    int ret;
    int worker_socket_fd,master_socket_fd;
    struct sockaddr_in worker_addr,master_addr;
    socklen_t master_len;

    // create socket using IPv4 protocol
    worker_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (worker_socket_fd < 0) {
	logMessage(log_fd,"Unable to open socket\n");
	return NULL;
    }

    // set up address for socket
    memset(&worker_addr, 0, sizeof(worker_addr));
    worker_addr.sin_family = AF_INET;
    worker_addr.sin_addr.s_addr = INADDR_ANY;
    worker_addr.sin_port = htons(port_num);

    // bind address to socket
    if (bind(worker_socket_fd, (struct sockaddr *) &worker_addr,
	     sizeof(worker_addr)) < 0) {
	logMessage(log_fd,"Unable to bind address to socket\n");
	return NULL;
    }

    // set up socket to listen
    listen(worker_socket_fd, 0);
    
    // init size of master address
    master_len = sizeof(master_addr);

    // loop until we receive a packet
    while(1) {
	// accept connection from some client
	master_socket_fd = accept(worker_socket_fd,
				  (struct sockaddr *) &master_addr,
				  &master_len);
	if (master_socket_fd < 0) 
	    logMessage(log_fd,"Error occurred on accept\n");

	// process connection from master
	ret = processConnection(master_socket_fd);
	// close connection
	ret = close(master_socket_fd);
	if (ret<0) logMessage(log_fd,"Unable to close connection\n");
    }
}

int loadRainbowTable(char *path) {

    int index=0;
    int fd;                      // file descriptor of files in directory
    int ret;                     // return value
    int count;                   // number of files to read through
    DIR *dir;                    // directory to search
    size_t len;		         // number of bytes to read from each file
    struct dirent *dirent;	 // directory entry
    char temp_path[MAX_STR_LEN]; // temp var for building path
    //unsigned char* buffer;	 
    struct ssid_table *ssid_entry;
    //unsigned char* ssid_name;

    // open directory to search
    dir = opendir(path);
    if (dir==NULL) return -1;
    
    // count the number of files to read
    count=0;
    while ((dirent = readdir(dir))!=NULL) {
	// ignore entries that aren't regular files
	//if (dirent->d_type != DT_REG) continue;
	logMessage(log_fd, "testing dirent %s\n", dirent->d_name);
	count++;
    }
    logMessage(log_fd, "Found %d dirents in %s\n", count, path);

    // rewind dirent pointer to beginning
    rewinddir(dir);

    // allocate memory for pointers to file chunks
    rainbow_table = (struct ssid_table**)malloc(count*sizeof(struct ssid_table*));
    if (rainbow_table==NULL) return -1;

    // open entries in directory
    while ((dirent = readdir(dir))!=NULL) {
	// ignore entries that aren't regular files
	//if (dirent->d_type != DT_REG) continue;

	// create path to file
	memset(temp_path,0,MAX_STR_LEN);
	snprintf(temp_path,MAX_STR_LEN,"%s/%s",path,dirent->d_name);
	logMessage(log_fd, "Trying path %s\n", temp_path);
    
	// allocate memory to ssid entry and ssid name
	ssid_entry = (struct ssid_table*)malloc(sizeof(struct ssid_table));
	ssid_entry->ssid = (char*)malloc(strlen(dirent->d_name)*sizeof(char));
	
	//copy hash file name to ssid name
	strcpy(ssid_entry->ssid, dirent->d_name);
    
	// open file
	fd = open(temp_path,O_RDONLY);
	if (fd<0) return -1;

	// seek to proper position
	ret = lseek(fd, start_offset, SEEK_SET);
	if (ret<0) return -1;

	// read in chunk of file
	len = end_offset-start_offset+1;
	ssid_entry->buffer = (unsigned char*)malloc(len*sizeof(unsigned char));
	if (ssid_entry->buffer==NULL) return -1;
	ret = read(fd, ssid_entry->buffer, len);
	//TODO: check number of bytes actually read
	if (ret<0) return -1;
	rainbow_table[index] = ssid_entry;
	
	// close file
	ret = close(fd);
	if (ret<0) return -1;

	index++;
    }
    // close directory
    ret = closedir(dir);
    if (ret<0) return -1;

    return count;
}

int parseOptsDist(int argc, char **argv) {

    static struct option long_options[] = {
	{"cluster-port",                         1, 0, 'p'},
	{"cluster-rainbow-table",                1, 0, 't'},
	{"cluster-rainbow-table-start-offset",   1, 0, 's'},
	{"cluster-rainbow-table-end-offset",     1, 0, 'e'},
	{"cluster-log",                          1, 0, 'l'},
	{"cluster-rainbow-table-number-records", 1, 0, 'n'},
	{"cluster-rainbow-table-record-start",   1, 0, 'a'},
	{"cluster-rainbow-table-record-end",     1, 0, 'd'},
	{"cluster-node-count",                   1, 0, 'c'},
	{"cluster-node-rank",                    1, 0, 'r'},
	{0,0,0,0}
    };
    int option_index = 0;
    int c;
    
    memset(&rainbow_table_path, 0, sizeof(rainbow_table_path));

    while ((c = getopt_long(argc, argv, "p:t:s:e:l:n:a:d:c:r:",long_options, 
			    &option_index)) != EOF) {
	switch (c) {
	case 'p':
	    port_num = strtol(optarg,NULL,10);
	    if (errno!=0 || port_num<0) return -1;
	    break;
	case 't':
	    strncpy(rainbow_table_path, optarg, sizeof(rainbow_table_path));
	    break;
	case 's':
	    start_offset = strtol(optarg,NULL,10);
	    if (errno!=0 || start_offset<0) return -1;
	    break;
	case 'e':
	    end_offset = strtol(optarg,NULL,10);
	    if (errno!=0 || end_offset<0) return -1;
	    break;
	case 'l':
	    printf("optarg: %s\n", optarg);
	    log_fd = open(optarg,O_RDWR|O_CREAT|O_APPEND,
			  S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	    if (log_fd<0) return -1;
	    break;
	case 'n':
	    //TODO: fill this in
	    break;
	case 'a':
	    //TODO: fill this in
	    break;
	case 'd':
	    //TODO: fill this in
	    break;
	case 'c':
	    node_count = strtol(optarg,NULL,10);
	    if (errno!=0 || node_count<0) return -1;
	    break;	    
	case 'r':
	    node_rank = strtol(optarg,NULL,10);
	    if (errno!=0 || node_rank<0) return -1;
	    break;
	default:
	    printf("incorrect argument(s)\n");
	    return -1;
	}
    }
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s %s - WPA-PSK dictionary attack. <jwright@hasborg.com>\n",
	   PROGNAME, VER);

    // parse arguments and test
    parseOptsDist(argc,argv);
    //TODO: test opts
    logMessage(log_fd,"Command line arguments parsed\n");

    // load rainbow table into memory
    int ret = loadRainbowTable(rainbow_table_path);
    if (ret<0) {
	logMessage(log_fd,"Unable to load rainbow table\n");
        exit(EXIT_FAILURE);
    } else {
	status = LOADED;
	logMessage(log_fd,"Rainbow table loaded with %d SSIDs\n", num_ssid);
    }
    num_ssid = ret;

    // create thread for communication
    pthread_t comm_thread;
    ret = pthread_create(&comm_thread,NULL,listenForPacket,NULL);
    if (ret!=0) {
	logMessage(log_fd,"Failed to create communication thread\n");
	exit(EXIT_FAILURE);
    }
    //TODO: possibly register clean up calls

    // exit when comm thread finishes
    pthread_join(comm_thread,NULL);
    exit(EXIT_SUCCESS);

    // old cowpatty main code
    /*
    struct user_opt opt;
    struct crack_data cdata;
    struct capture_data capdata;
    struct wpa_eapol_key *eapkeypacket;
    u8 eapolkey_nomic[99];
    struct timeval start, end;
    int ret;
    char passphrase[MAXPASSLEN + 1];
    
    memset(&opt, 0, sizeof(struct user_opt));
    memset(&capdata, 0, sizeof(struct capture_data));
    memset(&cdata, 0, sizeof(struct crack_data));
    memset(&eapolkey_nomic, 0, sizeof(eapolkey_nomic));
    
    // Collect and test command-line arguments
    parseopts(&opt, argc, argv);
    testopts(&opt);
    printf("\n");
    
    // Populate capdata struct
    strncpy(capdata.pcapfilename, opt.pcapfile,
            sizeof(capdata.pcapfilename));
    if (openpcap(&capdata) != 0) {
	printf("Unsupported or unrecognized pcap file.\n");
	exit(-1);
    }
    
    // populates global *packet
    while (getpacket(&capdata) > 0) {
	if (opt.verbose > 2) {
	    lamont_hdump(packet, h->len);
	}
	// test packet for data that we are looking for
	if (memcmp(&packet[capdata.l2type_offset], DOT1X_LLCTYPE, 2) ==
	    0 && (h->len >
		  capdata.l2type_offset + sizeof(struct wpa_eapol_key))) {
	    // It's a dot1x frame, process it
	    handle_dot1x(&cdata, &capdata, &opt);
	    if (cdata.aaset && cdata.spaset && cdata.snonceset &&
		cdata.anonceset && cdata.keymicset
		&& cdata.eapolframeset) {
		// We've collected everything we need.
		break;
	    }
	}
    }
    
    closepcap(&capdata);
    
    if (!(cdata.aaset && cdata.spaset && cdata.snonceset &&
	  cdata.anonceset && cdata.keymicset && cdata.eapolframeset)) {
	printf("End of pcap capture file, incomplete four-way handshake "
	       "exchange.  Try using a\ndifferent capture.\n");
	exit(-1);
    } else {
	if (cdata.ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
	    printf("Collected all necessary data to mount crack"
		   " against WPA2/PSK passphrase.\n");
	} else if (cdata.ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
	    printf("Collected all necessary data to mount crack"
		   " against WPA/PSK passphrase.\n");
	}
    }
    
    if (opt.verbose > 1) {
	dump_all_fields(cdata, &opt);
    }
    
    if (opt.checkonly) {
	// Don't attack the PSK, just return non-error return code
	return 0;
    }
    
    // Zero mic and length data for hmac-md5 calculation
    eapkeypacket =
	(struct wpa_eapol_key *)&cdata.eapolframe[EAPDOT1XOFFSET];
    memset(&eapkeypacket->key_mic, 0, sizeof(eapkeypacket->key_mic));
    if (opt.nonstrict == 0) {
	eapkeypacket->key_data_length = 0;
    }
    
    printf("Starting dictionary attack.  Please be patient.\n");
    fflush(stdout);
    
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGQUIT, cleanup);
    
    gettimeofday(&start, 0);
    
    if (!IsBlank(opt.hashfile)) {
	ret = hashfile_attack(&opt, passphrase, &cdata);
    } else if (!IsBlank(opt.dictfile)) {
	ret = dictfile_attack(&opt, passphrase, &cdata);
    } else {
	usage("Must specify dictfile or hashfile (-f or -d)");
	exit(-1);
    }
    
    if (ret == 0) {
	printf("\nThe PSK is \"%s\".\n", passphrase);
	gettimeofday(&end, 0);
	printstats(start, end, wordstested);
	return 0;
    } else {
	printf("Unable to identify the PSK from the dictionary file. " 
	       "Try expanding your\npassphrase list, and double-check"
	       " the SSID.  Sorry it didn't work out.\n");
	gettimeofday(&end, 0);
	printstats(start, end, wordstested);
	return 1;
    }
    
    return 1;
    */
}
