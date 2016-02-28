/*
 * sng_ss7mon
 *
 * SS7 message monitor for Sangoma devices
 *
 * Moises Silva <moises.silva@gmail.com>
 * Copyright (C) System One NOC
 * Copyright (C) N-SOFT
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contributors:
 *
 */

#include <syslog.h>
#include <sys/resource.h>
#include <libsangoma.h>
#include <zmq.h>
#include "wanpipe_hdlc.h"
#include "os.h"

#define SS7MON_SAFE_WAIT 5
#define sng_ss7mon_test_bit(bit, map) ((map) & (1 << bit)) 
#define ss7mon_arraylen(_array) sizeof(_array)/sizeof(_array[0])

typedef enum _ss7mon_log_level {
	SS7MON_DEBUG = 0,
	SS7MON_INFO,
	SS7MON_WARNING,
	SS7MON_ERROR,
} ss7mon_log_level_t;

static struct {
	const char *name;
	ss7mon_log_level_t level;
	int syslog;
} ss7mon_log_levels[] = {
	{ "DEBUG", SS7MON_DEBUG, LOG_DEBUG },
	{ "INFO", SS7MON_INFO, LOG_INFO },
	{ "WARNING", SS7MON_WARNING, LOG_WARNING },
	{ "ERROR", SS7MON_ERROR, LOG_ERR },
};
#define ss7mon_log(level, format, ...) \
	do { \
		if (level >= globals.loglevel) { \
			if (link && link->spanno >= 0) { \
				fprintf(stdout, "[%s] [s%dc%d] " format, ss7mon_log_levels[level].name, link->spanno, link->channo, ##__VA_ARGS__); \
			} else { \
				fprintf(stdout, "[%s] " format, ss7mon_log_levels[level].name, ##__VA_ARGS__); \
			} \
		} \
		if (globals.syslog_enable) { \
			if (link && link->spanno >= 0) { \
				syslog(ss7mon_log_levels[level].syslog, "[s%dc%d] " format, link->spanno, link->channo, ##__VA_ARGS__); \
			} else { \
				syslog(ss7mon_log_levels[level].syslog, format, ##__VA_ARGS__); \
			} \
		} \
	} while (0)


#define SS7MON_US_IN_SECOND 1000000
#define SS7MON_DEFAULT_TX_QUEUE_SIZE 500
#define SS7MON_DEFAULT_RX_QUEUE_SIZE 500
#define SS7MON_DEFAULT_RX_QUEUE_WATERMARK 60
#define SS7MON_DEFAULT_MTP2_MTU 300 /* Max MSU pack should be 272 per spec, give a bit of more room */
#define SS7MON_MAX_PCR_RTB_SIZE 128 /* RTB cannot store more than 128 MSUs because the FSN and BSN are 
				       cyclic binary counts going from 0 to 127, except for HSL (High Speed Links), which we 
				       don't support anyways */
#define SS7MON_DEFAULT_PCR_RTB_SIZE 128 /* Default retransmission buffer (RTB) for PCR (Preventive Cyclic Retransmission) error correction */

/* PCAP file magic identifier number */
#define SS7MON_PCAP_MAGIC 0xa1b2c3d4

/* http://www.tcpdump.org/linktypes.html, LINKTYPE_MTP2 (140), LINKTYPE_MTP2_WITH_PHDR (139) */
#define SS7MON_PCAP_LINKTYPE_MTP2 140
#define SS7MON_PCAP_LINKTYPE_MTP2_WITH_PHDR 139

/* http://wiki.wireshark.org/Development/LibpcapFileFormat  */
typedef struct pcap_hdr {
	uint32_t magic; /* magic */
	uint16_t version_major; /* major version number */
	uint16_t version_minor; /* minor version number */
	uint32_t thiszone; /* GMT to local correction */
	uint32_t sigfigs; /* accuracy of timestamps */
	uint32_t snaplen; /* max length of captured packets, in octets */
	uint32_t network; /* data link type */
} pcap_hdr_t;

typedef struct pcap_record_hdr {
	uint32_t ts_sec; /* timestamp seconds */
	uint32_t ts_usec; /* timestamp microseconds */
	uint32_t incl_len; /* length of packet as saved */
	uint32_t orig_len; /* length of the packet as seen in the network */
} pcap_record_hdr_t;

typedef struct _msu_buf {
	char *buf;
	int16_t len;
	struct _msu_buf *next;
	struct _msu_buf *prev;
} msu_buf_t;

struct _globals {
	char server_addr[512];
	int rxq_watermark; /* When to warn about queue overflow (percentage) */
	int txq_size; /* Tx queue size */
	int rxq_size; /* Rx queue size */
	int loglevel; /* Current logging level */
	volatile uint8_t running; /* Monitor application is running */
	const char *pcap_file_p; /* File name or prefix for pcap file(s) */
	const char *pcap_tx_file_p; /* File name of the tx pcap file (if any) */
	int pcap_mtp2_link_type; /* MTP2 pcap type */
	uint8_t swhdlc_enable; /* whether software HDLC should be performed in user space */
	uint8_t syslog_enable; /* whether to use syslog for logging (in addition to stdout) */
	uint8_t fisu_enable; /* whether to include FISU frames in the output */
	uint8_t lssu_enable; /* whether to include LSSU frames in the output */
	const char *hexdump_file_p; /* hexdump file name or prefix */
	uint8_t hexdump_flush_enable; /* Flush the file as every hex packet is received */
	int watchdog_seconds; /* time to wait before warning about no messages being received */
	int32_t mtp2_mtu; /* MTP2 max transfer unit */
	uint8_t pcr_enable; /* Enable PCR support to avoid reporting retransmitted frames */
	int32_t pcr_rtb_size; /* PCR retransmission buffer size */
	uint8_t rotate_request; /* Request to rotate all link files */
} globals = {
	.server_addr = { 0 },
	.rxq_watermark = SS7MON_DEFAULT_RX_QUEUE_WATERMARK,
	.txq_size = SS7MON_DEFAULT_TX_QUEUE_SIZE,
	.rxq_size = SS7MON_DEFAULT_RX_QUEUE_SIZE,
	.loglevel = SS7MON_WARNING,
	.running = 0,
	.pcap_file_p = NULL,
	.pcap_tx_file_p = NULL,
 	.pcap_mtp2_link_type = SS7MON_PCAP_LINKTYPE_MTP2,
	.swhdlc_enable = 0,
	.syslog_enable = 0,
	.fisu_enable = 0,
	.lssu_enable = 0,
	.hexdump_file_p = NULL,
	.hexdump_flush_enable = 0,
	.watchdog_seconds = 300,
	.mtp2_mtu = SS7MON_DEFAULT_MTP2_MTU,
	.pcr_enable = 0,
	.pcr_rtb_size = 0,
	.rotate_request = 0,
};

typedef struct _ss7link_context {
	char *dev; /* Device name */
	int spanno; /* TDM device span number */
	int channo; /* TDM device channel number */
	int fd; /* TDM device file descriptor */
	uint8_t connected; /* E1 link is connected */
	int rx_errors; /* Number of errors */
	wanpipe_hdlc_engine_t *wanpipe_hdlc_decoder; /* HDLC engine when done in software */
	char *pcap_file_name; /* pcap file name */
	FILE *pcap_file; /* pcap file to write MTP2 frames to */
	FILE *tx_pcap_file; /* pcap file where to read MTP2 frames from */
	pcap_record_hdr_t tx_pcap_hdr; /* next pcap record to transmit */
	int tx_pcap_cnt; /* number of frames transmitted */
	struct timespec tx_pcap_next_delivery; /* time to next frame delivery */
	uint8_t rotate_request; /* request to rotate dump files */
	int rotate_cnt; /* number of rotated files */
	/* Message counters */
	uint64_t fisu_cnt;
	uint64_t lssu_cnt;
	uint64_t msu_cnt;
	char *hexdump_file_name; /* hexdump file name */
	FILE *hexdump_file;
	int32_t consecutive_read_errors; /* How many read errors have we had in a row */
	time_t last_recv_time; /* seconds since the last message was received */
	uint64_t missing_msu_periods; /* how many -watchdog_seconds- periods have passed without receiving messages */
	uint8_t link_aligned; /* whether the SS7 link is aligned (FISUs or MSUs flowing) */
	uint8_t link_probably_dead; /* Whether the SS7 link is probably dead (incorrectly tapped or something) */
	unsigned char *mtp2_buf; /* MTP2 buffer */
	uint8_t fisu_enable; /* whether to include FISU frames in the output */
	uint8_t lssu_enable; /* whether to include LSSU frames in the output */
	uint8_t pcr_enable; /* Enable PCR support to avoid reporting retransmitted frames */
	int watchdog_seconds; /* time to wait before warning about no messages being received */
	uint8_t watchdog_ready; /* Watchdog notification ready */
	msu_buf_t *pcr_bufs; /* PCR buffers linked list */
	msu_buf_t *pcr_curr_msu; /* latest received MSU */
	os_thread_t *thread; /* Running thread */
	/* Link them together */
	struct _ss7link_context *next;
} ss7link_context_t;

static ss7link_context_t *ss7link_context_new(int span, int chan)
{
#define MAX_FILE_PATH 1024
	ss7link_context_t *link = NULL;
	ss7link_context_t slink = { 0 };
	slink.spanno = span;
	slink.channo = chan;
	slink.fd = -1;
	slink.rotate_cnt = 1;
	slink.fisu_enable = globals.fisu_enable;
	slink.lssu_enable = globals.lssu_enable;
	slink.pcr_enable = globals.pcr_enable;
	slink.watchdog_seconds = globals.watchdog_seconds;
	slink.hexdump_file_name = os_calloc(1, MAX_FILE_PATH);
	slink.pcap_file_name = os_calloc(1, MAX_FILE_PATH);
	if (globals.hexdump_file_p) {
		snprintf(slink.hexdump_file_name, MAX_FILE_PATH, "%s_%d-%d.hex",
				globals.hexdump_file_p, span, chan);
	}
	if (globals.pcap_file_p) {
		snprintf(slink.pcap_file_name, MAX_FILE_PATH, "%s_%d-%d.pcap",
				globals.pcap_file_p, span, chan);
	}
	/* All went good, return a dynamic persistent copy of the link */
	link = os_calloc(1, sizeof(*link));
	memcpy(link, &slink, sizeof(*link));
	return link;
}

static void ss7link_context_destroy(ss7link_context_t **link_p)
{
	ss7link_context_t *link = *link_p;
	os_free(link->hexdump_file_name);
	os_free(link->pcap_file_name);
	os_free(link);
	*link_p = NULL;
}

static void write_pcap_header(ss7link_context_t *link)
{
	size_t wrote = 0;
	pcap_hdr_t hdr;

	hdr.magic = SS7MON_PCAP_MAGIC;
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.thiszone = 0;
	hdr.sigfigs = 0;
	hdr.snaplen = 65535;
	hdr.network = globals.pcap_mtp2_link_type;
	wrote = fwrite(&hdr, sizeof(hdr), 1, link->pcap_file);
	if (!wrote) {
		ss7mon_log(SS7MON_ERROR, "Failed writing pcap header!\n");
	}
}

static void write_hexdump_packet(FILE *f, void *packet_buffer, int len)
{
	struct timespec ts;
	int row_size = 16;
	int i = 0;
	uint8_t *byte_stream = packet_buffer;

	clock_gettime(CLOCK_REALTIME, &ts);

	fprintf(f, "Frame len = %d Timestamp = %llu.%09llu\n", len, (unsigned long long)ts.tv_sec, (unsigned long long)ts.tv_nsec);
	for (i = 1; i <= len; i++) {
		fprintf(f, "%02X ", byte_stream[i-1]);
		if (!(i % row_size)) {
			fprintf(f, "\n");
		}
	}
	fprintf(f, "\n\n");
	if (globals.hexdump_flush_enable) {
		fflush(f);
	}
}

#define SS7MON_MTP2_SENT_OFFSET 0 /* 1 byte */
#define SS7MON_MTP2_ANNEX_A_USED_OFFSET 1 /* 1 byte */
#define SS7MON_MTP2_LINK_NUMBER_OFFSET 2 /* 2 bytes */
#define SS7MON_MTP2_HDR_LEN 4
static void write_pcap_packet(ss7link_context_t *link, FILE *f, void *packet_buffer, int packet_len)
{
	size_t wrote = 0;
	struct timespec ts;
	char mtp2_hdr[SS7MON_MTP2_HDR_LEN];
	pcap_record_hdr_t hdr;

	clock_gettime(CLOCK_REALTIME, &ts);

	if (globals.pcap_mtp2_link_type == SS7MON_PCAP_LINKTYPE_MTP2_WITH_PHDR) {
		packet_len += sizeof(mtp2_hdr);
	}
	hdr.ts_sec = ts.tv_sec;
	hdr.ts_usec = (ts.tv_nsec / 1000);
	hdr.incl_len = packet_len;
	hdr.orig_len = packet_len;
	wrote = fwrite(&hdr, 1, sizeof(hdr), f);
	if (wrote != sizeof(hdr)) {
		ss7mon_log(SS7MON_ERROR, "Failed writing pcap packet header: wrote %zd out of %zd btyes, %s\n", 
				wrote, sizeof(hdr), strerror(errno));
		return;
	}

	if (globals.pcap_mtp2_link_type == SS7MON_PCAP_LINKTYPE_MTP2_WITH_PHDR) {
#if 0
		mtp2_hdr[SS7MON_MTP2_SENT_OFFSET] = 0;
		mtp2_hdr[SS7MON_MTP2_ANNEX_A_USED_OFFSET] = 0;
		mtp2_hdr[SS7MON_MTP2_LINK_NUMBER_OFFSET] = 0;
#endif
		memset(mtp2_hdr, 0, sizeof(mtp2_hdr));
		wrote = fwrite(mtp2_hdr, 1, sizeof(mtp2_hdr), f);
		if (wrote != sizeof(mtp2_hdr)) {
			ss7mon_log(SS7MON_ERROR, "Failed writing pcap MTP2 packet header: wrote %zd out of %zd btyes, %s\n", 
					wrote, sizeof(mtp2_hdr), strerror(errno));
			return;
		}
		packet_len -= sizeof(mtp2_hdr);
	}

	wrote = fwrite(packet_buffer, 1, packet_len, f);
	if (wrote != packet_len) {
		ss7mon_log(SS7MON_ERROR, "Failed writing pcap packet: wrote %zd out of %d btyes, %s\n", 
				wrote, packet_len, strerror(errno));
	}
}

static int tx_pcap_frame(ss7link_context_t *link)
{
	struct timespec ts;
	pcap_record_hdr_t next_hdr;
	os_size_t bytes_read = 0;
	int bytes_sent = 0;
	time_t diff_sec = 0;
	long diff_usec = 0;
	size_t elements = 0;
	wp_tdm_api_tx_hdr_t hdrframe;
	char data[MAX_SOCK_HDLC_BUF];
	char errbuf[512];

	/* get current time */
	clock_gettime(CLOCK_REALTIME, &ts);

	/* check next delivery time */
	if (link->tx_pcap_next_delivery.tv_sec) {
		if (link->tx_pcap_next_delivery.tv_sec >= ts.tv_sec) {
			return 0;
		}
		if ((link->tx_pcap_next_delivery.tv_sec == ts.tv_sec) &&
			link->tx_pcap_next_delivery.tv_nsec > ts.tv_nsec) {
			return 0;
		}
		/* time to deliver! */
	}

	/* read header now if this is the first time we transmit a frame */
	if (!link->tx_pcap_cnt) {
		elements = fread(&link->tx_pcap_hdr, sizeof(link->tx_pcap_hdr), 1, link->tx_pcap_file);
		if (elements != 1) {
			strerror_r(errno, errbuf, sizeof(errbuf));
			ss7mon_log(SS7MON_ERROR, "Failed to read tx pcap frame hdr: %s\n", errbuf);
			goto done_tx;
		}
	}

	if (link->tx_pcap_hdr.incl_len > sizeof(data)) {
		ss7mon_log(SS7MON_ERROR, "tx pcap frame too big: %d bytes\n", link->tx_pcap_hdr.incl_len);
		goto done_tx;
	}

	/* if this is a pcap packet with an MTP2 enclosing, drop it */
	if (globals.pcap_mtp2_link_type == SS7MON_PCAP_LINKTYPE_MTP2_WITH_PHDR) {
		bytes_read = fread(data, 1, SS7MON_MTP2_HDR_LEN, link->tx_pcap_file);
		if (bytes_read != SS7MON_MTP2_HDR_LEN) {
			ss7mon_log(SS7MON_ERROR, "failed to read tx pcap frame MTP2 header: %s\n", strerror(errno));
			goto done_tx;
		}
		link->tx_pcap_hdr.incl_len -= SS7MON_MTP2_HDR_LEN;
	}

	bytes_read = fread(data, 1, link->tx_pcap_hdr.incl_len, link->tx_pcap_file);
	if (bytes_read != link->tx_pcap_hdr.incl_len) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		ss7mon_log(SS7MON_ERROR, "failed to read tx pcap frame: %s\n", errbuf);
		goto done_tx;
	}

	/* read the actual frame data and transmit it */
	memset(&hdrframe, 0, sizeof(hdrframe));
	bytes_sent = sangoma_writemsg(link->fd, &hdrframe, sizeof(hdrframe), data, link->tx_pcap_hdr.incl_len, 0);
	if (bytes_sent != link->tx_pcap_hdr.incl_len) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		ss7mon_log(SS7MON_ERROR, "Failed to transmit pcap frame: %s\n", errbuf);
		goto done_tx;
	}
	link->tx_pcap_cnt++;
	ss7mon_log(SS7MON_DEBUG, "Tx frame: %d [%d bytes]\n", link->tx_pcap_cnt, bytes_sent);

	/* calculate next delivery time by reading next header */
	elements = fread(&next_hdr, sizeof(next_hdr), 1, link->tx_pcap_file);
	if (elements != 1) {
		if (feof(link->tx_pcap_file)) {
			ss7mon_log(SS7MON_INFO, "Ended pcap transmission\n");
			goto done_tx;
		}
		strerror_r(errno, errbuf, sizeof(errbuf));
		ss7mon_log(SS7MON_ERROR, "Failed to read next tx pcap frame hdr: %s\n", errbuf);
		goto done_tx;
	}

	diff_sec = next_hdr.ts_sec - link->tx_pcap_hdr.ts_sec;
	if (!diff_sec || (next_hdr.ts_usec >= link->tx_pcap_hdr.ts_usec)) {
		diff_usec = next_hdr.ts_usec - link->tx_pcap_hdr.ts_usec;
	} else {
		diff_sec--;
		diff_usec = next_hdr.ts_usec;
		diff_usec += (SS7MON_US_IN_SECOND - link->tx_pcap_hdr.ts_usec);
	}

	clock_gettime(CLOCK_REALTIME, &link->tx_pcap_next_delivery);
	link->tx_pcap_next_delivery.tv_sec += diff_sec;
	link->tx_pcap_next_delivery.tv_nsec += (diff_usec * 1000);

	/* save next header to be used on next delivery time */
	memcpy(&link->tx_pcap_hdr, &next_hdr, sizeof(link->tx_pcap_hdr));

	ss7mon_log(SS7MON_DEBUG, "Next frame to be delivered in %ld, diff_sec = %ld, diff_usec = %ld\n", 
			link->tx_pcap_next_delivery.tv_sec, diff_sec, diff_usec);
	return 0;

done_tx:

	fclose(link->tx_pcap_file);
	link->tx_pcap_file = NULL;
	link->tx_pcap_next_delivery.tv_sec = 0;
	link->tx_pcap_next_delivery.tv_nsec = 0;

	return 0;
}

static void ss7mon_handle_oob_event(ss7link_context_t *link)
{
	char errbuf[512];
	wanpipe_api_t tdm_api = { 0 };
	wp_api_event_t *wp_event = NULL;

	if (sangoma_read_event(link->fd, &tdm_api)) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		ss7mon_log(SS7MON_ERROR, "Failed to read event from device: %s\n", errbuf);
		return;
	}
	wp_event = &tdm_api.wp_cmd.event;

	switch (wp_event->wp_api_event_type) {
	case WP_API_EVENT_LINK_STATUS:
		switch (wp_event->wp_api_event_link_status) {
		case WP_API_EVENT_LINK_STATUS_CONNECTED:
			link->connected = 1;
			ss7mon_log(SS7MON_INFO, "Line Connected\n");
			sangoma_tdm_flush_bufs(link->fd, &tdm_api);
			sangoma_flush_stats(link->fd, &tdm_api);
			break;
		case WP_API_EVENT_LINK_STATUS_DISCONNECTED:
			link->connected = 0;
			ss7mon_log(SS7MON_WARNING, "Line Disconnected\n");
			break;
		default:
			ss7mon_log(SS7MON_ERROR, "Unknown link status: %d\n", wp_event->wp_api_event_link_status);
			break;
		}
		break;
	case WP_API_EVENT_ALARM:
		ss7mon_log(SS7MON_DEBUG, "Alarm raised\n");
		break;
	default:
		ss7mon_log(SS7MON_ERROR, "Unknown event: %d\n", wp_event->wp_api_event_type);
		break;
	}
}

#define SS7MON_MAX_CONSECUTIVE_READ_ERRORS 100
static int ss7mon_handle_hdlc_frame(ss7link_context_t *link, void *frame_data, int len);
static void ss7mon_handle_input(ss7link_context_t *link)
{
	wp_api_hdr_t rxhdr;
	char errbuf[512];
	int mlen = 0;
	int queue_level = 0;
	unsigned char *buf = link->mtp2_buf;
	do {
		memset(buf, 0, globals.mtp2_mtu);
		memset(&rxhdr, 0, sizeof(rxhdr));
		mlen = sangoma_readmsg(link->fd, &rxhdr, sizeof(rxhdr), buf, globals.mtp2_mtu, 0);
		if (mlen < 0) {
			int op_errno = errno;
			strerror_r(op_errno, errbuf, sizeof(errbuf));
			ss7mon_log(SS7MON_ERROR, "Error reading SS7 message: %s (errno=%d, %s)\n", 
					SDLA_DECODE_SANG_STATUS(rxhdr.operation_status), op_errno, errbuf);
			link->consecutive_read_errors++;
			if (link->consecutive_read_errors >= SS7MON_MAX_CONSECUTIVE_READ_ERRORS) {
				ss7mon_log(SS7MON_ERROR, "Max consecutive read errors reached, closing fd!\n");
				sangoma_close(&link->fd);
			}
			return;
		}
		link->consecutive_read_errors = 0;

		if (mlen == 0) {
			ss7mon_log(SS7MON_ERROR, "Read empty message\n");
			return;
		}

		/*ss7mon_log(SS7MON_DEBUG, "Read HDLC frame of size %d\n", mlen);*/
		if (rxhdr.wp_api_rx_hdr_errors > link->rx_errors) {
			int print_errors = 0;
			if (link->rx_errors) {
				print_errors = 1;
			}
			link->rx_errors = rxhdr.wp_api_rx_hdr_errors;
			if (print_errors) {
				ss7mon_log(SS7MON_ERROR, "Rx errors: %d\n", link->rx_errors);
			}
		}

		if (rxhdr.wp_api_rx_hdr_error_map) {
			ss7mon_log(SS7MON_ERROR, "Rx error map 0x%X\n", rxhdr.wp_api_rx_hdr_error_map);
			if (sng_ss7mon_test_bit(WP_FIFO_ERROR_BIT, rxhdr.wp_api_rx_hdr_error_map)) {
				ss7mon_log(SS7MON_ERROR, "HDLC FIFO Error\n");
			}
			if (sng_ss7mon_test_bit(WP_CRC_ERROR_BIT, rxhdr.wp_api_rx_hdr_error_map)) {
				ss7mon_log(SS7MON_ERROR, "HDLC CRC Error\n");
			}
			if (sng_ss7mon_test_bit(WP_ABORT_ERROR_BIT, rxhdr.wp_api_rx_hdr_error_map)) {
				ss7mon_log(SS7MON_ERROR, "HDLC Abort Error\n");
			}
			if (sng_ss7mon_test_bit(WP_FRAME_ERROR_BIT, rxhdr.wp_api_rx_hdr_error_map)) {
				ss7mon_log(SS7MON_ERROR, "HDLC Frame Error\n");
			}
			if (sng_ss7mon_test_bit(WP_DMA_ERROR_BIT, rxhdr.wp_api_rx_hdr_error_map)) {
				ss7mon_log(SS7MON_ERROR, "HDLC DMA Error\n");
			}
		} else if (link->connected) {
			/* Feed the software HDLC engine or report the new HDLC frame in the case of HW HDLC */
			if (globals.swhdlc_enable) {
				/*ss7mon_log(SS7MON_DEBUG, "Feeding hdlc engine %d bytes of data\n", mlen);*/
				/* fill in data to the HDLC engine */
				wanpipe_hdlc_decode(link->wanpipe_hdlc_decoder, buf, mlen);
			} else {
				/* HDLC frame comes already in the read data from the wanpipe device*/
				ss7mon_handle_hdlc_frame(link, buf, mlen);
			}
		}

		queue_level = (rxhdr.wp_api_rx_hdr_number_of_frames_in_queue * 100) / (rxhdr.wp_api_rx_hdr_max_queue_length);
		if (queue_level >= globals.rxq_watermark) {
			ss7mon_log(SS7MON_WARNING,
					"Rx queue is %d%% full (number of frames in queue = %d, max queue length = %d, connected = %d)\n",
					queue_level, rxhdr.wp_api_rx_hdr_number_of_frames_in_queue,
					rxhdr.wp_api_rx_hdr_max_queue_length, link->connected);
		}
	} while (rxhdr.wp_api_rx_hdr_number_of_frames_in_queue > 1);
}

static int rotate_file(ss7link_context_t *link,
					   FILE **file, const char *fname,
					   const char *fmode, const char *ftype, int rotate_cnt)
{
	char errbuf[255];
	int rc = 0;
	char *new_name = os_calloc(1, strlen(fname) + 25);
	if (!new_name) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		ss7mon_log(SS7MON_ERROR, "Failed to allocate new name string: %s, name = %s\n", errbuf, fname);
		return -1;
	}
	if (fclose(*file) != 0) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		ss7mon_log(SS7MON_ERROR, "Failed to close %s file: %s\n", ftype, errbuf);
		/* continue anyways, do not return, we may still be able to rotate ... */
	}
	*file = NULL;
	sprintf(new_name, "%s.%i", fname, rotate_cnt);
	if (rename(fname, new_name)) {
		ss7mon_log(SS7MON_ERROR, "Failed to rename %s file %s to %s: %s\n", 
				ftype, fname, new_name, strerror(errno));
	} else {
		ss7mon_log(SS7MON_INFO, "Rotated SS7 monitor %s %s to %s\n", ftype, fname, new_name);
		*file = fopen(fname, fmode);
		if (!*file) {
			ss7mon_log(SS7MON_ERROR, "Failed to open %s file %s: %s\n", ftype, fname, strerror(errno));
			rc = -1;
		}
	}
	os_free(new_name);
	return rc;
}

static int wp_handle_hdlc_frame(struct wanpipe_hdlc_engine *engine, void *frame_data, int len)
{
	return ss7mon_handle_hdlc_frame(engine->context, frame_data, len);
}

#define FISU_PRINT_THROTTLE_SIZE 1333 /* FISU / second (assuming driver MTP1 filtering is not enabled) */
#define LSSU_PRINT_THROTTLE_SIZE 100 /* Since these ones are only seen during alignment we may want to print them more often when debugging */
static int ss7mon_handle_hdlc_frame(ss7link_context_t *link, void *frame_data, int len)
{
	/* Maintenance warning: engine may be null if using hardware HDLC or SW HDLC in the driver */
	msu_buf_t *msu = NULL;
	char *hdlc_frame = frame_data;
	uint8_t bsn = 0;
	uint8_t fsn = 0;

	link->last_recv_time = time(NULL);
	link->link_probably_dead = 0;

	/* check frame type */
	switch (hdlc_frame[2]) {
	case 0: /* FISU */
		if (!link->fisu_cnt || !(link->fisu_cnt % FISU_PRINT_THROTTLE_SIZE)) {
			ss7mon_log(SS7MON_DEBUG, "Got FISU of size %d [cnt=%llu]\n", len, (unsigned long long)link->fisu_cnt);
		}
		link->fisu_cnt++;
		if (!link->link_aligned) {
			ss7mon_log(SS7MON_INFO, "SS7 Link State: Up");
			link->link_aligned = 1;
		}
		if (!globals.fisu_enable) {
			return 0;
		}
		break;
	case 1: /* LSSU */
	case 2:
		if (!link->lssu_cnt || !(link->lssu_cnt % LSSU_PRINT_THROTTLE_SIZE)) {
			ss7mon_log(SS7MON_DEBUG, "Got LSSU of size %d [cnt=%llu]\n", len, (unsigned long long)link->lssu_cnt);
		}
		link->lssu_cnt++;
		if (link->link_aligned) {
			ss7mon_log(SS7MON_WARNING, "SS7 Link State: Down (alignment procedure in progress)");
			link->link_aligned = 0;
		}
		if (!globals.lssu_enable) {
			return 0;
		}
		break;
	default: /* MSU */
		link->msu_cnt++;
		bsn = (hdlc_frame[0] & 0x7F);
		fsn = (hdlc_frame[1] & 0x7F);
		ss7mon_log(SS7MON_DEBUG, "Got MSU of size %d [cnt=%llu FSN=%u BSN=%u]\n",
				len, (unsigned long long)link->msu_cnt,
				fsn, bsn);

		if (globals.pcr_enable) {
			int cnt = 0;
			/* check if the MSU is repeated */
			for (msu = link->pcr_curr_msu;
			     cnt < globals.pcr_rtb_size && msu->len;
			     msu = msu->prev, cnt++) {
				if (msu->len != len) {
					continue;
				}
				if (!memcmp(msu->buf, frame_data, len)) {
					ss7mon_log(SS7MON_DEBUG, "Ignoring MSU of size %d [cnt=%llu FSN=%u BSN=%u]\n", 
							len, (unsigned long long)link->msu_cnt,
							fsn, bsn);
					/* Ignore repeated MSU */
					return 0;
				}
			}

			/* save the new MSU */
			msu = link->pcr_curr_msu->next;
			memcpy(msu->buf, frame_data, len);
			msu->len = len;
			link->pcr_curr_msu = msu;
		}

		break;
	}

	/* write the HDLC frame in the PCAP file if needed */
	if (link->pcap_file) {
		write_pcap_packet(link, link->pcap_file, frame_data, len);
	}

	/* write the HDLC frame to the hexdump file */
	if (link->hexdump_file) {
		write_hexdump_packet(link->hexdump_file, frame_data, len);
	}

	return 0;
}

static void ss7mon_handle_termination_signal(int signum)
{
	globals.running = 0;
}

static void ss7mon_handle_rotate_signal(int signum)
{
	/* rotate the dump files */
	if (!globals.rotate_request) {
		globals.rotate_request = 1;
	}
	/* FIXME: Notify all links of rotation in the main thread */
}

static sangoma_wait_obj_t *ss7mon_open_device(ss7link_context_t *link)
{
	wanpipe_api_t tdm_api = { 0 };
	sangoma_status_t status = SANG_STATUS_GENERAL_ERROR;
	sangoma_wait_obj_t *ss7_wait_obj = NULL;
	char errbuf[512];
	int ss7_txq_size = 0;
	int ss7_rxq_size = 0;
	unsigned char link_status = 0;

	link->fd = sangoma_open_api_span_chan(link->spanno, link->channo);
	if (link->fd == INVALID_HANDLE_VALUE) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		ss7mon_log(SS7MON_ERROR, "Failed to open device s%dc%d: %s\n",
				link->spanno, link->channo, errbuf);
		return NULL;
	}
	ss7mon_log(SS7MON_INFO, "Opened device s%dc%d\n", link->spanno, link->channo);

	/* Flush buffers and stats */
	sangoma_tdm_flush_bufs(link->fd, &tdm_api);
	sangoma_flush_stats(link->fd, &tdm_api);
	status = sangoma_wait_obj_create(&ss7_wait_obj, link->fd, SANGOMA_DEVICE_WAIT_OBJ);
	if (status != SANG_STATUS_SUCCESS) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		ss7mon_log(SS7MON_ERROR, "Failed to create wait object for device s%dc%d: %s\n",
				link->spanno, link->channo, errbuf);
		sangoma_close(&link->fd);
		return NULL;
	}

	ss7_txq_size = sangoma_get_tx_queue_sz(link->fd, &tdm_api);
	ss7mon_log(SS7MON_DEBUG, "Current tx queue size = %d\n", ss7_txq_size);
	ss7_txq_size = globals.txq_size;
	if (sangoma_set_tx_queue_sz(link->fd, &tdm_api, ss7_txq_size)) {
		ss7mon_log(SS7MON_ERROR, "Failed to set tx queue size to %d\n", ss7_txq_size);
	} else {
		ss7mon_log(SS7MON_DEBUG, "Set tx queue size to %d\n", ss7_txq_size);
	}

	ss7_rxq_size = sangoma_get_rx_queue_sz(link->fd, &tdm_api);
	ss7mon_log(SS7MON_DEBUG, "Current rx queue size = %d\n", ss7_rxq_size);
	ss7_rxq_size = globals.rxq_size;
	if (sangoma_set_rx_queue_sz(link->fd, &tdm_api, ss7_rxq_size)) {
		ss7mon_log(SS7MON_ERROR, "Failed to set rx queue size to %d\n", ss7_rxq_size);
	} else {
		ss7mon_log(SS7MON_DEBUG, "Set rx queue size to %d\n", ss7_rxq_size);
	}

	if (sangoma_get_fe_status(link->fd, &tdm_api, &link_status)) {
		ss7mon_log(SS7MON_ERROR, "Failed to get link status, assuming connected!\n");
		link->connected = 1;
	} else {
		ss7mon_log(SS7MON_DEBUG, "Current link status = %s (%u)\n",
				link_status == 2 ? "Connected" : "Disconnected", link_status);
		if (link_status == 2) {
			link->connected = 1;
		} else {
			link->connected = 0;
		}
	}

	return ss7_wait_obj;
}

static void handle_client_command(void *zsocket, char *cmd)
{
	ss7link_context_t *link = NULL;
	char response[4096];
	zmq_msg_t reply;
	size_t msglen = 0;

	/* FIXME: This needs to now check for an optional second argument indicating which link */
	if (!strcasecmp(cmd, "stats")) {
		time_t diff = 0;
		time_t now = time(NULL);
		diff = now - link->last_recv_time;
		/* Send statistics */
		msglen = snprintf(response, sizeof(response),
					"device: s%dc%d\r\n"
					"connected: %s\r\n"
					"ss7-link-aligned: %s\r\n"
					"ss7-link-probably-dead: %s\r\n"
					"ss7-errors: %d\r\n"
					"fisu-count: %lu\r\n"
					"lssu-count: %lu\r\n"
					"msu-count: %lu\r\n"
					"last-frame-recv-time: %ld\r\n"
					"seconds-since-last-recv-frame: %ld\r\n\r\n",
					link->spanno, link->channo,
					link->connected ? "true" : "false",
					link->link_aligned ? "true" : "false",
					link->link_probably_dead ? "true" : "false",
					link->rx_errors,
					link->fisu_cnt,
					link->lssu_cnt,
					link->msu_cnt,
					link->last_recv_time,
					diff);

	} else if (!strcasecmp(cmd, "status")) {
		msglen = snprintf(response, sizeof(response), "%s\r\n\r\n", globals.running ? "running" : "stopped");
	} else {
		msglen = snprintf(response, sizeof(response), "Invalid command: %s\r\n\r\n", cmd);
	}

	if (msglen) {
		zmq_msg_init_size(&reply, msglen);
		memcpy(zmq_msg_data(&reply), response, msglen);
		if (zmq_msg_send(zsocket, &reply, 0) < 0) {
			ss7mon_log(SS7MON_ERROR, "Failed sending response to client:\n%s\n", response);
		} else {
			ss7mon_log(SS7MON_DEBUG, "Sent response to client:\n%s\n", response);
		}
	} else {
		ss7mon_log(SS7MON_ERROR, "No response for client command\n");
	}
}


static void watchdog_exec(ss7link_context_t *link)
{
	time_t now;
	time_t diff;

	now = time(NULL);
	if (now < link->last_recv_time) {
		ss7mon_log(SS7MON_INFO, "Time changed to the past, resetting last_recv_time from %ld to %ld\n", link->last_recv_time, now);
		link->last_recv_time = now;
		return;
	}

	diff = now - link->last_recv_time;
	if (diff >= link->watchdog_seconds && !(diff % link->watchdog_seconds)) {
		if (link->watchdog_ready) {
			ss7mon_log(SS7MON_WARNING, "Time since last message was received: %ld seconds\n", diff);
			link->missing_msu_periods++;
			link->link_probably_dead = 1;
		}
		link->watchdog_ready = 0;
	} else {
		link->watchdog_ready = 1;
	}
}

static void *monitor_link(os_thread_t *thread, void *data)
{
	ss7link_context_t *link = data;
	sangoma_wait_obj_t *ss7_wait_obj = NULL;
	msu_buf_t *msu = NULL;
	sangoma_status_t status = SANG_STATUS_GENERAL_ERROR;
	char errbuf[512] = { 0 };
	uint32_t input_flags = SANG_WAIT_OBJ_HAS_INPUT | SANG_WAIT_OBJ_HAS_EVENTS;
	uint32_t output_flags = 0;

	ss7mon_log(SS7MON_INFO, "Starting up monitoring thread for link s%dc%d\n", link->spanno, link->channo);

	/* Open the Sangoma device */
	ss7_wait_obj = ss7mon_open_device(link);
	if (!ss7_wait_obj) {
		return NULL;
	}

	if (globals.pcap_tx_file_p) {
		link->tx_pcap_file = fopen(globals.pcap_tx_file_p, "r");
		if (!link->tx_pcap_file) {
			strerror_r(errno, errbuf, sizeof(errbuf));
			ss7mon_log(SS7MON_ERROR, "Failed to open tx pcap file %s: %s\n", globals.pcap_tx_file_p, errbuf);
		}
	}

	/* Prepare the rx buffer */
	link->mtp2_buf = calloc(1, globals.mtp2_mtu);
	if (!link->mtp2_buf) {
		ss7mon_log(SS7MON_ERROR, "Failed to allocate MTP2 buffer of size %d\n", globals.mtp2_mtu);
		return NULL;
	}

	/* initialize the HDLC engine (this is not thread-safe, must be done before launching any threads) */
	link->wanpipe_hdlc_decoder = wanpipe_reg_hdlc_engine();
	if (!link->wanpipe_hdlc_decoder) {
		ss7mon_log(SS7MON_ERROR, "Failed to create Wanpipe HDLC engine\n");
		return NULL;
	}
	link->wanpipe_hdlc_decoder->context = link;
	link->wanpipe_hdlc_decoder->hdlc_data = wp_handle_hdlc_frame;

	/* Write the pcap header */
	if (link->pcap_file) {
		write_pcap_header(link);
	}

	/* skip tx pcap header */
	if (link->tx_pcap_file) {
		pcap_hdr_t hdr;
		size_t elements = 0;
		elements = fread(&hdr, sizeof(hdr), 1, link->tx_pcap_file);
		if (elements != 1) {
			fclose(link->tx_pcap_file);
			link->tx_pcap_file = NULL;
		} else {
			if (hdr.magic != SS7MON_PCAP_MAGIC) {
				ss7mon_log(SS7MON_ERROR, "Invalid Tx pcap file (magic number is 0x%X and not 0x%X)\n", hdr.magic, SS7MON_PCAP_MAGIC);
				return NULL;
			}
			ss7mon_log(SS7MON_DEBUG, "Tx pcap major = %d, minor = %d, snaplen = %d, network = %d\n",
					hdr.version_major, hdr.version_minor, hdr.snaplen, hdr.network);
			if (hdr.network != globals.pcap_mtp2_link_type) {
				ss7mon_log(SS7MON_ERROR, "Invalid Tx pcap file (linktype is %d and not %d)\n", hdr.network, globals.pcap_mtp2_link_type);
				return NULL;
			}
		}
	}


	/* Setup PCR buffers if PCR is enabled */
	if (globals.pcr_enable) {
		int i = 0;
		msu = NULL;
		/* FIXME: Change this to single allocation, we know the full size already! */
		for (i = 0; i < globals.pcr_rtb_size; i++) {
			if (!msu) {
				link->pcr_bufs = os_calloc(1, sizeof(*msu));
				msu = link->pcr_bufs;
				if (!msu) {
					ss7mon_log(SS7MON_ERROR, "Failed to allocate PCR MSU element\n");
					goto thread_done;
				}
			} else {
				msu_buf_t *new_msu = os_calloc(1, sizeof(*msu));
				if (!new_msu) {
					ss7mon_log(SS7MON_ERROR, "Failed to allocate PCR MSU element\n");
					goto thread_done;
				}
				msu->next = new_msu;
				new_msu->prev = msu;
				msu = new_msu;
			}
			msu->buf = os_calloc(1, globals.mtp2_mtu);
			if (!msu->buf) {
				ss7mon_log(SS7MON_ERROR, "Failed to allocate PCR MSU buffer\n");
				goto thread_done;
			}
		}
		/* last MSU points to first (circular linked list) */
		msu->next = link->pcr_bufs;
		link->pcr_bufs->prev = msu;
		/* Force the curr msu to be the last one so the logic of storing next MSU upon reception stays the same */
		link->pcr_curr_msu = msu;
	}

	link->last_recv_time = time(NULL);
	while (globals.running) {
		watchdog_exec(link);

		if (link->fd == INVALID_HANDLE_VALUE) {
			os_sleep(SS7MON_SAFE_WAIT);
			ss7_wait_obj = ss7mon_open_device(link);
			if (!ss7_wait_obj) {
				continue;
			}
		}

		status = sangoma_waitfor(ss7_wait_obj, input_flags, &output_flags, 10);
		switch (status) {
		case SANG_STATUS_APIPOLL_TIMEOUT:
			break;
		case SANG_STATUS_SUCCESS:
			if (output_flags & SANG_WAIT_OBJ_HAS_EVENTS) {
				ss7mon_handle_oob_event(link);
			}
			if (output_flags & SANG_WAIT_OBJ_HAS_INPUT) {
				ss7mon_handle_input(link);
			}
			break;
		default:
			strerror_r(errno, errbuf, sizeof(errbuf));
			ss7mon_log(SS7MON_ERROR, "Failed to wait for device (status = %d, %s)\n", status, errbuf);
			break;
		}

		if (link->tx_pcap_file) {
			tx_pcap_frame(link);
		}

		if (link->rotate_request) {
			link->rotate_request = 0;
			if (!rotate_file(link, &link->pcap_file, link->pcap_file_name, "wb", "pcap", link->rotate_cnt)) {
				write_pcap_header(link);
			}
			rotate_file(link, &link->hexdump_file, link->hexdump_file_name, "w", "hexdump", link->rotate_cnt);
			link->rotate_cnt++;
		}
	}

thread_done:
	if (globals.pcr_enable && link->pcr_bufs) {
		msu_buf_t *next = NULL;
		msu = link->pcr_bufs->next;
		while (msu != link->pcr_bufs) {
			next = msu->next;
			os_free(msu->buf);
			os_free(msu);
			msu = next;
		}
		os_free(link->pcr_bufs->buf);
		os_free(link->pcr_bufs);
		link->pcr_bufs = NULL;
	}

	if (link->pcap_file) {
		fclose(link->pcap_file);
		link->pcap_file = NULL;
	}

	if (link->hexdump_file) {
		fclose(link->hexdump_file);
		link->hexdump_file = NULL;
	}

	if (link->mtp2_buf) {
		free(link->mtp2_buf);
	}

	return NULL;
}

static int parse_device(const char *dev, int *spanno, int *channo)
{
	ss7link_context_t *link = NULL;
	*spanno = 0;
	*channo = 0;
	int elements = sscanf(dev, "s%dc%d", spanno, channo);
	if (elements != 2) {
		ss7mon_log(SS7MON_ERROR, "Invalid string '%s' for -dev option (device must be specified in format sXcY)\n", dev);
		return -1;
	}
	if (*spanno <= 0) {
		ss7mon_log(SS7MON_ERROR, "Invalid string '%s' for -dev option (span must be bigger than 0)\n", dev);
		return -1;
	}
	if (*channo <= 0) {
		ss7mon_log(SS7MON_ERROR, "Invalid string '%s' for -dev option (channel must be bigger than 0)\n", dev);
		return -1;
	}
	return 0;
}

static char *trim(char *s)
{
	char endchars[] = { ' ', '\r', '\n', 0 };
    char *e = NULL;
    char *c = NULL;
    /* Skip space in the front */
    while (*s == ' ') {
        s++;
    }

    /* Null-terminate once we find space at the end, \r or \n */
    e = endchars;
    for (e = endchars; e; e++) {
        c = strchr(s, *e);
        if (c) {
            *c = '\0';
            break;
        }
    }
    return s;
}

#define DEFAULT_SERVER_ADDR_FMT "ipc:///tmp/sng_ss7mon-s%dc%d"
static ss7link_context_t *configure_links(const char *conf)
{
	char line[512];
	char strval[512];
	int intval;
	int span, chan;
	ss7link_context_t *link = NULL;
	ss7link_context_t *links = NULL;
	FILE *cf = fopen(conf, "r");
	if (!cf) {
		return NULL;
	}
	while (fgets(line, sizeof(line), cf)) {
		char *s = line;
		s = trim(s);
		if (!s[0]) {
			continue;
		}
		if (*s == ';' || *s == '#') {
			continue;
		}
		if (sscanf(s, "[s%dc%d]", &span, &chan)) {
			/* Allocate new link */
			link = ss7link_context_new(span, chan);
			if (links) {
				link->next = links;
			} else if (!globals.server_addr[0]) {
				/* First configured link, use its address as the default */
				snprintf(globals.server_addr, sizeof(globals.server_addr), DEFAULT_SERVER_ADDR_FMT, span, chan);
			}
			links = link;
			continue;
		}

		if (sscanf(s, "hexdump=%s", strval)) {
			snprintf(link->hexdump_file_name, MAX_FILE_PATH, "%s", strval);
		} else if (sscanf(s, "pcap=%s", strval)) {
			snprintf(link->pcap_file_name, MAX_FILE_PATH, "%s", strval);
		} else if (sscanf(s, "fisu_enable=%s", strval)) {
			link->fisu_enable = !strcasecmp(strval, "yes") ? 1 : 0;
		} else if (sscanf(s, "lssu_enable=%s", strval)) {
			link->lssu_enable = !strcasecmp(strval, "yes") ? 1 : 0;
		} else if (sscanf(s, "pcr_enable=%s", strval)) {
			link->pcr_enable = !strcasecmp(strval, "yes") ? 1 : 0;
		} else if (sscanf(s, "watchdog_seconds=%d", &intval)) {
			if (intval < 1) {
				ss7mon_log(SS7MON_ERROR, "Invalid watchdog_seconds parameter: %s\n", s);
			} else {
				link->watchdog_seconds = intval;
			}
		} else {
			ss7mon_log(SS7MON_ERROR, "Unknown configuration parameter %s\n", s);
		}
	}
	return links;
}

static void ss7mon_print_usage(void)
{
	printf("USAGE:\n"
		"-dev <sXcY>            - Indicate Sangoma device to monitor, ie -dev s1c16 will monitor span 1 channel 16\n"
		"-conf <file>           - Configuration file (recommended when monitoring multiple links). Do not use if using -dev.\n"
		"-lssu                  - Include LSSU frames (default is to ignore them)\n"
		"-fisu                  - Include FISU frames (default is to ignore them)\n"
		"-hexdump <file|prefix> - Dump SS7 messages into the given file (or prefix per link) in hexadecimal text format\n"
		"-hexdump_flush         - Flush the hex dump on each packet received\n"
		"-pcap <file|prefix>    - pcap file path name (or prefix) to record the SS7 messages\n"
		"-pcap_mtp2_hdr         - Include the MTP2 pcap header\n"
		"-log <name>            - Log level name (DEBUG, INFO, WARNING, ERROR)\n"
		"-rxq_watermark <size>  - Receive queue watermark percentage (when to print warnings about rx queue size overflowing)\n"
		"-rxq <size>            - Receive queue size\n"
		"-txq <size>            - Transmit queue size\n"
		"-swhdlc                - HDLC done in software (not FPGA or Driver)\n"
		"-txpcap <file>         - Transmit the given PCAP file\n"
		"-syslog                - Send logs to syslog\n"
		"-core                  - Enable core dumps\n"
		"-server                - Server string to listen for commands (ipc:///tmp/ss7mon_s1c1 or tcp://127.0.0.1:5555)\n"
		"-watchdog <time-secs>  - Set the number of seconds before warning about messages not being received\n"
		"-mtp2_mtu              - MTU for MTP2 (minimum and default is %d)\n"
		"-pcr                   - Whether to enable PCR (Preventive Cyclic Retransmission) detection\n"
		"-pcr_rtb_size <size>   - Size of the PCR buffer in MSU units. Implies -pcr\n"
		"-h[elp]                - Print usage\n",
		SS7MON_DEFAULT_MTP2_MTU
	);
}

static int termination_signals[] = { SIGINT, SIGTERM, SIGQUIT };
#define INC_ARG(arg_i) \
	arg_i++; \
	if (arg_i >= argc) { \
		ss7mon_log(SS7MON_ERROR, "No option value was given for option %s\n", argv[arg_i - 1]); \
		exit(1); \
	} 
int main(int argc, char *argv[])
{
	ss7link_context_t *curr = NULL;
	ss7link_context_t *link = NULL;
	ss7link_context_t *links = NULL;
	struct rlimit rlp = { 0 };
	int arg_i = 0;
	int i = 0;
	int rc = 0;
	char *dev = NULL;
	void *zmq_context = NULL;
	void *zsocket = NULL;
	int spanno = 0;
	int channo = 0;
	const char *conf = NULL;

	if (argc < 2) {
		ss7mon_print_usage();
		exit(0);
	}

	for (i = 0; i < ss7mon_arraylen(termination_signals); i++) {
		if (signal(termination_signals[i], ss7mon_handle_termination_signal) == SIG_ERR) {
			ss7mon_log(SS7MON_ERROR, "Failed to install signal handler for signal %d: %s\n",
					termination_signals[i], strerror(errno));
			exit(1);
		}
	}

	if (signal(SIGHUP, ss7mon_handle_rotate_signal) == SIG_ERR) {
		ss7mon_log(SS7MON_ERROR, "Failed to install SIGHUP signal handler %s\n", strerror(errno));
		exit(1);
	}

	for (arg_i = 1; arg_i < argc; arg_i++) {
		if (!strcasecmp(argv[arg_i], "-dev")) {
			INC_ARG(arg_i);
			if (parse_device(argv[arg_i], &spanno, &channo)) {
				exit(1);
			}
			dev = argv[arg_i];
			if (!globals.server_addr[0]) {
				snprintf(globals.server_addr, sizeof(globals.server_addr), DEFAULT_SERVER_ADDR_FMT, spanno, channo);
			}
		} else if (!strcasecmp(argv[arg_i], "-rxq_watermark")) {
			INC_ARG(arg_i);
			globals.rxq_watermark = atoi(argv[arg_i]);
			if (globals.rxq_watermark <= 0) {
				ss7mon_log(SS7MON_ERROR, "Invalid rx queue watermark '%s' (must be bigger than 0%% and probably something smaller than 20%% is not smart)\n", argv[arg_i]);
				exit(1);
			}
		} else if (!strcasecmp(argv[arg_i], "-txq")) {
			INC_ARG(arg_i);
			globals.txq_size = atoi(argv[arg_i]);
			if (globals.txq_size <= 0) {
				ss7mon_log(SS7MON_ERROR, "Invalid tx queue size '%s' (must be bigger than 0)\n", argv[arg_i]);
				exit(1);
			}
		} else if (!strcasecmp(argv[arg_i], "-rxq")) {
			INC_ARG(arg_i);
			globals.rxq_size = atoi(argv[arg_i]);
			if (globals.rxq_size <= 0) {
				ss7mon_log(SS7MON_ERROR, "Invalid rx queue size '%s' (must be bigger than 0)\n", argv[arg_i]);
				exit(1);
			}
		} else if (!strcasecmp(argv[arg_i], "-mtp2_mtu")) {
			INC_ARG(arg_i);
			globals.mtp2_mtu = atoi(argv[arg_i]);
			if (globals.mtp2_mtu <= SS7MON_DEFAULT_MTP2_MTU) {
				ss7mon_log(SS7MON_ERROR, "Invalid -mtp2_mtu option '%s' (must be >= than %d)\n", argv[arg_i], SS7MON_DEFAULT_MTP2_MTU);
				exit(1);
			}
		} else if (!strcasecmp(argv[arg_i], "-pcr")) {
			globals.pcr_enable = 1;
			if (globals.pcr_rtb_size == 0) {
				globals.pcr_rtb_size = SS7MON_DEFAULT_PCR_RTB_SIZE;
			}
		} else if (!strcasecmp(argv[arg_i], "-pcr_rtb_size")) {
			globals.pcr_enable = 1;
			INC_ARG(arg_i);
			globals.pcr_rtb_size = atoi(argv[arg_i]);
			if (globals.pcr_rtb_size <= 0) {
				ss7mon_log(SS7MON_ERROR, "Invalid -pcr_rtb_size option '%s' (must be >= 1 and <= %d)\n", 
						argv[arg_i], SS7MON_MAX_PCR_RTB_SIZE);
				exit(1);
			}
		} else if (!strcasecmp(argv[arg_i], "-swhdlc")) {
			globals.swhdlc_enable = 1;
		} else if (!strcasecmp(argv[arg_i], "-hexdump_flush")) {
			globals.hexdump_flush_enable = 1;
		} else if (!strcasecmp(argv[arg_i], "-hexdump")) {
			INC_ARG(arg_i);
			globals.hexdump_file_p = os_strdup(argv[arg_i]);
		} else if (!strcasecmp(argv[arg_i], "-pcap")) {
			INC_ARG(arg_i);
			globals.pcap_file_p = os_strdup(argv[arg_i]);
		} else if (!strcasecmp(argv[arg_i], "-txpcap")) {
			INC_ARG(arg_i);
			globals.pcap_tx_file_p = os_strdup(argv[arg_i]);
		} else if (!strcasecmp(argv[arg_i], "-log")) {
			INC_ARG(arg_i);
			for (i = 0; i < ss7mon_arraylen(ss7mon_log_levels); i++) {
				if (!strcasecmp(argv[arg_i], ss7mon_log_levels[i].name)) {
					globals.loglevel = ss7mon_log_levels[i].level;
					break;
				}
			}
			if (i == ss7mon_arraylen(ss7mon_log_levels)) {
				ss7mon_log(SS7MON_ERROR, "Invalid log level specified: '%s'\n", argv[arg_i]);
				exit(1);
			}
		} else if (!strcasecmp(argv[arg_i], "-pcap_mtp2_hdr")) {
			globals.pcap_mtp2_link_type = SS7MON_PCAP_LINKTYPE_MTP2_WITH_PHDR;
		} else if (!strcasecmp(argv[arg_i], "-syslog")) {
			globals.syslog_enable = 1;
			openlog("sng_ss7mon", LOG_CONS | LOG_NDELAY, LOG_USER);
		} else if (!strcasecmp(argv[arg_i], "-lssu")) {
			globals.lssu_enable = 1;
		} else if (!strcasecmp(argv[arg_i], "-fisu")) {
			globals.fisu_enable = 1;
		} else if (!strcasecmp(argv[arg_i], "-core")) {
			/* Enable core dumps */
			memset(&rlp, 0, sizeof(rlp));
			rlp.rlim_cur = RLIM_INFINITY;
			rlp.rlim_max = RLIM_INFINITY;
			setrlimit(RLIMIT_CORE, &rlp);
		} else if (!strcasecmp(argv[arg_i], "-server")) {
			INC_ARG(arg_i);
			snprintf(globals.server_addr, sizeof(globals.server_addr), "%s", argv[arg_i]);
		} else if (!strcasecmp(argv[arg_i], "-watchdog")) {
			INC_ARG(arg_i);
			globals.watchdog_seconds = atoi(argv[arg_i]);
			if (globals.watchdog_seconds < 1) {
				ss7mon_log(SS7MON_ERROR, "Invalid watchdog time specified: '%s'\n", argv[arg_i]);
				exit(1);
			}
		} else if (!strcasecmp(argv[arg_i], "-conf")) {
			INC_ARG(arg_i);
			conf = os_strdup(argv[arg_i]);
		} else if (!strcasecmp(argv[arg_i], "-h") || !strcasecmp(argv[arg_i], "-help")) {
			ss7mon_print_usage();
			exit(0);
		} else {
			ss7mon_log(SS7MON_ERROR, "Invalid option %s\n", argv[arg_i]);
			exit(1);
		}
	}

	if ((!dev && !conf) || (dev && conf)) {
		ss7mon_log(SS7MON_ERROR, "-dev or -conf option must be specified, but not both\n");
		exit(1);
	}

	/* monitoring loop */
	globals.running = 1;

	if (conf) {
		if (!(links = configure_links(conf))) {
			ss7mon_log(SS7MON_ERROR, "No links found in configuration %s\n", conf);
			goto terminate;
		}
	} else {
		links = ss7link_context_new(spanno, channo);
		if (!links) {
			ss7mon_log(SS7MON_ERROR, "Failed to create ss7 link for device %s\n", dev);
			goto terminate;
		}
	}

	link = links;
	while (link) {
		if (os_thread_create(monitor_link, link, &link->thread) != OS_SUCCESS) {
			ss7mon_log(SS7MON_ERROR, "Failed to launch link monitoring thread\n");
		}
		link = link->next;
	}

	/* ZeroMQ initialization */
	zmq_context = zmq_init(1);
	if (!zmq_context) {
		ss7mon_log(SS7MON_ERROR, "Failed to create ZeroMQ context\n");
		exit(1);
	}
	zsocket = zmq_socket(zmq_context, ZMQ_REP);
	if (!zsocket) {
		ss7mon_log(SS7MON_ERROR, "Failed to create ZeroMQ socket\n");
		exit(1);
	}
	rc = zmq_bind(zsocket, globals.server_addr);
	if (rc) {
		ss7mon_log(SS7MON_ERROR, "Failed to bind ZeroMQ socket to address %s: %s\n", globals.server_addr, strerror(errno));
		exit(1);
	}
	ss7mon_log(SS7MON_INFO, "Successfully bound server to address %s\n", globals.server_addr);


	ss7mon_log(SS7MON_INFO, "SS7 main monitor loop now running ...\n");
	while (globals.running) {
		/* service any client requests */
		if (zsocket) {
			char cmd[255] = { 0 };
			void *data = NULL;
			size_t len = 0;
			zmq_msg_t request;

			zmq_msg_init(&request);
			rc = zmq_msg_recv(zsocket, &request, ZMQ_DONTWAIT);
			if (rc > 0) {
				memset(cmd, 0, sizeof(cmd));
				data = zmq_msg_data(&request);
				len = zmq_msg_size(&request);
				if (len <= (sizeof(cmd) - 1)) {
					memcpy(cmd, data, len);
					ss7mon_log(SS7MON_DEBUG, "Server received command of length %zd: %s\n", len, cmd);
					handle_client_command(zsocket, cmd);
				} else {
					ss7mon_log(SS7MON_ERROR, "Dropping command of unexpected length %zd\n", len);
				}
			}
			zmq_msg_close(&request);
		}
	}

terminate:
	globals.running = 0;
	link = links;
	while (link) {
		if (link->thread) {
			os_thread_join(link->thread);
		}
		curr = link;
		link = link->next;
		ss7link_context_destroy(&curr);
	}

	if (zsocket) {
		zmq_close(zsocket);
		zsocket = NULL;
	}

	if (zmq_context) {
		zmq_term(zmq_context);
		zmq_context = NULL;
	}

	ss7mon_log(SS7MON_INFO, "Terminating SS7 monitoring ...\n");

	if (globals.syslog_enable) {
		closelog();
	}
	exit(0);
}

