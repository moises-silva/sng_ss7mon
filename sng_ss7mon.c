/*
 * sng_ss7mon
 *
 * SS7 message monitor for Sangoma devices
 *
 * Moises Silva <moises.silva@gmail.com>
 * Copyright (C) System One NOC
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
			if (globals.spanno >= 0) { \
				fprintf(stdout, "[%s] [s%dc%d] " format, ss7mon_log_levels[level].name, globals.spanno, globals.channo, ##__VA_ARGS__); \
			} else { \
				fprintf(stdout, "[%s]" format, ss7mon_log_levels[level].name, ##__VA_ARGS__); \
			} \
		} \
		if (globals.syslog_enable) { \
			if (globals.spanno >= 0) { \
				syslog(ss7mon_log_levels[level].syslog, "[s%dc%d] " format, globals.spanno, globals.channo, ##__VA_ARGS__); \
			} else { \
				syslog(ss7mon_log_levels[level].syslog, format, ##__VA_ARGS__); \
			} \
		} \
	} while (0)


#define SS7MON_US_IN_SECOND 1000000
#define SS7MON_DEFAULT_TX_QUEUE_SIZE 500
#define SS7MON_DEFAULT_RX_QUEUE_SIZE 500
#define SS7MON_DEFAULT_RX_QUEUE_WATERMARK 60

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

struct _globals {
	int rxq_watermark; /* When to warn about queue overflow (percentage) */
	int txq_size; /* Tx queue size */
	int rxq_size; /* Rx queue size */
	int loglevel; /* Current logging level */
	int spanno; /* TDM device span number */
	int channo; /* TDM device channel number */
	int ss7_fd; /* TDM device file descriptor */
	uint8_t connected; /* E1 link is connected */
	volatile uint8_t running; /* Monitor application is running */
	int ss7_rx_errors; /* Number of errors */
	wanpipe_hdlc_engine_t *wanpipe_hdlc_decoder; /* HDLC engine when done in software */
	FILE *pcap_file; /* pcap file to write MTP2 frames to */
	FILE *tx_pcap_file; /* pcap file where to read MTP2 frames from */
	pcap_record_hdr_t tx_pcap_hdr; /* next pcap record to transmit */
	int tx_pcap_cnt; /* number of frames transmitted */
	int pcap_mtp2_link_type; /* MTP2 pcap type */
	struct timespec tx_pcap_next_delivery; /* time to next frame delivery */
	char pcap_file_name[1024]; /* pcap file name */
	uint8_t rotate_request; /* request to rotate dump files */
	int rotate_cnt; /* number of rotated files */
	uint8_t swhdlc_enable; /* whether software HDLC should be performed in user space */
	uint8_t syslog_enable; /* whether to use syslog for logging (in addition to stdout) */
	uint8_t fisu_enable; /* whether to include FISU frames in the output */
	uint8_t lssu_enable; /* whether to include LSSU frames in the output */
	/* Message counters */
	uint64_t fisu_cnt; 
	uint64_t lssu_cnt;
	uint64_t msu_cnt;
	FILE *hexdump_file;
	char hexdump_file_name[1024]; /* hexdump file name */
	uint8_t hexdump_flush_enable; /* Flush the file as every hex packet is received */
	int32_t consecutive_read_errors; /* How many read errors have we had in a row */
	time_t last_recv_time; /* seconds since the last message was received */
	int watchdog_seconds; /* time to wait before warning about no messages being received */
	uint64_t missing_msu_periods; /* how many -watchdog_seconds- periods have passed without receiving messages */
	uint8_t link_aligned; /* whether the SS7 link is aligned (FISUs or MSUs flowing) */
	uint8_t link_probably_dead; /* Whether the SS7 link is probably dead (incorrectly tapped or something) */
	void *zmq_socket; /* ZeroMQ socket to accept commands and send responses */
} globals = {
	.rxq_watermark = SS7MON_DEFAULT_RX_QUEUE_WATERMARK,
	.txq_size = SS7MON_DEFAULT_TX_QUEUE_SIZE,
	.rxq_size = SS7MON_DEFAULT_RX_QUEUE_SIZE,
	.loglevel = SS7MON_WARNING,
	.spanno = -1,
	.channo = -1,
	.ss7_fd = -1,
	.connected = 0,
	.running = 0,
	.ss7_rx_errors = 0,
	.wanpipe_hdlc_decoder = NULL,
	.pcap_file = NULL,
	.tx_pcap_file = NULL,
	.tx_pcap_hdr = { 0, 0, 0, 0 },
	.tx_pcap_cnt = 0,
 	.pcap_mtp2_link_type = SS7MON_PCAP_LINKTYPE_MTP2,
	.pcap_file_name = { 0 },
	.rotate_request = 0,
	.rotate_cnt = 1,
	.swhdlc_enable = 0,
	.syslog_enable = 0,
	.fisu_enable = 0,
	.lssu_enable = 0,
	.fisu_cnt = 0,
	.lssu_cnt = 0,
	.msu_cnt = 0,
	.hexdump_file = NULL,
	.hexdump_file_name = { 0 },
	.hexdump_flush_enable = 0,
	.consecutive_read_errors = 0,
	.last_recv_time = 0,
	.watchdog_seconds = 0,
	.missing_msu_periods = 0,
	.link_aligned = 0,
	.link_probably_dead = 0,
	.zmq_socket = NULL,
};

static void write_pcap_header(FILE *f)
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
	wrote = fwrite(&hdr, sizeof(hdr), 1, f);
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
static void write_pcap_packet(FILE *f, void *packet_buffer, int packet_len)
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

static int tx_pcap_frame(void)
{
	struct timespec ts;
	pcap_record_hdr_t next_hdr;
	int bsent = 0;
	time_t diff_sec = 0;
	long diff_usec = 0;
	size_t elements = 0;
	wp_tdm_api_tx_hdr_t hdrframe;
	char data[MAX_SOCK_HDLC_BUF];

	/* get current time */
	clock_gettime(CLOCK_REALTIME, &ts);

	/* check next delivery time */
	if (globals.tx_pcap_next_delivery.tv_sec) {
		if (globals.tx_pcap_next_delivery.tv_sec >= ts.tv_sec) {
			return 0;
		}
		if ((globals.tx_pcap_next_delivery.tv_sec == ts.tv_sec) && globals.tx_pcap_next_delivery.tv_nsec > ts.tv_nsec) {
			return 0;
		}
		/* time to deliver! */
	}

	/* read header now if this is the first time we transmit a frame */
	if (!globals.tx_pcap_cnt) {
		elements = fread(&globals.tx_pcap_hdr, sizeof(globals.tx_pcap_hdr), 1, globals.tx_pcap_file);
		if (elements != 1) {
			ss7mon_log(SS7MON_ERROR, "Failed to read tx pcap frame hdr: %s\n", strerror(errno));
			goto done_tx;
		}
	}

	if (globals.tx_pcap_hdr.incl_len > sizeof(data)) {
		ss7mon_log(SS7MON_ERROR, "tx pcap frame too big: %d bytes\n", globals.tx_pcap_hdr.incl_len);
		goto done_tx;
	}

	/* if this is a pcap packet with an MTP2 enclosing, drop it */
	if (globals.pcap_mtp2_link_type == SS7MON_PCAP_LINKTYPE_MTP2_WITH_PHDR) {
		bsent = fread(data, 1, SS7MON_MTP2_HDR_LEN, globals.tx_pcap_file);
		if (bsent != SS7MON_MTP2_HDR_LEN) {
			ss7mon_log(SS7MON_ERROR, "failed to read tx pcap frame MTP2 header: %s\n", strerror(errno));
			goto done_tx;
		}
		globals.tx_pcap_hdr.incl_len -= SS7MON_MTP2_HDR_LEN;
	}

	bsent = fread(data, 1, globals.tx_pcap_hdr.incl_len, globals.tx_pcap_file);
	if (bsent != globals.tx_pcap_hdr.incl_len) {
		ss7mon_log(SS7MON_ERROR, "failed to read tx pcap frame: %s\n", strerror(errno));
		goto done_tx;
	}

	/* read the actual frame data and transmit it */
	memset(&hdrframe, 0, sizeof(hdrframe));
	bsent = sangoma_writemsg(globals.ss7_fd, &hdrframe, sizeof(hdrframe), data, globals.tx_pcap_hdr.incl_len, 0);
	if (bsent != globals.tx_pcap_hdr.incl_len) {
		ss7mon_log(SS7MON_ERROR, "Failed to transmit pcap frame: %s\n", strerror(errno));
		goto done_tx;
	}
	globals.tx_pcap_cnt++;
	ss7mon_log(SS7MON_DEBUG, "Tx frame: %d [%d bytes]\n", globals.tx_pcap_cnt, bsent);

	/* calculate next delivery time by reading next header */
	elements = fread(&next_hdr, sizeof(next_hdr), 1, globals.tx_pcap_file);
	if (elements != 1) {
		if (feof(globals.tx_pcap_file)) {
			ss7mon_log(SS7MON_INFO, "Ended pcap transmission\n");
			goto done_tx;
		}
		ss7mon_log(SS7MON_ERROR, "Failed to read next tx pcap frame hdr: %s\n", strerror(errno));
		goto done_tx;
	}

	diff_sec = next_hdr.ts_sec - globals.tx_pcap_hdr.ts_sec;
	if (!diff_sec || (next_hdr.ts_usec >= globals.tx_pcap_hdr.ts_usec)) {
		diff_usec = next_hdr.ts_usec - globals.tx_pcap_hdr.ts_usec;
	} else {
		diff_sec--;
		diff_usec = next_hdr.ts_usec;
		diff_usec += (SS7MON_US_IN_SECOND - globals.tx_pcap_hdr.ts_usec);
	}

	clock_gettime(CLOCK_REALTIME, &globals.tx_pcap_next_delivery);
	globals.tx_pcap_next_delivery.tv_sec += diff_sec;
	globals.tx_pcap_next_delivery.tv_nsec += (diff_usec * 1000);

	/* save next header to be used on next delivery time */
	memcpy(&globals.tx_pcap_hdr, &next_hdr, sizeof(globals.tx_pcap_hdr));

	ss7mon_log(SS7MON_DEBUG, "Next frame to be delivered in %ld, diff_sec = %ld, diff_usec = %ld\n", 
			globals.tx_pcap_next_delivery.tv_sec, diff_sec, diff_usec);
	return 0;

done_tx:

	fclose(globals.tx_pcap_file);
	globals.tx_pcap_file = NULL;
	globals.tx_pcap_next_delivery.tv_sec = 0;
	globals.tx_pcap_next_delivery.tv_nsec = 0;

	return 0;
}

static void ss7mon_handle_oob_event(void)
{
	wanpipe_api_t tdm_api;
	wp_api_event_t *wp_event = NULL;

	memset(&tdm_api, 0, sizeof(tdm_api));
	if (sangoma_read_event(globals.ss7_fd, &tdm_api)) {
		ss7mon_log(SS7MON_ERROR, "Failed to read event from device: %s\n", strerror(errno));
		return;
	}
	wp_event = &tdm_api.wp_cmd.event;

	switch (wp_event->wp_api_event_type) {
	case WP_API_EVENT_LINK_STATUS:
		switch (wp_event->wp_api_event_link_status) {
		case WP_API_EVENT_LINK_STATUS_CONNECTED:
			globals.connected = 1;
			ss7mon_log(SS7MON_INFO, "Line Connected\n");
			sangoma_tdm_flush_bufs(globals.ss7_fd, &tdm_api);
			sangoma_flush_stats(globals.ss7_fd, &tdm_api);
			break;
		case WP_API_EVENT_LINK_STATUS_DISCONNECTED:
			globals.connected = 0;
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
static int ss7mon_handle_hdlc_frame(struct wanpipe_hdlc_engine *engine, void *frame_data, int len);
static void ss7mon_handle_input(void)
{
	wp_api_hdr_t rxhdr;
	unsigned char buf[300]; /* Max MSU pack should be 272 per spec, give a bit of more room */
	int mlen = 0;
	int queue_level = 0;
	do {
		memset(buf, 0, sizeof(buf));
		memset(&rxhdr, 0, sizeof(rxhdr));
		mlen = sangoma_readmsg(globals.ss7_fd, &rxhdr, sizeof(rxhdr), buf, sizeof(buf), 0);
		if (mlen < 0) {
			int op_errno = errno;
			ss7mon_log(SS7MON_ERROR, "Error reading SS7 message: %s (errno=%d, %s)\n", 
					SDLA_DECODE_SANG_STATUS(rxhdr.operation_status), op_errno, strerror(op_errno));
			globals.consecutive_read_errors++;
			if (globals.consecutive_read_errors >= SS7MON_MAX_CONSECUTIVE_READ_ERRORS) {
				ss7mon_log(SS7MON_ERROR, "Max consecutive read errors reached, closing fd!\n");
				sangoma_close(&globals.ss7_fd);
				globals.ss7_fd = -1;
			}
			return;
		}
		globals.consecutive_read_errors = 0;

		if (mlen == 0) {
			ss7mon_log(SS7MON_ERROR, "Read empty message\n");
			return;
		}

		/*ss7mon_log(SS7MON_DEBUG, "Read HDLC frame of size %d\n", mlen);*/
		if (rxhdr.wp_api_rx_hdr_errors > globals.ss7_rx_errors) {
			int print_errors = 0;
			if (globals.ss7_rx_errors) {
				print_errors = 1;
			}
			globals.ss7_rx_errors = rxhdr.wp_api_rx_hdr_errors;
			if (print_errors) {
				ss7mon_log(SS7MON_ERROR, "Rx errors: %d\n", globals.ss7_rx_errors);
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
		} else if (globals.connected) {
			/* Feed the software HDLC engine or report the new HDLC frame in the case of HW HDLC */
			if (globals.swhdlc_enable) {
				/*ss7mon_log(SS7MON_DEBUG, "Feeding hdlc engine %d bytes of data\n", mlen);*/
				/* fill in data to the HDLC engine */
				wanpipe_hdlc_decode(globals.wanpipe_hdlc_decoder, buf, mlen);
			} else {
				/* HDLC frame comes already in the read data */
				ss7mon_handle_hdlc_frame(NULL, buf, mlen);
			}
		}

		queue_level = (rxhdr.wp_api_rx_hdr_number_of_frames_in_queue * 100) / (rxhdr.wp_api_rx_hdr_max_queue_length);
		if (queue_level >= globals.rxq_watermark) {
			ss7mon_log(SS7MON_WARNING, "Rx queue is %d%% full (number of frames in queue = %d, max queue length = %d, connected = %d)\n",
					queue_level, rxhdr.wp_api_rx_hdr_number_of_frames_in_queue, rxhdr.wp_api_rx_hdr_max_queue_length, globals.connected);
		}

	} while (rxhdr.wp_api_rx_hdr_number_of_frames_in_queue > 1);
}

static int rotate_file(FILE **file, const char *fname, const char *fmode, const char *ftype, int rotate_cnt)
{
	int rc = 0;
	char *new_name = malloc(strlen(fname) + 25);
	if (!new_name) {
		ss7mon_log(SS7MON_ERROR, "Failed to malloc new name string: %s, name = %s\n", strerror(errno), fname);
		return -1;
	}
	if (fclose(*file) != 0) {
		ss7mon_log(SS7MON_ERROR, "Failed to close %s file: %s\n", ftype, strerror(errno));
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
	free(new_name);
	return rc;
}

#define FISU_PRINT_THROTTLE_SIZE 1333 /* FISU / second (assuming driver MTP1 filtering is not enabled) */
#define LSSU_PRINT_THROTTLE_SIZE 100 /* Since these ones are only seen during alignment we may want to print them more often when debugging */
static int ss7mon_handle_hdlc_frame(struct wanpipe_hdlc_engine *engine, void *frame_data, int len)
{
	/* Maintenance warning: engine may be null if using hardware HDLC or SW HDLC in the driver */
	char *hdlc_frame = frame_data;

	globals.last_recv_time = time(NULL);
	globals.link_probably_dead = 0;

	/* check frame type */
	switch (hdlc_frame[2]) {
	case 0: /* FISU */
		if (!globals.fisu_cnt || !(globals.fisu_cnt % FISU_PRINT_THROTTLE_SIZE)) {
			ss7mon_log(SS7MON_DEBUG, "Got FISU of size %d [cnt=%llu]\n", len, (unsigned long long)globals.fisu_cnt);
		}
		globals.fisu_cnt++;
		if (!globals.link_aligned) {
			ss7mon_log(SS7MON_INFO, "SS7 Link State: Up");
			globals.link_aligned = 1;
		}
		if (!globals.fisu_enable) {
			return 0;
		}
		break;
	case 1: /* LSSU */
	case 2:
		if (!globals.lssu_cnt || !(globals.lssu_cnt % LSSU_PRINT_THROTTLE_SIZE)) {
			ss7mon_log(SS7MON_DEBUG, "Got LSSU of size %d [cnt=%llu]\n", len, (unsigned long long)globals.lssu_cnt);
		}
		globals.lssu_cnt++;
		if (globals.link_aligned) {
			ss7mon_log(SS7MON_WARNING, "SS7 Link State: Down (alignment procedure in progress)");
			globals.link_aligned = 0;
		}
		if (!globals.lssu_enable) {
			return 0;
		}
		break;
	default: /* MSU */
		globals.msu_cnt++;
		ss7mon_log(SS7MON_DEBUG, "Got MSU of size %d [cnt=%llu]\n", len, (unsigned long long)globals.msu_cnt);
		break;
	}

	/* write the HDLC frame in the PCAP file if needed */
	if (globals.pcap_file) {
		write_pcap_packet(globals.pcap_file, frame_data, len);	
	}

	/* write the HDLC frame to the hexdump file */
	if (globals.hexdump_file) {
		write_hexdump_packet(globals.hexdump_file, frame_data, len);
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
}

static sangoma_wait_obj_t *ss7mon_open_device(void)
{
	wanpipe_api_t tdm_api;
	sangoma_status_t status = SANG_STATUS_GENERAL_ERROR;
	sangoma_wait_obj_t *ss7_wait_obj = NULL;
	int ss7_txq_size = 0;
	int ss7_rxq_size = 0;
	unsigned char link_status = 0;

	globals.ss7_fd = sangoma_open_api_span_chan(globals.spanno, globals.channo);
	if (globals.ss7_fd == INVALID_HANDLE_VALUE) {
		ss7mon_log(SS7MON_ERROR, "Failed to open device s%dc%d: %s\n", globals.spanno, globals.channo, strerror(errno));
		return NULL;
	}
	ss7mon_log(SS7MON_INFO, "Opened device s%dc%d\n", globals.spanno, globals.channo);

	memset(&tdm_api, 0, sizeof(tdm_api));

	/* Flush buffers and stats */
	sangoma_tdm_flush_bufs(globals.ss7_fd, &tdm_api);
	sangoma_flush_stats(globals.ss7_fd, &tdm_api);
	status = sangoma_wait_obj_create(&ss7_wait_obj, globals.ss7_fd, SANGOMA_DEVICE_WAIT_OBJ);
	if (status != SANG_STATUS_SUCCESS) {
		ss7mon_log(SS7MON_ERROR, "Failed to create wait object for device s%dc%d: %s\n", globals.spanno, globals.channo, strerror(errno));
		sangoma_close(&globals.ss7_fd);
		globals.ss7_fd = -1;
		return NULL;
	}

	ss7_txq_size = sangoma_get_tx_queue_sz(globals.ss7_fd, &tdm_api);
	ss7mon_log(SS7MON_DEBUG, "Current tx queue size = %d\n", ss7_txq_size);
	ss7_txq_size = globals.txq_size;
	if (sangoma_set_tx_queue_sz(globals.ss7_fd, &tdm_api, ss7_txq_size)) {
		ss7mon_log(SS7MON_ERROR, "Failed to set tx queue size to %d\n", ss7_txq_size);
	} else {
		ss7mon_log(SS7MON_DEBUG, "Set tx queue size to %d\n", ss7_txq_size);
	}

	ss7_rxq_size = sangoma_get_rx_queue_sz(globals.ss7_fd, &tdm_api);
	ss7mon_log(SS7MON_DEBUG, "Current rx queue size = %d\n", ss7_rxq_size);
	ss7_rxq_size = globals.rxq_size;
	if (sangoma_set_rx_queue_sz(globals.ss7_fd, &tdm_api, ss7_rxq_size)) {
		ss7mon_log(SS7MON_ERROR, "Failed to set rx queue size to %d\n", ss7_rxq_size);
	} else {
		ss7mon_log(SS7MON_DEBUG, "Set rx queue size to %d\n", ss7_rxq_size);
	}

	if (sangoma_get_fe_status(globals.ss7_fd, &tdm_api, &link_status)) {
		ss7mon_log(SS7MON_ERROR, "Failed to get link status, assuming connected!\n");
		globals.connected = 1;
	} else {
		ss7mon_log(SS7MON_DEBUG, "Current link status = %s (%u)\n", link_status == 2 ? "Connected" : "Disconnected", link_status);
		if (link_status == 2) {
			globals.connected = 1;
		} else {
			globals.connected = 0;
		}
	}

	return ss7_wait_obj;
}

static void watchdog_exec(void)
{
	time_t now;
	time_t diff;
	static int watchdog_ready = 0;

	/* service any client requests */
	if (globals.zmq_socket) {
		int rc = 0;
		zmq_msg_t request;

		zmq_msg_init(&request);
		rc = zmq_recv(globals.zmq_socket, &request, ZMQ_NOBLOCK);
		if (!rc) {
			ss7mon_log(SS7MON_WARNING, "Server received message!\n");

			zmq_send(globals.zmq_socket, &request, 0);

		}

		zmq_msg_close(&request);
	}

	/* Check if message expiry should be checked */
	if (!globals.watchdog_seconds || !globals.last_recv_time) {
		return;
	}
	now = time(NULL);
	if (now < globals.last_recv_time) {
		ss7mon_log(SS7MON_DEBUG, "Time changed to the past, resetting last_recv_time from %ld to %ld\n", globals.last_recv_time, now);
		globals.last_recv_time = now;
		return;
	}
	diff = now - globals.last_recv_time;
	if (diff >= globals.watchdog_seconds && !(diff % globals.watchdog_seconds)) {
		if (watchdog_ready) {
			ss7mon_log(SS7MON_WARNING, "Time since last message was received: %ld seconds\n", diff);
			globals.missing_msu_periods++;
			globals.link_probably_dead = 1;
		}
		watchdog_ready = 0;
	} else {
		watchdog_ready = 1;
	}

}

static void ss7mon_print_usage(void)
{
	printf("USAGE:\n"
		"-dev <sXcY>           - Indicate Sangoma device to monitor, ie -dev s1c16 will monitor span 1 channel 16\n"
		"-lssu                 - Include LSSU frames (default is to ignore them)\n"
		"-fisu                 - Include FISU frames (default is to ignore them)\n"
		"-hexdump <file>       - Dump SS7 messages into the given file in hexadecimal text format\n"
		"-hexdump_flush        - Flush the hex dump on each packet received\n"
		"-pcap <file>          - pcap file path name to record the SS7 messages\n"
		"-pcap_mtp2_hdr        - Include the MTP2 pcap header\n"
		"-log <name>           - Log level name (DEBUG, INFO, WARNING, ERROR)\n"
		"-rxq_watermark <size> - Receive queue watermark percentage (when to print warnings about rx queue size overflowing)\n"
		"-rxq <size>           - Receive queue size\n"
		"-txq <size>           - Transmit queue size\n"
		"-swhdlc               - HDLC done in software (not FPGA or Driver)\n"
		"-txpcap <file>        - Transmit the given PCAP file\n"
		"-syslog               - Send logs to syslog\n"
		"-core                 - Enable core dumps\n"
		"-server               - Server string to listen for commands (ipc:///tmp/ss7mon_s1c1 or tcp://127.0.0.1:5555)\n"
		"-watchdog <time-secs> - Enable and set the number of seconds before warning about messages not being received\n"
		"-h[elp]               - Print usage\n"
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
	sangoma_status_t status = SANG_STATUS_GENERAL_ERROR;
	sangoma_wait_obj_t *ss7_wait_obj = NULL;
	struct rlimit rlp;
	int arg_i = 0;
	int i = 0;
	int rc = 0;
	char *dev = NULL;
	uint32_t input_flags = SANG_WAIT_OBJ_HAS_INPUT | SANG_WAIT_OBJ_HAS_EVENTS;
	uint32_t output_flags = 0;
	void *zmq_context = NULL;

	if (argc < 2) {
		ss7mon_print_usage();
		exit(0);
	}

	for (i = 0; i < ss7mon_arraylen(termination_signals); i++) {
		if (signal(termination_signals[i], ss7mon_handle_termination_signal) == SIG_ERR) {
			ss7mon_log(SS7MON_ERROR, "Failed to install signal handler for signal %d: %s\n", termination_signals[i], strerror(errno));
			exit(1);
		}
	}

	if (signal(SIGHUP, ss7mon_handle_rotate_signal) == SIG_ERR) {
		ss7mon_log(SS7MON_ERROR, "Failed to install SIGHUP signal handler %s\n", strerror(errno));
		exit(1);
	}

	for (arg_i = 1; arg_i < argc; arg_i++) {
		if (!strcasecmp(argv[arg_i], "-dev")) {
			int elements = 0;
			INC_ARG(arg_i);
			elements = sscanf(argv[arg_i], "s%dc%d", &globals.spanno, &globals.channo);
			if (elements != 2) {
				ss7mon_log(SS7MON_ERROR, "Invalid string '%s' for -dev option (device must be specified in format sXcY)\n", argv[arg_i]);
				exit(1);
			}
			if (globals.spanno <= 0) {
				ss7mon_log(SS7MON_ERROR, "Invalid string '%s' for -dev option (span must be bigger than 0)\n", argv[arg_i]);
				exit(1);
			}
			if (globals.channo <= 0) {
				ss7mon_log(SS7MON_ERROR, "Invalid string '%s' for -dev option (channel must be bigger than 0)\n", argv[arg_i]);
				exit(1);
			}
			dev = argv[arg_i];
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
		} else if (!strcasecmp(argv[arg_i], "-swhdlc")) {
			globals.swhdlc_enable = 1;
		} else if (!strcasecmp(argv[arg_i], "-hexdump_flush")) {
			globals.hexdump_flush_enable = 1;
		} else if (!strcasecmp(argv[arg_i], "-hexdump")) {
			INC_ARG(arg_i);
			globals.hexdump_file = fopen(argv[arg_i], "w");
			if (!globals.hexdump_file) {
				ss7mon_log(SS7MON_ERROR, "Failed to open hexdump file '%s'\n", argv[arg_i]);
				exit(1);
			}
			snprintf(globals.hexdump_file_name, sizeof(globals.hexdump_file_name), "%s", argv[arg_i]);
		} else if (!strcasecmp(argv[arg_i], "-pcap")) {
			INC_ARG(arg_i);
			globals.pcap_file = fopen(argv[arg_i], "wb");
			if (!globals.pcap_file) {
				ss7mon_log(SS7MON_ERROR, "Failed to open pcap file '%s'\n", argv[arg_i]);
				exit(1);
			}
			snprintf(globals.pcap_file_name, sizeof(globals.pcap_file_name), "%s", argv[arg_i]);
		} else if (!strcasecmp(argv[arg_i], "-txpcap")) {
			INC_ARG(arg_i);
			globals.tx_pcap_file = fopen(argv[arg_i], "rb");
			if (!globals.tx_pcap_file) {
				ss7mon_log(SS7MON_ERROR, "Failed to open tx pcap file '%s'\n", argv[arg_i]);
				exit(1);
			}
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
			zmq_context = zmq_init(1);
			if (!zmq_context) {
				ss7mon_log(SS7MON_ERROR, "Failed to create ZeroMQ context\n");
				exit(1);
			}
			globals.zmq_socket = zmq_socket(zmq_context, ZMQ_REP);
			if (!globals.zmq_socket) {
				ss7mon_log(SS7MON_ERROR, "Failed to create ZeroMQ socket\n");
				exit(1);
			}
			rc = zmq_bind(globals.zmq_socket, argv[arg_i]);
			if (rc) {
				ss7mon_log(SS7MON_ERROR, "Failed to bind ZeroMQ socket to address %s: %s\n", argv[arg_i], strerror(errno));
				exit(1);
			}
			ss7mon_log(SS7MON_INFO, "Successfully bound server to address %s\n", argv[arg_i]);
		} else if (!strcasecmp(argv[arg_i], "-watchdog")) {
			INC_ARG(arg_i);
			globals.watchdog_seconds = atoi(argv[arg_i]);
			if (globals.watchdog_seconds < 1) {
				ss7mon_log(SS7MON_ERROR, "Invalid watchdog time specified: '%s'\n", argv[arg_i]);
				exit(1);
			}
		} else if (!strcasecmp(argv[arg_i], "-h") || !strcasecmp(argv[arg_i], "-help")) {
			ss7mon_print_usage();
			exit(0);
		} else {
			ss7mon_log(SS7MON_ERROR, "Invalid option %s\n", argv[arg_i]);
			exit(1);
		}
	}

	if (!dev) {
		ss7mon_log(SS7MON_ERROR, "-dev option must be specified\n");
		exit(1);
	}

	/* Open the Sangoma device */
	ss7_wait_obj = ss7mon_open_device();
	if (!ss7_wait_obj) {
		exit(1);
	}

	/* initialize the HDLC engine */
	globals.wanpipe_hdlc_decoder = wanpipe_reg_hdlc_engine();
	if (!globals.wanpipe_hdlc_decoder) {
		ss7mon_log(SS7MON_ERROR, "Failed to create Wanpipe HDLC engine\n");
		exit(1);
	}
	globals.wanpipe_hdlc_decoder->hdlc_data = ss7mon_handle_hdlc_frame;

	/* Write the pcap header */
	if (globals.pcap_file) {
		write_pcap_header(globals.pcap_file);
	}

	/* skip tx pcap header */
	if (globals.tx_pcap_file) {
		pcap_hdr_t hdr;
		size_t elements = 0;
		elements = fread(&hdr, sizeof(hdr), 1, globals.tx_pcap_file);
		if (elements != 1) {
			fclose(globals.tx_pcap_file);
			globals.tx_pcap_file = NULL;
		} else {
			if (hdr.magic != SS7MON_PCAP_MAGIC) {
				ss7mon_log(SS7MON_ERROR, "Invalid Tx pcap file (magic number is 0x%X and not 0x%X)\n", hdr.magic, SS7MON_PCAP_MAGIC);
				exit(1);
			}
			ss7mon_log(SS7MON_DEBUG, "Tx pcap major = %d, minor = %d, snaplen = %d, network = %d\n", 
					hdr.version_major, hdr.version_minor, hdr.snaplen, hdr.network);
			if (hdr.network != globals.pcap_mtp2_link_type) {
				ss7mon_log(SS7MON_ERROR, "Invalid Tx pcap file (linktype is %d and not %d)\n", hdr.network, globals.pcap_mtp2_link_type);
				exit(1);
			}
		}
	}

	/* monitoring loop */
	globals.running = 1;
	ss7mon_log(SS7MON_INFO, "SS7 monitor loop now running ...\n");
	globals.last_recv_time = time(NULL);
	while (globals.running) {

		watchdog_exec();
		
		if (globals.ss7_fd == -1) {
			sleep(SS7MON_SAFE_WAIT);
			ss7_wait_obj = ss7mon_open_device();
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
				ss7mon_handle_oob_event();
			}
			if (output_flags & SANG_WAIT_OBJ_HAS_INPUT) {
				ss7mon_handle_input();
			}
			break;
		default:
			ss7mon_log(SS7MON_ERROR, "Failed to wait for device (status = %d, %s)\n", status, strerror(errno));
			break;
		}

		if (globals.tx_pcap_file) {
			tx_pcap_frame();
		}

		if (globals.rotate_request) {
			globals.rotate_request = 0;
			if (!rotate_file(&globals.pcap_file, globals.pcap_file_name, "wb", "pcap", globals.rotate_cnt)) {
				write_pcap_header(globals.pcap_file);
			}
			rotate_file(&globals.hexdump_file, globals.hexdump_file_name, "w", "hexdump", globals.rotate_cnt);
			globals.rotate_cnt++;
		}
	}

	if (globals.pcap_file) {
		fclose(globals.pcap_file);
		globals.pcap_file = NULL;
	}

	if (globals.zmq_socket) {
		zmq_close(globals.zmq_socket);
		globals.zmq_socket = NULL;
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

