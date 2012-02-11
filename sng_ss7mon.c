/*
 * ss7mon
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

#include <libsangoma.h>
#include "wanpipe_hdlc.h"

#define ss7mon_araylen(_array) sizeof(_array)/sizeof(_array[0])

typedef enum _ss7mon_log_level {
	SS7MON_DEBUG = 0,
	SS7MON_INFO,
	SS7MON_WARNING,
	SS7MON_ERROR,
} ss7mon_log_level_t;

static struct {
	const char *name;
	ss7mon_log_level_t level;
} ss7mon_log_levels[] = {
	{ "DEBUG", SS7MON_DEBUG },
	{ "INFO", SS7MON_INFO },
	{ "WARNING", SS7MON_WARNING },
	{ "ERROR", SS7MON_ERROR },
};
#define ss7mon_log(level, format, ...) \
	do { \
		if (level >= globals.loglevel) { \
			if (globals.spanno >= 0) { \
				fprintf(stderr, "[%s] [s%dc%d] " format, ss7mon_log_levels[level].name, globals.spanno, globals.channo, ##__VA_ARGS__); \
			} else { \
				fprintf(stderr, "[%s]" format, ss7mon_log_levels[level].name, ##__VA_ARGS__); \
			} \
		} \
	} while (0)

#define SS7MON_DEFAULT_TX_QUEUE_SIZE 500
#define SS7MON_DEFAULT_RX_QUEUE_SIZE 500

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
	int txq_size;
	int rxq_size;
	int loglevel;
	int spanno;
	int channo;
	int ss7_fd;
	int connected;
	volatile int running;
	int ss7_rx_errors;
	wanpipe_hdlc_engine_t *wanpipe_hdlc_decoder;
	FILE *pcap_file;
	char pcap_file_name[1024];
	int rotate_pcap;
	int pcap_count;
} globals = {
	SS7MON_DEFAULT_TX_QUEUE_SIZE,
	SS7MON_DEFAULT_RX_QUEUE_SIZE,
	SS7MON_WARNING,
	-1,
	-1,
	-1,
	0,
	0,
	0,
	NULL,
	NULL,
	{ 0 },
	0,
	1,
};

static void write_pcap_header(FILE *f)
{
	size_t wrote = 0;
	pcap_hdr_t hdr;
	hdr.magic = 0xa1b2c3d4; /* pcap magic */
	hdr.version_major = 2;
	hdr.version_minor = 4;
	hdr.thiszone = 0;
	hdr.sigfigs = 0;
	hdr.snaplen = 65535;
	hdr.network = 140; /* http://www.tcpdump.org/linktypes.html, LINKTYPE_MTP2 (140), 
			      could be 139 if we add extra hdr manually, LINKTYPE_MTP2_WITH_PHDR */
	wrote = fwrite(&hdr, sizeof(hdr), 1, f);
	if (!wrote) {
		ss7mon_log(SS7MON_ERROR, "Failed writing pcap header!\n");
	}
}

static void write_pcap_packet(FILE *f, void *packet_buffer, int packet_len)
{
	size_t wrote = 0;
	struct timespec ts;
	pcap_record_hdr_t hdr;

	clock_gettime(CLOCK_REALTIME, &ts);

	hdr.ts_sec = ts.tv_sec;
	hdr.ts_usec = (ts.tv_nsec / 1000);
	hdr.incl_len = packet_len;
	hdr.orig_len = packet_len;
	wrote = fwrite(&hdr, 1, sizeof(hdr), f);
	if (!wrote) {
		ss7mon_log(SS7MON_ERROR, "Failed writing pcap packet header: %s\n", strerror(errno));
	}
	wrote = fwrite(packet_buffer, 1, packet_len, f);
	if (!wrote) {
		ss7mon_log(SS7MON_ERROR, "Failed writing pcap packet data: %s\n", strerror(errno));
	}
}

static void ss7mon_handle_oob_event(void)
{
	wanpipe_api_t tdm_api;
	wp_api_event_t *wp_event = NULL;

	memset(wp_event, 0, sizeof(wp_event));
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
			break;
		case WP_API_EVENT_LINK_STATUS_DISCONNECTED:
			globals.connected = 0;
			break;
		default:
			ss7mon_log(SS7MON_ERROR, "Unkown link status: %d\n", wp_event->wp_api_event_link_status);
			break;
		}
		break;
	default:
		ss7mon_log(SS7MON_ERROR, "Unkown event: %d\n", wp_event->wp_api_event_type);
		break;
	}
}

static void ss7mon_handle_input(void)
{
	wp_api_hdr_t rxhdr;
	unsigned char buf[300]; /* Max MSU pack should be 272 per spec, give a bit of more room */
	int mlen = 0;
	int queue_level = 0;
	int print_queue_level = 1;
	do {
		memset(buf, 0, sizeof(buf));
		mlen = sangoma_readmsg(globals.ss7_fd, &rxhdr, sizeof(rxhdr), buf, sizeof(buf), 0);
		if (mlen < 0) {
			ss7mon_log(SS7MON_ERROR, "Error reading SS7 message: %s\n", strerror(errno));
			return;
		}

		if (mlen == 0) {
			ss7mon_log(SS7MON_ERROR, "Read empty message\n");
			return;
		}

		if (rxhdr.wp_api_rx_hdr_errors > globals.ss7_rx_errors) {
			globals.ss7_rx_errors = rxhdr.wp_api_rx_hdr_errors;
			ss7mon_log(SS7MON_ERROR, "Rx errors: %d\n", globals.ss7_rx_errors);
		}

		if (rxhdr.wp_api_rx_hdr_error_map) {
			ss7mon_log(SS7MON_ERROR, "Rx error map 0x%X\n", rxhdr.wp_api_rx_hdr_error_map);
			return;
		}

		/* check frame type */
		switch (buf[2]) {
		case 0: /* FISU */
			break;
		case 1: /* LSSU */
		case 2:
			break;
		default: /* MSU */
			break;
		}

		queue_level = (rxhdr.wp_api_rx_hdr_number_of_frames_in_queue * 100) / (rxhdr.wp_api_rx_hdr_max_queue_length);
		if (queue_level > 10 && print_queue_level) {
			ss7mon_log(SS7MON_INFO, "Rx queue is %d%% full\n", queue_level);
			print_queue_level = 0;
		}
		if (queue_level > 85) {
			ss7mon_log(SS7MON_WARNING, "Rx queue is %d%% full\n", queue_level);
		}

		if (globals.connected) {
			/* fill in data to the HDLC engine */
			wanpipe_hdlc_decode(globals.wanpipe_hdlc_decoder, buf, mlen);
		}
	} while (rxhdr.wp_api_rx_hdr_number_of_frames_in_queue > 1);
}

static int ss7mon_handle_hdlc_frame(struct wanpipe_hdlc_engine *engine, void *frame_data, int len)
{
	/* write the HDLC frame in the PCAP file if needed */
	if (globals.pcap_file) {
		if (globals.rotate_pcap) {
			char new_name[sizeof(globals.pcap_file_name)+25];
			globals.rotate_pcap = 0;
			if (fclose(globals.pcap_file)) {
				ss7mon_log(SS7MON_ERROR, "Failed to close pcap file: %s\n", strerror(errno));
			}
			globals.pcap_file = NULL;
			snprintf(new_name, sizeof(new_name), "%s.%d", globals.pcap_file_name, globals.pcap_count);
			if (rename(globals.pcap_file_name, new_name)) {
				ss7mon_log(SS7MON_ERROR, "Failed to rename pcap file %s to %s: %s\n", 
						globals.pcap_file_name, new_name, strerror(errno));
			} else {
				ss7mon_log(SS7MON_INFO, "Rotated SS7 monitor pcap %s to %s\n", globals.pcap_file_name, new_name);
				globals.pcap_count++;
				globals.pcap_file = fopen(globals.pcap_file_name, "wb");
				if (!globals.pcap_file) {
					ss7mon_log(SS7MON_ERROR, "Failed to open pcap file %s: %s\n", 
							globals.pcap_file_name, strerror(errno));
					return 0;
				} else {
					write_pcap_header(globals.pcap_file);
				}
			}
		}
		write_pcap_packet(globals.pcap_file, frame_data, len);	
	}
	return 0;
}

static void ss7mon_handle_termination_signal(int signum)
{
	globals.running = 0;
}

static void ss7mon_handle_rotate_signal(int signum)
{
	/* rotate the pcap file */
	if (!globals.rotate_pcap) {
		globals.rotate_pcap = 1;
	}
}

static void ss7mon_print_usage(void)
{
	printf("USAGE:\n"
		"-dev <sXcY>  - Indicate Sangoma device to monitor, ie -dev s1c16 will monitor span 1 channel 16\n"
		"-pcap <file> - pcap file path name to record the SS7 messages\n"
		"-log <name>  - Log level name (DEBUG, INFO, WARNING, ERROR)\n"
		"-rxq <size>  - Receive queue size\n"
		"-rxq <size>  - Receive queue size\n"
		"-h[elp]      - Print usage\n"
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
	wanpipe_api_t tdm_api;
	int ss7_txq_size = 0;
	int ss7_rxq_size = 0;
	int arg_i = 0;
	int i = 0;
	char *dev = NULL;
	unsigned char link_status = 0;
	uint32_t input_flags = SANG_WAIT_OBJ_HAS_INPUT | SANG_WAIT_OBJ_HAS_EVENTS;
	uint32_t output_flags = 0;

	if (argc < 2) {
		ss7mon_print_usage();
		exit(0);
	}

	for (i = 0; i < ss7mon_araylen(termination_signals); i++) {
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
		} else if (!strcasecmp(argv[arg_i], "-pcap")) {
			INC_ARG(arg_i);
			globals.pcap_file = fopen(argv[arg_i], "wb");
			if (!globals.pcap_file) {
				ss7mon_log(SS7MON_ERROR, "Failed to open pcap file '%s'\n", argv[arg_i]);
				exit(1);
			}
			snprintf(globals.pcap_file_name, sizeof(globals.pcap_file_name), "%s", argv[arg_i]);
		} else if (!strcasecmp(argv[arg_i], "-log")) {
			INC_ARG(arg_i);
			for (i = 0; i < ss7mon_araylen(ss7mon_log_levels); i++) {
				if (!strcasecmp(argv[arg_i], ss7mon_log_levels[i].name)) {
					globals.loglevel = ss7mon_log_levels[i].level;
					break;
				}
			}
			if (i == ss7mon_araylen(ss7mon_log_levels)) {
				ss7mon_log(SS7MON_ERROR, "Invalid log level specified: '%s'\n", argv[arg_i]);
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
	globals.ss7_fd = sangoma_open_api_span_chan(globals.spanno, globals.channo);
	if (globals.ss7_fd == INVALID_HANDLE_VALUE) {
		exit(1);
	}

	status = sangoma_wait_obj_create(&ss7_wait_obj, globals.ss7_fd, SANGOMA_DEVICE_WAIT_OBJ);
	if (status != SANG_STATUS_SUCCESS) {
		exit(1);
	}

	memset(&tdm_api, 0, sizeof(tdm_api));

	ss7_txq_size = sangoma_get_tx_queue_sz(globals.ss7_fd, &tdm_api);
	ss7mon_log(SS7MON_DEBUG, "Current tx queue size = %d\n", ss7_txq_size);
	ss7_txq_size = globals.txq_size;
	if (sangoma_set_tx_queue_sz(globals.ss7_fd, &tdm_api, ss7_txq_size)) {
		ss7mon_log(SS7MON_ERROR, "Failed to set tx queue size to %d\n", ss7_txq_size);
		exit(1);
	}
	ss7mon_log(SS7MON_DEBUG, "Set tx queue size to %d\n", ss7_txq_size);

	ss7_rxq_size = sangoma_get_rx_queue_sz(globals.ss7_fd, &tdm_api);
	ss7mon_log(SS7MON_DEBUG, "Current rx queue size = %d\n", ss7_rxq_size);
	ss7_rxq_size = globals.rxq_size;
	if (sangoma_set_rx_queue_sz(globals.ss7_fd, &tdm_api, ss7_rxq_size)) {
		ss7mon_log(SS7MON_ERROR, "Failed to set rx queue size to %d\n", ss7_rxq_size);
		exit(1);
	}
	ss7mon_log(SS7MON_DEBUG, "Set rx queue size to %d\n", ss7_rxq_size);

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

	if (sangoma_get_fe_status(globals.ss7_fd, &tdm_api, &link_status)) {
		ss7mon_log(SS7MON_ERROR, "Failed to get link status\n");
		exit(1);
	}

	ss7mon_log(SS7MON_DEBUG, "Current link status = %u\n", link_status);
	if (link_status == 2) {
		globals.connected = 1;
	} else {
		globals.connected = 0;
	}

	/* monitoring loop */
	globals.running = 1;
	ss7mon_log(SS7MON_INFO, "SS7 monitor loop now running ...\n");
	while (globals.running) {
		status = sangoma_waitfor(ss7_wait_obj, input_flags, &output_flags, 1000);
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
			ss7mon_log(SS7MON_ERROR, "Failed to wait for device (status = %d)\n", status);
			break;
		}
	}

	if (globals.pcap_file) {
		fclose(globals.pcap_file);
		globals.pcap_file = NULL;
	}

	ss7mon_log(SS7MON_INFO, "Terminating SS7 monitoring ...\n");
	exit(0);
}




