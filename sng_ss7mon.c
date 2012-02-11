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

typedef enum _ss7mon_log_level {
	SS7MON_DEBUG = 0,
	SS7MON_INFO,
	SS7MON_WARNING,
	SS7MON_ERROR,
} ss7mon_log_level_t;

#define ss7mon_log(loglevel, format, ...) \
	do { \
		if (globals.spanno >= 0) { \
			fprintf(stderr, "[s%dc%d] "format, globals.spanno, globals.channo, ##__VA_ARGS__); \
		} else { \
			fprintf(stderr, format, ##__VA_ARGS__); \
		} \
	} while (0)

#define SS7MON_DEFAULT_TX_QUEUE_SIZE 500
#define SS7MON_DEFAULT_RX_QUEUE_SIZE 500
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
};

static void ss7mon_print_usage(void)
{
	printf("USAGE:\n"
		"-dev <sXcY> - Indicate Sangoma device to monitor, ie -dev s1c16 will monitor span 1 channel 16\n"
		"-h[elp]     - Print usage\n"
	);
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

		/* fill in data to the HDLC engine */
#if 0
		hdlc_rx_put(globals.hdlc_rx, buf, mlen);
#else
		wanpipe_hdlc_decode(globals.wanpipe_hdlc_decoder, buf, mlen);

#endif
	} while (rxhdr.wp_api_rx_hdr_number_of_frames_in_queue > 1);
}

static int ss7mon_handle_hdlc_frame(struct wanpipe_hdlc_engine *engine, void *frame_data, int len)
{
	ss7mon_log(SS7MON_ERROR, "Received HDLC frame of size %d\n", len);
	return 0;
}

static void ss7mon_handle_signal(int signum)
{
	if (signum == SIGINT) {
		globals.running = 0;
	}
}

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
	char *dev = NULL;
	unsigned char link_status = 0;
	uint32_t input_flags = SANG_WAIT_OBJ_HAS_INPUT | SANG_WAIT_OBJ_HAS_EVENTS;
	uint32_t output_flags = 0;

	if (argc < 2) {
		ss7mon_print_usage();
		exit(0);
	}

	if (signal(SIGINT, ss7mon_handle_signal) == SIG_ERR) {
		ss7mon_log(SS7MON_ERROR, "Failed to install signal handler %s\n", strerror(errno));
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
	ss7mon_log(SS7MON_INFO, "Current tx queue size = %d\n", ss7_txq_size);
	ss7_txq_size = globals.txq_size;
	if (sangoma_set_tx_queue_sz(globals.ss7_fd, &tdm_api, ss7_txq_size)) {
		ss7mon_log(SS7MON_ERROR, "Failed to set tx queue size to %d\n", ss7_txq_size);
		exit(1);
	}
	ss7mon_log(SS7MON_INFO, "Set tx queue size to %d\n", ss7_txq_size);

	ss7_rxq_size = sangoma_get_rx_queue_sz(globals.ss7_fd, &tdm_api);
	ss7mon_log(SS7MON_INFO, "Current rx queue size = %d\n", ss7_rxq_size);
	ss7_rxq_size = globals.rxq_size;
	if (sangoma_set_rx_queue_sz(globals.ss7_fd, &tdm_api, ss7_rxq_size)) {
		ss7mon_log(SS7MON_ERROR, "Failed to set rx queue size to %d\n", ss7_rxq_size);
		exit(1);
	}
	ss7mon_log(SS7MON_INFO, "Set rx queue size to %d\n", ss7_rxq_size);

	/* initialize the HDLC engine */
	globals.wanpipe_hdlc_decoder = wanpipe_reg_hdlc_engine();
	if (!globals.wanpipe_hdlc_decoder) {
		ss7mon_log(SS7MON_ERROR, "Failed to create Wanpipe HDLC engine\n");
		exit(1);
	}
	globals.wanpipe_hdlc_decoder->hdlc_data = ss7mon_handle_hdlc_frame;

	if (sangoma_get_fe_status(globals.ss7_fd, &tdm_api, &link_status)) {
		ss7mon_log(SS7MON_ERROR, "Failed to get link status\n");
		exit(1);
	}

	ss7mon_log(SS7MON_INFO, "Current link status = %u\n", link_status);
	if (link_status == 2) {
		globals.connected = 1;
	} else {
		globals.connected = 0;
	}

	/* monitoring loop */
	globals.running = 1;
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

	ss7mon_log(SS7MON_INFO, "Terminating monitoring ...\n");
	exit(0);
}




