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
} globals = {
	SS7MON_DEFAULT_TX_QUEUE_SIZE,
	SS7MON_DEFAULT_RX_QUEUE_SIZE,
	SS7MON_WARNING,
	-1,
	-1,
	-1	
};

static void ss7mon_print_usage(void)
{
	printf("USAGE:\n"
		"-dev <sXcY> - Indicate Sangoma device to monitor, ie -dev s1c16 will monitor span 1 channel 16\n"
		"-h[elp]     - Print usage\n"
	);
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

	if (argc < 2) {
		ss7mon_print_usage();
		exit(0);
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

	exit(0);
}

