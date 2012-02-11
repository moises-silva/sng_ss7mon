/*===================================================
  wanpipe_hdlc.h:  WANPIPE HDLC Library
*/

#ifndef _WANPIPE_HDLC_H
#define _WANPIPE_HDLC_H

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#if defined(__WINDOWS__)
# define wan_inline __inline
# ifdef __cplusplus
   extern "C" {	/* for C++ users */
# endif
#else
# include <ctype.h>
# include <unistd.h>
# include <errno.h>
# define wan_inline inline
#endif
#include <errno.h>

/*===================================================================
 * 
 * DEFINES
 * 
 *==================================================================*/

#define MAX_SOCK_CRC_QUEUE 3
#define MAX_SOCK_HDLC_BUF 15000
#define MAX_SOCK_HDLC_LIMIT MAX_SOCK_HDLC_BUF-500
#define HDLC_ENG_BUF_LEN 8000

 
#define INC_CRC_CNT(a)   if (++a >= MAX_SOCK_CRC_QUEUE) a=0;
#define GET_FIN_CRC_CNT(a)  { if (--a < 0) a=MAX_SOCK_CRC_QUEUE-1; \
		              if (--a < 0) a=MAX_SOCK_CRC_QUEUE-1; }

#define FLIP_CRC(a,b)  { b=0; \
			 b |= (a&0x000F)<<12 ; \
			 b |= (a&0x00F0) << 4; \
			 b |= (a&0x0F00) >> 4; \
			 b |= (a&0xF000) >> 12; }

#define DECODE_CRC(a) { a=( (((~a)&0x000F)<<4) | \
		            (((~a)&0x00F0)>>4) | \
			    (((~a)&0x0F00)<<4) | \
			    (((~a)&0xF000)>>4) ); }
#define BITSINBYTE 8

#define NO_FLAG 	0
#define OPEN_FLAG 	1
#define CLOSING_FLAG 	2       


typedef struct wanpipe_hdlc_stats
{
	int packets;
	int errors;

	int crc;
	int abort;
	int frame_overflow;

}wanpipe_hdlc_stats_t;

#define MAX_HDLC_RING_SIZE 5 
typedef struct wanpipe_hdlc_ring
{
	unsigned char data[MAX_SOCK_HDLC_BUF];
	unsigned int  len;
}wanpipe_hdlc_ring_buf_t;

typedef	struct wanpipe_hdlc_decoder{
	unsigned char 	rx_decode_buf[MAX_SOCK_HDLC_BUF];
	unsigned int  	rx_decode_len;
	unsigned char 	rx_decode_bit_cnt;
	unsigned char 	rx_decode_onecnt;
	
	unsigned long	hdlc_flag;
	unsigned short 	rx_orig_crc;
	unsigned short 	rx_crc[MAX_SOCK_CRC_QUEUE];
	unsigned short 	crc_fin;

	wanpipe_hdlc_ring_buf_t rx_decode_ring[MAX_HDLC_RING_SIZE];
	unsigned int 	rx_ring_idx;

	unsigned short 	rx_crc_tmp;
	int 		crc_cur;
	int 		crc_prv;
	wanpipe_hdlc_stats_t stats;
}wanpipe_hdlc_decoder_t;


typedef	struct wanpipe_hdlc_encoder{
	
	unsigned char tx_decode_buf[HDLC_ENG_BUF_LEN];
	unsigned int  tx_decode_len;
	unsigned char tx_decode_bit_cnt;
	unsigned char tx_decode_onecnt;        

	unsigned short tx_crc;
	unsigned char tx_flag;
	unsigned char tx_flag_offset;
	unsigned char tx_flag_offset_data;
	unsigned char tx_flag_idle;  
	
	unsigned short tx_crc_fin;
	unsigned short tx_crc_tmp;   
	unsigned char  tx_idle_flag;
	unsigned char  bits_in_byte;
	  
	wanpipe_hdlc_stats_t stats;
}wanpipe_hdlc_encoder_t;

typedef struct wanpipe_hdlc_engine
{

	wanpipe_hdlc_decoder_t decoder;
	wanpipe_hdlc_encoder_t encoder;

	unsigned char	raw_rx[MAX_SOCK_HDLC_BUF];
	unsigned char	raw_tx[MAX_SOCK_HDLC_BUF];

	int 		refcnt;

	unsigned char	bound;

	unsigned long	active_ch;
	unsigned short  timeslots;
	struct wanpipe_hdlc_engine *next;

	int 		skb_decode_size;
	unsigned char	seven_bit_hdlc;
	unsigned char 	bits_in_byte;

	int (*hdlc_data) (struct wanpipe_hdlc_engine *hdlc_eng, void *data, int len);

    void *context; /* user can store a pointer here, so it can be used when
					* hdlc_data() callback runs */

}wanpipe_hdlc_engine_t;

typedef struct hdlc_list
{
	wanpipe_hdlc_engine_t *hdlc;
	struct hdlc_list *next;
}wanpipe_hdlc_list_t; 


#define set_bit(bit_no,ptr) ((*ptr)|=(1<<bit_no)) 
#define clear_bit(bit_no,ptr) ((*ptr)&=~(1<<bit_no))
#define test_bit(bit_no,ptr)  ((*ptr)&(1<<bit_no))

#if 0
#define DEBUG_TX	printf
#define DEBUG_EVENT	printf	
#else
#define DEBUG_EVENT	
#define DEBUG_TX	
#endif

static wan_inline 
void init_hdlc_decoder(wanpipe_hdlc_decoder_t *hdlc_decoder)
{
	hdlc_decoder->hdlc_flag=0;
	set_bit(NO_FLAG,&hdlc_decoder->hdlc_flag);
	
	hdlc_decoder->rx_decode_len=0;
	hdlc_decoder->rx_decode_buf[hdlc_decoder->rx_decode_len]=0;
	hdlc_decoder->rx_decode_bit_cnt=0;
	hdlc_decoder->rx_decode_onecnt=0;
	hdlc_decoder->rx_crc[0]=-1;
	hdlc_decoder->rx_crc[1]=-1;
	hdlc_decoder->rx_crc[2]=-1;
	hdlc_decoder->crc_cur=0; 
	hdlc_decoder->crc_prv=0;
}                   

static wan_inline
void init_hdlc_encoder(wanpipe_hdlc_encoder_t *chan)
{
	chan->tx_crc=-1;
	chan->tx_flag= 0x7E; 
	chan->tx_flag_idle= 0x7E;
	chan->tx_idle_flag=0x7E;
}

/* External Functions */

extern wanpipe_hdlc_engine_t *wanpipe_reg_hdlc_engine (void);
extern void wanpipe_unreg_hdlc_engine(wanpipe_hdlc_engine_t *hdlc_eng);
extern int wanpipe_hdlc_decode (wanpipe_hdlc_engine_t *hdlc_eng, 
			 	unsigned char *buf, int len);
extern int wanpipe_hdlc_encode(wanpipe_hdlc_engine_t *hdlc_eng, 
		       unsigned char *usr_data, int usr_len,
		       unsigned char *hdlc_data, int *hdlc_len,
		       unsigned char *next_idle);
extern int wanpipe_get_rx_hdlc_errors (wanpipe_hdlc_engine_t *hdlc_eng);
extern int wanpipe_get_tx_hdlc_errors (wanpipe_hdlc_engine_t *hdlc_eng);
extern int wanpipe_get_rx_hdlc_packets (wanpipe_hdlc_engine_t *hdlc_eng);
extern int wanpipe_get_tx_hdlc_packets (wanpipe_hdlc_engine_t *hdlc_eng);
extern int wanpipe_hdlc_dump_ring(wanpipe_hdlc_engine_t *hdlc_eng);

#if defined(__WINDOWS__)
#ifdef __cplusplus
}	/* for C++ users */
#endif /* __cplusplus */
#endif

#endif /* _WANPIPE_HDLC_H */
