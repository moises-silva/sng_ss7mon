/*=====================================================
 * wanpipe_hdlc.c: WANPIPE HDLC Library
 *
 */

#include <string.h>
#include "wanpipe_hdlc.h"

 
/*===================================================================
   PROTOTYPES
*/
static void init_crc(void);
static void calc_rx_crc(wanpipe_hdlc_decoder_t *chan);
static int decode_byte (wanpipe_hdlc_engine_t *hdlc_eng, 
		        wanpipe_hdlc_decoder_t *chan,
			unsigned char *byte_ptr);
static void encode_byte (wanpipe_hdlc_encoder_t *chan, 
			 unsigned char *byte_ptr, int flag);
static void calc_tx_crc(wanpipe_hdlc_encoder_t *chan, unsigned char byte);

/*===================================================================
 * 
 * GLOBAL VARIABLES
 * 
 *==================================================================*/

static const int MagicNums[8] = { 0x1189, 0x2312, 0x4624, 0x8C48, 0x1081, 0x2102, 0x4204, 0x8408 };
static unsigned short CRC_TABLE[256];
static unsigned long init_crc_g=0;
static const char FLAG[]={ 0x7E, 0xFC, 0xF9, 0xF3, 0xE7, 0xCF, 0x9F, 0x3F };         
 

wanpipe_hdlc_engine_t *wanpipe_reg_hdlc_engine (void)
{
	wanpipe_hdlc_engine_t *hdlc_eng;

	init_crc();
	
	hdlc_eng = malloc(sizeof(wanpipe_hdlc_engine_t));
	if (!hdlc_eng){
		return NULL;
	}	

	memset(hdlc_eng,0,sizeof(wanpipe_hdlc_engine_t));

	hdlc_eng->seven_bit_hdlc=0;
	hdlc_eng->bits_in_byte=BITSINBYTE;
	init_hdlc_decoder(&hdlc_eng->decoder);
	init_hdlc_encoder(&hdlc_eng->encoder);

	return hdlc_eng;	
}

void wanpipe_unreg_hdlc_engine(wanpipe_hdlc_engine_t *hdlc_eng)
{
	free(hdlc_eng);
}                   


static void print_packet(unsigned char *buf, int len)
{
	int x;
	printf("{  | ");
	for (x=0;x<len;x++){
		if (x && x%24 == 0){
			printf("\n  ");
		}
		if (x && x%8 == 0)
			printf(" | ");
		printf("%02x ",buf[x]);
	}
	printf("}\n");
}

int wanpipe_hdlc_dump_ring(wanpipe_hdlc_engine_t *hdlc_eng)
{
 	int i;
	wanpipe_hdlc_decoder_t *hdlc_decoder = &hdlc_eng->decoder;
    int ridx=hdlc_decoder->rx_ring_idx;
	
	for (i=0;i< MAX_HDLC_RING_SIZE;i++) {
     	print_packet(hdlc_decoder->rx_decode_ring[ridx].data,hdlc_decoder->rx_decode_ring[ridx].len);
		ridx++;
		if (ridx >= MAX_HDLC_RING_SIZE) {
         	ridx=0;
		}
	}

	return 0;
}

/* HDLC Bitstream Decode Functions */
int wanpipe_hdlc_decode (wanpipe_hdlc_engine_t *hdlc_eng, 
			 unsigned char *buf, int len)
{
	int i;
	int gotdata=0;
	/* Data found proceed to decode
	 * the bitstream and pull out data packets */
   	wanpipe_hdlc_decoder_t *hdlc_decoder = &hdlc_eng->decoder;

	if (hdlc_eng->seven_bit_hdlc){
		hdlc_eng->bits_in_byte=7;
		
	}else{
		hdlc_eng->bits_in_byte=8;
	}


	memcpy(&hdlc_decoder->rx_decode_ring[hdlc_decoder->rx_ring_idx].data[0],buf,len);
    hdlc_decoder->rx_decode_ring[hdlc_decoder->rx_ring_idx].len=len;
	hdlc_decoder->rx_ring_idx++;

	if (hdlc_decoder->rx_ring_idx >= MAX_HDLC_RING_SIZE) {
      	hdlc_decoder->rx_ring_idx=0;
	}


		for (i=0; i<len; i++){
			if (decode_byte(hdlc_eng,hdlc_decoder,&buf[i])){
				gotdata=1;
			}
		}

		if (hdlc_decoder->rx_decode_len >= MAX_SOCK_HDLC_LIMIT){
 			printf("ERROR Rx decode len (%i) > max (%i)\n",
				hdlc_decoder->rx_decode_len,MAX_SOCK_HDLC_LIMIT);	
			hdlc_decoder->stats.errors++;
			hdlc_decoder->stats.frame_overflow++;	
			init_hdlc_decoder(hdlc_decoder);
		}
	
	return gotdata;
}

int wanpipe_hdlc_encode(wanpipe_hdlc_engine_t *hdlc_eng, 
		       unsigned char *usr_data, int usr_len,
		       unsigned char *hdlc_data, int *hdlc_len,
		       unsigned char *next_idle)
{
	wanpipe_hdlc_encoder_t *chan=&hdlc_eng->encoder;
	unsigned char crc_tmp;
	int i;

	chan->tx_decode_len=0;
	chan->tx_crc=-1;
	chan->tx_crc_fin=0;
	chan->tx_decode_onecnt=0;

    if (hdlc_eng->seven_bit_hdlc){
		chan->bits_in_byte=7;
		hdlc_eng->bits_in_byte=7;
		
	}else{
		chan->bits_in_byte=8;
		hdlc_eng->bits_in_byte=8;
	}

	memset(&chan->tx_decode_buf[0],0,3);
	chan->tx_decode_bit_cnt=0;
	
#if 0 
//HDLC_IDLE_ABORT	
	chan->tx_flag_idle=0x7E;
	chan->tx_flag_offset_data=0;
	chan->tx_flag_offset=0;
	encode_byte(chan,&chan->tx_flag_idle,2);
#else
	encode_byte(chan,&chan->tx_flag_idle,2);
	encode_byte(chan,&chan->tx_flag_idle,2);
	encode_byte(chan,&chan->tx_flag_idle,2);
	encode_byte(chan,&chan->tx_flag_idle,2);
	encode_byte(chan,&chan->tx_flag_offset_data,2);
	
	if (!hdlc_eng->seven_bit_hdlc || chan->tx_flag_offset < 5){
		chan->tx_decode_len--;
	}
#endif
	

#if 0
	DEBUG_TX("TX: Flag Idle 0x%02X, Offset Data 0x%02X,  FlagBitCnt %i, DataBitCnt %i\n",
			chan->tx_flag_idle,
			chan->tx_flag_offset_data,
			chan->tx_flag_offset,
			chan->tx_decode_bit_cnt);
#endif

	if (hdlc_eng->seven_bit_hdlc){
		chan->bits_in_byte=7;
		hdlc_eng->bits_in_byte=7;
		chan->tx_decode_bit_cnt=
			((chan->tx_flag_offset+2)%hdlc_eng->bits_in_byte);
		
	}else{
		chan->bits_in_byte=8;
		hdlc_eng->bits_in_byte=8;
		chan->tx_decode_bit_cnt=chan->tx_flag_offset;
	}
	
			
	chan->tx_decode_onecnt=0;

	/* For all bytes in an incoming data packet, calculate
	 * crc bytes, and encode each byte into the outgoing
	 * bit stream (encoding buffer).  */
	for (i=0;i<usr_len;i++){
		calc_tx_crc(chan,usr_data[i]);
		encode_byte(chan,&usr_data[i],0);	
	}

	/* Decode and bit shift the calculated CRC values */
	FLIP_CRC(chan->tx_crc,chan->tx_crc_fin);
	DECODE_CRC(chan->tx_crc_fin);

	/* Encode the crc values into the bit stream 
	 * encode buffer */
	crc_tmp=(chan->tx_crc_fin>>8)&0xFF;	
	encode_byte(chan,&crc_tmp,0);
	crc_tmp=(chan->tx_crc_fin)&0xFF;
	encode_byte(chan,&crc_tmp,0);

	/* End the bit stream encode buffer with the
	 * closing flag */

	
	encode_byte(chan,&chan->tx_flag,1);
	
#if 0 
//HDLC_IDLE_ABORT
	chan->tx_flag_idle=0xFF;
	chan->tx_flag_offset_data=0;	
	encode_byte(chan,&chan->tx_flag_idle,2);
#endif

	memcpy(hdlc_data,chan->tx_decode_buf,chan->tx_decode_len);
	*hdlc_len=chan->tx_decode_len;
		
#if 0
	{
		int i;
		DEBUG_EVENT( "ENCPKT: ");
		for (i=0;i<chan->tx_decode_len;i++){
			printk("%02X ",	chan->tx_decode_buf[i]);		
		}
		printk("\n");
		DEBUG_EVENT( "\n");
	}
	
#endif
	
	/* Reset the encode buffer */
	chan->tx_decode_len=0;

	/* Record the tx idle flag that
	 * should follow after this packet
	 * is sent out the port */
	*next_idle=chan->tx_flag_idle;

#if 0
	{
		int i;
		unsigned char *data=wan_skb_data(skb);
		DEBUG_EVENT("PKT: ");
		for (i=0;i<wan_skb_len(skb);i++){
			printk("%02X ",data[i]);
		}
		printk("\n");
	}
#endif	
	return 0;
}               


int wanpipe_get_rx_hdlc_packets (wanpipe_hdlc_engine_t *hdlc_eng)
{
	return hdlc_eng->decoder.stats.packets;
}

int wanpipe_get_rx_hdlc_errors (wanpipe_hdlc_engine_t *hdlc_eng)
{
	return hdlc_eng->decoder.stats.errors;
}

int wanpipe_get_tx_hdlc_packets (wanpipe_hdlc_engine_t *hdlc_eng)
{
	return hdlc_eng->encoder.stats.packets;
}

int wanpipe_get_tx_hdlc_errors (wanpipe_hdlc_engine_t *hdlc_eng)
{
	return hdlc_eng->encoder.stats.errors;
}

/*==================================================
  HDLC Encode Function
*/


static void encode_byte (wanpipe_hdlc_encoder_t *chan, unsigned char *byte_ptr, int flag)
{
	int j;
	unsigned long byte=*byte_ptr;
	
	for (j=0;j<BITSINBYTE;j++){

		if (test_bit(j,&byte)){
			/* Got 1 */
			chan->tx_decode_buf[chan->tx_decode_len] |= (1<< chan->tx_decode_bit_cnt);
				
			if (++chan->tx_decode_bit_cnt >= chan->bits_in_byte){
				++chan->tx_decode_len;
				chan->tx_decode_buf[chan->tx_decode_len]=0;
				chan->tx_decode_bit_cnt=0;
			}

			if (++chan->tx_decode_onecnt == 5){
				/* Stuff a zero bit */
				if (!flag){
					if (++chan->tx_decode_bit_cnt >= chan->bits_in_byte){
						++chan->tx_decode_len;
						chan->tx_decode_buf[chan->tx_decode_len]=0;
						chan->tx_decode_bit_cnt=0;
					}
				}
				chan->tx_decode_onecnt=0;
			}
		}else{
			/* Got 0 */
			chan->tx_decode_onecnt=0;
			if (++chan->tx_decode_bit_cnt >= chan->bits_in_byte){
				++chan->tx_decode_len;
				chan->tx_decode_buf[chan->tx_decode_len]=0;
				chan->tx_decode_bit_cnt=0;
			}
		}
	}

	if (flag == 1){
		/* The closing flag has been encoded into the 
		 * buffer. We must check how much has the last flag
		 * bit shifted due to bit stuffing of previous data.
		 * The maximum bit shift is 7 bits, thus a standard
		 * flag 0x7E can be have 7 different values.  The
		 * FLAG buffer will give us a correct flag, based
		 * on the bit shift count. */
		chan->tx_flag_idle = FLAG[chan->tx_decode_bit_cnt];
		chan->tx_flag_offset=chan->tx_decode_bit_cnt;
	
		/* The bit shifted part of the flag, that crossed the byte
		 * boudary, must be saved, and inserted at the beginning of 
		 * the next outgoing packet */
		chan->tx_flag_offset_data=chan->tx_decode_buf[chan->tx_decode_len];
	}
	
	return;
}               

/*==================================================
  HDLC Decode Function
*/

static int decode_byte (wanpipe_hdlc_engine_t *hdlc_eng, 
		        wanpipe_hdlc_decoder_t *chan,
			unsigned char *byte_ptr)
{
	int i;
	int gotdata=0;
	unsigned long byte=*byte_ptr;

	/* Test each bit in an incoming bitstream byte.  Search
	 * for an hdlc flag 0x7E, six 1s in a row.  Once the
	 * flag is obtained, construct the data packets. 
	 * The complete data packets are sent up the API stack */
	
	for (i=0; i<BITSINBYTE; i++){

		if (hdlc_eng->seven_bit_hdlc && i == 7){
			continue;
		}
		
		if (test_bit(i,&byte)){
			/* Got a 1 */
			
			++chan->rx_decode_onecnt;
			
			/* Make sure that we received a valid flag,
			 * before we start decoding incoming data */
			if (!test_bit(NO_FLAG,&chan->hdlc_flag)){ 
				chan->rx_decode_buf[chan->rx_decode_len] |= (1 << chan->rx_decode_bit_cnt);
				
				if (++chan->rx_decode_bit_cnt >= BITSINBYTE){

					/* Completed a byte of data, update the
					 * crc count, and start on the next 
					 * byte.  */
					calc_rx_crc(chan);
#ifdef PRINT_PKT
					printk(" %02X", data);
#endif
					++chan->rx_decode_len;
					if (chan->rx_decode_len > MAX_SOCK_HDLC_BUF){
						chan->stats.errors++;
						chan->stats.frame_overflow++;
						init_hdlc_decoder(chan);	
					}else{
						chan->rx_decode_buf[chan->rx_decode_len]=0;
						chan->rx_decode_bit_cnt=0;
						chan->hdlc_flag=0;
						set_bit(CLOSING_FLAG,&chan->hdlc_flag);
					}
				}
			}
		}else{
			/* Got a zero */
			if (chan->rx_decode_onecnt == 5){
				
				/* bit stuffed zero detected,
				 * do not increment our decode_bit_count.
				 * thus, ignore this bit*/
				
			
			}else if (chan->rx_decode_onecnt == 6){
				
				/* Got a Flag */
				if (test_bit(CLOSING_FLAG,&chan->hdlc_flag)){
				
					/* Got a closing flag, thus asemble
					 * the packet and send it up the 
					 * stack */
					chan->hdlc_flag=0;
					set_bit(OPEN_FLAG,&chan->hdlc_flag);
				
					if (chan->rx_decode_len >= 3){
						
						GET_FIN_CRC_CNT(chan->crc_cur);
						FLIP_CRC(chan->rx_crc[chan->crc_cur],chan->crc_fin);
						DECODE_CRC(chan->crc_fin);
				
						/* Check CRC error before passing data up
						 * the API socket */
						if (chan->crc_fin==chan->rx_orig_crc){
							chan->stats.packets++;
							if (hdlc_eng->hdlc_data) {
								hdlc_eng->hdlc_data(hdlc_eng,
										      chan->rx_decode_buf,
										      chan->rx_decode_len); 	       
							}
							gotdata=1;
						}else{
							chan->stats.errors++;
							chan->stats.crc++;
							//CRC Error; initialize hdlc eng
							init_hdlc_decoder(chan);
						}
					}else{
						chan->stats.errors++;
						chan->stats.abort++;
						//Abort
					}

				}else if (test_bit(NO_FLAG,&chan->hdlc_flag)){
					/* Got a very first flag */
					chan->hdlc_flag=0;	
					set_bit(OPEN_FLAG,&chan->hdlc_flag);
				}

				/* After a flag, initialize the decode and
				 * crc buffers and get ready for the next 
				 * data packet */
				chan->rx_decode_len=0;
				chan->rx_decode_buf[chan->rx_decode_len]=0;
				chan->rx_decode_bit_cnt=0;
				chan->rx_crc[0]=-1;
				chan->rx_crc[1]=-1;
				chan->rx_crc[2]=-1;
				chan->crc_cur=0; 
				chan->crc_prv=0;
			}else{
				/* Got a valid zero, thus increment the
				 * rx_decode_bit_cnt, as a result of which
				 * a zero is left in the consturcted
				 * byte.  NOTE: we must have a valid flag */
				
				if (!test_bit(NO_FLAG,&chan->hdlc_flag)){ 	
					if (++chan->rx_decode_bit_cnt >= BITSINBYTE){
						calc_rx_crc(chan);
#ifdef PRINT_PKT
						printk(" %02X", data);
#endif
						++chan->rx_decode_len;
						if (chan->rx_decode_len > MAX_SOCK_HDLC_BUF){
							chan->stats.errors++;
							chan->stats.frame_overflow++;
							init_hdlc_decoder(chan);
						}else{
							chan->rx_decode_buf[chan->rx_decode_len]=0;
							chan->rx_decode_bit_cnt=0;
							chan->hdlc_flag=0;
							set_bit(CLOSING_FLAG,&chan->hdlc_flag);
						}
					}
				}
			}
			chan->rx_decode_onecnt=0;
		}
	}
	
	return gotdata;
}                  



/*==========================================================
  CRC Routines
*/

static void init_crc(void)
{
	int i,j;

	if (init_crc_g){
		return;
	}
	init_crc_g=1;
	
	for(i=0;i<256;i++){
		CRC_TABLE[i]=0;
		for (j=0;j<BITSINBYTE;j++){
			if (i & (1<<j)){
				CRC_TABLE[i] ^= MagicNums[j];
			}
		}
	}
}

static void calc_rx_crc(wanpipe_hdlc_decoder_t *chan)
{
	INC_CRC_CNT(chan->crc_cur);

	/* Save the incoming CRC value, so it can be checked
	 * against the calculated one */
	chan->rx_orig_crc = (((chan->rx_orig_crc<<8)&0xFF00) | chan->rx_decode_buf[chan->rx_decode_len]);
	
	chan->rx_crc_tmp = (chan->rx_decode_buf[chan->rx_decode_len] ^ chan->rx_crc[chan->crc_prv]) & 0xFF;
	chan->rx_crc[chan->crc_cur] =  chan->rx_crc[chan->crc_prv] >> 8;
	chan->rx_crc[chan->crc_cur] &= 0x00FF;
	chan->rx_crc[chan->crc_cur] ^= CRC_TABLE[chan->rx_crc_tmp];
	chan->rx_crc[chan->crc_cur] &= 0xFFFF;
	INC_CRC_CNT(chan->crc_prv);
}    
               
static void calc_tx_crc(wanpipe_hdlc_encoder_t *chan, unsigned char byte)
{
	chan->tx_crc_tmp = (byte ^ chan->tx_crc) & 0xFF;
	chan->tx_crc =  chan->tx_crc >> 8;
	chan->tx_crc &= 0x00FF;
	chan->tx_crc ^= CRC_TABLE[chan->tx_crc_tmp];
	chan->tx_crc &= 0xFFFF;
}         
