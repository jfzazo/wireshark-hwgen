/* hwgen.c
 *
 * Jose Fernando Zazo
 */


#include "config.h"

#include <string.h>
#include <wtap-int.h>
#include <file_wrappers.h>

#include "hw-gen.h"



#define max(x, y) (((x) > (y)) ? (x) : (y))
#define min(x, y) (((x) < (y)) ? (x) : (y))

#define ceil(a) ( ((a) - (int)(a))==0 ? (int)(a) : (int)(a)+1 )



#define HWGEN_MAX_PACKET_SIZE 0xFFFF

#define MIN_IFP                 3            /**< Minimum interframe gap. 10 Gbits needs at least a 12 Bytes ifp, 3 words of 32 bits.*/
#define MAX_IFP                 100000       /**< Maximum interframe gap. 10 Gbits needs at least a 12 Bytes ifp, 3 words of 32 bits.*/
#define DEFAULT_IFG             3 


static guint64 npackets = 0;
static guint64 lsize    = 0;
static nstime_t ltime;
static guint8  lpacket[HWGEN_MAX_PACKET_SIZE];


static guint32 crc32_tab[] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
        0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
        0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
        0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
        0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
        0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
        0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
        0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
        0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
        0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
        0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
        0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
        0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
        0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
        0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
        0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
        0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
        0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
        0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
        0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
        0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static guint32
crc32(guint32 crc, const void *buf, size_t size)
{
        const guint8 *p;

        p = (const guint8 *)buf;
        crc = crc ^ ~0U;

        while (size--)
                crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);



        return crc ^ ~0U;
}


static gboolean
hwgen_read_packet(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info)
{
  guint packet_size;
  guint orig_size;
  struct hwgen_hdr hdr;
  guint32 padding = 0;
  wth->file_encap = WTAP_ENCAP_ETHERNET;


  /*
   * Read the header.
   */
  if (file_read(&hdr, sizeof hdr, fh) != sizeof hdr) {
    return FALSE;
  }

  if(hdr.magic_word!=0x6969) {
    if(npackets!= *((guint64 *)&hdr)) {
	*err = WTAP_ERR_BAD_FILE;
	if (err_info != NULL) {
    	  *err_info = g_strdup_printf("hwgen format: It was impossible to locate the magic word in the header");
        }

        return FALSE; // We expect to receive the number of packets at the end.
    }
    *err = 0;
    return TRUE;    
  }

  packet_size = hdr.size;
  orig_size   = hdr.size;
  npackets++;

 /* phdr_len = pcap_process_pseudo_header(fh, wth->file_type_subtype,
      wth->file_encap, packet_size, TRUE, phdr, err, err_info);
  if (phdr_len < 0)
    return FALSE;  */



  phdr->rec_type = REC_TYPE_PACKET;
//  phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN; //We dont provide of timestamp or caplen
//  phdr->ts.secs = 0;
//  phdr->ts.nsecs = hdr.ifg; //hdr.hdr.ts_usec;

  phdr->caplen = packet_size;
  phdr->len    = orig_size;
  phdr->pseudo_header.eth.fcs_len = 4;
  /*
   * Read the packet data.
   */
  if (!wtap_read_packet_bytes(fh, buf, packet_size, err, err_info))
    return FALSE; /* failed */

  /*
   * Read the padding.
   */
  if (file_read(&padding, 4 - (phdr->caplen%4), fh) != (int)(4 - (phdr->caplen%4)))
    return FALSE; 

  *err = 0;
  return TRUE;
}


static gboolean hwgen_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
  *data_offset = file_tell(wth->fh);

  return hwgen_read_packet(wth, wth->fh, &wth->phdr,
      wth->frame_buffer, err, err_info);
}

static gboolean hwgen_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info)
{
  if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    return FALSE;

  if (!hwgen_read_packet(wth, wth->random_fh, phdr, buf, err,
      err_info)) {
    if (*err == 0)
      *err = WTAP_ERR_SHORT_READ;
    return FALSE;
  }
  *err = 0;
  return TRUE;
}


int hwgen_dump_can_write_encap(int encap)
{
  encap = encap; //Warnings are treat as errors -.-
  switch(encap) {
    case WTAP_ENCAP_NULL:
    case WTAP_ENCAP_ETHERNET:
    case WTAP_ENCAP_RAW_IP:
      return 0;
      break;
    default:
      return -1; //WTAP_ERR_UNWRITABLE_ENCAP;
      break;
  }
  
}


static void calculateInterFrameGap (guint32 *ifp, const struct nstime_t *ts)
{
  double ttime;
  ttime = ts->secs * 1e09 + ts->nsecs;
  /*
    10 Gbits/s = 10*1024*1024*1024/8 B/S = 10*128*1024*1024 B/S

    1 us = 1e-09 s
    1 W (word) = 4 bytes


    1/(10*128*1024*1024) s/B = 1/(10*128*1024*1024) * 1e06 us / B
                 = 4 * 1e06/(10*128*1024*1024)  us / W = 1e06/(10.0*32*1024*1024) us / W
   */
  *ifp =  max (MIN_IFP, min (ceil (ttime / (1e09 / (10.0 * 32 * 1024 * 1024))),  MAX_IFP));
  if( (*ifp) >= (MIN_IFP + lsize/4) ) 
    *ifp -=  (guint32)(lsize / 4);
  else 
    *ifp = MIN_IFP; 

  return;
}
static unsigned char etherbuffer[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x2c,0xb0,0x5d,0xb5,0x47,0x3e,0x08,0x00};
static unsigned char buffer[65536]; 
static gboolean hwgen_dump(wtap_dumper *wdh,
  const struct wtap_pkthdr *phdr,
  const guint8 *pd, int *err)
{
  //const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
  struct hwgen_hdr rec_hdr;
  guint32 padding = 0, lpadding = 0;
  unsigned int i, offset = 0;
  guint32 crc = 0;

  /* We can only write packet records. */
  if (phdr->rec_type != REC_TYPE_PACKET) {
    return FALSE;
  }

  /* Don't write anything we're not willing to read. */
  if (phdr->caplen + phdr->caplen + sizeof rec_hdr  > WTAP_MAX_PACKET_SIZE) {
    return FALSE;
  }

  if(npackets) {
    struct hwgen_hdr *prec_hdr = (struct hwgen_hdr *)lpacket;
    //Calculate the IFG of the previous packet and dump to disk
    if(phdr->presence_flags & WTAP_HAS_TS) {  
      
      nstime_t delta;
      guint32 ifg;

      nstime_delta (&delta, &(phdr->ts), &ltime);
      calculateInterFrameGap (&ifg, &delta);

      prec_hdr->ifg = ifg;
    } else {
      prec_hdr->ifg = DEFAULT_IFG;
    }
    // Write the last packet after calculate the IFG
    if (!wtap_dump_file_write(wdh, lpacket, lsize, err))
      return FALSE;
    wdh->bytes_dumped += lsize;
  }

  // Store the packet for the next iteration
  //rec_hdr.ifg = 3;  
  rec_hdr.magic_word = 0x6969;
  rec_hdr.size = phdr->len; 


  offset = (guint32) sizeof rec_hdr;
  // Obtain the correct size:
  // 1) Add the Ethernet encap if IP RAW data is being processed.
  if(phdr->pkt_encap == WTAP_ENCAP_RAW_IP) {
    rec_hdr.size  += sizeof etherbuffer;
  } 
  // 2) Add the FCS if none CRC is provided.
  if(phdr->pkt_encap == WTAP_ENCAP_RAW_IP) {
    memcpy(lpacket+offset, etherbuffer,sizeof etherbuffer ); 
    offset += (guint32) sizeof etherbuffer;
  }  

  memcpy(lpacket+offset, pd, phdr->caplen); 
  offset += phdr->caplen;

  if( (phdr->presence_flags & WTAP_HAS_CAP_LEN) && (phdr->caplen!=phdr->len)) {
    for(i=0; i<(phdr->len-phdr->caplen); i++) {
      lpacket[offset] = 0;
      offset++;
    }
  }  

  if((phdr->pseudo_header.eth.fcs_len <= 0) || (phdr->caplen!=phdr->len)) {
    rec_hdr.size  += 4;
    offset += rec_hdr.size < 64 ? 64-rec_hdr.size : 0;
    rec_hdr.size = rec_hdr.size < 64 ? 64 : rec_hdr.size;
    crc = crc32(0, lpacket+sizeof rec_hdr, rec_hdr.size-4); // Substract 4, the FCS size
  }   


  memcpy( lpacket, &rec_hdr, sizeof rec_hdr );
  if((phdr->pseudo_header.eth.fcs_len <= 0) || (phdr->caplen!=phdr->len)) {
    memcpy(lpacket+offset, &crc, 4);
    offset += 4;
  } 
  lpadding = 4 - (rec_hdr.size%4);
  memcpy(lpacket+offset, &padding, lpadding);
  offset += lpadding ;
  lsize = offset;
  ltime = phdr->ts;
  npackets++;
  *err = 0;
  return TRUE;
}

static gboolean hwgen_close(wtap_dumper *wdh,
  int *err)
{
  if(lsize) {
  	struct hwgen_hdr *rec_hdr = (struct hwgen_hdr *)lpacket;
  	rec_hdr->ifg = DEFAULT_IFG;

	  if (!wtap_dump_file_write(wdh, lpacket, lsize, err))
	    return FALSE;
	  wdh->bytes_dumped += lsize;
	  if (!wtap_dump_file_write(wdh, &npackets, sizeof(guint64), err))
	    return FALSE;
	  wdh->bytes_dumped += sizeof(guint64);

  }
  lsize = 0;
  *err = 0;
  return TRUE;
}
/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean hwgen_dump_open(wtap_dumper *wdh, int *err)
{
  
  *err = 0;

  wdh->subtype_write = hwgen_dump;
  wdh->subtype_close = hwgen_close;


  return TRUE;  
}



int hwgen_open(wtap *wth, int *err, gchar **err_info _U_)
{
  guint8  block[4];

  if (file_read(block, sizeof(block),wth->fh)!=sizeof(block)) {
      *err = file_error(wth->fh, err_info);
	if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
		return -1;
	return 0;
  }

  if (!(block[2]==0x69 && block[3] == 0x69)) {
    return 2; 
  }


  /* rewind the fh so we re-read from the beginning */
  if (-1 == file_seek(wth->fh, 0, SEEK_SET, err))
      return 0;

  wth->file_encap = WTAP_ENCAP_HW_GENERATOR;
  wth->snapshot_length = 0;
 // wth->file_tsprec = WTAP_TSPREC_NSEC;

  wth->priv = NULL;

  wth->subtype_read = hwgen_read;
  wth->subtype_seek_read = hwgen_seek_read;
  wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_HWGEN_V1;

  *err = 0;
  return 1;
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
