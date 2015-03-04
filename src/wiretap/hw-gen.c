/* hwgen.c
 *
 * Jose Fernando Zazo
 */


#include "config.h"

#include <string.h>
#include <wtap-int.h>
#include <file_wrappers.h>

#include "hw-gen.h"



static gboolean
hwgen_read_packet(wtap *wth, FILE_T fh, struct wtap_pkthdr *phdr,
    Buffer *buf, int *err, gchar **err_info)
{
  guint packet_size;
  guint orig_size;
  struct hwgen_hdr hdr;
  guint32 padding = 0;
  wth = wth;


  /*
   * Read the header.
   */
  if (!wtap_read_bytes_or_eof(fh, &hdr, sizeof hdr, err, err_info))
    return FALSE;

  if(hdr.magic_word!=0x6969) {
    *err = WTAP_ERR_BAD_FILE;
    if (err_info != NULL) {
      *err_info = g_strdup_printf("hwgen format: It was impossible to locate the magic word in the header");
    }
    return FALSE;    
  }

  packet_size = hdr.size;
  orig_size   = hdr.size;


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

  /*
   * Read the packet data.
   */
  if (!wtap_read_packet_bytes(fh, buf, packet_size, err, err_info))
    return FALSE; /* failed */

  /*
   * Read the padding.
   */
  if (!wtap_read_bytes_or_eof(fh, &padding, 4 - (phdr->caplen%4), err, err_info))
    return FALSE; 


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
  return TRUE;
}


int hwgen_dump_can_write_encap(int encap)
{
  encap = 0; //Warnings are treat as errors -.-
  return 0;
}


static gboolean hwgen_dump(wtap_dumper *wdh,
  const struct wtap_pkthdr *phdr,
  const guint8 *pd, int *err, gchar **err_info _U_)
{
  //const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
  struct hwgen_hdr rec_hdr;
  guint32 padding = 0;

  /* We can only write packet records. */
  if (phdr->rec_type != REC_TYPE_PACKET) {
    *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
    return FALSE;
  }

  /* Don't write anything we're not willing to read. */
  if (phdr->caplen + phdr->caplen + sizeof rec_hdr  > WTAP_MAX_PACKET_SIZE) {
    *err = WTAP_ERR_PACKET_TOO_LARGE;
    return FALSE;
  }

  rec_hdr.ifg = 3;  
  rec_hdr.magic_word = 0x6969;
  rec_hdr.size = phdr->caplen;

  if (!wtap_dump_file_write(wdh, &rec_hdr, sizeof rec_hdr, err))
    return FALSE;
  wdh->bytes_dumped += sizeof rec_hdr;

  if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
    return FALSE;
  if (!wtap_dump_file_write(wdh, &padding, 4 - (phdr->caplen%4), err))
    return FALSE;
  wdh->bytes_dumped += phdr->caplen + 4 - (phdr->caplen%4);
  return TRUE;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean hwgen_dump_open(wtap_dumper *wdh, int *err)
{
  
  err = NULL;

  wdh->subtype_write = hwgen_dump;
  wdh->subtype_close = NULL;


  return TRUE;  
}



wtap_open_return_val hwgen_open(wtap *wth, int *err, gchar **err_info _U_)
{
  guint8  block[4];

  if (!wtap_read_bytes(wth->fh, block, sizeof(block), err, err_info)) {
      if (*err == WTAP_ERR_SHORT_READ)
        return WTAP_OPEN_ERROR;
  }

  if (!(block[2]==0x69 && block[3] == 0x69)) {
    return WTAP_OPEN_NOT_MINE; 
  }


  /* rewind the fh so we re-read from the beginning */
  if (-1 == file_seek(wth->fh, 0, SEEK_SET, err))
      return WTAP_OPEN_ERROR;

  wth->file_encap = WTAP_ENCAP_HW_GENERATOR;
  wth->snapshot_length = 0;
  wth->file_tsprec = WTAP_TSPREC_NSEC;

  wth->priv = NULL;

  wth->subtype_read = hwgen_read;
  wth->subtype_seek_read = hwgen_seek_read;
  wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_HWGEN_V1;

  *err = 0;
  return WTAP_OPEN_MINE;
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
