/*
  Zlib example to compress strings in C
  Based on http://zlib.net/zlib_how.html
  Compile with:
    $ gcc -o zstrings zstrings.c -lz
 */

#include <stdio.h>
#include <string.h>
#include "zlib.h"

/* This errors are far from deflate/inflate errors, will indicate
   our destination buffer is not big enough to store the whole
   compressed or uncompressed data. */

#define ERR_UNDERSIZED -100
#define ERR_DEFLATE_PARTIAL -101
#define ERR_DEFLATE_PARTIAL_STREAM -102

/* Make it bigger to use it */
//#define CHUNK 8192
/* But you can define CHUNKs smaller for testing purposes */
#define CHUNK 128

/** ***********************************
 * Compress source data from memory to memory.
 *
 * @param source Source data
 * @param source_size Size of source data (if compressing a string, it can be strlen(source)+1)
 * @param dest Where to store compressed data
 * @param destination_size Max. size of compressed data
 * @param level Compession level
 *
 * @return If <0, error, Z_MEM_ERROR if could not allocate memory.
 *                       Z_VERSION_ERROR if version of zlib.h and linked library
 *                       Z_STREAM_ERROR if invalid compression level supplied.
 *                       ERR_UNDERSIZED if dest is not big enough to store all data
 *                       ERR_DEFLATE_PARTIAL if there was a problem running deflate 
 *                                           and it was not fully deflated
 *                       ERR_DEFLATE_PARTIAL_STREAM there was a problem and the compressed
 *                                                  stream does not ends right.
 *         If >0, size of compressed data
 */
int dodeflate(char* source, size_t source_size, char* dest, size_t destination_size, int level)
{
  int ret, flush;
  size_t have;
  z_stream strm;
  unsigned char *in = source;
  unsigned char *out = dest;
  size_t original_dest_size = destination_size;

  /* Initialize deflate */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  ret = deflateInit(&strm, level);
  if (ret != Z_OK)
    return ret;

  /* compress !! */
  do
    {
      if (source_size>CHUNK)
      	{
      	  strm.avail_in = CHUNK;
      	  source_size-=CHUNK;
      	}
      else
      	{
      	  strm.avail_in = source_size;
      	  source_size = 0;
      	}
      flush = (source_size == 0) ? Z_FINISH : Z_NO_FLUSH;
      strm.next_in = in;

      /* run deflate() on input until output buffer not full, finish
	 compression if all of source has been read in */
      do
	{
	  strm.avail_out = CHUNK;
	  strm.next_out = out;
	  if (destination_size < CHUNK)
	    return ERR_UNDERSIZED;		   /* Not enough size */

	  ret = deflate(&strm, flush);    /* no bad return value */
	  if (ret == Z_STREAM_ERROR)	  /* error check */
	    return ret;

	  have = CHUNK - strm.avail_out;
	  out+=have;		  /* Move out pointer */
	  destination_size-=have; /* calculate destination size left */
        } while (strm.avail_out == 0);

      if (strm.avail_in != 0)
	return ERR_DEFLATE_PARTIAL;

      in+=CHUNK;	   /* Move in to the next chunk */
      /* done when last data in file processed */
    } while (flush != Z_FINISH);

  if (ret != Z_STREAM_END)
    return ERR_DEFLATE_PARTIAL_STREAM;

  /* clean up and return */
  (void)deflateEnd(&strm);
  return original_dest_size-destination_size;
}

/** ***********************************
 * Uncompress source data from memory to memory.
 *
 * @param source Source data (compressed data)
 * @param source_size Size of source data
 * @param dest Where to store uncompressed data
 * @param destination_size Max. size of compressed data
 *
 * @return If <0, error, Z_DATA_ERROR if deflated data is invalid or incomplete
 *                       Z_VERSION_ERROR if version of zlib.h and linked library
 *                       Z_STREAM_ERROR if there was a problem deflating.
 *                       Z_MEM_ERROR problem allocating memory
 *                       ERR_UNDERSIZED if dest is not big enough to store all data
 *         If >0, size of uncompressed data
 */
int doinflate(char* source, size_t source_size, char* dest, size_t destination_size)
{
    int ret;
    size_t have;
    z_stream strm;
    unsigned char* in = source;
    unsigned char* out = dest;
    size_t original_dest_size = destination_size;

    /* initialize z_stream */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return ret;

    /* decompress until source is completelly read */
    do 
      {
	if (source_size>CHUNK)
	  {
	    strm.avail_in = CHUNK;
	    source_size-=CHUNK;
	  }
	else
	  {
	    strm.avail_in = source_size;
	    source_size = 0;
	  }

	strm.next_in = in;

        /* run inflate() on input until output buffer  */
        do 
	  {
	    if (destination_size<CHUNK)
	      return ERR_UNDERSIZED;

            strm.avail_out = CHUNK;
            strm.next_out = out;

	    /* inflate data */
            ret = inflate(&strm, Z_NO_FLUSH);

            switch (ret) 
	      {
	      case Z_NEED_DICT:
		ret = Z_DATA_ERROR;
	      case Z_DATA_ERROR:
	      case Z_MEM_ERROR:
		(void)inflateEnd(&strm);
	      case Z_STREAM_ERROR:
		return ret;
	      }
            have = CHUNK - strm.avail_out;
	    out+=have;		/* Move out pointer */
	    destination_size-=have;
	  } while (strm.avail_out == 0);
	in+=CHUNK;

	/* done when inflate() says it's done or we have no more input data */
      } while ( (ret != Z_STREAM_END) && (source_size != 0) );

    /* clean up and return */
    (void)inflateEnd(&strm);
    return (ret == Z_STREAM_END) ? original_dest_size-destination_size : Z_DATA_ERROR;
}

/* compress or decompress from stdin to stdout */
int main(int argc, char **argv)
{
    int ret;
    // Song Coffee by Josh Woodward (http://www.joshwoodward.com/song/coffee)
    // Just to put something different to lorem ipsum. You can listen to the
    // song, download and use it.
    char *text = "A cup of coffee in the morning and I get the paper\n"
      "I check the headlines and decide that I am bored\n"
      "I check my email and decide to answer later\n"
      "Another cup of coffee and I drag myself to work\n"
      "\n"
      "     My life is grounded in a firm routine\n"
      "     Of coffee sleep and work\n"
      "     I am not boring, I just stick to what I know\n"
      "\n"
      "I'm sitting there at work and I realized I forgot to  wake up\n"
      "Can't be productive when I'm dreaming 'bout a  sheep\n"
      "I go upstairs and get myself another cup of coffee\n"
      "I get downstairs and then I spill it on the floor\n"
      "\n"
      "     My life is grounded in a firm routine\n"
      "     Of coffee sleep and work\n"
      "     I am not boring, I just stick to what I know\n"
      "\n"
      "(solo)\n"
      "\n"
      "Rockabye baby, on the tree top\n"
      "Lunch hour's over, and I can't stay up\n"
      "I wanna drink coffee, but that's a mistake\n"
      "I best switch to decaf or I'll stay awake\n"
      "\n"
      "     My life is grounded in a firm routine\n"
      "     Of coffee sleep and work\n"
      "     I am not boring, I just stick to what I know";
    char dest [CHUNK * 5];	/* Test size */
    char orig [CHUNK * 10];
    unsigned siz;
    siz = dodeflate(text, strlen(text)+1, dest, CHUNK*5, Z_BEST_COMPRESSION);
    fprintf (stderr, "ORIGINAL SIZE: %zu\n", strlen(text));
    fprintf (stderr, "SIZE: %d\n", siz);
    /* Do we really want to show this, I don't think you want to write this on
       screen but you can uncomment the following line and run the program as follows:
         $ ./zstrings | hexdump -C
       It's more beautiful to read data this way
    */
    /* write(1, dest, siz);  */
    fprintf (stderr, "INFLATED SIZE: %d\nSTRING: %s\n", doinflate(dest, siz, orig, CHUNK*10), orig);

    return 0;
}
