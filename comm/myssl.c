/**
*************************************************************
* @file myssl.c
* @brief SSL Client HTTP Connection example getting information
*     and verifying certificates.
* These are just some SSL notes
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version
* @date 17 abr 2015
*
* To compile:
*  $ gcc -o myssl myssl.c -lcrypto -lssl
*
*************************************************************/

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/select.h>
#include <sys/time.h>

#define CAPATH "/etc/ssl/certs"	/* Where to look for the Certificate Authorities */
#define BUFFERSIZE 16384	/* 16Kb SSL_read block size */
#define STRBUFFERSIZE 256	/* For temporary strings */
#define USERAGENT "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:37.0) Gecko/20100101 Firefox/37.0"
#define CRLF "\r\n"

/* Useful Structure. Just to have everything in one place and avoid
 passing lot of arguments to the functions. */

/* sslc handles SSL and SSL_CTX and socket */
typedef struct
{
  int skt;
  int err;
  SSL* ssl;
  SSL_CTX* ctx;
} Sslc;

/* First some useful stuff */

/**
 * Transforms ASN1 time sring to time_t (except milliseconds and time zone)
 *
 * @param ASN1_TIME* time    SSL ASN1_TIME pointer
 * @param time_t*    tmt     time_t pointer to write to
 *
 * @return int 0 if OK, <0 if anything goes wrong
 */
int ASN1_TIME_to_time_t(ASN1_TIME* time, time_t *tmt);

/**
 * Extract a substring from origin into buffer, updating starting
 * value to call in chain. Used by ASN1_TIME_to_time_t to extract
 * substrings easyly
 *
 * @param char*      buffer  Where to write to
 * @param char*      origin  Original string
 * @param size_t*    from    Where to start from. 
 *                           Updated to the last position after end.
 * @param size_t     size    Characters to extract.
 *
 * @return char* reference to buffer
 */
char* join(char* buffer, const char* origin, size_t *from, size_t size);

/**
 * Check certificate validity
 *
 * @param X509*      certificate Certificate to check
 *
 * @return long int  error code (0 is OK. See x509_vfy.h for 
 *                   constants (X509_V_ERR_UNABLE_*). You can also
 *                   use X509_verify_cert_error_string(long int) to
 *                   see the error string
 */
long int check_cert_validity(X509* certificate);

/**
 * Creates a basic TCP client connection to a server on a port.
 * Uses simple sockets
 *
 * @param Sslc*      h       Our structure. Only the socket will be used
 * @param char*      server  Where to connect
 * @param int        port    The port to use (443 for HTTPS)
 *
 * @return int       (0 if OK, else fail)
 */
int TCP_Connection(Sslc* h, char* server, int port);

/**
 * Uses select to test if there is anything waiting to be read.
 *
 * @param Sslc*      h       Our structure. Only the socket will be used
 * @param double     timeout Timeout before giving up
 *
 * @return int       (0 timeout, 1 data waiting, <0 fail)
 */
int TCP_select(Sslc* h, double timeout);

/**
 * SSL initialization and handshake
 *
 * @param Sslc*      h       Our structure. 
 *
 * @return int       (0 if OK, else fail)
 */
int SSL_Connection(Sslc* h);

/**
 * SSL send. To be called instead of send. It will send data through
 * the socket and decode information, or even perform a handshake 
 * if needed.
 *
 * @param Sslc*      h       Our structure. 
 * @param char*      msg     Message to send

 * @return int       (0 if OK, else fail)
 */
int SSL_send(Sslc* h, char* msg);

/**
 * SSL recv. To be called instead of recs. It will read the socket
 * and decode information, or even perform a handshake if needed
 *
 * @param Sslc*      h       Our structure. 
 * @param char**     data    Data to be read (caution a pointer by
 *                           reference that must be freed manually

 * @return int       (0 if OK, else fail)
 */
int SSL_recv(Sslc* h, char** data);

/**
 * Prints out SSL information: SSL Version, cipher used and certificate
 * information.
 *
 * @param Sslc*      h       Our structure. 
 *
 * @return void
 */
void SSL_print_info(Sslc* h);

/**
 * Prints out certificate information. Run throught the entries, print the
 * not before and not after information and verify the certificate.
 *
 * @param X509*      cert       The certificate to check
 *
 * @return void
 */
void SSL_print_certificate_info(X509* cert);

/**
 * Gets cipher description in a string
 * Please free the resulting string, don't do it like me ;)
 *
 * @param SSL_CIPHER*     cipher       Cipher
 *
 * @return char*    String with the description
 */
char *SSL_cipher_description(SSL_CIPHER* cipher);

/**
 * Gets a string with the time_t into a string
 *
 * @param char*     buffer      Buffer to write to
 * @param size_t    bufsize     Total buffer size
 * @param char*     format      Date/Time format (@see strftime())
 * @param time_t*   tim         Time
 *
 * @return char*    buffer
 */
char *time_t_to_str(char *buffer, size_t bufsize, const char* format, time_t *tim);

/**
 * Prints ASN1_TIME on screen
 *
 * @param ASN1_TIME*     asn1time     Time to write
 * @param char*          pre_string   String to write before the date
 * @param char*          dateformat   Date format (@see strftime())
 *
 * @return void
 */
void print_time(ASN1_TIME* asn1time, char* pre_string, char* dateformat);


/**
 * Prints program usage
 *
 * @param char*          executable   Program executable (argv[0])
 *
 * @return void
 */
void print_usage(char* executable);

/**
 * Prints a tragic error and exit
 *
 * @param char*          msg   Error text
 *
 * @return void
 */
void panic(char *msg);

int main(int argc, char *argv[])
{
  Sslc sslc;
  char *response;
  char *server = argv[1];
  int port;
  char *httpquerytemplate ="GET / HTTP/1.1" CRLF "Host: %s" CRLF "User-Agent: %s" CRLF CRLF;
  char httpquery[1024];

  /* What will be sent to the server */
  sprintf (httpquery, httpquerytemplate, server, USERAGENT);

  if (argc<2)
    print_usage(argv[0]);

  if (argc>2)
    port = atoi (argv[2]);
  else
    port = 443;			/* default https port */

  if (TCP_Connection(&sslc, server, port)<0)
    panic ("Couldn't connect host");

  if (SSL_Connection(&sslc)<0)
    panic ("Couldn't stablish secure connection");

  if (SSL_send(&sslc, httpquery)<0)
    panic ("Couldn't send anything to the server");

  SSL_print_info(&sslc);

  if (SSL_recv(&sslc, &response)<0)
    panic ("Couldn't receive the message");

  printf ("Received %lu bytes\n", strlen(response));

  free(response);

  return EXIT_SUCCESS;
}

char* join(char* buffer, const char* origin, size_t *from, size_t size)
{
  size_t i=0;
  while (i<size)
    {
      buffer[i++] = origin[(*from)++];
    }
  buffer[i] = '\0';
  return buffer;
}

int ASN1_TIME_to_time_t(ASN1_TIME* time, time_t *tmt)
{
  const char* data = time->data;
  size_t p = 0;
  char buf[5];
  struct tm t;
  int temp;
  memset(&t, 0, sizeof(t));
  size_t datalen = strlen(data);

  if (time->type == V_ASN1_UTCTIME) {/* two digit year */
    /* error checking YYMMDDHH at least */
    if (datalen<8)
      return -1;
    t.tm_year = atoi (join(buf, data, &p, 2));
    if (t.tm_year<70)
      t.tm_year += 100;
    datalen = strlen(data+2);
  } else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
    /* error checking YYYYMMDDHH at least*/
    if (datalen<10)
      return -1;

    t.tm_year = atoi (join(buf, data, &p, 4));
    t.tm_year -= 1900;
    datalen = strlen(data+4);
  }

  /* the year is out of datalen. Now datalen is fixed */

  t.tm_mon = atoi (join(buf, data, &p, 2))-1; /* January is 0 for time_t */
  t.tm_mday= atoi (join(buf, data, &p, 2));
  t.tm_hour= atoi (join(buf, data, &p, 2));

  if (datalen<8)
    return !(*tmt = mktime(&t));
  t.tm_min = atoi (join(buf, data, &p, 2));

  if (datalen<10)
    return !(*tmt = mktime(&t));
  t.tm_sec = atoi (join(buf, data, &p, 2));

  /* Ignore millisecnds and time zone */
  return !(*tmt = mktime(&t));
}

long int check_certificate_validity(X509* certificate)
{
  int status;
  X509_STORE_CTX *ctx;
  ctx = X509_STORE_CTX_new();
  X509_STORE *store = X509_STORE_new();
  X509_STORE_load_locations(store, NULL, CAPATH);
  X509_STORE_add_cert(store, certificate);

  X509_STORE_CTX_init(ctx, store, certificate, NULL);

  status = X509_verify_cert(ctx);

  return ctx->error;
}

int TCP_Connection(Sslc* h, char* server, int port)
{
  h->err = 0;
  struct hostent *host = gethostbyname (server);
  struct sockaddr_in addr;

  if (host == NULL)
    return -1;			/* Couldn't get host */

  h->skt = socket (AF_INET, SOCK_STREAM, 0);
  if (h->skt < 0)
    {
      return -2;
    }
  else
    {
      /* fill in address data */
      addr.sin_family = AF_INET;
      addr.sin_port = htons (port);
      addr.sin_addr = *((struct in_addr *) host->h_addr);
      bzero (&(addr.sin_zero), 8);

      /* connect */
      h->err = connect (h->skt, (struct sockaddr *) &addr, sizeof (struct sockaddr));
      if (h->err == -1)
        {
	  return -3;
        }
    }
  return 0;
}

int SSL_Connection(Sslc* h)
{
  SSL_library_init();		/* not reentrant! */
  SSL_load_error_strings();

  /* try SSL methods (TLSv1.2 ... SSLv3 and SSLv2 (caution! SSLv2 and SSLv3 are deprecated!) */
  /* you could use TLSv1_client_method(), TLSv1_2_client_method()... */
  h->ctx = SSL_CTX_new(SSLv23_client_method());
  if (h->ctx == NULL)
    return -3;			/* Context not created */

  /* SSL will fail if cerificate can't be validated */
  /* h->ctx->verify_mode = 1; */

  h->ssl = SSL_new (h->ctx);
  if (h->ssl == NULL)
    return -4;			/* SSL struct not created */

  if (SSL_set_fd(h->ssl, h->skt) == 0)
    return -5;			/* Couldn't bind SSL with our connection */

  if (SSL_CTX_load_verify_locations(h->ctx, NULL, CAPATH) == 0)
    return -6;			/* Couldn't load verify locations */

  /* Verify depth. How many certs from the chain to verify */
  /* -1 to verify all certificates. */
  printf ("VDepth: %d\n", SSL_get_verify_depth(h->ssl));

  if (SSL_connect (h->ssl) < 1)
    return -7;			/* Couldn't finish SSL handshake */

  /* Get certificate information */
  return 0;
}

int SSL_send(Sslc* h, char* msg)
{
  int bytes = SSL_write(h->ssl, msg, strlen(msg));
  if (bytes<1)
    h->err = bytes;

  return bytes;
}

int TCP_select(Sslc* h, double timeout)
{
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(h->skt, &fds);
  fd_set *rset=&fds;
  fd_set *wset=NULL;

  struct timeval tv;
  tv.tv_sec = (int)(timeout);
  tv.tv_usec = (int)((timeout - (int)(timeout)) * 1000000.0);

  int ret = select(h->skt+1, rset, wset, NULL, &tv);
  return ret;
}

int SSL_recv(Sslc* h, char** data)
{
  size_t bytes, totalbytes = 0;
  char buffer[BUFFERSIZE];
  int sel;
  size_t allocated = BUFFERSIZE;
  *data = malloc (sizeof(char) * BUFFERSIZE);
  *data[0] = '\0';

  while (1)
    {
      sel = TCP_select(h, 1);
      if (sel<0)
	return -6;		/* select fail */
      else if (sel==0)
	{
	  return totalbytes;
	}
      /* We must include terminator after reading */
      bytes = SSL_read (h->ssl, buffer, BUFFERSIZE -1);
      buffer[bytes] = '\0';

      if (bytes<1)
	return -7;

      if (totalbytes + bytes > allocated)
	{
	  allocated+=BUFFERSIZE;
	  *data = realloc(*data, allocated * sizeof(char));
	}
      strcat(*data, buffer);
      totalbytes+=bytes;
    }
  return totalbytes;
}

void SSL_print_info(Sslc* h)
{
  long vresult = SSL_get_verify_result (h->ssl);
  X509* cert;
  STACK_OF(X509) *chain;
  int i;

  printf ("Verify result: %ld (%s)\n", vresult, X509_verify_cert_error_string(vresult));
  printf ("Verify mode: %d\n", SSL_get_verify_mode(h->ssl)); /* If it's 1 SSL will fail if not verified */
  printf ("SSL version: %s\n", SSL_get_version(h->ssl));
  printf ("Cipher name : %s\n", SSL_get_cipher_name(h->ssl));
  printf ("Cipher version: %s\n", SSL_get_cipher_version(h->ssl));
  printf ("Cipher description: %s\n", SSL_cipher_description((SSL_CIPHER*)SSL_get_current_cipher(h->ssl)));
  printf ("--------------------------------------------\n");
  printf ("Certificate:\n");
  cert = SSL_get_peer_certificate(h->ssl);
  if (cert)
    {
      SSL_print_certificate_info(cert);
      /* X509_free(cert); */
    }
  else
    fprintf(stderr, "------ ERROR: Peer certificate not present!!\n");

  printf ("--------------------------------------------\n");
  printf ("The entire certificate chain: \n");
  chain = SSL_get_peer_cert_chain(h->ssl);
  if (chain)
    {
      printf ("Certificates on chain: %d\n", sk_X509_num(chain));
      for (i=0; i<sk_X509_num(chain); i++)
	{
	  cert = sk_X509_value(chain, i);
	  if (cert)
	    {
	      SSL_print_certificate_info(cert);
	      /* Not a good idea to free, it's an internal pointer and may
	         break something*/
	      /* X509_free(cert); */
	      printf ("            ·················\n");
	    }
	}
    }
  else
    fprintf (stderr, "------- ERROR: Couldn't get certificate chain!!\n");
}

void SSL_print_certificate_info(X509* cert)
{
  X509_NAME *certname;
  X509_NAME_ENTRY* entry;
  char *s;
  char buffer[STRBUFFERSIZE];
  int i, n;

  certname = X509_get_subject_name(cert);
  for (i=0; i< X509_NAME_entry_count(certname); i++)
    {
      entry = X509_NAME_get_entry(certname, i);
      if (entry == NULL)	/* error test. May exit the loop */
	continue;

      /* extracted from X509_NAME_print_ex() */
      int n = OBJ_obj2nid(entry->object);
      if ((n == NID_undef) || ((s = (char*)OBJ_nid2sn(n)) == NULL)) 
	{
	  i2t_ASN1_OBJECT(buffer, sizeof(buffer), entry->object);
	  s = buffer;
	}
      printf ("%s = %s\n", s, entry->value->data);
      /* We must NOT free entries (they are internal pointers) */
    }
  print_time(X509_get_notBefore(cert), "Not Before", "%d/%m/%Y %H:%M:%S");
  print_time(X509_get_notAfter(cert),  "Not After", "%d/%m/%Y %H:%M:%S");
  printf ("Valid certificate?: %s\n", X509_verify_cert_error_string(check_certificate_validity(cert)));

  /* We must NOT free X509_get_subject_name() objects */
  /* X509_NAME_free(certname); */
}

char *time_t_to_str(char *buffer, size_t bufsize, const char* format, time_t *tim)
{
  struct tm _tm;
  gmtime_r(tim, &_tm);
  strftime(buffer, bufsize, format, &_tm);
  return buffer;
}

void print_time(ASN1_TIME* asn1time, char* pre_string, char* dateformat)
{
  time_t tim;
  char buffer[STRBUFFERSIZE];

  if (ASN1_TIME_to_time_t(asn1time, &tim)==0)
    printf ("%s: %s\n", pre_string, time_t_to_str(buffer, STRBUFFERSIZE, dateformat, &tim));
  else
    printf ("%s: (error)\n", pre_string);
}

char *SSL_cipher_description(SSL_CIPHER* cipher)
{
  char *tmp = malloc(sizeof(char)*STRBUFFERSIZE);
  tmp[0] = '\0';
  if (cipher)
    SSL_CIPHER_description(cipher, tmp, STRBUFFERSIZE);

  return tmp;
}

void print_usage(char *executable)
{
  fprintf(stderr, "You must specify a web server to connect through HTTPS and additionally a port:\n");
  fprintf(stderr, "  %s server [port]\n", executable);
  fprintf(stderr, "------------\n\n");
  exit(-1);
}

void panic(char *msg)
{
  fprintf (stderr, "Error: %s (errno %d, %s)\n", msg, errno, strerror(errno));
  /* Print SSL errors */
  ERR_print_errors_fp(stderr);
  exit(2);
}
