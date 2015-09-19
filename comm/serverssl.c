/**
*************************************************************
* @file serverssl.c
* @brief Example web server using SSL connection.
*   It will always send the same web. It's just a test
*   to stablish a secure connection and send some data
*   This server cannot attend simultaneous connections
*
* @author Gaspar Fernández <blakeyed@totaki.com>
* @version 0.1
* @date 18 apr 2015
*
* Changelog:
*   20150422 - Some more doc.
*
* To compile
*   $ gcc -o serverssl serverssl.c -lcrypto -lssl
*
*************************************************************/

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/** Port  */
#define PORT       1430

/** Buffer Size to use  */
#define BUFFERSIZE 16384

/** CRLF  */
#define CRLF       "\r\n"

/** The only response of this server  */
#define RESPONSE "HTTP/1.1 200 OK" CRLF		\
  "Content-Type: text/html charset=utf-8" CRLF	\
  "Server: ServerTest" CRLF			\
  CRLF						\
  "<html><head><title>Server Test</title></head><body>This is just a test</body></html>" CRLF

/** Certificate file, or certificate chain file  */
#define CERTFILE  "sslserverchain.pem"
/** Key file  */
#define KEYFILE   "sslserver.key"

/** sslc handles SSL and SSL_CTX and socket.
 The same as myssl.c */
typedef struct
{
  /** socket handler  */
  int skt;
  /** client socket handler  */
  int client_skt;
  /** error, if any  */
  int err;
  /** SSL handler  */
  SSL* ssl;
  /** SSL Context  */
  SSL_CTX* ctx;
} Sslc;

/**
 *
 * @param h    Our struct
 * @param port Por to listen to 
 *
 * @return (0 if OK, else fail)
 */
int TCP_Server(Sslc* h, int port);

/**
 * Uses select to test if there is anything waiting to be read.
 * The same function as myssl.c
 *
 * @param h       Our structure. Only the socket will be used
 * @param timeout Timeout before giving up
 *
 * @return (0 timeout, 1 data waiting, <0 fail)
 */
int TCP_select(Sslc* h, double timeout);

/**
 * Initializes SSL connection and creates the SSL Context
 *
 * @param h     Our struct to store everything
 *
 * @return 0 if OK
 */
int SSL_init(Sslc* h);

/**
 * Loads certificates in the context. 
 *
 * @param h     Our struct to store everything
 * @param cert  PEM certificate file or chain (we can store several 
 *              certificates in one file, just concatenating them.
 * @param key   Encryption key
 *
 * @return 0 if OK
 */
int SSL_load_certificates(Sslc* h, char* cert, char* key);

/**
 * Accepts client and start dialog
 *
 * @param h     Our struct 
 *
 * @return 0 if OK
 */
int TCP_acceptClient(Sslc* h);

/**
 * Just a test, replace SSL_clientDialog() in acceptClient() by
 * TCP_clientDialog() to create an insecure web server.
 *
 * @param h     Our struct
 *
 * @return 0 if OK
 */
int TCP_clientDialog(Sslc* h);

/**
 * It's everything we're here for. SSL dialog with the clients
 *
 * @param h     Our struct
 *
 * @return 0 if OK
 */
int SSL_clientDialog(Sslc* h);

/**
 * Prints a tragic error and exit
 *
 * @param msg   Error text
 *
 * @return void
 */
void panic(char* msg);

/**
 * ASCII clock to wait for clients
 *
 * @param loop  Just a number, when it changes, it draws a new character.
 *              If loop == 0, restarts
 *
 * @return void
 */
void aclock(int loop);

int main(int argv, char** argc){

  Sslc sslc;
  int activated=1;
  int loop=0;
  int sel_res;

  if (SSL_init(&sslc)<0)
    panic ("Couldn't initialize SSL");

  if (SSL_load_certificates(&sslc, CERTFILE, KEYFILE))
    panic ("Couln't load certificates");

  if (TCP_Server(&sslc, PORT)<0)
    panic ("Couldn't make a TCP Connection");

  while(activated)
    {
      aclock(loop);
      sel_res =TCP_select(&sslc, 1);
      if (sel_res<0)
	panic("Failed on selec()");
      else if (sel_res==1)
	{
	  if (TCP_acceptClient(&sslc)<0)
	    panic ("Tragic error accepting client");
	  loop = -1;		/* Reset clock */
	}

      loop++;
    }

  /* Wont' reach this point as the server never ends... */
  close(sslc.skt);

  return 0;
}

int TCP_Server(Sslc* h, int port)
{
  struct sockaddr_in my_addr;

  h->skt = socket(AF_INET, SOCK_STREAM, 0);
  if(h->skt < 0)
    return -1;

  my_addr.sin_family = AF_INET ;
  my_addr.sin_port = htons(port);
  my_addr.sin_addr.s_addr = INADDR_ANY ;

  if( bind( h->skt, (struct sockaddr*)&my_addr, sizeof(my_addr)) == -1 )
    return -2;

  if(listen( h->skt, 10) == -1 )
    return -3;

  return 0;
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

int TCP_acceptClient(Sslc* h)
{
  struct sockaddr_in client_addr;
  socklen_t size_addr = sizeof(struct sockaddr_in);

  if ((h->client_skt = accept( h->skt, (struct sockaddr*)&client_addr, &size_addr))!= -1)
    {
      printf("\nNew client connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
      int r = SSL_clientDialog(h);
      if (r<0)
	{
	  printf ("There was a problem with this client connection\n");
	  ERR_print_errors_fp(stderr);
	}
      close(h->client_skt);
    }

  /* Returns 0 to avoid tragic fails, just display on screen*/
  return -6;
}

int TCP_clientDialog(Sslc* h)
{
  char buffer[BUFFERSIZE];
  int bytecount;

  memset(buffer, 0, BUFFERSIZE);
  if((bytecount = recv(h->client_skt, buffer, BUFFERSIZE, 0))== -1)
    return -7;

  if (send(h->client_skt, RESPONSE, strlen(RESPONSE), 0)<0)
    return -8;

  return 0;
}

int SSL_clientDialog(Sslc* h)
{
  char buffer[BUFFERSIZE];
  int bytecount;

  h->ssl = SSL_new(h->ctx);
  if (h->ssl == NULL)
    return -11;
  /* SSL_set_options(h->ssl, SSL_OP_ALL ); */

  if (SSL_set_fd(h->ssl, h->client_skt) == 0)
    return -12;

  /* Accept SSL connection and handshake */
  if (SSL_accept(h->ssl) < 1)
    return -13;

  memset(buffer, 0, BUFFERSIZE);
  if((bytecount = SSL_read(h->ssl, buffer, BUFFERSIZE)) < 1)
    return -7;

  if (SSL_write(h->ssl, RESPONSE, strlen(RESPONSE))< 1)
    return -8;

  SSL_free(h->ssl);		/* free mem */

  return 0;
}

int SSL_init(Sslc* h)
{
  SSL_library_init();		/* not reentrant! */

  SSL_load_error_strings();

  OpenSSL_add_all_algorithms();		/* load & register all cryptos, etc. */

  /* We can try SSLv23_server_method() to try several 
   methods, starting from the more secure*/
  h->ctx = SSL_CTX_new(TLSv1_2_server_method());
  if (h->ctx == NULL)
    return -4;

  return 0;
}

int SSL_load_certificates(Sslc* h, char* cert, char* key)
{
  if ( SSL_CTX_use_certificate_chain_file(h->ctx, cert) < 1 )
      return -8;

  /* set the private key */
  if ( SSL_CTX_use_PrivateKey_file(h->ctx, key, SSL_FILETYPE_PEM) <= 0 )
    return -9;

  /* verify private key */
  if ( !SSL_CTX_check_private_key(h->ctx) )
    {
      printf("Private key doesn't match the public certificate\n");
      return -10;
    }

  return 0;
}

void aclock(int loop)
{
  if (loop==0)
    printf("[SERVER] Waiting for connections  ");

  printf("\033[1D");        /* ANSI code to go back 2 characters */
  switch (loop%4)
    {
    case 0: printf("|"); break;
    case 1: printf("/"); break;
    case 2: printf("-"); break;
    case 3: printf("\\"); break;
    default:            /* Nothing here */
      break;
    }

  fflush(stdout);       /* Update screen */
}


void panic(char *msg)
{
  fprintf (stderr, "Error: %s (errno %d, %s)\n", msg, errno, strerror(errno));
  /* Print SSL errors */
  ERR_print_errors_fp(stderr);
  exit(2);
}
