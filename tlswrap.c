#include <unistd.h>
#include <string.h>
#include <time.h>
#include <syslog.h>

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>

//#define FORCE_SNI //whether SNI is required to connect to this server.

int ssl_init(void) {
#if OPENSSL_VERSION_NUMBER>=0x10100000L
  OPENSSL_init_ssl(
	OPENSSL_INIT_LOAD_SSL_STRINGS
      | OPENSSL_INIT_LOAD_CRYPTO_STRINGS
      | OPENSSL_INIT_LOAD_CONFIG
      , NULL);
#else
  OPENSSL_config(NULL);
  SSL_load_error_strings();
  SSL_library_init();
#endif
  return 0;
}

const char *servername;

char *X509_NAME2text(X509_NAME *name) {
  char *text;
  BIO *bio;
  int n;
  bio=BIO_new(BIO_s_mem());
  if(!bio) return 0;
  X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB & ~XN_FLAG_SPC_EQ);
  n=BIO_pending(bio);
  text=malloc((size_t)n+1);
  n=BIO_read(bio, text, n);
  if(n<0) {
    BIO_free(bio);
    free(text);
    return 0;
  }
  text[n]='\0';
  BIO_free(bio);
  return text;
}

int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len) {
  int rc;
  BIO *b = BIO_new(BIO_s_mem());
  rc = ASN1_TIME_print(b, t);
  if (rc <= 0) {
    BIO_free(b);
    return EXIT_FAILURE;
  }
  rc = BIO_gets(b, buf, (int)len);//BIO_gets uses int for len I guess.
  if (rc <= 0) {
    BIO_free(b);
    return EXIT_FAILURE;
  }
  BIO_free(b);
  return EXIT_SUCCESS;
}

void hex_encode(unsigned char *readbuf,void *writebuf, size_t len) {
  for(size_t i=0;i<len;i++) {
    char *l = (char *) (2*i + ((intptr_t)writebuf));
    sprintf(l,"%02x",readbuf[i]);
  }
}

#define DATE_LEN 128
#define SHA256LEN 32

int client_cert(const SSL *ssl) {
  X509 *peer_cert;
  char *client_i_dn;
  char *client_dn;
  char not_before_str[DATE_LEN];
  char not_after_str[DATE_LEN];
  unsigned char client_hash_bin[SHA256LEN];
  char client_hash_str[7+(2*SHA256LEN)+1]="sha256:";//7 for strlen("sha256:") and two bytes for each byte and 1 null at the end
  char *serial_str;
  unsigned int len;
  int rc;
  const EVP_MD *digest = EVP_sha256();
  ASN1_TIME *atime;
  ASN1_INTEGER *serial;
  BIGNUM *bn;
  peer_cert=SSL_get_peer_certificate(ssl);
  if(!peer_cert) return 0;

  atime=X509_get_notBefore(peer_cert);
  convert_ASN1TIME(atime,not_before_str,DATE_LEN);
  setenv("TLS_CLIENT_NOT_BEFORE",not_before_str,1);

  atime=X509_get_notAfter(peer_cert);
  convert_ASN1TIME(atime,not_after_str,DATE_LEN);
  setenv("TLS_CLIENT_NOT_AFTER",not_after_str,1);

  setenv("AUTH_TYPE","CERTIFICATE",1);

  serial = X509_get_serialNumber(peer_cert);
  if((bn = ASN1_INTEGER_to_BN(serial, NULL))) {
    if((serial_str = BN_bn2dec(bn))) {
      setenv("TLS_CLIENT_SERIAL_NUMBER",serial_str,1);
    }
  }

  if((rc = X509_digest(peer_cert, digest, (unsigned char *)client_hash_bin, &len))) {
    hex_encode(client_hash_bin, client_hash_str+7, SHA256LEN);// +7 because we want to skip the sha256: that is already in it.
    setenv("TLS_CLIENT_HASH",client_hash_str,1);
  }

  client_dn=X509_NAME2text(X509_get_subject_name(peer_cert));
  setenv("SSL_CLIENT_DN",client_dn,1);

  client_i_dn=X509_NAME2text(X509_get_issuer_name(peer_cert));
  setenv("SSL_CLIENT_I_DN",client_i_dn,1);
  return 1;
}

//what is ad and arg?
int sni_cb(SSL *ssl, int *ad, void *arg) {
  if(!ssl) return SSL_TLSEXT_ERR_NOACK;
  servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if(!servername || servername[0] == '\0') {
    syslog(LOG_DAEMON|LOG_DEBUG,"no SNI");
#ifdef FORCE_SNI
    return SSL_TLSEXT_ERR_NOACK;
#else
    return SSL_TLSEXT_ERR_OK;
#endif
  }
  syslog(LOG_DAEMON|LOG_DEBUG,"SNI: %s",servername);
  //TODO: figure out a good way to do certs based on vhost here.
  //probably attempt to open certs named after the vhosts in a config dir.
  return SSL_TLSEXT_ERR_OK;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
  syslog(LOG_DAEMON|LOG_DEBUG,"got into the varify_callback!");
  return 1;
}

int main(int argc,char *argv[]) {
  syslog(LOG_DAEMON|LOG_DEBUG,"started");
  struct sockaddr_in6 sa6;
  char ra[NI_MAXHOST],rp[NI_MAXSERV];
  char sa[NI_MAXHOST],sp[NI_MAXSERV];
  unsigned int sl=sizeof(sa6);
  if(getsockname(0,(struct sockaddr *)&sa6,&sl) != -1) {
    if(getnameinfo((struct sockaddr *)&sa6,sl,sa,sizeof(sa),sp,sizeof(sp),NI_NUMERICHOST|NI_NUMERICSERV) == 0) {
      setenv("SERVER_ADDR",sa,1);
      setenv("SERVER_PORT",sp,1);
    }
  }
  if(getpeername(0,(struct sockaddr *)&sa6,&sl) != -1) {
    if(getnameinfo((struct sockaddr *)&sa6,sl,ra,sizeof(ra),rp,sizeof(rp),NI_NUMERICHOST|NI_NUMERICSERV) == 0) {
      setenv("REMOTE_ADDR",ra,1);
      setenv("REMOTE_PORT",rp,1);
    }
  }
  int x;
  ssl_init();
  SSL_CTX *ctx;
  SSL *ssl;
  const SSL_METHOD *method;
  method=TLS_server_method();
  ctx = SSL_CTX_new(method);
  if(!ctx) {
    syslog(LOG_DAEMON|LOG_ERR,"could not create new SSL context");
    return 1;
  }

  int a[2]; //a is subprocess's stdin, so need to read decrypted data from stdin and write to a[1]
  int b[2]; //b is subprocees's stdout, so need to read it, and give it to SSL to encrypt and push out.
  int c[2]; //c is subprocess's stderr, so need to read it, and write lines to syslog.
  pipe(a);
  pipe(b);
  pipe(c);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_ecdh_auto(ctx, 1);

  if(SSL_CTX_use_certificate_chain_file(ctx, argv[1]) <= 0) {
    syslog(LOG_DAEMON|LOG_ERR,"failed to load cert chain file: %s",argv[1]);
    return 1;
  }
  if(SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) <= 0) {
    syslog(LOG_DAEMON|LOG_ERR,"failed to load private key file: %s",argv[2]);
    return 1;
  }

  SSL_CTX_set_tlsext_servername_callback(ctx,sni_cb);
  ssl = SSL_new(ctx);

  SSL_set_rfd(ssl, 0);
  SSL_set_wfd(ssl, 1);

  if(SSL_accept(ssl) <= 0) {
    syslog(LOG_DAEMON|LOG_WARNING,"tcp://%s:%s -> tcp://%s:%s SSL_accept() failed. %s",ra,rp,sa,sp,ERR_error_string(ERR_get_error(),NULL));
    return 1;
  }
  syslog(LOG_DAEMON|LOG_DEBUG,"accepted a connection!");
  size_t r;
  char buffer[9001];

  if(servername && servername[0]) {
    setenv("SSL_TLS_SNI",servername,1);
  }

  if(client_cert(ssl)) {
    syslog(LOG_DAEMON|LOG_DEBUG,"tcp://%s:%s -> tcp://%s:%s we were provided a client cert!",ra,rp,sa,sp);
  } else {
    syslog(LOG_DAEMON|LOG_DEBUG,"tcp://%s:%s -> tcp://%s:%s no client cert provided",ra,rp,sa,sp);
  }

  argv+=3;
  int child=fork();
  if(child == 0) {
    x=dup(0);
    dup2(a[0],0);
    dup2(b[1],1);
    dup2(c[1],2);
    close(a[0]);
    close(b[1]);
    close(a[1]);
    close(b[0]);
    close(c[0]);
    close(c[1]);
    dup2(x,3);//we're passing this to the child ONLY so it can do getpeername and stuff.
    execv(argv[0],argv);
  }
  if(child == -1) {
    syslog(LOG_DAEMON|LOG_WARNING,"failed to fork");
    return 1;
  }
  int j;
  int r2;
  int fdmax=0;
  fd_set master;
  fd_set readfs;
  FD_ZERO(&master);
  FD_ZERO(&readfs);
  FD_SET(0,&master);//SSL is ready to be read from
  FD_SET(b[0],&master);//subprocess's stdout is ready to be read from
  FD_SET(c[0],&master);//subprocess's stderr
  fdmax=b[0]>c[0]?b[0]:c[0];
  struct timeval *tout=NULL;
  close(a[0]);
  close(b[1]);
  close(c[1]);
  syslog(LOG_DAEMON|LOG_DEBUG,"entering select loop");
  while(1) { //a select() brick that reads from ssl and writes to subprocess and reads from subprocess and writes to ssl
    readfs=master;
    if((j=select(fdmax+1,&readfs,0,0,tout)) == -1 ) {
      syslog(LOG_DAEMON|LOG_WARNING,"giving up. error'd in select: %s",strerror(errno));
      break;
    }
    if(FD_ISSET(0,&readfs)) {
      if(SSL_read_ex(ssl,buffer,sizeof(buffer),&r) <= 0) break;
        syslog(LOG_DAEMON|LOG_DEBUG,"read %d bytes from ssl!",r);
      if(r > 9000) {
        syslog(LOG_DAEMON|LOG_WARNING,"read %d bytes from ssl, and that's close to the buffer size. watch for bugs.",r);
      }
      write(a[1],buffer,r);
    }
    if(FD_ISSET(b[0],&readfs)) {
      if((r2=read(b[0],buffer,sizeof(buffer))) <= 0) break;
      syslog(LOG_DAEMON|LOG_DEBUG,"read %d bytes from subprocess!",r2);
      if(r2 > 9000) {
        syslog(LOG_DAEMON|LOG_WARNING,"read %d bytes from subprocess, and that's close to the buffer size. watch for bugs.",r2);
      }
      SSL_write(ssl,buffer,r2);
    }
    if(FD_ISSET(c[0],&readfs)) {
      if((r2=read(c[0],buffer,sizeof(buffer)-1)) <= 0) break;
      buffer[r2]=0;//gotta null this off sice we're passing to something that expects a string.
      syslog(LOG_DAEMON|LOG_WARNING,"stderr: %s",buffer);
    }
  }
  SSL_shutdown(ssl);
  SSL_free(ssl);
  EVP_cleanup();
}
