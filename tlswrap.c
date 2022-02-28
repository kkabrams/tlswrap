#include <unistd.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <openssl/ssl.h>
#include <errno.h>

//#define FORCE_SNI

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

void ssl_deinit() {
  EVP_cleanup();
}

const char *servername;

char *X509_NAME2text(X509_NAME *name) {
    char *text;
    BIO *bio;
    int n;
    bio=BIO_new(BIO_s_mem());
    if(!bio)
        return 0;
    X509_NAME_print_ex(bio, name, 0,
        XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB & ~XN_FLAG_SPC_EQ);
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

int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len)
{
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
  char client_hash_str[2*SHA256LEN+1];//two bytes for each byte and 1 null at the end
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
    hex_encode(client_hash_bin, client_hash_str, SHA256LEN);
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
    syslog(LOG_INFO,"no SNI");
#ifdef FORCE_SNI
    return SSL_TLSEXT_ERR_NOACK;
#else
    return SSL_TLSEXT_ERR_OK;
#endif
  }
  syslog(LOG_INFO,"SNI: %s",servername);
  //TODO: figure out a good way to do certs based on vhost here.
  //probably attempt to open certs named after the vhosts in a config dir.
  return SSL_TLSEXT_ERR_OK;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
  syslog(LOG_WARNING,"got into the varify_callback!");
  return 1;
}

int main(int argc,char *argv[]) {
  syslog(LOG_INFO,"sslwrap started");
  int x;
  ssl_init();
  SSL_CTX *ctx;
  SSL *ssl;
  const SSL_METHOD *method;
  method=TLS_server_method();
  ctx = SSL_CTX_new(method);
  if(!ctx) {
    syslog(LOG_INFO,"could not create new SSL context");
    return 1;
  }

  int a[2]; //a is subprocess's stdin, so need to read decrypted data from stdin and write to a[1]
  int b[2]; //b is subprocees's stdout, so need to read it, and give it to SSL to encrypt and push out.
  pipe(a);
  pipe(b);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_ecdh_auto(ctx, 1);

  if(SSL_CTX_use_certificate_chain_file(ctx, argv[1]) <= 0) {
    syslog(LOG_INFO,"failed to load cert chain file: %s",argv[1]);
    return 1;
  }
  if(SSL_CTX_use_PrivateKey_file(ctx, argv[2], SSL_FILETYPE_PEM) <= 0) {
    syslog(LOG_INFO,"failed to load private key file: %s",argv[2]);
    return 1;
  }

  SSL_CTX_set_tlsext_servername_callback(ctx,sni_cb);
  ssl = SSL_new(ctx);

  SSL_set_rfd(ssl, 0);//this is right
  SSL_set_wfd(ssl, 1);//docs say "these are usually a nework connection"

  if(SSL_accept(ssl) <= 0) {
    syslog(LOG_INFO,"sslwrap failed to accept");
    return 1;
  }
  syslog(LOG_INFO,"sslwrap accepted a connection!");
  //how do I auto-SSL_write stuff from another fd? I figure a select() block or something
  size_t r;
  char buffer[9001]; //set it bigger thna a packet to hide the problem that I didn't write this problem.
  // (at least until I get to rewriting it so it'll work however)
  // can I exec into a subprocess? I doubt it... probably need to fork and wait so I can shutdown properly.

  if(servername && servername[0]) {
    setenv("SSL_TLS_SNI",servername,1);
  }

  if(client_cert(ssl)) {
    syslog(LOG_INFO,"we were provided a client cert!");
  } else {
    syslog(LOG_INFO,"no client cert provided");
  }

  argv+=3;
  int child=fork();
  if(child == 0) {
    x=dup(0);
    dup2(a[0],0);
    dup2(b[1],1);
    dup2(b[1],2);//probably log this instead of sending through the ssl socket
    close(a[0]);
    close(b[1]);
    close(a[1]);
    close(b[0]);
    dup2(x,3);
    execv(argv[0],argv);
  }
  if(child == -1) {
    fprintf(stderr,"fork fucked\n");
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
  FD_SET(b[0],&master);//subprocess is ready to be read from
  fdmax=b[0];
  struct timeval *tout=NULL;
  close(b[1]);
  close(a[0]);
  syslog(LOG_INFO,"entering select loop");
  while(1) { //a select() brick that reads from ssl and writes to subprocess. then reads from subprocess and writes to ssl
    readfs=master;
    if((j=select(fdmax+1,&readfs,0,0,tout)) == -1 ) {
      syslog(LOG_INFO,"sslwrap error'd in select: %s",strerror(errno));
    }
    if(FD_ISSET(0,&readfs)) {
      if(SSL_read_ex(ssl,buffer,sizeof(buffer),&r) <= 0) break;
      syslog(LOG_INFO,"read %d bytes from ssl!",r);
      write(a[1],buffer,r);
    }
    if(FD_ISSET(b[0],&readfs)) {
      r2=read(b[0],buffer,sizeof(buffer));
      if(r2 <= 0) break;
      syslog(LOG_INFO,"read %d bytes from subprocess!",r2);
      SSL_write(ssl,buffer,r2);
    }
  }

  //what do we do here?
  SSL_shutdown(ssl);
  SSL_free(ssl);
  ssl_deinit();
}