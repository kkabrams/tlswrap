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

const char *SSL_error_string(int e) {
  switch(e) {
    case SSL_ERROR_NONE: return "SSL_ERROR_NONE";
    case SSL_ERROR_ZERO_RETURN: return "SSL_ERROR_ZERO_RETURN";
    case SSL_ERROR_WANT_READ: return "SSL_ERROR_WANT_READ";
    case SSL_ERROR_WANT_WRITE: return "SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_CONNECT: return "SSL_ERROR_WANT_CONNECT";
    case SSL_ERROR_WANT_ACCEPT: return "SSL_ERROR_WANT_ACCEPT";
    case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
    case SSL_ERROR_WANT_ASYNC: return "SSL_ERROR_WANT_ASYNC";
    case SSL_ERROR_WANT_ASYNC_JOB: return "SSL_ERROR_WANT_ASYNC_JOB";
    case SSL_ERROR_WANT_CLIENT_HELLO_CB: return "SSL_ERROR_WANT_CLIENT_HELLO_CB";
    case SSL_ERROR_SYSCALL: return "SSL_ERROR_SYSCALL";
    case SSL_ERROR_SSL: return "SSL_ERROR_SSL";
    default: return "unknown error";
  }
  return "impossible.";
}

int ssl_init(void) {
#if OPENSSL_VERSION_NUMBER>=0x10100000L
  OPENSSL_init_ssl(
	OPENSSL_INIT_LOAD_SSL_STRINGS
      | OPENSSL_INIT_LOAD_CRYPTO_STRINGS
      | OPENSSL_INIT_LOAD_CONFIG
      , NULL);
#else
  OPENSSL_config(NULL);
  ERR_load_crypto_strings();
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
  //SSL_CTX *ctx=SSL_get_SSL_CTX(ssl);
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
  return SSL_TLSEXT_ERR_OK;
  //TODO: figure out a good way to do certs based on vhost here.
  if(chdir("/etc/ssl/certs/") != 0) {
    return SSL_TLSEXT_ERR_OK;//skipping per-vhost certs and keys
  }
  //if(SSL_CTX_use_certificate_chain_file(ctx, servername) <= 0) {
  //  syslog(LOG_DAEMON|LOG_ERR,"failed to load servername cert");
  //  return SSL_TLSEXT_ERR_NOACK;
 // }
  if(chdir("/etc/ssl/keys/") != 0) {
    return SSL_TLSEXT_ERR_OK;//not sure if returning here will break stuff or not
  }
  //if(SSL_CTX_use_PrivateKey_file(ctx, servername, SSL_FILETYPE_PEM) <= 0) {
  //  syslog(LOG_DAEMON|LOG_ERR,"failed to load servername key");
  //  return SSL_TLSEXT_ERR_NOACK;
 // }
  //probably attempt to open certs named after the vhosts in a config dir.
  return SSL_TLSEXT_ERR_OK;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
  syslog(LOG_DAEMON|LOG_DEBUG,"got into the verify_callback!");
  return 1;
}

int main(int argc,char *argv[]) {
  syslog(LOG_DAEMON|LOG_DEBUG,"started");
  struct sockaddr_in6 sa6;
  char ra[NI_MAXHOST],rp[NI_MAXSERV];
  char sa[NI_MAXHOST],sp[NI_MAXSERV];
  char ru[6+3+NI_MAXHOST+NI_MAXSERV+1];//6 for "tcp://", 3 just in case [ and ] are needed and the :, +1 for null
  char su[6+3+NI_MAXHOST+NI_MAXSERV+1];
  unsigned int sl=sizeof(sa6);
  char *cert_chain_file, *priv_key_file;
  int verify_mode = SSL_VERIFY_PEER;

  argv++;//skip argv[0]
  argc--;

  if(argc == 0
    || !strcmp(argv[0],"--help")
    || !strcmp(argv[0],"-h")) {
    fprintf(argc?stdout:stderr,"usage: tlswrap [--help|-h][--verify-mode integer] <cert_chain_file> <priv_key_file> <absolute_path_to_exe> [<arg1>] [<arg2>] [...]\n");
    fprintf(argc?stdout:stderr,"verify mode flags (can be or'd together):\n");
    fprintf(argc?stdout:stderr,"SSL_VERIFY_NONE: %d (no other flags may be set)\n",SSL_VERIFY_NONE);
    fprintf(argc?stdout:stderr,"SSL_VERIFY_PEER: %d\n",SSL_VERIFY_PEER);
    fprintf(argc?stdout:stderr,"SSL_VERIFY_FAIL_IF_NO_PEER_CERT: %d\n",SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
    fprintf(argc?stdout:stderr,"SSL_VERIFY_CLIENT_ONCE: %d\n",SSL_VERIFY_CLIENT_ONCE);
    fprintf(argc?stdout:stderr,"SSL_VERIFY_POST_HANDSHAKE: %d\n",SSL_VERIFY_POST_HANDSHAKE);
    return 1;
  }
  if(argc >= 2) {
    if(!strcmp(argv[0],"--verify-mode")) {
      verify_mode=atoi(argv[1]);
      argc-=2;
      argv+=2;
    }
  }
  if(argc >= 1) {
    cert_chain_file=argv[0];
    argv++;
    argc--;
  }
  if(argc >= 1) {
    priv_key_file=argv[0];
    argv++;
    argc--;
  }
  if(argc == 0) {
    fprintf(stderr,"missing argument. need the absolute path of an executable and arguments to execv into at the end.\n");
    return 1;
  }

  if(getsockname(0,(struct sockaddr *)&sa6,&sl) != -1) {
    if(getnameinfo((struct sockaddr *)&sa6,sl,sa,sizeof(sa),sp,sizeof(sp),NI_NUMERICHOST|NI_NUMERICSERV) == 0) {
      setenv("SERVER_ADDR",sa,1);
      setenv("SERVER_PORT",sp,1);
      if(sa6.sin6_family == AF_INET6) {
        snprintf(su,sizeof(su)-1,"tcp://[%s]:%s",sa,sp);
      } else {
        snprintf(su,sizeof(su)-1,"tcp://%s:%s",sa,sp);
      }
      setenv("SERVER_URL",su,1);
    }
  }
  if(getpeername(0,(struct sockaddr *)&sa6,&sl) != -1) {
    if(getnameinfo((struct sockaddr *)&sa6,sl,ra,sizeof(ra),rp,sizeof(rp),NI_NUMERICHOST|NI_NUMERICSERV) == 0) {
      setenv("REMOTE_ADDR",ra,1);
      setenv("REMOTE_PORT",rp,1);
      if(sa6.sin6_family == AF_INET6) {
        snprintf(ru,sizeof(ru)-1,"tcp://[%s]:%s",ra,rp);
      } else {
        snprintf(ru,sizeof(ru)-1,"tcp://%s:%s",ra,rp);
      }
      setenv("REMOTE_URL",ru,1);
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

  SSL_CTX_set_verify(ctx, verify_mode, verify_callback); SSL_CTX_set_ecdh_auto(ctx, 1);

  if(SSL_CTX_use_certificate_chain_file(ctx, cert_chain_file) <= 0) {
    syslog(LOG_DAEMON|LOG_ERR,"failed to load cert chain file: %s",cert_chain_file);
    return 1;
  }
  if(SSL_CTX_use_PrivateKey_file(ctx, priv_key_file, SSL_FILETYPE_PEM) <= 0) {
    syslog(LOG_DAEMON|LOG_ERR,"failed to load private key file: %s",priv_key_file);
    return 1;
  }

  SSL_CTX_set_tlsext_servername_callback(ctx,sni_cb);
  ssl = SSL_new(ctx);

  SSL_set_rfd(ssl, 0);
  SSL_set_wfd(ssl, 1);
  int err;
  int ssl_err;
  int err_err;
  //fprintf(stderr,"made it here\n");
  if((err=SSL_accept(ssl)) <= 0) {
    ssl_err = SSL_get_error(ssl,err); //this value should NOT get passed to ERR_error_string.
    if(ssl_err == SSL_ERROR_SYSCALL) {
      if(errno == 0) {
        //The SSL_ERROR_SYSCALL with errno value of 0 indicates unexpected EOF from the peer.
        //ignore this error by default. not really that interesting.
        syslog(LOG_DAEMON|LOG_NOTICE,"%s -> %s SSL_accept() failed. %s",ru,su,strerror(errno));
        return 1;
      }
      if(errno == 104) { //connection reset by peer. also not interesting.
        syslog(LOG_DAEMON|LOG_NOTICE,"%s -> %s SSL_accept() failed. %s",ru,su,strerror(errno));
        return 1;
      }
    }
    //now, let's try harder on these error messages.
    err_err = ERR_get_error(); //???

    syslog(LOG_DAEMON|LOG_ERR,"%s -> %s SSL_accept() failed. %d / %d / %d / %s / %s / %d / %s",
      ru,
      su,
      err,
      ssl_err,
      err_err,
      ERR_error_string(err_err,NULL),
      SSL_error_string(ssl_err),
      errno,
      strerror(errno)
    );
    //syslog(LOG_DAEMON|LOG_NOTICE,"%s -> %s SSL_accept() failed. %s",ru,su,ERR_error_string(ERR_get_error(),NULL));
    //fprintf(stderr,"SSL_accept() failed. %s\n",ERR_lib_error_string(SSL_get_error(ssl,err)));
    return 1;
  }
  //fprintf(stderr,"made it here\n");
  syslog(LOG_DAEMON|LOG_DEBUG,"accepted a connection!");
  size_t r;
  char buffer[9001];

  if(servername && servername[0]) {
    setenv("SSL_TLS_SNI",servername,1);
  }

  if(client_cert(ssl)) {
    syslog(LOG_DAEMON|LOG_DEBUG,"%s -> %s we were provided a client cert!",ru,su);
  } else {
    syslog(LOG_DAEMON|LOG_DEBUG,"%s -> %s no client cert provided",ru,su);
  }
  //fprintf(stderr,"made it here\n");

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
    dup2(x,3);//we're passing this to the child ONLY so it can do getpeername and stuff. this can probably be closed.
    execv(argv[0],argv);
  }
  if(child == -1) {
    syslog(LOG_DAEMON|LOG_WARNING,"failed to fork");
    return 1;
  }
  //fprintf(stderr,"made it here\n");
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
  //fprintf(stderr,"made it here\n");
  for(;FD_ISSET(b[0],&master) || FD_ISSET(c[0],&master);) { //a select() brick that reads from ssl and writes to subprocess and reads from subprocess and writes to ssl
    readfs=master;
    if((j=select(fdmax+1,&readfs,0,0,tout)) == -1 ) {
      syslog(LOG_DAEMON|LOG_ERR,"giving up. error'd in select");
      break;
    }
    if(FD_ISSET(0,&readfs)) {
      if((r=SSL_read(ssl,buffer,sizeof(buffer))) <= 0) {
        syslog(LOG_DAEMON|LOG_DEBUG,"SSL done. %d msg: %s",r,ERR_error_string(ERR_get_error(),NULL));
        if(write(a[1],buffer,r) < 0) {
          syslog(LOG_DAEMON|LOG_ERR,"write failed. -_-");
        }
        FD_CLR(0,&master);
      } else {
        syslog(LOG_DAEMON|LOG_DEBUG,"SSL read? %d msg: %s",r,ERR_error_string(ERR_get_error(),NULL));
        syslog(LOG_DAEMON|LOG_DEBUG,"read %d bytes from ssl!",r);
        if(write(a[1],buffer,r) < 0) {
          syslog(LOG_DAEMON|LOG_ERR,"a write failed. -_-");
        }
      }
    }
    if(FD_ISSET(b[0],&readfs)) {
      if((r2=read(b[0],buffer,sizeof(buffer))) <= 0) {
        syslog(LOG_DAEMON|LOG_DEBUG,"subprocess stdout done.");
        FD_CLR(b[0],&master);
      } else {
        syslog(LOG_DAEMON|LOG_DEBUG,"read %d bytes from subprocess!",r2);
        if(SSL_write(ssl,buffer,r2) <= 0) {
          syslog(LOG_DAEMON|LOG_ERR,"SSL_write had an error: %s",ERR_error_string(ERR_get_error(),NULL));
        }
      }
    }
    if(FD_ISSET(c[0],&readfs)) {
      if((r2=read(c[0],buffer,sizeof(buffer)-1)) <= 0) {
        syslog(LOG_DAEMON|LOG_DEBUG,"subprocess stderr done.");
        FD_CLR(c[0],&master);
      } else {
        //write(2,buffer,r2);
        buffer[r2]=0;//gotta null this off sice we're passing to something that expects a string.
        //fprintf(stderr,"%s",buffer);
        syslog(LOG_DAEMON|LOG_WARNING,"%s -> %s stderr: %s",ru,su,buffer);
      }
    }
  }
  SSL_shutdown(ssl);
  SSL_free(ssl);
  EVP_cleanup();
}
