# ftplibpp

Platform independent c++ library providing ftp client functionality.

ftplibpp contains a c++ class providing ftp client functionality. It supports all basic 
ftp functionality plus some advanced features like resuming, fxp, ssl/tls encryption, 
large file support, or logging to fit todays standards.

## Documentation

### Public types

* [int (* FtpCallbackIdle )(void *arg)](#ftpcallbackidle)
* [void (* FtpCallbackLog )(char *str, void* arg, bool out)](#ftpcallbacklog)
* [int (* FtpCallbackXfer )(off64_t xfered, void *arg)](#ftpcallbackxfer)
* [bool (* FtpCallbackCert )(void *arg, X509 *cert)](#ftpcallbackCert)
* [enum accesstype](#accesstype)
* [enum transfermode](#transfermode)
* [enum connmode](#connmode)
* [enum fxpmethod](#fxpmethod)
* [enum dataencryption](#dataencryption)

### Methods

* [ftplib ()](#ftplib)
* [char* LastResponse ()](#lastresponse)
* [int Connect (const char *host)](#connect)
* [int Login (const char *user, const char *pass)](#login)
* [int Site (const char *cmd)](#site)
* [int Raw (const char *cmd)](#raw)
* [int SysType (char* buf, int max)](#systype)
* [int Mkdir (const char *path)](#mkdir)
* [int Chdir (const char *path)](#chdir)
* [int Cdup ()](#cdup)
* [int Rmdir (const char *path)](#rmdir)
* [int Pwd (char *path, int max)](#pwd)
* [int Nlst (const char *outputfile, const char *path)](#nlst)
* [int Dir (const char *outputfile, const char *path)](#dir)
* [int Size (const char *path, int *size, transfermode mode)](#size)
* [int ModDate (const char *path, char *dt, int max)](#moddate)
* [int Get (const char *outputfile, const char *path, transfermode mode)](#get)
* [int Get (const char *outputfile, const char *path, transfermode mode, off64_t offset)](#get2)
* [int Put (const char *inputfile, const char *path, transfermode mode)](#put)
* [int Put (const char *inputfile, const char *path, transfermode mode, off64_t offset)](#put2)
* [int Rename (const char *src, const char *dst)](#rename)
* [int Delete (const char *path)](#delete)
* [int SetDataEncryption (dataencryption enc)](#setdataencryption)
* [int NegotiateEncryption ()](#negotiateencryption)
* [ftphandle* RawOpen (const char *path, accesstype type, transfermode mode)](#rawopen)
* [int RawRead (void *buf, int max, ftphandle *handle)](#rawread)
* [int RawWrite (void *buf, int len, ftphandle *handle)](#rawwrite)
* [int RawClose (ftphandle *handle)](#rawclose)
* [void Quit ()](#quit)
* [void SetCallbackIdleFunction (FtpCallbackIdle pointer)](#setcallbackidlefunction)
* [void SetCallbackLogFunction (FtpCallbackLog pointer)](#setcallbacklogfunction)
* [void SetCallbackXferFunction (FtpCallbackXfer pointer)](#setcallbackxferfunction)
* [void SetCallbackCertFunction (FtpCallbackCert pointer)](#setcallbackcertfunction)
* [void SetCallbackArg (void *arg)](#setcallbackarg)
* [void SetCallbackBytes (off64_t bytes)](#setcallbackbytes)
* [void SetCallbackIdletime (int time)](#setcallbackidletime)
* [void SetCorrectPasv (bool b)](#setcorrectpasv)
* [void SetConnmode (ftplib::ftp mode)](#setconnmode)

### Public static methods

* [static int Fxp (ftplib* src, ftplib* dst, const char *pathSrc, const char *pathDst, ftplib::ftp mode, ftplib::ftp method)](#fxp)
