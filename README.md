# ftplibpp

Platform independent c++ library providing ftp client functionality.

ftplibpp contains a c++ class providing ftp client functionality. It supports all basic ftp functionality plus some advanced features like resuming, fxp, ssl/tls encryption, large file support, or logging to fit todays standards.

## Build

### Docker (Linux)

```
docker build -t build-env .
docker run -e -v $PWD:/src -w /src build-env make
```

### MacOS without SSL

```
NOSSL=1 make
```

## Documentation

ftplibpp provides a c++ class providing ftp client functionality. It supports all basic ftp functionality plus some
advanced features like resuming, fxp, ssl/tls encryption, large file support, or logging to fit todays standards. The
very base of ftplibpp is Thomas Pfau's [ftplib c library](http://nbpfaus.net/%7Epfau/ftplib/).

Every ftp session is represented by an ftplib object, whose methods are called to communicate with the ftp server. The
ftp sessions should begin with a call to `myftp.Connect("myftp.org:21")` (and maybe `myftp.NegotiateEncryption()` ), be
followed with `myftp.Login("myuser","mypass")` and ended by `myftp.Quit()`. For the magic in between, read the class
methods documentation. Most methods have their tasks pretty much explained in their name. ftplibpp uses OpenSSL for
encryption functionality, if you don't need it you can set the `NOSSL` flag (e.g. `g++ -c ftplib.cpp -DNOSSL`). If your
system does not feature large file support (or does not need specific LFS functions, because it's built in yet) you can
use the `NOLFS` flag (e.g. `g++ -c ftplib.cpp -DNOLFS`). The flag `_FTPLIB_SSL_CLIENT_METHOD_` exists to override the
openssl client method in use, the default is `TLSv1_2_client_method`, override by compiling with `-D_FTPLIB_SSL_CLIENT_METHOD_=${SOME_METHOD}`.

### Public types

* [`int (* FtpCallbackIdle )(void *arg)`](#ftpcallbackidle)
* [`void (* FtpCallbackLog )(char *str, void* arg, bool out)`](#ftpcallbacklog)
* [`int (* FtpCallbackXfer )(off64_t xfered, void *arg)`](#ftpcallbackxfer)
* [`bool (* FtpCallbackCert )(void *arg, X509 *cert)`](#ftpcallbackCert)
* [`enum accesstype`](#accesstype)
* [`enum transfermode`](#transfermode)
* [`enum connmode`](#connmode)
* [`enum fxpmethod`](#fxpmethod)
* [`enum dataencryption`](#dataencryption)

### Methods

* [`ftplib ()`](#ftplib)
* [`char* LastResponse ()`](#lastresponse)
* [`int Connect (const char *host)`](#connect)
* [`int Login (const char *user, const char *pass)`](#login)
* [`int Site (const char *cmd)`](#site)
* [`int Raw (const char *cmd)`](#raw)
* [`int SysType (char* buf, int max)`](#systype)
* [`int Mkdir (const char *path)`](#mkdir)
* [`int Chdir (const char *path)`](#chdir)
* [`int Cdup ()`](#cdup)
* [`int Rmdir (const char *path)`](#rmdir)
* [`int Pwd (char *path, int max)`](#pwd)
* [`int Nlst (const char *outputfile, const char *path)`](#nlst)
* [`int Dir (const char *outputfile, const char *path)`](#dir)
* [`int Size (const char *path, int *size, transfermode mode)`](#size)
* [`int ModDate (const char *path, char *dt, int max)`](#moddate)
* [`int Get (const char *outputfile, const char *path, transfermode mode)`](#get)
* [`int Get (const char *outputfile, const char *path, transfermode mode, off64_t offset)`](#get2)
* [`int Put (const char *inputfile, const char *path, transfermode mode)`](#put)
* [`int Put (const char *inputfile, const char *path, transfermode mode, off64_t offset)`](#put2)
* [`int Rename (const char *src, const char *dst)`](#rename)
* [`int Delete (const char *path)`](#delete)
* [`int SetDataEncryption (dataencryption enc)`](#setdataencryption)
* [`int NegotiateEncryption ()`](#negotiateencryption)
* [`ftphandle* RawOpen (const char *path, accesstype type, transfermode mode)`](#rawopen)
* [`int RawRead (void *buf, int max, ftphandle *handle)`](#rawread)
* [`int RawWrite (void *buf, int len, ftphandle *handle)`](#rawwrite)
* [`int RawClose (ftphandle *handle)`](#rawclose)
* [`void Quit ()`](#quit)
* [`void SetCallbackIdleFunction (FtpCallbackIdle pointer)`](#setcallbackidlefunction)
* [`void SetCallbackLogFunction (FtpCallbackLog pointer)`](#setcallbacklogfunction)
* [`void SetCallbackXferFunction (FtpCallbackXfer pointer)`](#setcallbackxferfunction)
* [`void SetCallbackCertFunction (FtpCallbackCert pointer)`](#setcallbackcertfunction)
* [`void SetCallbackArg (void *arg)`](#setcallbackarg)
* [`void SetCallbackBytes (off64_t bytes)`](#setcallbackbytes)
* [`void SetCallbackIdletime (int time)`](#setcallbackidletime)
* [`void SetCorrectPasv (bool b)`](#setcorrectpasv)
* [`void SetConnmode (ftplib::ftp mode)`](#setconnmode)

### Public static methods

* [`static int Fxp (ftplib* src, ftplib* dst, const char *pathSrc, const char *pathDst, ftplib::ftp mode, ftplib::ftp method)`](#fxp)

## Details

<a name="ftpcallbackidle" />

### int (* FtpCallbackIdle )(void *arg)

[typedef]

`typedef int (*FtpCallbackIdle)(void *arg);`

<a name="ftpcallbacklog" />

### void (* FtpCallbackLog )(char *str, void* arg, bool out)

[typedef]

`typedef void (* FtpCallbackLog)(char *str, void* arg, bool out);`

#### Notes:

*out* indicates wether the log information in *str* is incoming or outgoing.

<a name="ftpcallbackxfer" />

### int (* FtpCallbackXfer )(off64_t xfered, void *arg)

[typedef]

`typedef int (*FtpCallbackXfer)(off64_t xfered, void *arg);`

<a name="ftpcallbackcert" />

### bool (* FtpCallbackCert )(void* arg, X509 *cert)

[typedef]

`typedef int (*FtpCallbackCert)(void *arg, X509 *cert);`

<a name="accesstype" />

### enum accesstype { dir = 1, dirverbose, fileread, filewrite, filereadappend, filewriteappend };

This type is used in [RawOpen](#rawopen).

<a name="transfermode" />

### enum transfermode { ascii = 'A', image = 'I' };

This type determines how data is transferred.

<a name="connmode" />

### enum connmode { pasv = 1, port };

This type determines wether data is to be transferred using the pasv or active mode.

<a name="fxpmethod" />

### enum fxpmethod { defaultfxp = 0, alternativefxp };

This type is used in the Fxp method.

<a name="dataencryption" />

### enum dataencryption { unencrypted = 0, secure };

This type determines wether data is encrypted or not.

<a name="ftplib" />

### ftplib()

[constructor]

Class constructor, an ftplib object is responsible for the ftp session.

<a name="lastresponse" />

### char* LastResponse()

LastResponse returns a pointer to the last response c-styled string sent by the server. This can be parsed by the
user program todetermine more information about the last request or can be displayed along with an error message.

#### Returns:

A pointer to the last server response string. Otherwise, `NULL` is returned.

<a name="connect" />

### int Connect ( const char* host )

Connect establishes a connection to the FTP server on the specified machine and returns a handle which can be used to
initiate data transfers. The host name should be specified in the form of `<host>:<port>` `<host>` may be either a host name or ip
address. `<port>` may be either a service name or a port number.

#### Parameters:

- `host`: The name of the host machine to connect to and optionally an alternate port number to use (`ftp.myftp.com:321`).

#### Returns:

If the connection to the remote server if successful, `Connect()` returns `1`. Otherwise, `0` is returned.

<a name="login" />

### int Login( const char* user, const char* pass )

Login attempts to login to the remote system with the supplied username and password.

#### Parameters:

- `user`: Specifies the username.
- `pass`: Specifies the user's password.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="site" />

### int Site( const char *cmd )

Site sends the specified command as an argument to a `SITE` command.

#### Parameters:

- `cmd`: A string containing a `SITE` subcommand.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="raw" />

### int Raw ( const char *cmd )

Raw sends the specified command unmodified.

#### Parameters:

- `cmd`: A string containing a custom ftp command.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="systype" />

### int SysType ( char *buf, int max )

SysType issues a `SYST` command to the remote system and attempts to parse the system type out of the response and return
it to the user's buffer.

#### Parameters:

- `buf`: A pointer to a buffer where the result will be returned to.
- `max`: Specifies the size of the user buffer.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="mkdir" />

### int Mkdir ( const char* path)

Mkdir sends a make directory request to the remote system.

#### Parameters:

- `path`: Specifies the argument to mkdir on the remote system.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="chdir" />

### int Chdir ( const char* path)

Sends a change working directory request to the server using the specified path.

#### Parameters:

- `path`: Specifies the desired working directory on the server.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="cdup" />

### int Cdup ()

Cdup sends a CDUP command to the remote server.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="rmdir" />

### int Rmdir ( const char* path )

Rmdir sends a remove directory request to the remote server.

#### Parameters:

- `path`: A string containing the name of a remote directory.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="pwd" />

### int Pwd (char* path, int max )

Pwd attempts to determine the current default directory at the server and return it to the user's buffer.

#### Parameters:

- `path`: A pointer to a buffer where the result should be returned.
- `max`: Specifies the size of the user's buffer.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="nlst" />

### int Nlst ( const char* outputfile, const char* path )

Performs a short form directory listing of the specified path on the remote system. The results are written to the
specified file.

#### Parameters:

- `output`: Specifies the name of a file to receive the directory listing. path Specifies an argument to `ls` on the remote system.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="dir" />

### int Dir ( const char* outputfile, const char* path )

Sends a `LIST -aL` command to the server with the specified path. The response to this is usually a long format directory
listing which will be written to the file named in outputfile. If outputfile is specified as `NULL`, the list will be
written to stdout.

#### Parameters:

- `output`: Specifies the name of a file to receive the directory listing.
- `path`: Specifies an argument to 'ls' on the remote system.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="size" />

### int Size ( const char* path, int* size, transfermode mode )

Size attempts to determine the size of a remote file.

#### Parameters:

- `path`: A pointer to a buffer where the result should be returned.
- `size`: A pointer to an int where the size will be returned.
- `mode`: Specifies the transfer mode as `ftplib::image` or `ftplib::ascii`.

#### Returns:

If a good response is received and the size is successfully parsed out of the result, `1` is returned. Otherwise, `0` is returned.

<a name="moddate" />

### int ModDate ( const char* path, char* dt, int max )

ModDate attempts to determine the last access time of a remote file and return it to the user's buffer. The date and
time are returned as a string in the format 'YYYYMMDDHHMMSS'.

#### Parameters:

- `path`: Name of remote file to be checked.
- `buf`: A pointer to a buffer where the result should be returned.
- `max`: Specifies the size of the user's buffer.

#### Returns:

If a good response is received and the size is successfully parsed out of the result, `1` is returned. Otherwise, `0` is returned.

<a name="get" />

### int Get (const char* outputfile, const char *path, transfermode mode )

Copies the contents of a remote file to a local file.

#### Parameters:

- `output`: Name of a local file to receive the contents of the remote file.
- `path`: Name of remote file to be retrieved.
- `mode`: Specifies the transfer mode as `ftplib::image` or `ftplib::ascii`.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="get2" />

### int Get (const char* outputfile, const char *path, transfermode mode, off64_t offset )

Copies the contents of a remote file from a given offset and appends it to a local file. Not all ftp servers might
implement this feature.

#### Parameters:

- `output`: Name of a local file to receive the contents of the remote file.
- `path`: Name of remote file to be retrieved. mode Specifies the transfer mode as `ftplib::image` or `ftplib::ascii`.
- `offset`: Point from where the copy is suppossed to begin.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="put" />

### int Put ( const char* inputfile, const char *path, transfermode mode )

Transfers a local file to the remote system.

#### Parameters:

- `input`: Specifies the name of a local file to be transfered to the server.
- `path`: Specifies the name to be given to the file on the remote system.
- `mode`: Specifies the transfer mode as `ftplib::image` or `ftplib::ascii`.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="put2" />

### int Put ( const char* inputfile, const char *path, transfermode mode, off64_t offset )

Copies the contents of a local file from a given offset and appends it to a remote file. Not all ftp servers might
implement this feature.

#### Parameters:

- `input`: Specifies the name of a local file to be transfered to the server.
- `path`: Specifies the name to be given to the file on the remote system.
- `mode`: Specifies the transfer mode as `ftplib::image` or `ftplib::ascii`.
- `offset`: Point from where the copy begins.

#### Returns: Returns 1 if successful or 0 on error.

<a name="rename" />

### int Rename ( const char *src, const char *dst )

FtpRename sends a rename request to the remote server.

#### Parameters:

- `src`: A string containing the current name of the remote file.
- `dst`: A string containing the desired new name for the remote file.

#### Returns: Returns 1 if successful or 0 on error.

<a name="delete" />

### int Delete ( const char *path )

Requests that the server remove the specified file from the remote file system.

#### Parameters:

- `path`: The path to the file which is to be removed.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="setdataencryption" />

### int SetDataEncryption ( dataencryption enc )

On an already secured ftp session, SetDataEncryption() specifies if the data connection channel will be secured for the next data transfer.

#### Parameters:

- `enc`: either `ftplib::unencrypted` or `ftplib::secure`.

#### Returns:

Returns `1` if successful and `0` if the control connection isn't secure or on error.

#### Notes:

See [NegotiateEncryption](#negotiateencryption)

<a name="negotiateencryption" />

### int NegotiateEncryption ()

This Method is to be called after Connect and before Login to secure the ftp communication channel.

#### Returns:

Returns `1` if successful and `0` if the ssl negotiation failed.

#### Notes:

The ftplibpp library uses an ssl/tls encryption approach defined in the RFC4217 standard.

<a name="quit" />

### void Quit ()

Quit() issues a 'QUIT' command and closes the connection to the remote server.

<a name="setcallbackxferfunction" />

### void SetCallbackXferFunction ( FtpCallbackXfer pointer )

When SetCallbackBytes is set to a bigger value than `0`, a callback function can be called during an ftp data transfer. If
the callback function returns 0, the data transfer is aborted. The callback function has two parameters: `xfered` & `arg`.
`xfered` is the amount of bytes yet transfered during the data connection and `arg` contains either `NULL` or a custom
pointer set by [SetCallbackArg](#setcallbackarg). If `pointer` is specified as `NULL` the xfer callback is disabled.

#### Parameters:

- `pointer`: A pointer to a static function of the type FtpCallbackXfer.

#### Notes:

Since `FtpCallbackXferFunction` only accepts pointers to static functions, it might appear problematic in an oo c++ context.
However there's an easy way to use it anyway. Using `SetCallbackArg` you supply the class a pointer to the object the method
of which you'd like to call from the ftplib object. That pointer is then passed back with call to the callback function.
From the static callback function you can perform a cast of `arg` to a pointer of the your desired object, and call its
method. valid code could look like this:

```cpp
...
static int callback(off64_t xfered, void* arg); // static callback function defined in myclass.h
void mymethod(); // common myclass method
...
int myclass::callback(off64_t xfered, void* arg) {
  ((*myclass)(arg)->mymethod(); // casting the pointers to the correct type and calling class method
  return 1;
}
...
void myclass::mymethod() {
  DoSomething();
}
...
myftp.SetCallbackArg(this); // supply the myftp object the pointer to the current (myclass) object
myftp.SetCallbackBytes(1024); // issue a xfer callback every kb
myftp.SetCallbackXferFunction(class::callback);
...
```
<a name="setcallbacklogfunction" />

### void SetCallbackLogFunction ( FtpCallbackLog pointer )

`SetCallbackLogFunction` enables the logging callback. Every time there's been data read from the control connection,
`pointer` is called with a c-styled string and a custom pointer specified in [SetCallbackArg](#setcallbackarg). If
`pointer` is specified as `NULL` logging callback is disabled.

#### Parameters:

- `pointer`: A pointer to a static function of the type [FtpCallbackLog](#ftpcallbacklog).

#### Notes:

See SetCallbackIdleFunction.

<a name="setcallbackcertfunction" />

### bool SetCallbackCertFunction ( FtpCallbackCert pointer )

SetCallbackCertFunction enables the ssl/tls certification callback. When you use encryption and you call this method
with a certification callback function, it is called when connecting to the server. In the callback function you decide
via the boolean return value whether the certificate is valid or not. Certification checking is an advanced issue, and
you should read into the openssl documentation if you plan to implement it. `pointer` is called with a custom pointer
specified in [SetCallbackArg](#setcallbackarg) and the certificate from the Server. If pointer is specified as `NULL`
certification callback is disabled.

#### Parameters:

- `pointer`: a pointer to a static function of the type [FtpCallbackCert](#ftpcallbackcert).

#### Notes:

Sample implementation:
```cpp
bool MyCallbackCert(void *arg, X509 *cert) {
  if (cert == NULL) {
    printf("Peer sent no certificate.\n");
    return false;
  } else {
    char peer_CN[265];
    int len;
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, peer_CN, 256);
    printf("subject: %s\n", peer_CN);
    X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_commonName, peer_CN, 256);
    printf("issuer: %s\n", peer_CN); return true;
  }
}
```
### void SetCallbackIdleFunction ( FtpCallbackIdle pointer )

SetCallbackLogFunction enables the idle callback. When a connection idles, for a period bigger than 0 set in
[SetCallbackIdletime](#setcallbackidletime) a callback to the argument function is issued.

#### Parameters:

- `pointer`: A pointer to a static function of the type [FtpCallbackIdle](#ftpcallbackidle).

#### Notes:

See SetCallbackXferFunction.

<a name="setcallbackarg" />

### void SetCallbackArg ( void* arg )

SetCallbackArg submits a pointer of custom type to the object, this pointer is returned with a callback function. A good
idea is to store the ftplib owners (or whatever object should handle the callback) pointer in it to use it the way
described in the [SetCallbackXferFunction](#setcallbackxferfunction) entry.

#### Parameters:

- `arg`: A pointer of a custom type.

<a name="setcallbackbytes" />

### void SetCallbackBytes ( off64_t bytes )

SetCallbackBytes specifies the frequency of xfer callbacks. The xfer callback returns the amount of bytes yet transfered
on this transfer.

#### Parameters:

- `bytes`: Specifies the frequency in transfered bytes. A value of 100000 would mean every 100000 bytes an xfer callback is
issued.

<a name="setcallbackidletime" />

### void SetCallbackIdletime ( int time )

SetCallbackIdletime specifies how long a data socket can idle, without an idle callback beeing issued.

#### Parameters:

- `time`: Time in msec.

#### Notes:

The default value of `0`, means that on every idle a callback happens. if you don't want this behaviour you have to set a
(higher) value.

<a name="setconnmode" />

### void SetConnmode ( ftplib::ftp mode )

SetConnmode specifies which data connection method is to be used for the next data transfer.

#### Parameters:

- `mode`: Either `ftplib::pasv` (passive mode, default) or `ftplib::port` (active mode).

<a name="setcorrectpasv" />

### void SetCorrectPasv ( bool b )

Some Ftp-Servers, which run behind a NAT, return their local ip-adresses as PASV replies. When this option is turned on
PASV replies are corrected using the ip address the ftp session is currently connected to.

#### Parameters:

- `b`: `true` turns the correction on, `false` turns it off.

<a name="fxp" />

### int Fxp ( ftplib* src, ftplib* dst, const char *pathSrc, const char *pathDst, ftplib::ftp mode, ftplib::ftp method )

[static]

Fxp is a static function. It uses two ftp session objects and transfer a certain file between them.

#### Parameters:

- `src`: Source ftplib object.
- `dst`: Destination ftplib object.
- `pathSrc`: Path to file to be copied copy (`/incoming/myfile.tar.gz`).
- `pathDst`: Path to file destination (`/pub/myfile_from_some_ftp.tar.gz`).
- `mode`: Either `ftplib::ascii` (ascii) or `ftplib::image` (binary). Method either `ftplib::defaultfxp` (`PASV` on `dst`, `PORT` on `src`) or `ftplib::alternativefxp` (`PASV` on `src`, `PORT` on `dst`).

#### Returns:

Returns `1` if successful, `-`1 if initilization failed ("PORT" and "PASV"), or `0` if the data transfer somehow failed.

#### Notes:

Fxp - direct Ftp to Ftp transfer - is rather an exploit than a feature and might thus be prevented by many servers.
Currently Fxp does not work with encrypted data connections, so be sure to switch to unencrypted data channels before
performing fxp.

<a name="rawread" />
### int RawRead ( void* buf, int max, ftphandle *handle )

RawRead copies up to max bytes of data from the specified data connection and returns it to the user's buffer. If the data
connection was opened in ascii mode, no more than one line of data will be returned.

#### Parameters:

- `buf`: Specifies the address of a buffer where received data will be written. max Specifies the size of the user's buffer.
- `handle`: A handle returned by FtpAccess().

#### Returns:

Returns the number of bytes written to the user's buffer or `-1` on error or end of file.

<a name="rawwrite" />

#### int RawWrite ( void* buf, int len, ftphandle *handle )

RawWrite sends data to a remote file. If the file were accessed in record mode, the necessary conversions are performed.

#### Parameters:

- `buf`: A buffer containing the data to be sent to the remote file.
- `len`: The number of bytes to be sent from 'buf'.
- `handle`: A handle returned by [RawOpen()](#rawopen).

#### Returns:

Returns the number of bytes sent from the user's buffer or `-1` on error.

<a name="rawopen" />

### ftphandle* RawOpen ( const char *path, accesstype type, transfermode mode )

RawOpen() opens a remote file or directory and returns a handle for the calling program to use to transfer data.

#### Parameters:

- `path`: Specifies the name of the remote file or directory to open.
- `type`: Specifies the type of transfer to be performed. `ftplib::dir` performs a terse directory. `ftplib::dirverbose`
performs a verbose directory. `ftplib::fileread` opens a remote file for reading. `ftplib::filewrite` creates a remote
file and readies it for writing. `ftplib::filewriteappend` and `ftplib::filereadappend` are for appending file operations.
- `mode`: Specifies the transfer mode as `ftplib::ascii` or `ftplib::image`.

#### Returns:

Returns `1` if successful or `0` on error.

<a name="rawclose" />

### int RawClose ( ftphandle* handle )

Closes the data connection specified by handle and frees associated resources.

#### Parameters:

- `handle`: A handle returned by [RawOpen()](#rawopen).

#### Returns:

Returns `1` if successful or `0` on error.
