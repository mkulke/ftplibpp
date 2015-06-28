/***************************************************************************
                          ftplib.h  -  description
                             -------------------
    begin                : Son Jul 27 2003
    copyright            : (C) 2013 by magnus kulke
    email                : mkulke@gmail.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Lesser General Public License as        *
 *   published by the Free Software Foundation; either version 2.1 of the  *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 ***************************************************************************/

/***************************************************************************
 * Note: ftplib, on which ftplibpp was originally based upon used to be    *
 * licensed as GPL 2.0 software, as of Jan. 26th 2013 its author Thomas    *
 * Pfau allowed the distribution of ftplib via LGPL. Thus the license of   *
 * ftplibpp changed aswell.                                                *
 ***************************************************************************/

#ifndef FTPLIB_H
#define FTPLIB_H

#if defined(_WIN32)

#if BUILDING_DLL
# define DLLIMPORT __declspec (dllexport)
#else /* Not BUILDING_DLL */
# define DLLIMPORT __declspec (dllimport)
#endif /* Not BUILDING_DLL */

#include <time.h>    // struct timeval
#endif

#ifndef _WIN32
#include <unistd.h>
#include <sys/param.h>  // PATH_MAX
#include <sys/time.h>
#endif


#include <limits.h>     // _POSIX_XXX_MAX values
#include <sys/types.h>  // off64_t/off_t
#include <sys/param.h>  // PATH_MAX

#ifndef PATH_MAX
#error "PATH_MAX undefined!"
#endif

#if defined(__APPLE__)
#undef NOLFS
#define NOSSL
typedef off_t off64_t;
#define fseeko64 fseeko
#define fopen64 fopen
#endif

#ifdef NOLFS
typedef long off64_t;
#endif

#ifndef NOSSL
#include <openssl/ssl.h>
#endif


/**
  *@author mkulke
  */

typedef int (*FtpCallbackXfer)(off64_t xfered, void *arg);
typedef int (*FtpCallbackIdle)(void *arg);
typedef void (*FtpCallbackLog)(char *str, void* arg, bool out);

#ifndef NOSSL
typedef bool (*FtpCallbackCert)(void *arg, X509 *cert);
#endif

struct ftphandle
{
	/* FTP io types */
	enum direction
	{
		FTPLIB_CONTROL = 0,
		FTPLIB_READ = 1,
		FTPLIB_WRITE = 2
	};

	char *cput, *cget;
	int handle;
	size_t cavail, cleft;
	char *buf;
	direction dir;
	ftphandle *ctrl;
	int cmode;
	struct timeval idletime;
	FtpCallbackXfer xfercb;
	FtpCallbackIdle idlecb;
	FtpCallbackLog logcb;
	void *cbarg;
	off64_t xfered;
	off64_t cbbytes;
	off64_t xfered1;
	char response[PATH_MAX];

#ifndef NOSSL
	SSL* ssl;
	SSL_CTX* ctx;
	BIO* sbio;
	int tlsctrl;
	int tlsdata;
	FtpCallbackCert certcb;
#endif

	off64_t offset;
	bool correctpasv;
};

#if defined(_WIN32)
class DLLIMPORT ftplib
{
#else
class ftplib
{
#endif
public:

	enum accesstype
	{
		mlsd = 0,
		dir = 1,
		dirverbose,
		fileread,
		filewrite,
		filereadappend,
		filewriteappend
	};

	enum transfermode
	{
		ascii = 'A',
		image = 'I'
	};

	enum connmode
	{
		pasv = 1,
		port
	};

	enum fxpmethod
	{
		defaultfxp = 0,
		alternativefxp
	};

	enum dataencryption
	{
		unencrypted = 0,
		secure
	};

	ftplib();
	~ftplib();
	char* LastResponse();
	int Connect(const char *host);
	int Login(const char *user, const char *pass);
	int Site(const char *cmd);
	int Raw(const char *cmd);
	int SysType(char *buf, int max);
	int Mkdir(const char *path);
	int Chdir(const char *path);
	int Cdup();
	int Rmdir(const char *path);
	int Pwd(char *path, int max);
	int Mlsd(const char *outputfile, const char *path);
	int Nlst(const char *outputfile, const char *path);
	int Dir(const char *outputfile, const char *path);
	int Size(const char *path, off64_t *size, transfermode mode = image);
	int ModDate(const char *path, char *dt, size_t max);
	int Get(const char *outputfile, const char *path, transfermode mode, off64_t offset = 0);
	int Put(const char *inputfile, const char *path, transfermode mode, off64_t offset = 0);
	int Rename(const char *src, const char *dst);
	int Delete(const char *path);

#ifndef NOSSL
	int SetDataEncryption(dataencryption enc);
	int NegotiateEncryption();
	void SetCallbackCertFunction(FtpCallbackCert pointer);
#endif

	int Quit();
	void SetCallbackIdleFunction(FtpCallbackIdle pointer);
	void SetCallbackLogFunction(FtpCallbackLog pointer);
	void SetCallbackXferFunction(FtpCallbackXfer pointer);
	void SetCallbackArg(void *arg);
	void SetCallbackBytes(off64_t bytes);
	void SetCorrectPasv(bool b)
	{
		mp_ftphandle->correctpasv = b;
	};
	void SetCallbackIdletime(int time);
	void SetConnmode(connmode mode);

#ifdef SUPPORT_FXP_FTP
	static int Fxp(ftplib* src, ftplib* dst, const char *pathSrc, const char *pathDst, transfermode mode, fxpmethod method);
#endif

private:

#ifdef SUPPORT_ROW_FTP
	ftphandle* RawOpen(const char *path, accesstype type, transfermode mode);
	int RawClose(ftphandle* handle);
	ssize_t RawWrite(void* buf, size_t len, ftphandle* handle);
	ssize_t RawRead(void* buf, size_t max, ftphandle* handle);
#endif

	ftphandle* mp_ftphandle;

	int FtpXfer(const char *localfile, const char *path, ftphandle *nControl, accesstype type, transfermode mode);
	int FtpOpenPasv(ftphandle *nControl, ftphandle **nData, transfermode mode, ftphandle::direction dir, char *cmd);
	int FtpSendCmd(const char *cmd, char expresp, ftphandle *nControl);
	int FtpAcceptConnection(ftphandle *nData, ftphandle *nControl);
	int FtpOpenPort(ftphandle *nControl, ftphandle **nData, transfermode mode, ftphandle::direction dir, char *cmd);
	ssize_t FtpRead(void *buf, size_t max, ftphandle *nData);
	ssize_t FtpWrite(void *buf, size_t len, ftphandle *nData);
	int FtpAccess(const char *path, accesstype type, transfermode mode, ftphandle *nControl, ftphandle **nData);
	int FtpClose(ftphandle *nData);

	int socket_wait(ftphandle *ctl);
	int readline(char *buf, size_t max, ftphandle *ctl);
	int writeline(char *buf, size_t len, ftphandle *nData);
	int readresp(char c, ftphandle *nControl);

	void ClearHandle();
	int CorrectPasvResponse(unsigned char *v);
};

#endif
