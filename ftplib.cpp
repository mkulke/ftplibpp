
// enable > 2gb support (LFS)
#ifndef NOLFS
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#include "ftplib.h"

#if defined(_WIN32)
#include <windows.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>

#if defined(_WIN32)
#define SETSOCKOPT_OPTVAL_TYPE(x) static_cast<const char *>(x)
#else
#define SETSOCKOPT_OPTVAL_TYPE(x) (x) //TODO not needed! ck static_cast<void *>(x)
#endif

#if defined(_WIN32)
#define net_read(x,y,z) recv(x,static_cast<(char*>(y),z,0)
#define net_write(x,y,z) send(x,static_cast<char*>(y),z,0)
#define net_close closesocket
#else
#define net_read read
#define net_write write
#define net_close close
#endif

#if defined(_WIN32)
typedef int socklen_t;
#endif

#if defined(_WIN32)
#define memccpy _memccpy
#define strdup _strdup
#endif

/* socket values */
#define FTPLIB_BUFSIZ   (16 * 1024)
#define ACCEPT_TIMEOUT  30

/* win32 dll initializer */

#if defined(_WIN32)
BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}

	/* Returns TRUE on success, FALSE on failure */
	return TRUE;
}
#endif

/*
 * Constructor
 */
ftplib::ftplib() : mp_ftphandle(NULL)
{

#if defined(_WIN32)
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(1, 1), &wsa))
	{
		fprintf(stderr, "WSAStartup() failed, %lu\n", (unsigned long)GetLastError());
	}
#endif

#ifndef NOSSL
	SSL_library_init();
#endif

	mp_ftphandle = static_cast<ftphandle *>(calloc(1, sizeof(ftphandle)));
	if (mp_ftphandle == NULL)
	{
		perror("calloc()");
		exit(1);    //FIXME: can`t continue! ck
	}
	mp_ftphandle->buf = static_cast<char *>(malloc(FTPLIB_BUFSIZ));
	if (mp_ftphandle->buf == NULL)
	{
		perror("malloc()");
		free(mp_ftphandle);
		exit(1);    //FIXME: can`t continue! ck
	}

#ifndef NOSSL
	mp_ftphandle->ctx = SSL_CTX_new(SSLv3_method());
	SSL_CTX_set_verify(mp_ftphandle->ctx, SSL_VERIFY_NONE, NULL);
	mp_ftphandle->ssl = SSL_new(mp_ftphandle->ctx);
#endif

	ClearHandle();
}

/*
 * Destructor
 */
ftplib::~ftplib()
{

#ifndef NOSSL
	SSL_free(mp_ftphandle->ssl);
	SSL_CTX_free(mp_ftphandle->ctx);
#endif

	free(mp_ftphandle->buf);
	free(mp_ftphandle);
}

/*
 * socket_wait - wait for socket to receive or flush data
 *
 * return 1 if no user callback, otherwise, return value returned by
 * user callback
 */
int ftplib::socket_wait(ftphandle *ctl)
{
	fd_set fd, *rfd = NULL, *wfd = NULL;
	struct timeval tv;
	int rv = 0;     // default error

	if (ctl->idlecb == NULL)
	{
		return 1;   // ok
	}

	/*if ((ctl->dir == ftphandle::FTPLIB_CONTROL)
		|| (ctl->idlecb == NULL)
		|| ((ctl->idletime.tv_sec == 0)
		&& //(ctl->idletime.tv_usec 0))
	return 1;*/

	if (ctl->dir == ftphandle::FTPLIB_WRITE)
	{
		wfd = &fd;
	}
	else
	{
		rfd = &fd;
	}

	FD_ZERO(&fd);
	do
	{
		FD_SET(ctl->handle, &fd);
		tv = ctl->idletime;
		rv = select(ctl->handle + 1, rfd, wfd, NULL, &tv);
		if (rv == -1)
		{
			rv = 0; // error
			strncpy(ctl->ctrl->response, strerror(errno), sizeof(ctl->ctrl->response));
			break;
		}
		else if (rv > 0)
		{
			rv = 1; // ok
			break;
		} //XXX else timeout
	}
	while ((rv = ctl->idlecb(ctl->cbarg)));

	return rv;
}

/*
 * read a line of text
 *
 * return -1 on error or bytecount
 */
int ftplib::readline(char *buf, size_t max, ftphandle *ctl)
{
	size_t x;
	int retval = 0;
	char *end, *bp = buf;
	int eof = 0;

	if ((ctl->dir != ftphandle::FTPLIB_CONTROL) && (ctl->dir != ftphandle::FTPLIB_READ))
	{
		return -1;
	}
	if (max == 0)
	{
		return 0;
	}
	do
	{
		if (ctl->cavail > 0)
		{
			x = (max >= ctl->cavail) ? ctl->cavail : max - 1;
			end = static_cast<char*>(memccpy(bp, ctl->cget, '\n', x));
			if (end != NULL)
			{
				x = static_cast<size_t>(end - bp);
			}
			retval += static_cast<int>(x);
			bp += x;
			*bp = '\0';
			max -= x;
			ctl->cget += x;
			ctl->cavail -= x;
			if (end != NULL)
			{
				bp -= 2;
				if (strcmp(bp, "\r\n") == 0)    //XXX ascii mode
				{
					*bp++ = '\n';
					*bp++ = '\0';
					--retval;
				}
				break;
			}
		}
		if (max == 1)
		{
			*buf = '\0';
			break;
		}
		if (ctl->cput == ctl->cget)
		{
			ctl->cput = ctl->cget = ctl->buf;
			ctl->cavail = 0;
			ctl->cleft = FTPLIB_BUFSIZ;
		}
		if (eof)
		{
			if (retval == 0)
			{
				retval = -1;
			}
			break;
		}

		if (!socket_wait(ctl))
		{
			return -1;  // error
		}

		ssize_t len;

#ifndef NOSSL
		if (ctl->tlsdata)
		{
			len = SSL_read(ctl->ssl, ctl->cput, ctl->cleft);
		}
		else
		{
			if (ctl->tlsctrl)
			{
				len = SSL_read(ctl->ssl, ctl->cput, ctl->cleft);
			}
			else
			{
				len = net_read(ctl->handle, ctl->cput, ctl->cleft);
			}
		}
#else
		len = net_read(ctl->handle, ctl->cput, ctl->cleft);
#endif

		if (len == -1)
		{
			perror("read()");
			retval = -1;
			break;
		}

		// LOGGING FUNCTIONALITY!!!

		if ((ctl->dir == ftphandle::FTPLIB_CONTROL) && (mp_ftphandle->logcb != NULL))
		{
			*((ctl->cput) + len) = '\0';
			mp_ftphandle->logcb(ctl->cput, mp_ftphandle->cbarg, true);
		}

		if (len == 0)
		{
			eof = 1;
		}
		ctl->cleft -= static_cast<size_t>(len);
		ctl->cavail += static_cast<size_t>(len);
		ctl->cput += len;
	}
	while (1);
	return retval;
}

/*
 * write lines of text
 *
 * return -1 on error or bytecount
 */
int ftplib::writeline(char *buf, size_t len, ftphandle *nData)
{
	size_t nb = 0;
	size_t x;
	ssize_t w;
	char *ubp = buf, *nbp;
	char lc = 0;

	if (nData->dir != ftphandle::FTPLIB_WRITE)
	{
		return -1;
	}
	nbp = nData->buf;   //XXX ascii buffer
	for (x = 0; x < len; x++)
	{
		if ((*ubp == '\n') && (lc != '\r'))
		{
			if (nb == FTPLIB_BUFSIZ)
			{
				if (!socket_wait(nData))
				{
					return -1;  // error
				}

#ifndef NOSSL
				if (nData->tlsctrl)
				{
					w = SSL_write(nData->ssl, nbp, FTPLIB_BUFSIZ);
				}
				else
				{
					w = net_write(nData->handle, nbp, FTPLIB_BUFSIZ);
				}
#else
				w = net_write(nData->handle, nbp, FTPLIB_BUFSIZ);
#endif

				if (w != FTPLIB_BUFSIZ)
				{
					fprintf(stderr, "write(1) returned %ld, errno = %d\n", w, errno);
					return (-1);
				}
				nb = 0;
			}
			nbp[nb++] = '\r';
		}
		if (nb == FTPLIB_BUFSIZ)
		{
			if (!socket_wait(nData))
			{
				return -1;  // error
			}

#ifndef NOSSL
			if (nData->tlsctrl)
			{
				w = SSL_write(nData->ssl, nbp, FTPLIB_BUFSIZ);
			}
			else
			{
				w = net_write(nData->handle, nbp, FTPLIB_BUFSIZ);
			}
#else
			w = net_write(nData->handle, nbp, FTPLIB_BUFSIZ);
#endif

			if (w != FTPLIB_BUFSIZ)
			{
				fprintf(stderr, "write(2) returned %ld, errno = %d\n", w, errno);
				return (-1);
			}
			nb = 0;
		}
		nbp[nb++] = lc = *ubp++;
	}
	if (nb)
	{
		if (!socket_wait(nData))
		{
			return -1;  // error
		}

#ifndef NOSSL
		if (nData->tlsctrl)
		{
			w = SSL_write(nData->ssl, nbp, nb);
		}
		else
		{
			w = net_write(nData->handle, nbp, nb);
		}
#else
		w = net_write(nData->handle, nbp, nb);
#endif

		if (w != static_cast<ssize_t>(nb))
		{
			fprintf(stderr, "write(3) returned %ld, errno = %d\n", w, errno);
			return (-1);
		}
	}
	return static_cast<int>(len);
}

/*
 * read a response from the server
 *
 * return 0 if first char doesn't match
 * return 1 if first char matches
 */
int ftplib::readresp(char c, ftphandle *nControl)
{
	char match[5];

	if (readline(nControl->response, PATH_MAX, nControl) == -1)
	{
		perror("Control socket read failed");
		return 0;
	}

	if (nControl->response[3] == '-')
	{
		strncpy(match, nControl->response, 3);
		match[3] = ' ';
		match[4] = '\0';
		do
		{
			if (readline(nControl->response, PATH_MAX, nControl) == -1)
			{
				perror("Control socket read failed");
				return 0;
			}
		}
		while (strncmp(nControl->response, match, 4));
	}
	if (nControl->response[0] == c)
	{
		return 1;
	}
	return 0;
}

/*
 * LastResponse - return a pointer to the last response received
 */
char* ftplib::LastResponse()
{
	if ((mp_ftphandle) && (mp_ftphandle->dir == ftphandle::FTPLIB_CONTROL))
	{
		return mp_ftphandle->response;
	}
	return NULL;
}

/*
 * ftplib::Connect - connect to remote server
 *
 * return 1 if connected, 0 if not
 */
int ftplib::Connect(const char *host)
{
	int sControl;
	union
	{
		struct sockaddr sa;
		struct sockaddr_in in;
	} sin;
	struct hostent *phe;
	struct servent *pse;
	int on = 1;
	int ret;
	char *lhost;
	char *pnum;

	mp_ftphandle->dir = ftphandle::FTPLIB_CONTROL;
	mp_ftphandle->ctrl = NULL;
	mp_ftphandle->xfered = 0;
	mp_ftphandle->xfered1 = 0;

#ifndef NOSSL
	mp_ftphandle->tlsctrl = 0;
	mp_ftphandle->tlsdata = 0;
#endif

	mp_ftphandle->offset = 0;
	mp_ftphandle->handle = 0;

	memset(&sin, 0, sizeof(sin));
	sin.in.sin_family = AF_INET;
	lhost = strdup(host);
	pnum = strchr(lhost, ':');
	if (pnum == NULL)
	{
		if ((pse = getservbyname("ftp", "tcp")) == NULL)
		{
			perror("getservbyname()");
			free(lhost);
			return 0;
		}
		sin.in.sin_port = static_cast<uint16_t>(pse->s_port);
	}
	else
	{
		*pnum++ = '\0';
		if (isdigit(*pnum))
		{
			sin.in.sin_port = htons(atoi(pnum));
		}
		else
		{
			if ((pse = getservbyname(pnum, "tcp")) == NULL);
			{
				perror("getservbyname()");
				free(lhost);
				return 0;
			}
			sin.in.sin_port = static_cast<uint16_t>(pse->s_port);
		}
	}

#if defined(_WIN32)
	if ((sin.in.sin_addr.s_addr = inet_addr(lhost)) == -1)
#else
	ret = inet_aton(lhost, &sin.in.sin_addr);
	if (ret == 0)
#endif

	{
		if ((phe = gethostbyname(lhost)) == NULL)
		{
			perror("gethostbyname()");
			free(lhost);
			return 0;
		}
		memcpy(&sin.in.sin_addr, phe->h_addr, static_cast<size_t>(phe->h_length));
	}

	free(lhost);

	sControl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sControl == -1)
	{
		perror("socket()");
		return 0;
	}

	if (setsockopt(sControl, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPT_OPTVAL_TYPE(& on), sizeof(on)) == -1)
	{
		perror("setsockopt()");
		net_close(sControl);
		return 0;
	}
	if (connect(sControl, &sin.sa, sizeof(sin.sa)) == -1)
	{
		perror("connect()");
		net_close(sControl);
		return 0;
	}

	mp_ftphandle->handle = sControl;

	if (readresp('2', mp_ftphandle) == 0)
	{
		net_close(sControl);
		mp_ftphandle->handle = 0;
		return 0;
	}

	return 1;
}

/*
 * SendCmd - send a command and wait for expected response
 *
 * return 1 if proper response received, 0 otherwise
 */
int ftplib::FtpSendCmd(const char *cmd, char expresp, ftphandle *nControl)
{
	char buf[PATH_MAX];
	ssize_t x;

	if (!nControl->handle)
	{
		return 0;
	}

	if (nControl->dir != ftphandle::FTPLIB_CONTROL)
	{
		return 0;
	}
	sprintf(buf, "%s\r\n", cmd);

#ifndef NOSSL
	if (nControl->tlsctrl)
	{
		x = SSL_write(nControl->ssl, buf, strlen(buf));
	}
	else
	{
		x = net_write(nControl->handle, buf, strlen(buf));
	}
#else
	x = net_write(nControl->handle, buf, strlen(buf));
#endif

	if (x <= 0)
	{
		perror("write()");
		return 0;
	}

	if (mp_ftphandle->logcb != NULL)
	{
		mp_ftphandle->logcb(buf, mp_ftphandle->cbarg, false);
	}

	return readresp(expresp, nControl);
}

/*
 * Login - log in to remote server
 *
 * return 1 if logged in, 0 otherwise
 */
int ftplib::Login(const char *user, const char *pass)
{
	char tempbuf[64];

	if (((strlen(user) + 7) > sizeof(tempbuf)) || ((strlen(pass) + 7) > sizeof(tempbuf)))
	{
		return 0;
	}
	sprintf(tempbuf, "USER %s", user);
	if (!FtpSendCmd(tempbuf, '3', mp_ftphandle))
	{
		if (mp_ftphandle->ctrl != NULL)
		{
			return 1;
		}
		if (*LastResponse() == '2')
		{
			return 1;
		}
		return 0;
	}
	sprintf(tempbuf, "PASS %s", pass);
	return FtpSendCmd(tempbuf, '2', mp_ftphandle);
}

/*
 * AcceptConnection - accept connection from server
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::FtpAcceptConnection(ftphandle *nData, ftphandle *nControl)
{
	int sData;
	struct sockaddr addr;
	socklen_t l;
	int i;
	struct timeval tv;
	fd_set mask;
	int rv = 0; // error

	FD_ZERO(&mask);
	FD_SET(nControl->handle, &mask);
	FD_SET(nData->handle, &mask);
	tv.tv_usec = 0;
	tv.tv_sec = ACCEPT_TIMEOUT;
	i = nControl->handle;
	if (i < nData->handle)
	{
		i = nData->handle;
	}
	i = select(i + 1, &mask, NULL, NULL, &tv);

	if (i == -1)
	{
		strncpy(nControl->response, strerror(errno), sizeof(nControl->response));
		net_close(nData->handle);
		nData->handle = 0;
		rv = 0;
	}
	else if (i == 0)
	{
		strcpy(nControl->response, "timed out waiting for connection");
		net_close(nData->handle);
		nData->handle = 0;
		rv = 0;
	}
	else
	{
		if (FD_ISSET(nData->handle, &mask))
		{
			l = sizeof(addr);
			sData = accept(nData->handle, &addr, &l);
			i = errno;  // save errno before close
			net_close(nData->handle);
			if (sData >= 0)      //FIXME accept return -1 on error!
			{
				rv = 1; // OK
				nData->handle = sData;
				nData->ctrl = nControl;
			}
			else
			{
				strncpy(nControl->response, strerror(i), sizeof(nControl->response));
				nData->handle = 0;
				rv = 0;
			}
		}
		else if (FD_ISSET(nControl->handle, &mask))
		{
			net_close(nData->handle);
			nData->handle = 0;
			readresp('2', nControl);
			rv = 0;
		}
	}
	return rv;
}

/*
 * Access - return a handle for a data stream
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::FtpAccess(const char *path, accesstype type, transfermode mode, ftphandle *nControl, ftphandle **nData)
{
	char buf[PATH_MAX];
	ftphandle::direction dir;

#ifndef NOSSL
	int ret;
#endif

	if ((path == NULL) && ((type == ftplib::filewrite)
	                       || (type == ftplib::fileread)
	                       || (type == ftplib::filereadappend)
	                       || (type == ftplib::filewriteappend)))
	{
		sprintf(nControl->response, "Missing path argument for file transfer\n");
		return 0;
	}
	sprintf(buf, "TYPE %c", mode);
	if (!FtpSendCmd(buf, '2', nControl))
	{
		return 0;
	}

	switch (type)
	{
	case ftplib::mlsd:
		strcpy(buf, "MLSD");
		dir = ftphandle::FTPLIB_READ;
		break;
	case ftplib::dir:
		strcpy(buf, "NLST");
		dir = ftphandle::FTPLIB_READ;
		break;
	case ftplib::dirverbose:
		strcpy(buf, "LIST");
		dir = ftphandle::FTPLIB_READ;
		break;
	case ftplib::filereadappend:
	case ftplib::fileread:
		strcpy(buf, "RETR");
		dir = ftphandle::FTPLIB_READ;
		break;
	case ftplib::filewriteappend:
	case ftplib::filewrite:
		strcpy(buf, "STOR");
		dir = ftphandle::FTPLIB_WRITE;
		break;
	default:
		sprintf(nControl->response, "Invalid open type %d\n", type);
		return 0;
	}
	if (path != NULL)
	{
		size_t i = strlen(buf);
		buf[i++] = ' ';
		if ((strlen(path) + i) >= sizeof(buf))
		{
			return 0;
		}
		strcpy(&buf[i], path);
	}

	if (nControl->cmode == ftplib::pasv)
	{
		if (FtpOpenPasv(nControl, nData, mode, dir, buf) == -1)
		{
			return 0;
		}
	}

	if (nControl->cmode == ftplib::port)
	{
		if (FtpOpenPort(nControl, nData, mode, dir, buf) == -1)
		{
			return 0;
		}
		if (!FtpAcceptConnection(*nData, nControl))
		{
			FtpClose(*nData);
			*nData = NULL;
			return 0;
		}
	}

#ifndef NOSSL
	if (nControl->tlsdata)
	{
		(*nData)->ssl = SSL_new(nControl->ctx);
		(*nData)->sbio = BIO_new_socket((*nData)->handle, BIO_NOCLOSE);
		SSL_set_bio((*nData)->ssl, (*nData)->sbio, (*nData)->sbio);
		ret = SSL_connect((*nData)->ssl);
		if (ret != 1)
		{
			return 0;
		}
		(*nData)->tlsdata = 1;
	}
#endif

	return 1;
}

/*
 * FtpOpenPort - Establishes a PORT connection for data transfer
 *
 * return 1 if successful, -1 otherwise
 */
int ftplib::FtpOpenPort(ftphandle *nControl, ftphandle **nData, transfermode mode, ftphandle::direction dir, char *cmd)
{
	int sData;
	union
	{
		struct sockaddr sa;
		struct sockaddr_in in;
	} sin;
	struct linger lng = { 0, 0 };
	socklen_t l;
	int on = 1;
	ftphandle *ctrl;
	char buf[PATH_MAX];

	if (nControl->dir != ftphandle::FTPLIB_CONTROL)
	{
		return -1;
	}
	if ((dir != ftphandle::FTPLIB_READ) && (dir != ftphandle::FTPLIB_WRITE))
	{
		sprintf(nControl->response, "Invalid direction %d\n", dir);
		return -1;
	}
	if ((mode != ftplib::ascii) && (mode != ftplib::image))
	{
		sprintf(nControl->response, "Invalid mode %c\n", mode);
		return -1;
	}
	l = sizeof(sin);

	if (getsockname(nControl->handle, &sin.sa, &l) < 0)
	{
		perror("getsockname()");
		return -1;
	}

	sData = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sData == -1)
	{
		perror("socket()");
		return -1;
	}
	if (setsockopt(sData, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPT_OPTVAL_TYPE(& on), sizeof(on)) == -1)
	{
		perror("setsockopt()");
		net_close(sData);
		return -1;
	}
	if (setsockopt(sData, SOL_SOCKET, SO_LINGER, SETSOCKOPT_OPTVAL_TYPE(& lng), sizeof(lng)) == -1)
	{
		perror("setsockopt()");
		net_close(sData);
		return -1;
	}

	sin.in.sin_port = 0;
	if (bind(sData, &sin.sa, sizeof(sin)) == -1)
	{
		perror("bind()");
		net_close(sData);
		return -1;
	}
	if (listen(sData, 1) < 0)
	{
		perror("listen()");
		net_close(sData);
		return -1;
	}
	if (getsockname(sData, &sin.sa, &l) < 0)
	{
		net_close(sData);
		return 0;
	}
	sprintf(buf, "PORT %hhu,%hhu,%hhu,%hhu,%hhu,%hhu",
	        static_cast<unsigned char>(sin.sa.sa_data[2]),
	        static_cast<unsigned char>(sin.sa.sa_data[3]),
	        static_cast<unsigned char>(sin.sa.sa_data[4]),
	        static_cast<unsigned char>(sin.sa.sa_data[5]),
	        static_cast<unsigned char>(sin.sa.sa_data[0]),
	        static_cast<unsigned char>(sin.sa.sa_data[1]));
	if (!FtpSendCmd(buf, '2', nControl))
	{
		net_close(sData);
		return -1;
	}

	if (mp_ftphandle->offset != 0)
	{
		char buf[PATH_MAX];
		sprintf(buf, "REST %lld", mp_ftphandle->offset);
		if (!FtpSendCmd(buf, '3', nControl))
		{
			net_close(sData);
			return 0;
		}
	}

	ctrl = static_cast<ftphandle*>(calloc(1, sizeof(ftphandle)));
	if (ctrl == NULL)
	{
		perror("calloc()");
		net_close(sData);
		return -1;
	}
	if ((mode == 'A') && ((ctrl->buf = static_cast<char*>(malloc(FTPLIB_BUFSIZ))) == NULL))
	{
		perror("malloc()");
		net_close(sData);
		free(ctrl);
		return -1;
	}

	if (!FtpSendCmd(cmd, '1', nControl))
	{
		if (*nData)
		{
			FtpClose(*nData);
			*nData = NULL;
		}
		free(ctrl);
		return -1;
	}

	//TODO use ctrl helper class with constructor
	ctrl->handle = sData;
	ctrl->dir = dir;
	ctrl->ctrl = (nControl->cmode == ftplib::pasv) ? nControl : NULL;
	ctrl->idletime = nControl->idletime;
	ctrl->cbarg = nControl->cbarg;
	ctrl->xfered = 0;
	ctrl->xfered1 = 0;
	ctrl->cbbytes = nControl->cbbytes;
	if (ctrl->idletime.tv_sec || ctrl->idletime.tv_usec)
	{
		ctrl->idlecb = nControl->idlecb;
	}
	else
	{
		ctrl->idlecb = NULL;
	}
	if (ctrl->cbbytes)
	{
		ctrl->xfercb = nControl->xfercb;
	}
	else
	{
		ctrl->xfercb = NULL;
	}
	*nData = ctrl;

	return 1;
}

/*
 * FtpOpenPasv - Establishes a PASV connection for data transfer
 *
 * return 1 if successful, -1 otherwise
 */
int ftplib::FtpOpenPasv(ftphandle *nControl, ftphandle **nData, transfermode mode, ftphandle::direction dir, char *cmd)
{
	int sData;
	union
	{
		struct sockaddr sa;
		struct sockaddr_in in;
	} sin;
	struct linger lng = { 0, 0 };
	socklen_t l;
	int on = 1;
	ftphandle *ctrl;
	char *cp;
	unsigned char v[6];
	ssize_t ret;

	if (nControl->dir != ftphandle::FTPLIB_CONTROL)
	{
		return -1;
	}
	if ((dir != ftphandle::FTPLIB_READ) && (dir != ftphandle::FTPLIB_WRITE))
	{
		sprintf(nControl->response, "Invalid direction %d\n", dir);
		return -1;
	}
	if ((mode != ftplib::ascii) && (mode != ftplib::image))
	{
		sprintf(nControl->response, "Invalid mode %c\n", mode);
		return -1;
	}
	l = sizeof(sin);

	memset(&sin, 0, l);
	sin.in.sin_family = AF_INET;
	if (!FtpSendCmd("PASV", '2', nControl))
	{
		return -1;
	}
	cp = strchr(nControl->response, '(');
	if (cp == NULL)
	{
		return -1;
	}
	cp++;

#if defined(_WIN32)
	unsigned int v_i[6];
	sscanf(cp, "%u,%u,%u,%u,%u,%u", &v_i[2], &v_i[3], &v_i[4], &v_i[5], &v_i[0], &v_i[1]);
	for (int i = 0; i < 6; i++)
	{
		v[i] = static_cast<unsigned char>(v_i[i]);
	}
#else
	sscanf(cp, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
#endif

	if (nControl->correctpasv) if (!CorrectPasvResponse(v))
		{
			return -1;
		}
	sin.sa.sa_data[2] = static_cast<char>(v[2]);
	sin.sa.sa_data[3] = static_cast<char>(v[3]);
	sin.sa.sa_data[4] = static_cast<char>(v[4]);
	sin.sa.sa_data[5] = static_cast<char>(v[5]);
	sin.sa.sa_data[0] = static_cast<char>(v[0]);
	sin.sa.sa_data[1] = static_cast<char>(v[1]);

	if (mp_ftphandle->offset != 0)
	{
		char buf[PATH_MAX];
		sprintf(buf, "REST %lld", mp_ftphandle->offset);
		if (!FtpSendCmd(buf, '3', nControl))
		{
			return -1;
		}
	}

	sData = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sData == -1)
	{
		perror("socket()");
		return -1;
	}
	if (setsockopt(sData, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPT_OPTVAL_TYPE(& on), sizeof(on)) == -1)
	{
		perror("setsockopt()");
		net_close(sData);
		return -1;
	}
	if (setsockopt(sData, SOL_SOCKET, SO_LINGER, SETSOCKOPT_OPTVAL_TYPE(& lng), sizeof(lng)) == -1)
	{
		perror("setsockopt()");
		net_close(sData);
		return -1;
	}

	if (nControl->dir != ftphandle::FTPLIB_CONTROL)
	{
		net_close(sData);
		return -1;
	}
	sprintf(cmd, "%s\r\n", cmd);

#ifndef NOSSL
	if (nControl->tlsctrl)
	{
		ret = SSL_write(nControl->ssl, cmd, strlen(cmd));
	}
	else
	{
		ret = net_write(nControl->handle, cmd, strlen(cmd));
	}
#else
	ret = net_write(nControl->handle, cmd, strlen(cmd));
#endif

	if (ret <= 0)
	{
		perror("write()");
		net_close(sData);
		return -1;
	}

	if (connect(sData, &sin.sa, sizeof(sin.sa)) == -1)
	{
		perror("connect()");
		net_close(sData);
		return -1;
	}
	if (!readresp('1', nControl))
	{
		net_close(sData);
		return -1;
	}
	ctrl = static_cast<ftphandle*>(calloc(1, sizeof(ftphandle)));
	if (ctrl == NULL)
	{
		perror("calloc()");
		net_close(sData);
		return -1;
	}
	if ((mode == 'A') && ((ctrl->buf = static_cast<char*>(malloc(FTPLIB_BUFSIZ))) == NULL))
	{
		perror("malloc()");
		net_close(sData);
		free(ctrl);
		return -1;
	}

	//TODO use ctrl helper class with constructor
	ctrl->handle = sData;
	ctrl->dir = dir;
	ctrl->ctrl = (nControl->cmode == ftplib::pasv) ? nControl : NULL;
	ctrl->idletime = nControl->idletime;
	ctrl->cbarg = nControl->cbarg;
	ctrl->xfered = 0;
	ctrl->xfered1 = 0;
	ctrl->cbbytes = nControl->cbbytes;
	if (ctrl->idletime.tv_sec || ctrl->idletime.tv_usec)
	{
		ctrl->idlecb = nControl->idlecb;
	}
	else
	{
		ctrl->idlecb = NULL;
	}
	if (ctrl->cbbytes)
	{
		ctrl->xfercb = nControl->xfercb;
	}
	else
	{
		ctrl->xfercb = NULL;
	}
	*nData = ctrl;

	return 1;
}

/*
 * FtpClose - close a data connection
 */
int ftplib::FtpClose(ftphandle *nData)
{
	ftphandle *ctrl;

	if (nData->dir == ftphandle::FTPLIB_WRITE)
	{
		if (nData->buf != NULL)
		{
			writeline(NULL, 0, nData);  //XXX ascii mode
		}
	}
	else if (nData->dir != ftphandle::FTPLIB_READ)
	{
		return 0;   // error
	}
	if (nData->buf)
	{
		free(nData->buf);
	}
	shutdown(nData->handle, SHUT_RDWR); // SHUT_RDWR = 2
	net_close(nData->handle);

	ctrl = nData->ctrl;

#ifndef NOSSL
	SSL_free(nData->ssl);
#endif

	free(nData);
	if (ctrl)
	{
		return readresp('2', ctrl);
	}
	return 1;   // ok
}

/*
 * FtpRead - read from a data connection
 */
ssize_t ftplib::FtpRead(void *buf, size_t max, ftphandle *nData)
{
	ssize_t i = 0;

	if (nData->dir != ftphandle::FTPLIB_READ)
	{
		return 0;
	}
	if (nData->buf)
	{
		i = readline(static_cast<char*>(buf), max, nData);  //XXX ascii mode
	}
	else
	{
		if (!socket_wait(nData))
		{
			return -1;  // error
		}

#ifndef NOSSL
		if (nData->tlsdata)
		{
			i = SSL_read(nData->ssl, buf, max);
		}
		else
		{
			i = net_read(nData->handle, buf, max);
		}
#else
		i = net_read(nData->handle, buf, max);
#endif

	}
	if (i == -1)
	{
		return -1;  // error
	}

	nData->xfered += i;
	if (nData->xfercb && nData->cbbytes)
	{
		nData->xfered1 += i;
		if (nData->xfered1 > nData->cbbytes)
		{
			if (nData->xfercb(nData->xfered, nData->cbarg) == 0)
			{
				return -1;  // error
			}
			nData->xfered1 = 0;
		}
	}
	return i;
}

/*
 * FtpWrite - write to a data connection
 */
ssize_t ftplib::FtpWrite(void *buf, size_t len, ftphandle *nData)
{
	ssize_t i = 0;

	if (nData->dir != ftphandle::FTPLIB_WRITE)
	{
		return 0;
	}
	if (nData->buf)
	{
		i = writeline(static_cast<char*>(buf), len, nData);  //XXX ascii mode
	}
	else
	{
		if (!socket_wait(nData))
		{
			return -1;  // error
		}

#ifndef NOSSL
		if (nData->tlsdata)
		{
			i = SSL_write(nData->ssl, buf, len);
		}
		else
		{
			i = net_write(nData->handle, buf, len);
		}
#else
		i = net_write(nData->handle, buf, len);
#endif

	}
	if (i == -1)
	{
		return -1;  // error
	}

	nData->xfered += i;
	if (nData->xfercb && nData->cbbytes)
	{
		nData->xfered1 += i;
		if (nData->xfered1 > nData->cbbytes)
		{
			if (nData->xfercb(nData->xfered, nData->cbarg) == 0)
			{
				return -1;  // error
			}
			nData->xfered1 = 0;
		}
	}
	return i;
}

/*
 * Site - send a SITE command
 *
 * return 1 if command successful, 0 otherwise
 */
int ftplib::Site(const char *cmd)
{
	char buf[PATH_MAX];

	if ((strlen(cmd) + 7) > sizeof(buf))
	{
		return 0;
	}
	sprintf(buf, "SITE %s", cmd);
	if (!FtpSendCmd(buf, '2', mp_ftphandle))
	{
		return 0;
	}
	return 1;
}

/*
 * Raw - send a raw string string
 *
 * return 1 if command successful, 0 otherwise
 */
int ftplib::Raw(const char *cmd)
{
	char buf[PATH_MAX];
	strncpy(buf, cmd, PATH_MAX);
	if (!FtpSendCmd(buf, '2', mp_ftphandle))
	{
		return 0;
	}
	return 1;
}

/*
 * SysType - send a SYST command
 *
 * Fills in the user buffer with the remote system type.  If more
 * information from the response is required, the user can parse
 * it out of the response buffer returned by LastResponse().
 *
 * return 1 if command successful, 0 otherwise
 */
int ftplib::SysType(char *buf, int max)
{
	int l = max;
	char *b = buf;
	char *s;
	if (!FtpSendCmd("SYST", '2', mp_ftphandle))
	{
		return 0;
	}
	s = &mp_ftphandle->response[4];
	while ((--l) && (*s != ' '))
	{
		*b++ = *s++;
	}
	*b++ = '\0';
	return 1;
}

/*
 * Mkdir - create a directory at server
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Mkdir(const char *path)
{
	char buf[PATH_MAX];

	if ((strlen(path) + 6) > sizeof(buf))
	{
		return 0;
	}
	sprintf(buf, "MKD %s", path);
	if (!FtpSendCmd(buf, '2', mp_ftphandle))
	{
		return 0;
	}
	return 1;
}

/*
 * Chdir - change path at remote
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Chdir(const char *path)
{
	char buf[PATH_MAX];

	if ((strlen(path) + 6) > sizeof(buf))
	{
		return 0;
	}
	sprintf(buf, "CWD %s", path);
	if (!FtpSendCmd(buf, '2', mp_ftphandle))
	{
		return 0;
	}
	return 1;
}

/*
 * Cdup - move to parent directory at remote
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Cdup()
{
	if (!FtpSendCmd("CDUP", '2', mp_ftphandle))
	{
		return 0;
	}
	return 1;
}

/*
 * Rmdir - remove directory at remote
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Rmdir(const char *path)
{
	char buf[PATH_MAX];

	if ((strlen(path) + 6) > sizeof(buf))
	{
		return 0;
	}
	sprintf(buf, "RMD %s", path);
	if (!FtpSendCmd(buf, '2', mp_ftphandle))
	{
		return 0;
	}
	return 1;
}

/*
 * Pwd - get working directory at remote
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Pwd(char *path, int max)
{
	int l = max;
	char *b = path;
	char *s;

	if (!FtpSendCmd("PWD", '2', mp_ftphandle))
	{
		return 0;
	}
	s = strchr(mp_ftphandle->response, '"');
	if (s == NULL)
	{
		return 0;
	}
	s++;
	while ((--l) && (*s) && (*s != '"'))
	{
		*b++ = *s++;
	}
	*b++ = '\0';
	return 1;
}

/*
 * FtpXfer - issue a command and transfer data
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::FtpXfer(const char *localfile, const char *path, ftphandle *nControl, accesstype type, transfermode mode)
{
	char *dbuf;
	FILE *local = NULL;
	ftphandle *nData = NULL;
	int rv = 1; // 3.1-1: default ok

	if (localfile != NULL)
	{
		fprintf(stderr, "localfile: -%s-\n", localfile);

		char ac[3] = "  ";
		if ((type == ftplib::dir) || (type == ftplib::dirverbose) || (type == ftplib::mlsd))
		{
			ac[0] = 'w';
			ac[1] = '\0';
		}
		if (type == ftplib::fileread)
		{
			ac[0] = 'w';
			ac[1] = '\0';
		}
		if (type == ftplib::filewriteappend)
		{
			ac[0] = 'r';
			ac[1] = '\0';
		}
		if (type == ftplib::filereadappend)
		{
			ac[0] = 'a';
			ac[1] = '\0';
		}
		if (type == ftplib::filewrite)
		{
			ac[0] = 'r';
			ac[1] = '\0';
		}
		if (mode == ftplib::image)
		{
			ac[1] = 'b';
		}

#ifndef NOLFS
		local = fopen64(localfile, ac);
		if (type == ftplib::filewriteappend)
		{
			fseeko64(local, mp_ftphandle->offset, SEEK_SET);
		}
#else
		local = fopen(localfile, ac);
		if (type == ftplib::filewriteappend)
		{
			fseeko(local, mp_ftphandle->offset, SEEK_SET);
		}
#endif

		if (local == NULL)
		{
			strncpy(nControl->response, strerror(errno), sizeof(nControl->response));
			return 0;
		}
	}
	if (local == NULL) local = ((type == ftplib::filewrite)
		                            || (type == ftplib::filewriteappend)) ? stdin : stdout;
	if (!FtpAccess(path, type, mode, nControl, &nData))
	{
		return 0;   // error
	}

	dbuf = static_cast<char*>(malloc(FTPLIB_BUFSIZ));
	if (dbuf)
	{
		if ((type == ftplib::filewrite) || (type == ftplib::filewriteappend))
		{
			size_t len;
			ssize_t cnt;
			while ((len = fread(dbuf, 1, FTPLIB_BUFSIZ, local)) > 0)
			{
				if ((cnt = FtpWrite(dbuf, len, nData)) < static_cast<int>(len))
				{
					fprintf(stderr, "short write: passed %ld, wrote %ld\n", len, cnt);
					rv = 0; // error
					break;
				}
			}
		}
		else
		{
			ssize_t len;
			while ((len = FtpRead(dbuf, FTPLIB_BUFSIZ, nData)) > 0)
			{
				if (fwrite(dbuf, 1, static_cast<size_t>(len), local) <= 0)
				{
					perror("localfile write");
					rv = 0; // error
					break;
				}
#ifdef __CYGWIN__
				fflush(local);  //TODO: needed for test only under cygwin? ck
#endif
			}
			if (len < 0)
			{
				perror("FtpRead()");
				rv = 0; // TODO ftp read error
			}
		}
		free(dbuf);
	}
	else
	{
		perror("malloc()");
		rv = 0; // error
	}
	fflush(local);
	if (localfile != NULL)
	{
		fclose(local);
	}
	rv &= FtpClose(nData);
	return rv;
}

/*
 * Mlsd - issue an MLSD command and write response to output
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Mlsd(const char *outputfile, const char *path)
{
	mp_ftphandle->offset = 0;
	return FtpXfer(outputfile, path, mp_ftphandle, ftplib::mlsd, ftplib::ascii);
}

/*
 * Nlst - issue an NLST command and write response to output
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Nlst(const char *outputfile, const char *path)
{
	mp_ftphandle->offset = 0;
	return FtpXfer(outputfile, path, mp_ftphandle, ftplib::dir, ftplib::ascii);
}

/*
 * Dir - issue a LIST command and write response to output
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Dir(const char *outputfile, const char *path)
{
	mp_ftphandle->offset = 0;
	return FtpXfer(outputfile, path, mp_ftphandle, ftplib::dirverbose, ftplib::ascii);
}

/*
 * Size - determine the size of a remote file
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Size(const char *path, off64_t *size, transfermode mode)
{
	char cmd[PATH_MAX];
	off64_t sz = 0;
	int resp, rv = 1;

	if (!path || (strlen(path) + 7) > sizeof(cmd))
	{
		return 0;
	}

	sprintf(cmd, "TYPE %c", mode);
	if (!FtpSendCmd(cmd, '2', mp_ftphandle))
	{
		return 0;
	}

	sprintf(cmd, "SIZE %s", path);
	if (!FtpSendCmd(cmd, '2', mp_ftphandle))
	{
		rv = 0;
	}
	else
	{
		if (sscanf(mp_ftphandle->response, "%d %lld", &resp, &sz) == 2)
		{
			if (size)
			{
				*size = sz;
			}
		}
		else
		{
			rv = 0;
		}
	}
	return rv;
}

/*
 * ModDate - determine the modification date of a remote file
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::ModDate(const char *path, char *dt, size_t max)
{
	char buf[PATH_MAX];
	int rv = 1;

	if (!path || (strlen(path) + 7) > sizeof(buf))
	{
		return 0;
	}
	sprintf(buf, "MDTM %s", path);
	if (!FtpSendCmd(buf, '2', mp_ftphandle))
	{
		rv = 0;
	}
	else
	{
		if (dt)
		{
			strncpy(dt, &mp_ftphandle->response[4], max);
		}
	}
	return rv;
}

/*
 * Get - issue a GET command and write received data to output
 *
 * return 1 if successful, 0 otherwise
 */

int ftplib::Get(const char *outputfile, const char *path, transfermode mode, off64_t offset)
{
	mp_ftphandle->offset = offset;
	if (offset == 0)
	{
		return FtpXfer(outputfile, path, mp_ftphandle, ftplib::fileread, mode);
	}
	else
	{
		return FtpXfer(outputfile, path, mp_ftphandle, ftplib::filereadappend, mode);
	}
}

/*
 * Put - issue a PUT command and send data from input
 *
 * return 1 if successful, 0 otherwise
 */

int ftplib::Put(const char *inputfile, const char *path, transfermode mode, off64_t offset)
{
	mp_ftphandle->offset = offset;
	if (offset == 0)
	{
		return FtpXfer(inputfile, path, mp_ftphandle, ftplib::filewrite, mode);
	}
	else
	{
		return FtpXfer(inputfile, path, mp_ftphandle, ftplib::filewriteappend, mode);
	}
}


int ftplib::Rename(const char *src, const char *dst)
{
	char cmd[PATH_MAX];

	if (((strlen(src) + 7) > sizeof(cmd)) || ((strlen(dst) + 7) > sizeof(cmd)))
	{
		return 0;
	}
	sprintf(cmd, "RNFR %s", src);
	if (!FtpSendCmd(cmd, '3', mp_ftphandle))
	{
		return 0;
	}
	sprintf(cmd, "RNTO %s", dst);
	if (!FtpSendCmd(cmd, '2', mp_ftphandle))
	{
		return 0;
	}

	return 1;
}

int ftplib::Delete(const char *path)
{
	char cmd[PATH_MAX];

	if ((strlen(path) + 7) > sizeof(cmd))
	{
		return 0;
	}
	sprintf(cmd, "DELE %s", path);
	if (!FtpSendCmd(cmd, '2', mp_ftphandle))
	{
		return 0;
	}
	return 1;
}

/*
 * Quit - disconnect from remote
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Quit()
{
	if (mp_ftphandle->dir != ftphandle::FTPLIB_CONTROL)
	{
		return 0;
	}
	if (mp_ftphandle->handle == 0)
	{
		strcpy(mp_ftphandle->response, "error: no anwser from server\n");
		return 0;
	}
	if (!FtpSendCmd("QUIT", '2', mp_ftphandle))
	{
		net_close(mp_ftphandle->handle);
		return 0;
	}
	else
	{
		net_close(mp_ftphandle->handle);
		return 1;
	}
}

#ifdef SUPPORT_FXP_FTP
/*
 * Fxp is a static function. Tt uses two ftp session objects and transfer a certain file between them.
 *
 * Returns 1 if successful,
 *        –1 if initilization failed (“PORT” and “PASV”),
 *      or 0 if the data transfer somehow failed.
 */
int ftplib::Fxp(ftplib* src, ftplib* dst, const char *pathSrc, const char *pathDst, transfermode mode, fxpmethod method)
{
	char *cp;
	unsigned char v[6];
	char buf[PATH_MAX];
	int retval = 0;

	sprintf(buf, "TYPE %c", mode);
	if (!dst->FtpSendCmd(buf, '2', dst->mp_ftphandle))
	{
		return -1;
	}
	if (!src->FtpSendCmd(buf, '2', src->mp_ftphandle))
	{
		return -1;
	}

	if (method == ftplib::defaultfxp)
	{
		// PASV dst

		if (!dst->FtpSendCmd("PASV", '2', dst->mp_ftphandle))
		{
			return -1;
		}
		cp = strchr(dst->mp_ftphandle->response, '(');
		if (cp == NULL)
		{
			return -1;
		}
		cp++;

#if defined(_WIN32)
		unsigned int v_i[6];
		sscanf(cp, "%u,%u,%u,%u,%u,%u", &v_i[2], &v_i[3], &v_i[4], &v_i[5], &v_i[0], &v_i[1]);
		for (int i = 0; i < 6; i++)
		{
			v[i] = (unsigned char) v_i[i];
		}
#else
		sscanf(cp, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
#endif

		if (dst->mp_ftphandle->correctpasv) if (!dst->CorrectPasvResponse(v))
			{
				return -1;
			}

		// PORT src

		sprintf(buf, "PORT %d,%d,%d,%d,%d,%d", v[2], v[3], v[4], v[5], v[0], v[1]);
		if (!src->FtpSendCmd(buf, '2', src->mp_ftphandle))
		{
			return -1;
		}

		// RETR src

		strcpy(buf, "RETR");
		if (pathSrc != NULL)
		{
			size_t i = strlen(buf);
			buf[i++] = ' ';
			if ((strlen(pathSrc) + i) >= sizeof(buf))
			{
				return 0;
			}
			strcpy(&buf[i], pathSrc);
		}
		if (!src->FtpSendCmd(buf, '1', src->mp_ftphandle))
		{
			return 0;
		}

		// STOR dst

		strcpy(buf, "STOR");
		if (pathDst != NULL)
		{
			size_t i = strlen(buf);
			buf[i++] = ' ';
			if ((strlen(pathDst) + i) >= sizeof(buf))
			{
				return 0;
			}
			strcpy(&buf[i], pathDst);
		}
		if (!dst->FtpSendCmd(buf, '1', dst->mp_ftphandle))
		{
			/* this closes the data connection, to abort the RETR on
			the source ftp. all hail pftp, it took me several
			hours and i was absolutely clueless, playing around with
			ABOR and whatever, when i desperately checked the pftp
			source which gave me this final hint. thanks dude(s). */

			dst->FtpSendCmd("PASV", '2', dst->mp_ftphandle);
			src->readresp('4', src->mp_ftphandle);
			return 0;
		}

		retval = (src->readresp('2', src->mp_ftphandle)) & (dst->readresp('2', dst->mp_ftphandle));

	}
	else
	{
		// PASV src

		if (!src->FtpSendCmd("PASV", '2', src->mp_ftphandle))
		{
			return -1;
		}
		cp = strchr(src->mp_ftphandle->response, '(');
		if (cp == NULL)
		{
			return -1;
		}
		cp++;

#if defined(_WIN32)
		unsigned int v_i[6];
		sscanf(cp, "%u,%u,%u,%u,%u,%u", &v_i[2], &v_i[3], &v_i[4], &v_i[5], &v_i[0], &v_i[1]);
		for (int i = 0; i < 6; i++)
		{
			v[i] = (unsigned char) v_i[i];
		}
#else
		sscanf(cp, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
#endif

		if (src->mp_ftphandle->correctpasv) if (!src->CorrectPasvResponse(v))
			{
				return -1;
			}

		// PORT dst

		sprintf(buf, "PORT %d,%d,%d,%d,%d,%d", v[2], v[3], v[4], v[5], v[0], v[1]);
		if (!dst->FtpSendCmd(buf, '2', dst->mp_ftphandle))
		{
			return -1;
		}

		// STOR dest

		strcpy(buf, "STOR");
		if (pathDst != NULL)
		{
			size_t i = strlen(buf);
			buf[i++] = ' ';
			if ((strlen(pathDst) + i) >= sizeof(buf))
			{
				return 0;
			}
			strcpy(&buf[i], pathDst);
		}
		if (!dst->FtpSendCmd(buf, '1', dst->mp_ftphandle))
		{
			return 0;
		}

		// RETR src

		strcpy(buf, "RETR");
		if (pathSrc != NULL)
		{
			size_t i = strlen(buf);
			buf[i++] = ' ';
			if ((strlen(pathSrc) + i) >= sizeof(buf))
			{
				return 0;
			}
			strcpy(&buf[i], pathSrc);
		}
		if (!src->FtpSendCmd(buf, '1', src->mp_ftphandle))
		{
			src->FtpSendCmd("PASV", '2', src->mp_ftphandle);
			dst->readresp('4', dst->mp_ftphandle);
			return 0;
		}

		// wait til its finished!

		retval = (src->readresp('2', src->mp_ftphandle)) & (dst->readresp('2', dst->mp_ftphandle));

	}

	return retval;
}
#endif


#ifndef NOSSL
int ftplib::SetDataEncryption(dataencryption enc)
{
	if (!mp_ftphandle->tlsctrl)
	{
		return 0;
	}
	if (!FtpSendCmd("PBSZ 0", '2', mp_ftphandle))
	{
		return 0;
	}
	switch (enc)
	{
	case ftplib::unencrypted:
		mp_ftphandle->tlsdata = 0;
		if (!FtpSendCmd("PROT C", '2', mp_ftphandle))
		{
			return 0;
		}
		break;
	case ftplib::secure:
		mp_ftphandle->tlsdata = 1;
		if (!FtpSendCmd("PROT P", '2', mp_ftphandle))
		{
			return 0;
		}
		break;
	default:
		return 0;
	}
	return 1;
}

int ftplib::NegotiateEncryption()
{
	int ret;

	if (!FtpSendCmd("AUTH TLS", '2', mp_ftphandle))
	{
		return 0;
	}

	mp_ftphandle->sbio = BIO_new_socket(mp_ftphandle->handle, BIO_NOCLOSE);
	SSL_set_bio(mp_ftphandle->ssl, mp_ftphandle->sbio, mp_ftphandle->sbio);

	ret = SSL_connect(mp_ftphandle->ssl);
	if (ret == 1)
	{
		mp_ftphandle->tlsctrl = 1;
	}

	if (mp_ftphandle->certcb != NULL)
	{
		X509 *cert = SSL_get_peer_certificate(mp_ftphandle->ssl);
		if (!mp_ftphandle->certcb(mp_ftphandle->cbarg, cert))
		{
			return 0;
		}
	}

	if (ret < 1)
	{
		return 0;
	}

	return 1;
}

void ftplib::SetCallbackCertFunction(FtpCallbackCert pointer)
{
	mp_ftphandle->certcb = pointer;
}
#endif


void ftplib::SetCallbackIdleFunction(FtpCallbackIdle pointer)
{
	mp_ftphandle->idlecb = pointer;
}

void ftplib::SetCallbackXferFunction(FtpCallbackXfer pointer)
{
	mp_ftphandle->xfercb = pointer;
}

void ftplib::SetCallbackLogFunction(FtpCallbackLog pointer)
{
	mp_ftphandle->logcb = pointer;
}

void ftplib::SetCallbackArg(void *arg)
{
	mp_ftphandle->cbarg = arg;
}

void ftplib::SetCallbackBytes(off64_t bytes)
{
	mp_ftphandle->cbbytes = bytes;
}

void ftplib::SetCallbackIdletime(int time)
{
	mp_ftphandle->idletime.tv_sec = time / 1000;
	mp_ftphandle->idletime.tv_usec = (time % 1000) * 1000;
}

void ftplib::SetConnmode(connmode mode)
{
	mp_ftphandle->cmode = mode;
}

void ftplib::ClearHandle()
{
	mp_ftphandle->dir = ftphandle::FTPLIB_CONTROL;
	mp_ftphandle->ctrl = NULL;
	mp_ftphandle->cmode = ftplib::pasv;
	mp_ftphandle->idlecb = NULL;
	mp_ftphandle->idletime.tv_sec = mp_ftphandle->idletime.tv_usec = 0;
	mp_ftphandle->cbarg = NULL;
	mp_ftphandle->xfered = 0;
	mp_ftphandle->xfered1 = 0;
	mp_ftphandle->cbbytes = 0;

#ifndef NOSSL
	mp_ftphandle->tlsctrl = 0;
	mp_ftphandle->tlsdata = 0;
	mp_ftphandle->certcb = NULL;
#endif

	mp_ftphandle->offset = 0;
	mp_ftphandle->handle = 0;
	mp_ftphandle->logcb = NULL;
	mp_ftphandle->xfercb = NULL;
	mp_ftphandle->correctpasv = false;
}

int ftplib::CorrectPasvResponse(unsigned char *v)
{
	struct sockaddr ipholder;
	socklen_t ipholder_size = sizeof(ipholder);

	if (getpeername(mp_ftphandle->handle, &ipholder, &ipholder_size) == -1)
	{
		perror("getpeername()");
		net_close(mp_ftphandle->handle);
		return 0;
	}

	for (int i = 2; i < 6; i++)
	{
		v[i] = static_cast<unsigned char>(ipholder.sa_data[i]);
	}

	return 1;
}


#ifdef SUPPORT_ROW_FTP
ftphandle* ftplib::RawOpen(const char *path, accesstype type, transfermode mode)
{
	int ret;
	ftphandle* datahandle;
	ret = FtpAccess(path, type, mode, mp_ftphandle, &datahandle);
	if (ret)
	{
		return datahandle;
	}
	else
	{
		return NULL;
	}
}

int ftplib::RawClose(ftphandle* handle)
{
	return FtpClose(handle);
}

ssize_t ftplib::RawWrite(void* buf, size_t len, ftphandle* handle)
{
	return FtpWrite(buf, len, handle);
}

ssize_t ftplib::RawRead(void* buf, size_t max, ftphandle* handle)
{
	return FtpRead(buf, max, handle);
}
#endif
