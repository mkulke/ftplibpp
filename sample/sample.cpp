#include "ftplib.h"

#include <stdlib.h>
#include <stdio.h>

#include <string>
#include <time.h>
#include <assert.h>


// get size of a local file
off_t Size(const std::string filename)
{
	off_t offset(0);
	FILE * in(fopen(filename.c_str(), "rb"));
	if (in)
	{
		if (fseek(in, 0, SEEK_END) == 0)
		{
			offset = ftello(in);
		}
		fclose(in);
		fprintf(stderr, "localfile: -%s- size: %lld Bytes.\n", filename.c_str(), offset);
	}
	else
	{
		perror(filename.c_str());
	}
	return offset;
}


class myclass
{
	off_t transferCount;

public:
	myclass() : transferCount(0) {};

	static int callbackIdle(void * arg);
	static void callbackLog(char *str, void* arg, bool out);
	static int callback(off64_t xfered, void* arg); // static callback function
	int mymethod(off64_t xfered);                   // common class method
};


int myclass::mymethod(off64_t xfered)
{
	fprintf(stderr, "callback(%lld)\n", xfered);
	transferCount = xfered;
	if (transferCount < (32 * 1024))
	{
		return true;    // continue
	}
	else
	{
		return false;    // break transfer
	}
}


int myclass::callback(off64_t xfered, void* arg)
{
	// casting the pointers to the correct type and calling class method
	return static_cast<myclass*>(arg)->mymethod(xfered);
}


void myclass::callbackLog(char *str, void* , bool in)
{
	if (in)
	{
		fprintf(stderr, "ftplib IN:%s", str);
	}
	else
	{
		fprintf(stderr, "ftplib OUT:%s", str);
	}
}


int myclass::callbackIdle(void * arg)
{
	fprintf(stderr, "callbackIdle()\n");
	if (static_cast<myclass*>(arg)->transferCount < (32 * 1024))
	{
		return true;    // continue transfer
	}
	else
	{
		return false;   // break transfer
	}
}


int main(int argc, char** argv)
{
	char buf[80] = {0};
	off64_t offset = 0;
	int ok = 1;

	ftplib *myftp = new ftplib::ftplib();

	if (argc > 1)
	{
		if (argc > 3)
		{
			myftp->SetConnmode(ftplib::port);   // test active ftp
		}

		ok = myftp->Connect(argv[1], ((argc > 2) ? argv[2] : "2121"));
	}
	else
	{
		myftp->SetConnmode(ftplib::pasv);       // test pasive ftp
		//                             ftp://ftp.gwdg.de/pub/incoming/
		ok = myftp->Connect("ftp.gwdg.de");     //TODO /pub/incoming/
	}

	if (ok)
	{
		ok = myftp->Login("ftp", "OK");
		//FIXME ok = myftp->Login("anonymous", "");
	}

	if (ok)
	{
		const std::string filename("sample");   // filename for upload and download test

		myftp->Cdup();
		if (myftp->Pwd(buf, sizeof(buf)))
		{
			puts(buf);
		}
		if (myftp->SysType(buf, sizeof(buf)))
		{
			puts(buf);
		}

		if (!myftp->Chdir("/pub/incoming/tmp"))
		{
			if (!myftp->Mkdir("/pub/incoming/tmp"))
			{
				perror("ftplib::Mkdir()");
			}
		}
		else
		{
			myftp->Put("README.md", "/pub/incoming/tmp/README.txt", ftplib::ascii);
			ok = myftp->Rmdir("/pub/incoming/tmp");
			assert(!ok);
		}

		ok = myftp->Dir("ftp-dir.txt", "/pub/incoming/");
		assert(ok);
		ok &= myftp->Nlst("ftp-list.txt", "/pub/incoming/");
		assert(ok);
		(void) myftp->Mlsd("ftp-mlsd.txt", "/pub/incoming/");

		// check the mod time of the remote file
		if (myftp->ModDate("/pub/incoming/sample", buf, sizeof(buf)))
		{
			struct tm dt;
			memset(&dt, 0, sizeof(struct tm));

			if (strptime(buf, "%Y%m%d%H%M%S", &dt) == NULL)
			{
				perror("strptime()");
				perror(buf);
			}
			else
			{
				//TODO: if older than local file, remove remote files first
				time_t seconds = mktime(&dt);
				if ((time(NULL) - seconds) > 60)
				{
					myftp->Delete("/pub/incoming/sample");
					myftp->Delete("/pub/incoming/sample.upload");
				}
			}
		}

		myclass helper;
		myftp->SetCallbackArg(&helper);     // supply the myftp object the pointer to the current (myclass) object
		myftp->SetCallbackBytes(8 * 1024);  // issue a xfer callback every 8 kb
		myftp->SetCallbackXferFunction(myclass::callback);
		myftp->SetCallbackIdletime(1000);   // ms; issue a callback after 1 sec idle time
		myftp->SetCallbackIdleFunction(myclass::callbackIdle);
		myftp->SetCallbackLogFunction(myclass::callbackLog);

		// =========================
		// upload
		// get remote file size first
		myftp->Size("/pub/incoming/sample.upload", &offset);
		if (!myftp->Put("sample", "/pub/incoming/sample.upload", ftplib::image, offset))
		{
			perror("ftplib::Put()");
			//TBD exit(EXIT_FAILURE);
		}
		else if (myftp->Chdir("/pub/incoming/"))
		{
			myftp->Rename("sample.upload", filename.c_str());
		}

		// =========================
		// download
		// get local file size first
		offset = Size("sample.download");
		if (!myftp->Get("sample.download", filename.c_str(), ftplib::image, offset))
		{
			perror("ftplib::Get()");
			//TBD exit(EXIT_FAILURE);
		}
		else if (rename("sample.download", "sample.bin"))
		{
			perror("rename()");
		}

		myftp->Cdup();
		myftp->Quit();
	}

	delete myftp;

	if (ok)
	{
		exit(EXIT_SUCCESS);
	}
	exit(EXIT_FAILURE);
}
