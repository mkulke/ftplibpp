#include "ftplib.h"

int main(void)
{
	ftplib *ftp = new ftplib();
	ftp->Connect("ftp.gwdg.de:21");
	ftp->Login("anonymous", "");
	ftp->Dir(NULL, "/pub/linux/apache");
	ftp->Quit();
	return 0;
}
