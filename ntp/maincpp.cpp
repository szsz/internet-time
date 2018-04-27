
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
//#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <algorithm> 
#include <process.h>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>

#define ReverseEndianInt(x) ((x) = \
    ((x)&0xff000000) >> 24 |\
    ((x)&0x00ff0000) >> 8 |\
    ((x)&0x0000ff00) << 8 |\
    ((x)&0x000000ff) << 24)



/**
* NTP Fixed-Point Timestamp Format.
* From [RFC 5905](http://tools.ietf.org/html/rfc5905).
*/
struct Timestamp
{
	unsigned int seconds; /**< Seconds since Jan 1, 1900. */
	unsigned int fraction; /**< Fractional part of seconds. Integer number of 2^-32 seconds. */

						   /**
						   * Reverses the Endianness of the timestamp.
						   * Network byte order is big endian, so it needs to be switched before
						   * sending or reading.
						   */
	void ReverseEndian() {
		ReverseEndianInt(seconds);
		ReverseEndianInt(fraction);
	}

	Timestamp()
	{
		seconds = 0;
		fraction = 0;
	}

	/**
	* Convert to time_t.
	* Returns the integer part of the timestamp in unix time_t format,
	* which is seconds since Jan 1, 1970.
	*/
	time_t to_time_t()
	{
		time_t res = seconds;
		res -= ((70 * 365 + 17) * 86400);
		return res & 0x7fffffff;
	}
};

/**
* A Network Time Protocol Message.
* From [RFC 5905](http://tools.ietf.org/html/rfc5905).
*/
struct NTPMessage
{
	unsigned char  mode : 3; /**< Mode of the message sender. 3 = Client, 4 = Server */
	unsigned char  version : 2; /**< Protocol version. Should be set to 3. */
	unsigned char  leap : 2; /**< Leap seconds warning. See the [RFC](http://tools.ietf.org/html/rfc5905#section-7.3) */
	unsigned char stratum; /**< Servers between client and physical timekeeper. 1 = Server is Connected to Physical Source. 0 = Unknown. */
	unsigned char poll; /**< Max Poll Rate. In log2 seconds. */
	unsigned char precision; /**< Precision of the clock. In log2 seconds. */
	unsigned int sync_distance; /**< Round-trip to reference clock. NTP Short Format. */
	unsigned int drift_rate; /**< Dispersion to reference clock. NTP Short Format. */
	unsigned char ref_clock_id[4]; /**< Reference ID. For Stratum 1 devices, a 4-byte string. For other devices, 4-byte IP address. */
	Timestamp ref; /**< Reference Timestamp. The time when the system clock was last updated. */
	Timestamp orig; /**< Origin Timestamp. Send time of the request. Copied from the request. */
	Timestamp rx; /**< Recieve Timestamp. Reciept time of the request. */
	Timestamp tx; /**< Transmit Timestamp. Send time of the response. If only a single time is needed, use this one. */


				  /**
				  * Reverses the Endianness of all the timestamps.
				  * Network byte order is big endian, so they need to be switched before
				  * sending and after reading.
				  *
				  * Maintaining them in little endian makes them easier to work with
				  * locally, though.
				  */
	void ReverseEndian() {
		ref.ReverseEndian();
		orig.ReverseEndian();
		rx.ReverseEndian();
		tx.ReverseEndian();
	}

	/**
	* Recieve an NTPMessage.
	* Overwrites this object with values from the recieved packet.
	*/
	int recv(int sock)
	{
		int ret = ::recv(sock, (char*)this, sizeof(*this), 0);
		ReverseEndian();
		return ret;
	}

	/**
	* Send an NTPMessage.
	*/
	int sendto(int sock, struct sockaddr_in* srv_addr)
	{
		ReverseEndian();
		int ret = ::sendto(sock, (const char*)this, sizeof(*this), 0, (sockaddr*)srv_addr, sizeof(*srv_addr));
		ReverseEndian();
		return ret;
	}

	/**
	* Zero all the values.
	*/
	void clear()
	{
		memset(this, 0, sizeof(*this));
	}
};

int dns_lookup(const char *host, sockaddr_in *out)
{
	struct addrinfo *result;
	int ret = getaddrinfo(host, "ntp", NULL, &result);
	for (struct addrinfo *p = result; p; p = p->ai_next)
	{
		if (p->ai_family != AF_INET)
			continue;

		memcpy(out, p->ai_addr, sizeof(*out));
	}
	freeaddrinfo(result);
	return ret;
}

volatile time_t GinternetTime;
volatile bool GgotInternet = false;
volatile int GBadTries = 0;


void gettime(void *arg)
{
	WSADATA wsaData;
	DWORD ret = WSAStartup(MAKEWORD(2, 0), &wsaData);

	const	char *host = "time.nist.gov"; /* Don't distribute stuff pointing here, it's not polite. */
									  //char *host = "time.nist.gov"; /* This one's probably ok, but can get grumpy about request rates during debugging. */

	NTPMessage msg;
	/* Important, if you don't set the version/mode, the server will ignore you. */
	msg.clear();
	msg.version = 4;
	msg.mode = 3 /* client */;

	NTPMessage response;
	response.clear();

	int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	sockaddr_in srv_addr;
	memset(&srv_addr, 0, sizeof(srv_addr));
	dns_lookup(host, &srv_addr); /* Helper function defined below. */

	int sentbytes = msg.sendto(sock, &srv_addr);
	//response.recv(sock);

	time_t localTime; // resulst

	if (sentbytes == 48)
	{

		char buf[500];

		int len = recv(sock, buf, sizeof(buf), 0);

		if (len < 44)
		{
			printf("error");
		}
		else
		{
			Timestamp time;
			for (int i = 40; i < 44; i++)
			{
				time.seconds *= 256;
				time.seconds += (unsigned int)(unsigned char)buf[i];
			}
			localTime = time.to_time_t();
			tm local_tm;
			localtime_s(&local_tm, &localTime);
			char s[50];
			ctime_s(s, sizeof(s), &localTime);
			printf("The time is %s. %d, %d, %d", s, local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday);
		}

		/*for (int i = 0; i < min(len, 52); i++)
		{
		if (i % 4 == 0)
		std::cout << std::endl << std::endl << i << '\t' << i/4 << std::endl;
		std::cout << (unsigned int)(unsigned char)buf[i] << '\t';
		}*/
	}
	else
	{
		printf("error could not send");
	}
	closesocket(sock);
	WSACleanup();
	GinternetTime = localTime;
	GgotInternet = true;
}


tm * ptm;

void GetTime()
{

	time_t rawtime;

	if (GgotInternet)
	{
		rawtime = GinternetTime;
	}
	else
	{
		if (GBadTries > 10)
		{
			time(&rawtime);
		}
		else
		{
			HANDLE h = (HANDLE)_beginthread(gettime, 0, NULL);
			if (WaitForSingleObject(h, 4000) == WAIT_TIMEOUT)
			{
				TerminateThread(h, 0);
				time(&rawtime);
				GBadTries++;
			}
			else
			{
				rawtime = GinternetTime;
			}
		}
	}

	ptm = gmtime(&rawtime);
}



using namespace std;


int x(void) {

	WSADATA wsaData;
	SOCKET Socket;
	SOCKADDR_IN SockAddr;
	int lineCount = 0;
	int rowCount = 0;
	struct hostent *host;
	locale local;
	char buffer[10000];
	int i = 0;
	int nDataLength;
	string website_HTML;

	// website url
	string url = "www.google.com";

	//HTTP GET
	string get_http = "GET / HTTP/1.1\r\nHost: " + url + "\r\nConnection: close\r\n\r\n";


	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		cout << "WSAStartup failed.\n";
		system("pause");
		//return 1;
	}

	Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	host = gethostbyname(url.c_str());

	SockAddr.sin_port = htons(80);
	SockAddr.sin_family = AF_INET;
	SockAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

	if (connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr)) != 0) {
		cout << "Could not connect";
		system("pause");
		//return 1;
	}

	// send GET / HTTP
	send(Socket, get_http.c_str(), strlen(get_http.c_str()), 0);

	// recieve html
	while ((nDataLength = recv(Socket, buffer, 10000, 0)) > 0) {
		int i = 0;
		while (buffer[i] >= 32 || buffer[i] == '\n' || buffer[i] == '\r') {

			website_HTML += buffer[i];
			i += 1;
		}
	}

	closesocket(Socket);
	WSACleanup();

	// Display HTML source 
	//cout << website_HTML;
	stringstream ss(website_HTML);

	while (!ss.eof())
	{
		string g;
		ss >> g;
		if (g == "Date:")
		{
			string y, m, d, s;
			ss >> g;
			ss >> d;
			ss >> m;
			ss >> y;
			ss >> s;




			time_t rawtime;
			struct tm * timeinfo;
			int year, month=0, day, hour, minute, second;
			const char * monthv[] = { "Jan", "Feb",
				"Mar", "Apr",
				"May", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dec" };
			m = m.substr(0, 3);
			while (month < 12 && monthv[month] != m) { month++; }

			{
				stringstream temp(y);
				temp >> year;
			} {
				stringstream temp(d);
				temp >> day;
			} {
				stringstream temp(s.substr(0, 2));
				temp >> hour;
			} {
				stringstream temp(s.substr(3, 2));
				temp >> minute;
			} {
				stringstream temp(s.substr(6, 2));
				temp >> second;
			}
			/* get current timeinfo and modify it to the user's choice */
			time(&rawtime);
			timeinfo = localtime(&rawtime);
			timeinfo->tm_year = year - 1900;
			timeinfo->tm_mon = month;
			timeinfo->tm_mday = day;
			timeinfo->tm_hour = hour;
			timeinfo->tm_min = minute;
			timeinfo->tm_sec = second;

			/* call mktime: timeinfo->tm_wday will be set */
			mktime(timeinfo);



			GinternetTime = rawtime;
			GgotInternet = true;

			ptm = gmtime(&rawtime);
			break;
		}
	}



	return 0;
}

int main()
{
	x();

	printf("%04d %02d %02d %02d:%02d:%02d \n", 1900 + ptm->tm_year, ptm->tm_mon + 1,ptm->tm_mday,ptm->tm_hour,ptm->tm_min,ptm->tm_sec);

	int g;
	scanf("%d", &g);
	return 0;
}