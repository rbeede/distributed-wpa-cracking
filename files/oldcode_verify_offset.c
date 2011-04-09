#include <stdlib.h>
#include <stdio.h>
#include "cowpatty.h"
#include <string.h>
#include <math.h>

char password_buf[65];
int nexthashrec(FILE * fp, struct hashdb_rec *rec)
{
	int recordlength, wordlen;
	if (fread(&rec->rec_size, sizeof(rec->rec_size), 1, fp) != 1) {
		perror("fread");
		return -1;
	}
	recordlength = abs(rec->rec_size);
	wordlen = recordlength - (sizeof(rec->pmk) + sizeof(rec->rec_size));
	if (wordlen > 63 || wordlen < 8) {
		fprintf(stderr, "Invalid word length: %d\n", wordlen);
		return -1;
	}
	rec->word = password_buf;
	if (fread(rec->word, wordlen, 1, fp) != 1) {
		perror("fread");
		return -1;
	}

	if (fread(rec->pmk, sizeof(rec->pmk), 1, fp) != 1) {
		perror("fread");
		return -1;
	}
	return recordlength;
}
char ssidlist[][20] = {
	"WANO",
	"WaveLAN Network",
	"Wayport_Access",
	"Webstar",
	"west",
	"WiFi",
	"Williams",
	"wilson",
	"Wingate",
	"Wireless",
	"Wireless1",
	"wirelesshome",
	"wirelesslan",
	"WirelessNet",
	"Wireless Network",
	"WLAN",
	"WLAN-AP",
	"WLAN-PS",
	"WLCM",
	"WNR2004",
	"WORK",
	"workgroup",
	"WRC_Network",
	"WSR-5000",
	"wxyz"
};
int main()
{
	char path[256] = "/home/asud/WPA_TABLES/";
	int i;
	FILE *fp;
	struct hashdb_rec rec;
	struct hashdb_head hf_head;
	char ssid[33] = "";
	char word[65] = "";
	int wordlen = 0;
	unsigned long wordstested = 0;
	long position = 0;
	for(i=0;i<25;i++)
	{
		strcat(path,ssidlist[i]);
		fp = fopen(path,"r");
		if(fp == NULL)
			perror("fopen");
		fread(&hf_head, sizeof(hf_head), 1, fp);
		memcpy(&ssid, hf_head.ssid, hf_head.ssidlen);
		ssid[hf_head.ssidlen] = '\0';
//		printf("%s\n",ssid);
		while(feof(fp) == 0)
		{
			wordlen = nexthashrec(fp,&rec);
			wordstested++;
			if(!(wordstested % 100000))
			{
				memcpy(word, rec.word, wordlen);
				word[wordlen] = '\0';
				position = ftell(fp);
				printf("SSID=%s WordCount=%ld Word=%s Position=%ld\n",ssid, wordstested,word, position);	
			}
		}
		fclose(fp);
		strcpy(path,"/home/asud/WPA_TABLES/");
		strcpy(ssid,"");
		wordstested = 0;
		memset(&hf_head,'\0',sizeof(hf_head));
	}
	return 0;
}
