#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[]) {

    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char buffer[256];
    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    char data[] = "START&&jobidF3234&&/var/length/path/to/wifi.pcap&&/var/length/path/to/job/output/dir/&&&";
    data[5]  = '\0'; data[6]  = '\31';
    data[17] = '\0'; data[18] = '\31';
    data[48] = '\0'; data[49] = '\31';
    data[85] = '\0'; data[86] = '\31'; data[87] = '\4';

    n = write(sockfd,data,88);//strlen(buffer));
    if (n < 0) 
         error("ERROR writing to socket");
    bzero(buffer,256);
    n = read(sockfd,buffer,255);
    if (n < 0) 
         error("ERROR reading from socket");

    int i;
    for (i=0; i<n; i++) {
	if (buffer[i]=='\31') printf("%d\t-31-\n",i);
	else if (buffer[i]=='\4') printf("%d\t-4-\n",i);
	else if (buffer[i]=='\0') printf("%d\t-0-\n",i);
	else printf("%d\t%c\n",i,buffer[i]);
	if (buffer[i] == '\4') break;
	/*
	if (buffer[i]!='\4' && buffer[i]!='\31')
	    printf("%c", buffer[i]);
	else 
	    printf("\n31 or 4\n");
	*/
    }
    printf("\n");

    //printf("%s\n",buffer);
    close(sockfd);
    return 0;
}
