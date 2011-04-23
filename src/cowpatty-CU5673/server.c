/*
 * Listen for packets over a certain port.  When a valid packet is received,
 * start cowpatty on the worker nodes with the information provided by in the
 * packet.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT_NUM 8080
#define MAX_BUFFER_SIZE 256
#define BACKLOG 10

/* Print error message and exit */
void fatal(const char *msg) {
    perror(msg);
    exit(1);
}

/* Process a connection.
 *  This is where we could tell the workers to start.
 */
void processConnection(int socket_fd) {

    char buffer[MAX_BUFFER_SIZE];    // packet buffer
    int packet_bytes_read;           // number of bytes read from packet

    // clear packet buffer
    memset(buffer, 0, MAX_BUFFER_SIZE);

    // read packet
    packet_bytes_read = read(socket_fd, buffer, MAX_BUFFER_SIZE);
    if (packet_bytes_read < 0) fatal("Error while reading from socket");

    // print packet data
    printf("PACKET DATA: %s\n", buffer);

}

/* Set up socket to listen over a port */
int main(int argc, char *argv[]) {

    int recv_socket_fd, send_socket_fd;     // send and receive sockets
    int pid;                                // child proc to handle connections
    struct sockaddr_in serv_addr, cli_addr; // addresses of server and clients
    socklen_t cli_len;                      // size of client address

    // create socket using IPv4 protocol
    recv_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (recv_socket_fd < 0) 
        fatal("Unable to open socket\n");

    // set up address for socket
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT_NUM);

    // bind address to socket
    if (bind(recv_socket_fd, (struct sockaddr *) &serv_addr, 
	     sizeof(serv_addr)) < 0) 
	fatal("Unable to bind address to socket\n");

    // set up socket to listen
    listen(recv_socket_fd, BACKLOG);

    // init size of client address
    cli_len = sizeof(cli_addr);

    // defense against zombies
    signal(SIGCHLD, SIG_IGN);

    // loop infinitely listening for packets
    while (1) {
	// accept connection from some client
	send_socket_fd = accept(recv_socket_fd, 
				(struct sockaddr *) &cli_addr, 
				&cli_len);
	if (send_socket_fd < 0) fatal("Error occurred on accept\n");
	
	// create child process to handle new connection
	pid = fork();
	if (pid<0) fatal("Unable to create child process\n");
	
	// child process
	if (pid == 0) {
	    close(recv_socket_fd);
	    processConnection(send_socket_fd);
	    exit(0);

	// parent process
	} else {
	    close(send_socket_fd);
	}
	
    }

    // close sockets
    close(send_socket_fd);
    close(recv_socket_fd);

    // return to OS
    return 0; 
}
