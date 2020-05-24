/*
 * TCPEchoClientIPv4.c
 *
 *  Created on: May 22, 2020
 *      Author: derekdecost
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define RCVBUFSIZE 32

void dieWithUserMessage(const char *msg, const char *detail);
void dieWithSystemMessage(const char *msg);
void dispConnectionInfo(int sock);

int main(int argc, char *argv[]){
	if (argc < 3 || argc > 4)	// Test for the correct number of arguments.
		dieWithUserMessage("Parameters", "<Server Address> <Echo Word> [Server Port]");
	char *servIP = argv[1];		// First arg: server IP address (dotted quad).
	char *echoString = argv[2];	// Second arg: string to echo.
	// Third arg (optional): server port (numeric). 7 is a well-known echo port.
	in_port_t servPort = (argc == 4) ? atoi(argv[3]) : 7;

	// Create a reliable stream socket using TCP.
	printf("Creating TCP socket...\n");
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		dieWithSystemMessage("socket() failed");
	else
		printf("Socket created.\n");

	// Construct the server address structure.
	struct sockaddr_in servAddr;			// Server Address.
	memset(&servAddr, 0, sizeof(servAddr));	// Zero out the structure.
	servAddr.sin_family = AF_INET;			// IPv4 address family.
	// Convert the address.
	int rtnVal = inet_pton(AF_INET, servIP, &servAddr.sin_addr.s_addr);
	if (rtnVal == 0)
		dieWithUserMessage("inet_pton() failed", "invalid address string");
	else if (rtnVal < 0)
		dieWithSystemMessage("inet_pton() failed");
	servAddr.sin_port = htons(servPort);	// Server port.

	// Establish the connection to the echo server.
	printf("Connecting to %s/%s...\n", argv[1], argv[3]);
	if (connect(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
		dieWithSystemMessage("connect() failed");
	printf("Connected.\n");
	dispConnectionInfo(sock);	// Display the local and remote addresses.

	// Actions to be taken once connected to the server.
	// Receive the initial welcome message from the server.
	unsigned int totalBytesRcvd = 0;	// Count of total bytes received.
	char buffer[RCVBUFSIZE];			// I/O buffer.
	ssize_t numBytes;					// Value used to determine the number of bytes that are sent/received during the appropriate operations.
	printf("Receiving greeting...\n");
	for (;;){	// Loop used to receive a welcome message that may be sent by the server.
		numBytes = recv(sock, buffer, RCVBUFSIZE - 1, 0);
		if (numBytes < 0){		// recv() returned -1, indicating that a connection error has occurred.
			printf("recv() failed.");
			dieWithSystemMessage("recv() failed");
		}
		else if (numBytes == 1){	// Server either had no data left to send, or the connection has ended before completion.
			printf("recv() connection has been closed.\n");
			break;
		}
		buffer[numBytes] = '\0';			// Terminate the string.
		printf("Greeting: %s", buffer);		// Print the data that is stored in buffer. The sent message includes a \n escape character.
	}
	// Send the string to the server.
	size_t echoStringLen = strlen(echoString);	// Determine the input length.
	printf("Sending string to be echoed...\n");
	numBytes = send(sock, echoString, echoStringLen, 0);
	if (numBytes < 0)
		dieWithSystemMessage("send() failed");
	else if (numBytes != echoStringLen)
		dieWithUserMessage("send()", "sent unexpected number of bytes.");
	printf("Echo string has been sent.\n");

	// Receive the same string back from the server.
	printf("Receive: ");			// Setup to print the echoed string.
	while (totalBytesRcvd < echoStringLen){

		// Receive up to the buffer size (minus 1 to leave space for a null terminator.
		numBytes = recv(sock, buffer, RCVBUFSIZE - 1, 0);
		if (numBytes < 0)
			dieWithSystemMessage("recv() failed");
		else if (numBytes == 0)
			dieWithUserMessage("recv()", "connection closed prematurely.");
		totalBytesRcvd += numBytes;	// Keep tally of total bytes.
		buffer[numBytes] = '\0';	// Terminate the string.
		printf("%s", buffer);		// Print the echo buffer.
	}

	printf("\n");	// Print a final line feed.

	close(sock);
	exit(0);
}

void dieWithUserMessage(const char *msg, const char *detail){
	fputs(msg, stderr);
	fputs(": ", stderr);
	fputs(detail, stderr);
	fputc('\n', stderr);
	exit(1);
}

void dieWithSystemMessage(const char *msg){
	perror(msg);
	exit(1);
}

void dispConnectionInfo(int sock){
	/*	dispConnectionInfo: Display the local and remote address of the connected socket. Must
	 * 		be performed AFTER the connection of a server. Attempting to use this function before
	 * 		a connection has been made will result in an error.
	 *
	 * 	:params:
	 * 		sock: Socket descriptor that has been successfully connected to a server.
 	 *
 	 *	:returns:
 	 *		None.
	 */
	struct sockaddr_in remAddr, locAddr;
	int remAddrLen, locAddrLen;
	remAddrLen = sizeof(remAddr);
	locAddrLen = sizeof(locAddr);
	// Get the remote address of the socket.
	if (getpeername(sock, (struct sockaddr*)&remAddr, &remAddrLen) < 0)	// Retrieve the peer name.
		dieWithSystemMessage("getpeername() failed");
	else{
		// Convert the retrieved numeric address of the socket and convert it to a string.
		char remoteIP[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, (struct sockaddr*)&remAddr.sin_addr, remoteIP, INET_ADDRSTRLEN) == NULL)
			dieWithSystemMessage("inet_ntop() failed");
		else
			printf("Remote Address: %s\n", remoteIP);
	}
	// Get the local address of the socket.
	if (getsockname(sock, (struct sockaddr*) &locAddr, &locAddrLen) < 0)	// Retrieve the socket name.
		dieWithSystemMessage("getsockname() failed");
	else{
		// Convert the retrieved numeric address of the socket and convert it to a string.
		char localIP[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, (struct sockaddr*)&locAddr.sin_addr, localIP, INET_ADDRSTRLEN) == NULL)
			dieWithSystemMessage("inet_ntop() failed");
		else
			printf("Local Address: %s\n", localIP);
	}
}
