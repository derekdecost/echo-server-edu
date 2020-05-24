/*
 * TCPEchoServerIPV4.c
 *
 *  Created on: May 21, 2020
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

static const int MAXPENDING = 5;

void dieWithUserMessage(const char *msg, const char *detail);
void dieWithSystemMessage(const char *msg);
void dispConnectionInfo(int sock);
void HandleTCPClient(int clntSocket);

int main(int argc, char *argv[]){
	if (argc != 2)	// Test for the correct number of ports.
		dieWithUserMessage("Parameter(s)", "<Server Port>");

	in_port_t servPort  = atoi(argv[1]);	// First arg: local port.

	// Create a socket for incoming connections.
	int servSock;	// Server socket descriptor.
	if ((servSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		dieWithSystemMessage("socket() failed.");

	// Construct local address structure.
	struct sockaddr_in servAddr;					// Local address.
	memset(&servAddr, 0, sizeof(servAddr));			// Zero out structure.
	servAddr.sin_family = AF_INET;					// IPv4 address family.
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);	// Any incoming interface.
	servAddr.sin_port = htons(servPort);			// Local port.

	dispConnectionInfo(servSock);		// Display the connection info before bind has been applied to the socket.
	// Bind to the local address.
	if (bind(servSock, (struct sockaddr*) &servAddr, sizeof(servAddr)) < 0)
		dieWithSystemMessage("bind() failed.");
	else
		dispConnectionInfo(servSock);	// Display the connection info once bind has been applied to the socket.
	

	// Mark the socket so it will listen for incoming messages.
	if (listen(servSock, MAXPENDING) < 0)
		dieWithSystemMessage("listen() failed.");

	// Connection loop.
	for(;;){
		struct sockaddr_in clntAddr;	// Client address.
		// Set length of the client address structure (in-out parameter).
		socklen_t clntAddrLen = sizeof(clntAddr);

		// Wait for the client to connect.
		int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
		if (clntSock < 0)
			dieWithSystemMessage("accept() failed.");
		else
			dispConnectionInfo(clntSock);	// Display the connection information after the server has accepted a client socket.

		// clntSock is connected to the client.
		char clntName[INET_ADDRSTRLEN];	// String to contain the client address.
		if (inet_ntop(AF_INET, &clntAddr.sin_addr.s_addr, clntName, sizeof(clntName)) != NULL)
			printf("Handling client %s/%d\n", clntName, ntohs(clntAddr.sin_port));
		else
			puts("Unable to get client address.");

		HandleTCPClient(clntSock);
	}
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
		printf("Remote address unassigned.\n");
	else{
		// Convert the retrieved numeric address of the socket and convert it to a string.
		char remoteIP[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, (struct sockaddr*)&remAddr.sin_addr, remoteIP, INET_ADDRSTRLEN) == NULL)
			printf("inet_ntop() failed.\n");
		else
			printf("Remote Address: %s\n", remoteIP);
	}
	// Get the local address of the socket.
	if (getsockname(sock, (struct sockaddr*) &locAddr, &locAddrLen) < 0)	// Retrieve the socket name.
		printf("Local address unassigned.\n");
	else{
		// Convert the retrieved numeric address of the socket and convert it to a string.
		char localIP[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, (struct sockaddr*)&locAddr.sin_addr, localIP, INET_ADDRSTRLEN) == NULL)
			printf("inet_ntop() failed.\n");
		else
			printf("Local Address: %s\n", localIP);
	}
}

void HandleTCPClient(int clntSocket){
    char rcvBuffer[RCVBUFSIZE];        /* Buffer for echo string */
    int rcvMsgSize, sendMsgSize;                    /* Size of received message */

    // Send a greeting message to the client.
    char welcMsg[RCVBUFSIZE] = "Welcome to the Echo Server.\n";
    int welcMsgSize;
    if ((welcMsgSize = send(clntSocket, welcMsg, RCVBUFSIZE, 0)) < 0)
    	dieWithSystemMessage("send() failed, greeting not sent");

    /* Receive message from client */
    if ((rcvMsgSize = recv(clntSocket, rcvBuffer, RCVBUFSIZE, 0)) < 0)
        dieWithSystemMessage("recv() failed");

    /* Send received string and receive again until end of transmission */
    while (rcvMsgSize > 0)      /* zero indicates end of transmission */
    {
        // Send the received data back to the client. ie. send the data in the rcvBuffer array back through the socket.
        if (send(clntSocket, rcvBuffer, rcvMsgSize, 0) != rcvMsgSize)
        	dieWithSystemMessage("send() failed");

        /* See if there is more data to receive */
        if ((rcvMsgSize = recv(clntSocket, rcvBuffer, RCVBUFSIZE, 0)) < 0)
        	dieWithSystemMessage("recv() failed");
    }
    close(clntSocket);    /* Close client socket */
}

