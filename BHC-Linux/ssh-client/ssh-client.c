/*

Executable name	: ssh-client
Designed OS	: Linux
Version		: 1.0
Created date	: 7/29/2017
Last update	: 7/29/2017
Author		: N4ss4r
Inspired by	: Black Hat Python
GCC Version	: 6.3.0
Description	: This is a port the simple SSH Client executing the "id" command
		  in Justin Seitz great book "Black Hat Python" This code is an
		  addition to the on-going 'Black Hat Python porting to C' project
		  by wetw0rk, https://wetw0rk.com/, http://github.com/wetw0rk. This
		  This peice of code uses libssh2 to create a client connection to a
		  remote SSHD server and execute the "id" command as per example in
		  the Black Hat Python book, page 26.

N4ss4r Github		   :
	https://github.com/N4ss4r?tab=repositories

Dependencies (libssh2)	   :
	apt-get install libssh2-1-dev

Build using these commands :
	gcc -Wall -Werror -Wshadow -g ssh-client.c -o ssh-client -lssh2

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <libssh2.h>

#define COMMAND		"id"			/* the command to execute on remote SSHD Server */
#define USERNAME	"username"		/* the username for the remote SSHD Server */
#define PASSWORD	"password"		/* the password for the remote SSHD Server */
#define IP		"192.168.142.128"	/* the IP Address of the SSHD Server */


int error(char *string)
{
	fprintf(stderr, "Error in %s\n", string);
	perror(string);

	return(EXIT_FAILURE);
}


int main(int argc , char **argv)

{

	struct sockaddr_in fd;
	struct hostent *a;	// for host information
	char buffer[4096];	// size of the buffer to read from remote SSHD server
	char *host = IP;
	int sock, n;		// socket fd , return value

	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;

	/* initialisation */
	n = libssh2_init(0);

	if(n != 0)
	{
		error("libssh2_init");
	}

	/*create socket */
	if ((sock = socket(AF_INET,SOCK_STREAM,0)) == -1 )
	{
		error("socket");
	}

	/* get host name */
	if ((a = gethostbyname(host)) == NULL)
	{
		error("gethostbyname");
	}

	bcopy((char *)a->h_addr,(char *)&fd.sin_addr.s_addr,a->h_length);
	fd.sin_family = AF_INET;
	fd.sin_port = htons(22);

	if(connect(sock,(struct sockaddr *) &fd, sizeof(fd)) < 0)
	{
		error("connect");
	}

	/* create a session */
	if((session = libssh2_session_init()) == NULL)
	{
		error("libssh2_session_init()");
	}

	/* execute SSH handshake */
	if (( n = libssh2_session_handshake(session,sock)) < 0)
	{
		error("libssh2_session_handshake()");
	}

	/* authentication. We use a username and password this time */
	if ((n = libssh2_userauth_password(session,USERNAME,PASSWORD)) < 0)
	{
		error("libssh2_userauth_password");
	}

	/* open a channel for communication */
	if ((channel = libssh2_channel_open_session(session)) == NULL)
	{
		error("libssh2_channell_open_session");
	}

	/* execute the "id" command on the remote SSHD Server */
	if ((n = libssh2_channel_exec(channel,COMMAND)) < 0)
	{
		error("libssh2_channel_exec");
	}

	/* read the respone and print out the buffer */
	if ((n = libssh2_channel_read( channel, buffer, sizeof(buffer))) < 0)
	{
		error("libssh2_channel_read");
	}

	if(n > 0)
	{
		/* printing all the buffer in one go */
		printf("%s\n",buffer);
	}

	return EXIT_SUCCESS;

}
