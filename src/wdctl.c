/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id: wdctl.c 1373 2008-09-30 09:27:40Z wichert $ */
/** @file wdctl.c
    @brief Monitoring and control of wifidog, client part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include "wdctl.h"

s_config config;

static void usage(void);
static void init_config(void);
static void parse_commandline(int, char **);
static int connect_to_server(char *);
static size_t send_request(int, char *);
static void wdctl_status(void);
static void wdctl_stop(void);
static void wdctl_reset(void);
static void wdctl_excess(void);
static void wdctl_restart(void);

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when wdctl is run with -h or with an unknown option
 */
static void
usage(void)
{
    printf("Usage: wdctl [options] command [arguments]\n");
    printf("\n");
    printf("options:\n");
    printf("  -s <path>         Path to the socket\n");
    printf("  -h                Print usage\n");
    printf("\n");
    printf("commands:\n");
    printf("  reset [mac|ip]    Reset the specified mac or ip connection\n");
    printf("  status            Obtain the status of wifidog\n");
    printf("  stop              Stop the running wifidog\n");
    printf("  restart           Re-start the running wifidog (without disconnecting active users!)\n");
    printf("  excess [0|1]      0:当前用户连接数正常 1:当前用户连接数超过额定值\n");
    printf("\n");
}

/** @internal
 *
 * Init default values in config struct
 */
static void
init_config(void)
{

	config.socket = strdup(DEFAULT_SOCK);
	config.command = WDCTL_UNDEF;
}

/** @internal
 *
 * Uses getopt() to parse the command line and set configuration values
 */
void
parse_commandline(int argc, char **argv)
{
    extern int optind;
    int c;

    while (-1 != (c = getopt(argc, argv, "s:h"))) {
        switch(c) {
            case 'h':
                usage();
                exit(1);
                break;

            case 's':
                if (optarg) {
		    free(config.socket);
		    config.socket = strdup(optarg);
                }
                break;

            default:
                usage();
                exit(1);
                break;
        }
    }

    if ((argc - optind) <= 0) {
	    usage();
	    exit(1);
    }

    if (strcmp(*(argv + optind), "status") == 0) {
	    config.command = WDCTL_STATUS;
    } else if (strcmp(*(argv + optind), "stop") == 0) {
	    config.command = WDCTL_STOP;
    } else if (strcmp(*(argv + optind), "reset") == 0) {
	    config.command = WDCTL_KILL;
	    if ((argc - (optind + 1)) <= 0) {
		    fprintf(stderr, "wdctl: Error: You must specify an IP "
				    "or a Mac address to reset\n");
		    usage();
		    exit(1);
	    }
	    config.param = strdup(*(argv + optind + 1));
    } else if (strcmp(*(argv + optind), "excess") == 0) {
	    config.command = WDCTL_EX;
	    if ((argc - (optind + 1)) <= 0) {
		    fprintf(stderr, "wdctl: Error: You must specify an value(0 or 1)\n");
		    usage();
		    exit(1);
	    }
	    config.param = strdup(*(argv + optind + 1));
    } else if (strcmp(*(argv + optind), "restart") == 0) {
	    config.command = WDCTL_RESTART;
    }
	 else {
	    fprintf(stderr, "wdctl: Error: Invalid command \"%s\"\n", *(argv + optind));
	    usage();
	    exit(1);
    }
}

static int
connect_to_server(char *sock_name)
{
	int sock;
	struct sockaddr_un	sa_un;
	
	/* Connect to socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

	if (connect(sock, (struct sockaddr *)&sa_un, 
			strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
		fprintf(stderr, "wdctl: wifidog probably not started (Error: %s)\n", strerror(errno));
		exit(1);
	}

	return sock;
}

static size_t
send_request(int sock, char *request)
{
	size_t	len;
        ssize_t written;
		
	len = 0;
	while (len != strlen(request)) {
		written = write(sock, (request + len), strlen(request) - len);
		if (written == -1) {
			fprintf(stderr, "Write to wifidog failed: %s\n",
					strerror(errno));
			exit(1);
		}
		len += written;
	}

	return len;
}

static void
wdctl_status(void)
{
	int	sock;
	char	buffer[4096];
	char	request[16];
	int	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "status\r\n\r\n", 15);

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';
		printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

static void
wdctl_stop(void)
{
	int	sock;
	char	buffer[4096];
	char	request[16];
	int	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "stop\r\n\r\n", 15);

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';
		printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

void
wdctl_reset(void)
{
	int	sock;
	char	buffer[4096];
	char	request[64];
	size_t	len;
	int	rlen;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "reset ", 64);
	strncat(request, config.param, (64 - strlen(request)));
	strncat(request, "\r\n\r\n", (64 - strlen(request)));

	len = send_request(sock, request);
	
	len = 0;
	memset(buffer, 0, sizeof(buffer));
	while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
				(sizeof(buffer) - len))) > 0)){
		len += rlen;
	}

	if (strcmp(buffer, "Yes") == 0) {
		printf("Connection %s successfully reset.\n", config.param);
	} else if (strcmp(buffer, "No") == 0) {
		printf("Connection %s was not active.\n", config.param);
	} else {
		fprintf(stderr, "wdctl: Error: WiFiDog sent an abnormal "
				"reply.\n");
	}

	shutdown(sock, 2);
	close(sock);
}

void
wdctl_excess(void)
{
	int	sock;
	char	buffer[4096];
	char	request[64];
	size_t	len;
	int	rlen;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "excess ", 64);
	strncat(request, config.param, (64 - strlen(request)));
	strncat(request, "\r\n\r\n", (64 - strlen(request)));

	len = send_request(sock, request);
	
	shutdown(sock, 2);
	close(sock);
}

static void
wdctl_restart(void)
{
	int	sock;
	char	buffer[4096];
	char	request[16];
	int	len;

	sock = connect_to_server(config.socket);
		
	strncpy(request, "restart\r\n\r\n", 15);

	len = send_request(sock, request);
	
	while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
		buffer[len] = '\0';
		printf("%s", buffer);
	}

	shutdown(sock, 2);
	close(sock);
}

int
main(int argc, char **argv)
{

	/* Init configuration */
	init_config();
	parse_commandline(argc, argv);

	switch(config.command) {
	case WDCTL_STATUS:
		wdctl_status();
		break;
	
	case WDCTL_STOP:
		wdctl_stop();
		break;

	case WDCTL_KILL:
		wdctl_reset();
		break;
		
	case WDCTL_RESTART:
		wdctl_restart();
		break;

	case WDCTL_EX:
		wdctl_excess();
		break;
		
	default:
		/* XXX NEVER REACHED */
		fprintf(stderr, "Oops\n");
		exit(1);
		break;
	}
	exit(0);
}
