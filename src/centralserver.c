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

/* $Id: centralserver.c 1377 2008-09-30 10:36:25Z wichert $ */
/** @file centralserver.c
  @brief Functions to talk to the central server (auth/send stats/get rules/etc...)
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "httpd.h"

#include "common.h"
#include "safe.h"
#include "util.h"
#include "log.h"
#include "auth.h"
#include "conf.h"
#include "debug.h"
#include "centralserver.h"
#include "firewall.h"
#include "../config.h"
#include <json/json.h>
#include "client_list.h"

extern pthread_mutex_t	config_mutex;

/** Initiates a transaction with the auth server, either to authenticate or to
 * update the traffic counters at the server
@param authresponse Returns the information given by the central server 
@param request_type Use the REQUEST_TYPE_* defines in centralserver.h
@param ip IP adress of the client this request is related to
@param mac MAC adress of the client this request is related to
@param token Authentification token of the client
@param incoming Current counter of the client's total incoming traffic, in bytes 
@param outgoing Current counter of the client's total outgoing traffic, in bytes 
*/
t_authcode
xhauth_server_request(t_authresponse *authresponse, const char *request_type, const char *ip, const char *mac, const char *token, unsigned long long int incoming, unsigned long long int outgoing, int type,char *cell_no)
{
	int sockfd;
	ssize_t	numbytes;
	size_t totalbytes;
	char buf[MAX_BUF];
	char *tmp;
        char *safe_token;
	int done, nfds;
	fd_set			readfds;
	struct timeval		timeout;
	t_auth_serv	*auth_server = NULL;
	
	/* Blanket default is error. */
	authresponse->authcode = AUTH_ERROR;
	
	sockfd = connect_auth_server();
	if (sockfd == -1) {
		/* Could not connect to any auth server */
		return (AUTH_ERROR);
	}

	memset(buf, 0, sizeof(buf));
        safe_token=httpdUrlEncode(token);

	auth_server = get_auth_server();
	snprintf(buf, (sizeof(buf) - 1),
		"POST %spartner/auth.json?ip=%s&mac=%s&token=%s&partner_token=%s&incoming=%llu&outgoing=%llu&gw_id=%s&type=%d&cell_no=%s HTTP/1.0\r\n"
		"User-Agent: WiFiDog %s\r\n"
		"Host: %s\r\n"
		"\r\n",
		auth_server->authserv_path,
//		auth_server->authserv_auth_script_path_fragment,
		ip,
		mac,
		auth_server->authserv_token,
		safe_token,
		incoming,
		outgoing,
                config_get_config()->gw_id,
		type,
		cell_no);
        free(safe_token);

	Ulog(ULOG_DEBUG, "Sending HTTP request to auth server: \n[%s]\n", buf);
	send(sockfd, buf, strlen(buf), 0);

	debug(LOG_DEBUG, "Reading response");
	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 2; /* XXX magic... 30 second is as good a timeout as any */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			numbytes = read(sockfd, buf + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				Ulog(ULOG_WARNING, "An error occurred while reading from auth server: %s\n", strerror(errno));
				/* FIXME */
				close(sockfd);
				return (AUTH_ERROR);
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				Ulog(ULOG_DEBUG, "Read %d bytes, total now %d\n", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			Ulog(ULOG_WARNING, "Timed out reading data via select() from auth server\n");
			/* FIXME */
			close(sockfd);
			return (AUTH_ERROR);
		}
		else if (nfds < 0) {
			Ulog(ULOG_WARNING, "Error reading data via select() from auth server: %s\n", strerror(errno));
			/* FIXME */
			close(sockfd);
			return (AUTH_ERROR);
		}
	} while (!done);
	close(sockfd);

	buf[totalbytes] = '\0';
	Ulog(ULOG_DEBUG, "HTTP Response from Server: [%s]\n", buf);
	
	//parse result code as json
	json_object *pAuth = NULL,	*pResult = NULL;
	char *pResStr = NULL;
	char *start, *end;
	char Msg[256];
	int iRet = 0;
	t_client *client;

	start = strchr(buf, '{');
	end = strrchr(buf, '}');

	if (start == NULL || end == NULL )	
	{
		Ulog(ULOG_DEBUG, "-------------------接收到到的数据非法\n"); //added by caosx 20160519
		return(AUTH_ERROR); //not find json struct
	}

	strncpy(Msg, start, end - start + 1);

	pAuth = json_tokener_parse(Msg); //parse result
	if (pAuth)
	{
		pResult = json_object_object_get(pAuth, "result_code"); //result_code
		if (pResult)
		{
			pResStr = json_object_get_string(pResult);
			if (pResStr)
			{
				if (0 == strncmp(pResStr, "0", 1)) { //analyze json struct			
					authresponse->authcode = AUTH_ALLOWED; //success
					Ulog(ULOG_DEBUG, "-------------------云认为认证成功\n");//added by caosx 20160519
					//return(authresponse->authcode);
				}else if (0 == strncmp(pResStr, "11120117", 8)) { //added by caosx 20160519 				
					authresponse->authcode = AUTH_DENIED; 
					Ulog(ULOG_DEBUG, "-------------------云认为认证失败\n");//added by caosx 20160519
					return(authresponse->authcode);
				}	
			}
		}
		else
		{
			Ulog(ULOG_DEBUG, "-------------------收到的数据没有result_code字段\n");//added by caosx 20160519
			return(AUTH_ERROR); //fail
		}

		pResult = json_object_object_get(pAuth, "cell_no"); //cell_no
		if (pResult)
		{
			pResStr = json_object_get_string(pResult);
			if (pResStr ) { //analyze json struct
				strncpy(authresponse->authphone, pResStr, sizeof(authresponse->authphone) - 1); //cell phone no
                               extern  pthread_mutex_t client_list_mutex;
                               LOCK_CLIENT_LIST();
                               client = client_list_find_by_ip(ip);
                               if(client){
					if(client->phone)
						free(client->phone);
                                       client->phone = safe_strdup(authresponse->authphone);
				}
                               UNLOCK_CLIENT_LIST();
			}		
		}

		pResult = json_object_object_get(pAuth, "expire_time"); //expire object
		if (pResult)
		{
			iRet = json_object_get_int(pResult); //get expire time
			if ( 0 == iRet ) { 
				authresponse->expire_time = DEFAULT_CLIENTTIMEOUT; //use default
			}		
			else
			{
				authresponse->expire_time = iRet; //set expire time
			}
		}
	
		return (authresponse->authcode); //return allow

	}
	else {
		Ulog(ULOG_DEBUG, "-------------------json数据非法\n");//added by caosx 20160519
		return(AUTH_ERROR);
	}

	/* XXX Never reached because of the above if()/else pair. */
	Ulog(ULOG_DEBUG, "-------------------json数据非法\n");//added by caosx 20160519
	return(AUTH_ERROR);
}

t_authcode
auth_server_request(t_authresponse *authresponse, const char *request_type, const char *ip, const char *mac, const char *token, unsigned long long int incoming, unsigned long long int outgoing, int type)
{
	int sockfd;
	ssize_t	numbytes;
	size_t totalbytes;
	char buf[MAX_BUF];
	char *tmp;
        char *safe_token;
	int done, nfds;
	fd_set			readfds;
	struct timeval		timeout;
	t_auth_serv	*auth_server = NULL;
	
	/* Blanket default is error. */
	authresponse->authcode = AUTH_ERROR;
	
	sockfd = connect_auth_server();
	if (sockfd == -1) {
		/* Could not connect to any auth server */
		return (AUTH_ERROR);
	}

	/**
	 * TODO: XXX change the PHP so we can harmonize stage as request_type
	 * everywhere.
	 */
	memset(buf, 0, sizeof(buf));
        safe_token=httpdUrlEncode(token);

	auth_server = get_auth_server();
	if(REQUEST_TYPE_LOGIN == request_type){
		s_config *config = config_get_config();
		if(config->portal_type[0] == '3')
		snprintf(buf, (sizeof(buf) - 1),
			"POST %spartner/dev_phone_pass.json?stage=%s&ip=%s&mac=%s&token=%s&gw_id=%s&type=%d HTTP/1.0\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: %s\r\n"
			"\r\n",
			auth_server->authserv_path,
//			auth_server->authserv_auth_script_path_fragment,
			request_type,
			ip,
			mac,
			auth_server->authserv_token,
        	        config->gw_id,
			type,
			VERSION,
			auth_server->authserv_hostname
		);
		else
		snprintf(buf, (sizeof(buf) - 1),
			"POST %s%s?stage=%s&ip=%s&mac=%s&token=%s&access_token=%s&incoming=%llu&outgoing=%llu&gw_id=%s&type=%d HTTP/1.0\r\n"
			"User-Agent: WiFiDog %s\r\n"
			"Host: %s\r\n"
			"\r\n",
			auth_server->authserv_path,
			auth_server->authserv_auth_script_path_fragment,
			request_type,
			ip,
			mac,
			auth_server->authserv_token,
			safe_token,
			incoming,
			outgoing,
        	        config->gw_id,
			type,
			VERSION,
			auth_server->authserv_hostname
		);
	}else
        snprintf(buf, (sizeof(buf) - 1),
                "POST %s%s?stage=%s&ip=%s&mac=%s&token=%s&access_token=%s&incoming=%llu&outgoing=%llu&gw_id=%s HTTP/1.0\r\n"
                "User-Agent: WiFiDog %s\r\n"
                "Host: %s\r\n"
                "\r\n",
                auth_server->authserv_path,
                auth_server->authserv_auth_script_path_fragment,
                request_type,
                ip,
                mac,
                auth_server->authserv_token,
                safe_token,
                incoming,
                outgoing,
                config_get_config()->gw_id,
                VERSION,
                auth_server->authserv_hostname
        );

        free(safe_token);

	Ulog(ULOG_DEBUG, "Sending HTTP request to auth server: \n[%s]\n", buf);
	send(sockfd, buf, strlen(buf), 0);

	debug(LOG_DEBUG, "Reading response");
	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 2; /* XXX magic... 30 second is as good a timeout as any */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			numbytes = read(sockfd, buf + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				Ulog(ULOG_WARNING, "An error occurred while reading from auth server: %s\n", strerror(errno));
				/* FIXME */
				close(sockfd);
				return (AUTH_ERROR);
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				Ulog(ULOG_DEBUG, "Read %d bytes, total now %d\n", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			Ulog(ULOG_WARNING, "Timed out reading data via select() from auth server\n");
			/* FIXME */
			close(sockfd);
			return (AUTH_ERROR);
		}
		else if (nfds < 0) {
			Ulog(ULOG_WARNING, "Error reading data via select() from auth server: %s\n", strerror(errno));
			/* FIXME */
			close(sockfd);
			return (AUTH_ERROR);
		}
	} while (!done);

	close(sockfd);

	buf[totalbytes] = '\0';
	Ulog(ULOG_DEBUG, "HTTP Response from Server: [%s]\n", buf);
	
#if	0 //use our specific msg
	if ((tmp = strstr(buf, "Auth: "))) {
		if (sscanf(tmp, "Auth: %d", (int *)&authresponse->authcode) == 1) {
			debug(LOG_INFO, "Auth server returned authentication code %d", authresponse->authcode);
			return(authresponse->authcode);
		} else {
			debug(LOG_WARNING, "Auth server did not return expected authentication code");
			return(AUTH_ERROR);
		}
	}
#else
	//parse result code as json

	json_object *pAuth = NULL,	*pResult = NULL;
	char *pResStr = NULL;
	char *start, *end;
	char Msg[256];
	int iRet = 0;
	t_client *client;

	start = strchr(buf, '{');
	end = strrchr(buf, '}');

	if (start == NULL || end == NULL )	
	{
		Ulog(ULOG_DEBUG, "-------------------接收到到的数据非法\n"); //added by caosx 20160519
		return(AUTH_ERROR); //not find json struct
	}

	strncpy(Msg, start, end - start + 1);

	pAuth = json_tokener_parse(Msg); //parse result
	if (pAuth)
	{
		pResult = json_object_object_get(pAuth, "result_code"); //result_code
		if (pResult)
		{
			pResStr = json_object_get_string(pResult);
			if (pResStr)
			{
				if (0 == strncmp(pResStr, "0", 1)) { //analyze json struct			
					authresponse->authcode = AUTH_ALLOWED; //success
					Ulog(ULOG_DEBUG, "-------------------云认为认证成功\n");//added by caosx 20160519
					//return(authresponse->authcode);
				}else if (0 == strncmp(pResStr, "11120117", 8)) { //added by caosx 20160519 				
					authresponse->authcode = AUTH_DENIED; 
					Ulog(ULOG_DEBUG, "-------------------云认为认证失败\n");//added by caosx 20160519
					return(authresponse->authcode);
				}	

			}
				
		}
		else
		{
			Ulog(ULOG_DEBUG, "-------------------收到的数据没有result_code字段\n");//added by caosx 20160519
			return(AUTH_ERROR); //fail
		}

		pResult = json_object_object_get(pAuth, "cell_no"); //cell_no
		if (pResult)
		{
			pResStr = json_object_get_string(pResult);
			if (pResStr ) { //analyze json struct
				strncpy(authresponse->authphone, pResStr, sizeof(authresponse->authphone) - 1); //cell phone no
                               extern  pthread_mutex_t client_list_mutex;
                               LOCK_CLIENT_LIST();
                               client = client_list_find_by_ip(ip);
                               if(client){
					if(client->phone)
						free(client->phone);
                                       client->phone = safe_strdup(authresponse->authphone);
				}
                               UNLOCK_CLIENT_LIST();
			}		
		}

		pResult = json_object_object_get(pAuth, "expire_time"); //expire object
		if (pResult)
		{
			iRet = json_object_get_int(pResult); //get expire time
			if ( 0 == iRet ) { 
				authresponse->expire_time = DEFAULT_CLIENTTIMEOUT; //use default
			}		
			else
			{
				authresponse->expire_time = iRet; //set expire time
			}
		}
	
		return (authresponse->authcode); //return allow

	}

#endif	
	else {
		Ulog(ULOG_DEBUG, "-------------------json数据非法\n");//added by caosx 20160519
		return(AUTH_ERROR);
	}

	/* XXX Never reached because of the above if()/else pair. */
	Ulog(ULOG_DEBUG, "-------------------json数据非法\n");//added by caosx 20160519
	return(AUTH_ERROR);
}

/* Tries really hard to connect to an auth server. Returns a file descriptor, -1 on error
 */
int connect_auth_server() {
	int sockfd;

	LOCK_CONFIG();
	sockfd = _connect_auth_server(0);
	UNLOCK_CONFIG();

	if (sockfd == -1) {
		Ulog(ULOG_WARNING, "Failed to connect to any of the auth servers\n");
		mark_auth_offline();
	}
	else {
		s_config *config = config_get_config();
		t_auth_serv *auth_server = NULL;

		auth_server = config->auth_servers;
		Ulog(ULOG_DEBUG, "Connected to auth server[%s]\n",auth_server->authserv_hostname);
		if(strncmp(auth_server->authserv_hostname,"0.0.0.0",strlen("0.0.0.0")))
			mark_auth_online();
	}
	return (sockfd);
}

/* Helper function called by connect_auth_server() to do the actual work including recursion
 * DO NOT CALL DIRECTLY
 @param level recursion level indicator must be 0 when not called by _connect_auth_server()
 */
int _connect_auth_server(int level) {
	s_config *config = config_get_config();
	t_auth_serv *auth_server = NULL;
	struct in_addr *h_addr;
	int num_servers = 0;
	char * hostname = NULL;
	char * popular_servers[] = {
		  "www.google.com",
		  "www.yahoo.com",
		  NULL
	};
	char ** popularserver;
	char * ip;
	struct sockaddr_in their_addr;
	int sockfd;

	/* XXX level starts out at 0 and gets incremented by every iterations. */
	level++;

	/*
	 * Let's calculate the number of servers we have
	 */
	for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
		num_servers++;
	}
	Ulog(ULOG_DEBUG, "Level %d: Calculated %d auth servers in list\n", level, num_servers);

	if (level > num_servers) {
		/*
		 * We've called ourselves too many times
		 * This means we've cycled through all the servers in the server list
		 * at least once and none are accessible
		 */
		return (-1);
	}

	/*
	 * Let's resolve the hostname of the top server to an IP address
	 */
	auth_server = config->auth_servers;
	hostname = auth_server->authserv_hostname;
	Ulog(ULOG_DEBUG, "Level %d: Resolving auth server [%s]\n", level, hostname);
	h_addr = wd_gethostbyname(hostname);
	if (!h_addr) {
		/*
		 * DNS resolving it failed
		 *
		 * Can we resolve any of the popular servers ?
		 */
		Ulog(ULOG_WARNING,"Level %d: Resolving auth server [%s] failed\n", level, hostname);

		for (popularserver = popular_servers; *popularserver; popularserver++) {
			debug(LOG_DEBUG, "Level %d: Resolving popular server [%s]", level, *popularserver);
			h_addr = wd_gethostbyname(*popularserver);
			if (h_addr) {
				debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] succeeded = [%s]", level, *popularserver, inet_ntoa(*h_addr));
				break;
			}
			else {
				Ulog(ULOG_WARNING,"Level %d: Resolving popular server [%s] failed\n", level, *popularserver);
			}
		}

		/* 
		 * If we got any h_addr buffer for one of the popular servers, in other
		 * words, if one of the popular servers resolved, we'll assume the DNS
		 * works, otherwise we'll deal with net connection or DNS failure.
		 */
		if (h_addr) {
			free (h_addr);
			/*
			 * Yes
			 *
			 * The auth server's DNS server is probably dead. Try the next auth server
			 */
			Ulog(ULOG_DEBUG, "Level %d: Marking auth server [%s] as bad and trying next if possible\n", level, hostname);
			if (auth_server->last_ip) {
				free(auth_server->last_ip);
				auth_server->last_ip = NULL;
			}
			mark_auth_server_bad(auth_server);
			return _connect_auth_server(level);
		}
		else {
			/*
			 * No
			 *
			 * It's probably safe to assume that the internet connection is malfunctioning
			 * and nothing we can do will make it work
			 */
			Ulog(ULOG_DEBUG,"Level %d: Failed to resolve auth server and all popular servers. "
					"The internet connection is probably down is_online()=%d\n", level,is_online());
			mark_offline();
			return(-1);
		}
	}
	else {
		/*
		 * DNS resolving was successful
		 */
		ip = safe_strdup(inet_ntoa(*h_addr));
		Ulog(ULOG_DEBUG, "Level %d: Resolving auth server [%s] succeeded = [%s]\n", level, hostname, ip);

		if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) {
			/*
			 * But the IP address is different from the last one we knew
			 * Update it
			 */
			Ulog(ULOG_DEBUG,"Level %d: Updating last_ip IP of server [%s] to [%s]\n", level, hostname, ip);
			if (auth_server->last_ip) free(auth_server->last_ip);
			auth_server->last_ip = ip;

			/* Update firewall rules */
			fw_clear_authservers();
			fw_set_authservers();
		}
		else {
			/*
			 * IP is the same as last time
			 */
			free(ip);
		}

		/*
		 * Connect to it
		 */
		debug(LOG_DEBUG, "Level %d: Connecting to auth server %s:%d\n", level, hostname, auth_server->authserv_http_port);
		their_addr.sin_family = AF_INET;
		their_addr.sin_port = htons(auth_server->authserv_http_port);
		their_addr.sin_addr = *h_addr;
		memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));
		free (h_addr);

		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			Ulog(ULOG_WARNING, "Level %d: Failed to create a new SOCK_STREAM socket: %s\n", strerror(errno));
			return(-1);
		}

		if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
			/*
			 * Failed to connect
			 * Mark the server as bad and try the next one
			 */
			Ulog(ULOG_DEBUG, "Level %d: Failed to connect to auth server %s:%d (%s). Marking it as bad and trying next if possible\n", level, hostname, auth_server->authserv_http_port, strerror(errno));
			close(sockfd);
			mark_auth_server_bad(auth_server);
			return _connect_auth_server(level); /* Yay recursion! */
		}
		else {
			/*
			 * We have successfully connected
			 */
			debug(LOG_DEBUG, "Level %d: Successfully connected to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
			return sockfd;
		}
	}
}
