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

/* $Id: auth.c 1373 2008-09-30 09:27:40Z wichert $ */
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>

#include "httpd.h"
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"
#include "log.h"
#include <sys/time.h>


/* Defined in clientlist.c */
extern	pthread_mutex_t	client_list_mutex;

/* Defined in util.c */
extern long served_this_session;

/** @internal
Do not use directly, use the debug macro */
#define SD_PATH "/mnt/share/"
#define LOG_PATH "/mnt/share/log"
#define LOG_NAME "/mnt/share/log/phonenumber"


/*char to upper case*/
void str2upper(char *s, int len)
{
	int i;

	for (i=0; i<len; i++)
	{
		if (s[i]>='a' && s[i]<='z')
			s[i] -= 0x20;
	}
}
/*char to lower case*/
void str2lower(char *s, int len)
{
	int i;

	for (i=0; i<len; i++)
	{
		if (s[i]>='A' && s[i]<='Z')
			s[i] += 0x20;
	}
}

/* write auth sucess to log */
void
authlog(char* phoneMac, char* phoneNumber)
{

    char buf[128], datetime[32] = {0};
	char *mac;
	time_t ts;
	struct tm *p;
	struct timeval start;


	s_config *config = config_get_config();

	if ( access(SD_PATH, F_OK))
	{
		return ; //sd card not exist 
	}

	if ( access(LOG_PATH, F_OK))
	{
		if (mkdir(LOG_PATH, 0755) < 0) //log path not exist
		return; 
	}

	if ((mac = get_iface_mac(config->external_interface)) == NULL)
	{
		return ; //get mac fail
	}
	str2lower(mac, strlen(mac)); //to lower

	time(&ts);
	p = localtime(&ts);

	snprintf(buf,sizeof(buf), "%s_%s_%d%02d%02d.log", LOG_NAME, mac,p->tm_year + 1900, p->tm_mon + 1, p->tm_mday);

	FILE *fp = fopen(buf, "a");

	if (fp)
	{
		gettimeofday(&start, NULL);

		fprintf(fp, "{\"phone_mac\":\"%s\",\"phone_number\": \"%s\", \"time\": %d%03d} \n", phoneMac, phoneNumber, start.tv_sec, start.tv_usec/1000);
	}
		
	fclose(fp);

	return ; 

}


/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/  
void
thread_client_timeout_check(const void *arg)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	
	while (1) {
		/* Sleep for config.checkinterval seconds... */
		timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	
		debug(LOG_DEBUG, "Running fw_counter()");
	
		fw_client_expire_time_check();
	}
}



void 
thread_weixin_timeout_check(const void *arg)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	
	while (1) {
		/* Sleep for config.checkinterval seconds... */
		timeout.tv_sec = time(NULL) + 20;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	
		debug(LOG_DEBUG, "Running fw_counter()");
	
		fw_weixin_expire_time_check();
	}

}

/** Authenticates a single client against the central server and returns when done
 * Alters the firewall rules depending on what the auth server says
@param r httpd request struct
return : 0  云不在白名单
	 1  云在白名单
	 2  出错
*/
int
authenticate_client(request *r,int is_ssid_id,char *ssid_id)
{
	t_client	*client;
	t_authresponse	auth_response;
	char	*mac,
		*token;
	int ret_send_cloud,ret_send_cloud_tmp;
	int is_allow;

	LOCK_CLIENT_LIST();

	client = client_list_find_by_ip(r->clientAddr);

	if (client == NULL) {
		Ulog(ULOG_ERR, "Could not find client for %s\n", r->clientAddr);
		UNLOCK_CLIENT_LIST();
		return 2;
	}

//	httpVar *type = NULL; type = httpdGetVariableByName(r, "type");if(type){debug(LOG_ERR, "type = %s", type->value);}
//	int authtype = 0; if(type){client->type = atoi(type->value); authtype = client->type;}
	int authtype = 0; 
	
	mac = safe_strdup(client->mac);
	token = safe_strdup(client->token);
	ret_send_cloud = client->ret_send_cloud;
	if(ret_send_cloud == 0)
		client->ret_send_cloud = 1;
	is_allow = client->is_allow;

	UNLOCK_CLIENT_LIST();

	if(ret_send_cloud == 2){
		free(token);
		free(mac);
		Ulog(ULOG_DEBUG,"其他线程已询问过云，is_allow = %d\n",is_allow);
		return is_allow;
	}

	if(ret_send_cloud){
		int i;
		for(i=0;i<2;i++){
			Ulog(ULOG_DEBUG,"其他线程已向云发送询问，正在等待结果...\n");
			sleep(1);
			LOCK_CLIENT_LIST();
		        client = client_list_find(r->clientAddr, mac);

		        if (client == NULL) {
		                debug(LOG_ERR, "Could not find client node for %s (%s)", r->clientAddr, mac);
		                free(token);
		                free(mac);
		                UNLOCK_CLIENT_LIST();
		                return 2;
		        }
			ret_send_cloud = client->ret_send_cloud;
			if(ret_send_cloud == 0)
				client->ret_send_cloud = 1;
			is_allow = client->is_allow;
			UNLOCK_CLIENT_LIST();
			if(ret_send_cloud == 2){
				free(token);
				free(mac);
				Ulog(ULOG_DEBUG,"-其他线程已询问过云，is_allow = %d\n",is_allow);
				return is_allow;
			}else if(ret_send_cloud == 0){
				break;
			}
		}
		Ulog(ULOG_DEBUG,"其他线程询问云未得到结果，本线程将再次请求\n");
		//free(token);
		//free(mac);
		//return 0;
	}
	
	Ulog(ULOG_DEBUG, "本线程向云发送询问请求...\n");
	/* 
	 * At this point we've released the lock while we do an HTTP request since it could
	 * take multiple seconds to do and the gateway would effectively be frozen if we
	 * kept the lock.
	 */
	auth_server_request(&auth_response, REQUEST_TYPE_LOGIN, r->clientAddr, mac, token, 0, 0, authtype);
	
	LOCK_CLIENT_LIST();
	
	/* can't trust the client to still exist after n seconds have passed */
	client = client_list_find(r->clientAddr, mac);
	
	if (client == NULL) {
		debug(LOG_ERR, "Could not find client node for %s (%s)", r->clientAddr, mac);
		free(token);
		free(mac);
		UNLOCK_CLIENT_LIST();
		return 2;
	}
	free(token);
	free(mac);

	if(auth_response.authcode == AUTH_ALLOWED) {
		/* Prepare some variables we'll need below */
		/* Logged in successfully as a regular account */
		debug(LOG_INFO, "isweixin:%d", client->isweixin); client->isweixin = 0;
//		authlog(client->mac, auth_response.authphone); // add auth success log 
//		fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
		client->ret_send_cloud = 2;
		client->is_allow = 1;	
		UNLOCK_CLIENT_LIST();
		Ulog(ULOG_DEBUG,"本线程已询问过云，is_allow = %d\n",is_allow);
		return 1;
	}else if(auth_response.authcode == AUTH_DENIED){
		client->ret_send_cloud = 2;
		client->is_allow = 0;
		UNLOCK_CLIENT_LIST();
		Ulog(ULOG_DEBUG,"本线程已询问过云，is_allow = %d\n",is_allow);
		return 0;
	}

	client->ret_send_cloud = 0;
	client->is_allow = 0;
	UNLOCK_CLIENT_LIST();
	Ulog(ULOG_DEBUG,"本线程询问云未得到回复，需再次询问\n");
//	if(auth_response.authcode == AUTH_DENIED) {
//		UNLOCK_CLIENT_LIST();
//		return 2;
//	}
	return 2;
}

