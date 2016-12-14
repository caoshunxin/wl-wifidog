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

/* $Id: http.c 1373 2008-09-30 09:27:40Z wichert $ */
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>

 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "httpd.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"

#include "util.h"
#include "log.h"

#include "../config.h"

#define CMS_PATH "/mnt/share/cms"
#define CMS_ERROR_PAGE "sderror.html"
#define SD_ERROR_FILE "/var/sdcard_abnormal"
#define MAC_SSIDID_FILE "/var/mac_ssidId"  //用于存储连接wifi的手机mac以及对应的ssid_id  //added by caosx 20160511
#define SSID_ID_FILE "/etc/ssidId.conf" //存储ssid及其对应的ssid_id的文件  //added by caosx 20160511
#define CHECK_SSSID_CHANGE_INTERVAL 10 //检测用户sta设备连接的ssid是否切换到其他ssid的时间间隔，单位 秒

extern long served_this_session;
extern int is_excess;
extern pthread_mutex_t	client_list_mutex;
pthread_mutex_t ssid_id_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct SNnode{
	char mac[32];		//sta  mac
	char ssid_id[64]; 	//mac连接的ssid的ssid_id
	char ssid_name[128]; 	//mac连接的ssid
	time_t add_time;	//mac发现时间
	struct SNnode *next;
}StaMacNode,*StaMacPtr;

static StaMacPtr StaMacHead = NULL;
/*added by caosx 20160531*/
unsigned long get_file_size(const char *path)
{
    unsigned long filesize = 0;
    struct stat statbuff;
    if(stat(path, &statbuff) < 0){
        return filesize;
    }else{
        filesize = statbuff.st_size;
    }
    return filesize;
}

/*added by caosx 20160510*/
char *scan_for_ssid_id(char *mac,char *ssid_name_tmp)
{
	FILE *pfFile = NULL;
	FILE *pfFile1 = NULL;
	FILE *pfFile2 = NULL;
	char ssid_info[128] = {0};
        char athx[64] = {0};
        char ssid[64] = {0};
        char cmd[64] = {0};
	char buf_mac[512]={0};
	char *reply = NULL;
        char ssid_id[64] = {0};
        char ssid_name[128] = {0};
	int isfindssid = 0;
	int isfindssidId = 0;

//	if(get_file_size(SSID_ID_FILE) == 0)
//		return reply;

	//获取mac对应的ssid
	pfFile = popen("iwconfig |grep ESSID", "r");
	if(!pfFile) return reply;
	while(fgets(ssid_info, sizeof(ssid_info), pfFile)){
		sscanf(ssid_info,"%s%*[^\"]\"%[^\"]",athx,ssid);
		sprintf(cmd,"wlanconfig %s list sta |grep :| tr -s ' '| cut -d' ' -f1",athx);
		pfFile1 = popen(cmd, "r");
		if(!pfFile1){
			pclose(pfFile);
			return reply;
		}
		fread(buf_mac,sizeof(char),sizeof(buf_mac),pfFile1);
		if(strstr(buf_mac,mac)){
			strcpy(ssid_name_tmp,ssid);
			isfindssid = 1;
			break;
		}
		pclose(pfFile1);	
	}
	pclose(pfFile);

	if(get_file_size(SSID_ID_FILE) == 0){
		reply = safe_strdup("0");
		return reply;
	}

	//获取ssid对应的ssid_id
	if(isfindssid){
		bzero(cmd,sizeof(cmd));
		sprintf(cmd,"cat %s",SSID_ID_FILE);
		pfFile2 = popen(cmd, "r");
		if(!pfFile2) return reply;
		while(fgets(ssid_info, sizeof(ssid_info), pfFile2)){
			sscanf(ssid_info,"%[^\t]\t%s",ssid_name,ssid_id);
			if(!strcmp(ssid_name,ssid)){
				isfindssidId = 1;
				break;
			}
			
		}
		pclose(pfFile2);
		if(isfindssidId)
			reply = safe_strdup(ssid_id);
	}
	return reply;
}

/*根据sta mac获取该mac所连接的ssid的ssid_id*/
char *get_ssid_id(char *mac,char *g_ssid_name)
{
	char *reply = NULL;
	char *reply1 = NULL;
	char StrSsidId[64] = {0};
	char buf_cmd[64] = {0};
	StaMacPtr StaMacTmp,StaMacPre;
	time_t now;
	FILE *pfFile=NULL;

	pthread_mutex_lock(&ssid_id_mutex);
	time(&now);

	/*从链表中查找mac对应的ssid_id*/
	StaMacTmp = StaMacHead;
	while(StaMacTmp){
		if(!strcmp(StaMacTmp->mac,mac)){
			reply = safe_strdup(StaMacTmp->ssid_id);
			strcpy(g_ssid_name,StaMacTmp->ssid_name);
			break;
		}
		StaMacTmp = StaMacTmp->next;
	};
	/*如果链表中没有查找到ssid_id，刚该mac很可能是新连接到ssid的，所以扫描设备查找，并在查找到后更新链表*/
	if(!reply){ 
		static int cnt=0;
		static int IsSsidIdFile=0;

		/*扫描新设备mac对应的ssid_id*/
		reply = scan_for_ssid_id(mac,g_ssid_name);
		if(reply){ //如果新扫描到mac对应的ssid_id，则将数据加入链表
		//if(0){ //如果新扫描到mac对应的ssid_id，则将数据加入链表

			StaMacTmp = (StaMacPtr)malloc(sizeof(StaMacNode));
			memset(StaMacTmp,0,sizeof(StaMacNode));
			StaMacTmp->add_time = now;
			strcpy(StaMacTmp->mac,mac);
			strcpy(StaMacTmp->ssid_id,reply);
			strcpy(StaMacTmp->ssid_name,g_ssid_name);
			if(StaMacHead){
				StaMacTmp->next = StaMacHead;
				StaMacHead = StaMacTmp;
			}else{
				StaMacTmp->next = NULL;
				StaMacHead = StaMacTmp;
			}

			if(!access(MAC_SSIDID_FILE,F_OK)){
				if(!IsSsidIdFile){
					sprintf(buf_cmd,"echo \"%s %s\" > %s",mac,reply,MAC_SSIDID_FILE);
					IsSsidIdFile = 1;
				}else
					sprintf(buf_cmd,"echo \"%s %s\" >> %s",mac,reply,MAC_SSIDID_FILE);
			}else{
				sprintf(buf_cmd,"touch %s&&echo \"%s %s\" > %s",MAC_SSIDID_FILE,mac,reply,MAC_SSIDID_FILE);
				IsSsidIdFile = 1;
			}
//printf(" buf_cmd= %s\n",buf_cmd);
			pfFile = popen(buf_cmd, "r");
			if(pfFile) pclose(pfFile);
//			system(buf_cmd);
		}

		cnt++;
		/*当链表数据新增到1000条时（链表大小约为100k），检测一次链表中的超时，超时时间为1小>时，这次操作将清空链表中的大部分数据*/
		if(cnt > 1000)
		{
			time_t now;
			int isfr = 1;
			now = time(&now);
			StaMacPre = StaMacTmp = StaMacHead;
			while(StaMacTmp){
				if(now - StaMacTmp->add_time >= 60*60*1){
					if(StaMacTmp == StaMacHead){
						StaMacHead = StaMacHead->next;
						free(StaMacTmp);
						StaMacPre = StaMacTmp = StaMacHead;
					}else{
						StaMacPre->next = StaMacTmp->next;
						free(StaMacTmp);
						StaMacTmp = StaMacPre->next;
					}
				}else{
					//更新链表数据存储文件
					if(isfr){
						if(!access(MAC_SSIDID_FILE,F_OK))
							sprintf(buf_cmd,"echo \"%s %s\" > %s",StaMacTmp->mac,StaMacTmp->ssid_id,MAC_SSIDID_FILE);
						else
							sprintf(buf_cmd,"touch %s&&echo \"%s %s\" > %s",MAC_SSIDID_FILE,StaMacTmp->mac,StaMacTmp->ssid_id,MAC_SSIDID_FILE);
						isfr = 0;
					}else
						sprintf(buf_cmd,"echo \"%s %s\" >> %s",StaMacTmp->mac,StaMacTmp->ssid_id,MAC_SSIDID_FILE);
					pfFile = popen(buf_cmd, "r");
                        		if(pfFile) pclose(pfFile);
				//	system(buf_cmd);

					//遍历下一个节点
					StaMacPre = StaMacTmp;
					StaMacTmp = StaMacTmp->next;
				}
			}
		}
	}else{ //如果链表中查找ssid_id，则检测该节点更新时间是否超过CHECK_SSSID_CHANGE_INTERVAL秒，如果超过CHECK_SSSID_CHANGE_INTERVAL秒，则再次扫描
		if(now - StaMacTmp->add_time > CHECK_SSSID_CHANGE_INTERVAL){
			reply1 = NULL;
			reply1 = scan_for_ssid_id(mac,g_ssid_name);
			if(reply1){
				StaMacTmp->add_time = now;
				if(strcmp(reply,reply1)){
					int isfr = 1;
					strcpy(StaMacTmp->ssid_id,reply1);
					strcpy(StaMacTmp->ssid_name,g_ssid_name);

					//更新链表数据存储文件
					StaMacTmp = StaMacHead;
					while(StaMacTmp){
						if(isfr){
							if(!access(MAC_SSIDID_FILE,F_OK))
								sprintf(buf_cmd,"echo \"%s %s\" > %s",StaMacTmp->mac,StaMacTmp->ssid_id,MAC_SSIDID_FILE);
							else
								sprintf(buf_cmd,"touch %s&&echo \"%s %s\" > %s",MAC_SSIDID_FILE,StaMacTmp->mac,StaMacTmp->ssid_id,MAC_SSIDID_FILE);
							isfr = 0;
						}else
							sprintf(buf_cmd,"echo \"%s %s\" >> %s",StaMacTmp->mac,StaMacTmp->ssid_id,MAC_SSIDID_FILE);
						pfFile = popen(buf_cmd, "r");
                        			if(pfFile) pclose(pfFile);
					//	system(buf_cmd);
						StaMacTmp = StaMacTmp->next;
					}
				}
				free(reply);
				reply = reply1;
			}
		}
	}

	pthread_mutex_unlock(&ssid_id_mutex);

	if(!reply)
		reply = safe_strdup("0");
	return reply;
}
/*end add*/

int is_cms_exist()
{

	if (0 == access(SD_ERROR_FILE, F_OK))
	{
		return (1); //sd mount error
	}

	if ( access(CMS_PATH, F_OK))
	{
		return (1); //cms path error
	}

	return (0); //cms path ok
}

char *
_client_list_make_auth_token(const char ip[], const char mac[])
{
	char *token;

	safe_asprintf(&token,"%04hx%04hx", rand16(), rand16());

	return token;
}

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_xh404(httpd *webserver, request *r)
{
	char *buf;
	char		tmp_url[MAX_BUF];
	int phone_type=0;
	t_client	*client;
	s_config	*config = config_get_config();
	t_auth_serv	*auth_server = get_auth_server();

	if(is_excess){
		safe_asprintf(&buf, "http://%s:9090%s/excess.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port); 
		http_send_redirect(r,buf,"Redirect to success"); //redirect to local page
		free(buf);
		return;
	}
	memset(tmp_url, 0, sizeof(tmp_url));
        snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
                        r->request.host,
                        r->request.path,
                        r->request.query[0] ? "?" : "",
                        r->request.query);

	char *mac = arp_get(r->clientAddr); 
	if(!mac)
	{
		return ;
	}

	LOCK_CLIENT_LIST();
	if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
		client = client_list_append(r->clientAddr, mac, "12345678");
	}
	if(client->phone_type == 0){
		if(strstr(tmp_url,"connectivitycheck.android.com"))
			client->phone_type = 1;		//安卓手机
		else if(strstr(tmp_url,"captive.apple.com"))
			client->phone_type = 2;		//苹果手机
	}
	phone_type = client->phone_type;
	UNLOCK_CLIENT_LIST();

	if(authenticate_client(r,0," ") == 1){
		LOCK_CLIENT_LIST();
		if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
			client = client_list_append(r->clientAddr, mac, "12345678");
		}

		if(client->fw_connection_state != FW_MARK_KNOWN){
			client->fw_connection_state = FW_MARK_KNOWN;
			served_this_session++;
			client->counters.last_updated = time(NULL); //update time 
			fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
		}
		UNLOCK_CLIENT_LIST();
		//debug(LOG_ERR,"\n\t\t\tIP:%s\tMAC:%s\n\t\t\tURL:%s\n",r->clientAddr,mac,tmp_url);	
		if(phone_type == 2) //如果是苹果手机
			safe_asprintf(&buf, "%s",tmp_url); 
		else
			safe_asprintf(&buf, "http://%s:9090%s/authok.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port); 
		http_send_redirect(r, buf, "Redirect to portal");
	}else{
		safe_asprintf(&buf, "%s?gw_id=%s&gw_address=%s&gw_port=%d&gw_mac=%s&gnu_version=%s&token=%s&mac=%s",
			auth_server->authserv_auth_allow_path_fragment,
			config->gw_id,
			config->gw_address, //gw_address
			config->gw_port,
			config->gw_mac,
			config->gnuversion,
			auth_server->authserv_token,
			mac);
		http_send_redirect(r, buf, "Redirect to portal");
	}
	free(buf);
	free(mac);
	return;
}

void
http_callback_404(httpd *webserver, request *r)
{
	char		tmp_url[MAX_BUF],
			*url;
	s_config	*config = config_get_config();
	t_auth_serv	*auth_server = get_auth_server();
	t_client	*client;
	char * access_token;
	int phone_type=0;
	int c_fw_connection_state = 0;

	if(is_excess){
		char *buf;
		safe_asprintf(&buf, "http://%s:9090%s/excess.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port); 
		http_send_redirect(r,buf,"Redirect to success"); //redirect to local page
		free(buf);
		return;
	}
	memset(tmp_url, 0, sizeof(tmp_url));
	/* 
	 * XXX Note the code below assumes that the client's request is a plain
	 * http request to a standard port. At any rate, this handler is called only
	 * if the internet/auth server is down so it's not a huge loss, but still.
	 */
        snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
                        r->request.host,
                        r->request.path,
                        r->request.query[0] ? "?" : "",
                        r->request.query);
	url = httpdUrlEncode(tmp_url);

	int net_state = 0 , server_state = 0;
	char * buf;
	char *localurl;
	int is_auth_allowed;

	if (is_online())  //网络是否通畅
	{
		net_state = 1; // internet 
	}
	/*added by caosx 20160510*/
	char *mac = arp_get(r->clientAddr); 
	if(!mac)
	{
		free(url);
		return ;
	}

	LOCK_CLIENT_LIST();
	if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
		if((client = client_list_find_for_mac(mac)) == NULL){  //判断是否为已认证mac，但ip改变 //added by caosx 20160817
			Ulog(ULOG_NOTICE, "[%s][%s]New client added\n",mac, r->clientAddr);
			access_token = _client_list_make_auth_token(r->clientAddr, mac);
			client = client_list_append(r->clientAddr, mac, access_token);
		}else{
			Ulog(ULOG_NOTICE,"[%s][%s]ip_changed\n",mac, r->clientAddr);
			if(client->fw_connection_state == FW_MARK_KNOWN){
				fw_allow(r->clientAddr, mac, FW_MARK_KNOWN);//添加新ip的放行规则
				fw_deny(client->ip, client->mac, client->fw_connection_state);//删除旧的放行规则

				if(client->ip != NULL)  //替换链表中的ip
					free(client->ip);
				client->ip = safe_strdup(r->clientAddr);
				UNLOCK_CLIENT_LIST();
	                	char *buf;
	                	safe_asprintf(&buf, "http://%s:9090%s/ip_change.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port);
	                	http_send_redirect(r,buf,"Redirect to success"); //redirect to local page
	                	free(buf);
				return ;
			}
			if(client->ip != NULL)  //替换链表中的ip
				free(client->ip);
			client->ip = safe_strdup(r->clientAddr);
			access_token = safe_strdup(client->token);
		}
	}else{
		access_token = safe_strdup(client->token);
		c_fw_connection_state = client->fw_connection_state;
	} 
	if(client->phone_type == 0){
		if(strstr(tmp_url,"connectivitycheck.android.com"))
			client->phone_type = 1;		//安卓手机
		else if(strstr(tmp_url,"captive.apple.com"))
			client->phone_type = 2;		//苹果手机
	}
	phone_type = client->phone_type;
	UNLOCK_CLIENT_LIST();

	safe_asprintf(&localurl, "http://%s:%d",config->gw_address,config->gw_port); //local portal page 
	/*end add*/
	if (is_auth_online())  //认证服务器是否连接正常
	{
		char *ssid_name[128]={0};
       		char *ssid_id = get_ssid_id(mac,ssid_name);			
		char *iosredurl;

		server_state = 1 ; //auth server
		is_auth_allowed = authenticate_client(r,0," ");

		auth_server = get_auth_server();
		config = config_get_config();

		if(c_fw_connection_state == FW_MARK_KNOWN){ //若已认证，直接跳转到外网portal
	                safe_asprintf(&buf, "%s?gw_id=%s&gw_address=%s&gw_port=%d&gw_mac=%s&mac=%s&ssid_id=%s",
	                        auth_server->authserv_portal_script_path_fragment,
	                        config->gw_id,
               		        config->gw_address, //gw_address
                       		config->gw_port,
                       		config->gw_mac,
                       		mac,
                       		ssid_id);
		
                	http_send_redirect_to_auth(r, buf, "Redirect to portal");
		}else if(is_auth_allowed == 1){//在云白名单中，跳转到免认证页
//			if(config->gnuversion[6] == 'g'){
			if(config->portal_type[0] == '2'){
				LOCK_CLIENT_LIST();
				if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
					debug(LOG_ERR, "Not found c_phone for %s", r->clientAddr);
				}else{
					if(client->fw_connection_state != FW_MARK_KNOWN){
						client->fw_connection_state = FW_MARK_KNOWN;
						served_this_session++;
					}
					client->counters.last_updated = time(NULL); //update time 
					fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
				}
				UNLOCK_CLIENT_LIST();
				//debug(LOG_ERR,"\n\t\t\tIP:%s\tMAC:%s\n\t\t\tURL:%s\n",r->clientAddr,mac,tmp_url);	
				if(phone_type == 2) //如果是苹果手机
					safe_asprintf(&buf, "%s",tmp_url); 
				else
					safe_asprintf(&buf, "http://%s:9090%s/authok.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port); 
				http_send_redirect(r, buf, "Redirect to portal");
			}else{
				char *c_phone = NULL;
				LOCK_CLIENT_LIST();
				if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
					debug(LOG_ERR, "Not found c_phone for %s", r->clientAddr);
					c_phone = safe_strdup("null");
				}else{
					c_phone = safe_strdup(client->phone);
				} 
				UNLOCK_CLIENT_LIST();
				safe_asprintf(&buf, "%s?gw_id=%s&gw_address=%s&gw_port=%d&gw_mac=%s&gnu_version=%s&token=%s&mac=%s&access_token=%s&ssid_id=%s&cell_no=%s&ssid=%s",
					auth_server->authserv_auth_allow_path_fragment,
					config->gw_id,
					config->gw_address, //gw_address
					config->gw_port,
					config->gw_mac,
					config->gnuversion,
					auth_server->authserv_token,
					mac,
					access_token,
					ssid_id,c_phone,ssid_name);
				if(c_phone)
					free(c_phone); 
				http_send_redirect(r, buf, "Redirect to portal");
			}
		}else if(is_auth_allowed == 0){//不在云白名单中，跳转到手机认证页
			safe_asprintf(&buf, "%s?gw_id=%s&gw_address=%s&gw_port=%d&gw_mac=%s&gnu_version=%s&portal_address=%s&portal_port=%d&token=%s&mac=%s&ssid_id=%s&cloud_version=v2.0&ssid=%s",
				auth_server->authserv_login_script_path_fragment,
				config->gw_id,
				config->gw_address, //gw_address
				config->gw_port,
				config->gw_mac,
				config->gnuversion,
				auth_server->authserv_hostname, auth_server->authserv_http_port,
				auth_server->authserv_token,
				mac,
				ssid_id,ssid_name); 
			http_send_redirect(r, buf, "Redirect to portal");
		}else if(is_auth_allowed == 2){  //未收到云回复或其他异常，提示用户认证失败/重试
//			safe_asprintf(&buf, "http://%s:9090%s/auth-failure.html?local_url=%s&net_state=%d&server_state=%d",config->gw_address,config->gw_path,localurl,net_state, server_state); 
//			http_send_redirect(r, buf, "Redirect to portal");
			LOCK_CLIENT_LIST();
			if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
				debug(LOG_ERR, "Not found c_phone for %s", r->clientAddr);
			}else{
				if(client->fw_connection_state != FW_MARK_KNOWN){
					client->fw_connection_state = FW_MARK_KNOWN;
					served_this_session++;
				}
				client->counters.last_updated = time(NULL); //update time 
				fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
			}
			UNLOCK_CLIENT_LIST();
			//debug(LOG_ERR,"\n\t\t\tIP:%s\tMAC:%s\n\t\t\tURL:%s\n",r->clientAddr,mac,tmp_url);	
			if(phone_type == 2) //如果是苹果手机
				safe_asprintf(&buf, "%s",tmp_url); 
			else
				safe_asprintf(&buf, "http://%s:9090%s/authok.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port); 
			http_send_redirect(r, buf, "Redirect to portal");
		}

		free(ssid_id);
	}	
	else
	{
		//认证服务器不通时，网络通畅，让用户上网，网络不通，提示用户网络故障
		server_state = 0 ; //auth server
		if (is_online()){  //网络是否通畅
			LOCK_CLIENT_LIST();
			if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
				debug(LOG_ERR, "Not found c_phone for %s", r->clientAddr);
			}else{
				if(client->fw_connection_state != FW_MARK_KNOWN){
					client->fw_connection_state = FW_MARK_KNOWN;
					served_this_session++;
				}
				client->counters.last_updated = time(NULL); //update time 
				fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
			}
			UNLOCK_CLIENT_LIST();
			//debug(LOG_ERR,"\n\t\t\tIP:%s\tMAC:%s\n\t\t\tURL:%s\n",r->clientAddr,mac,tmp_url);	
			if(phone_type == 2) //如果是苹果手机
				safe_asprintf(&buf, "%s",tmp_url); 
			else
				safe_asprintf(&buf, "http://%s:9090%s/authok.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port); 
			http_send_redirect(r, buf, "Redirect to portal");
		}else{
			safe_asprintf(&buf, "http://%s:9090%s?token=%s&gw_address=%s&gw_port=%d&gw_id=%s&mac=%s&url=%s&local_url=%s&portal_address=%s&portal_port=%d&net_state=%d&server_state=%d&gnu_version=%s",
				config->gw_address,config->gw_path,
				auth_server->authserv_token,
				config->gw_address, config->gw_port, config->gw_id, 
				mac,
				url, localurl,
				auth_server->authserv_hostname, auth_server->authserv_http_port,
				net_state, server_state, config->gnuversion); 
			http_send_redirect(r,buf,"Redirect to success"); //redirect to local page
		}
	}

	free(mac);  //added by caosx 20160510
	free(localurl);
	free(buf);
	free(url);
	free(access_token);
}

void 
http_callback_wifidog(httpd *webserver, request *r)
{
	send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void 
http_callback_about(httpd *webserver, request *r)
{
	send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

void 
http_callback_status(httpd *webserver, request *r)
{
	const s_config *config = config_get_config();
	char * status = NULL;
	char *buf;

	if (config->httpdusername && 
			(strcmp(config->httpdusername, r->request.authUser) ||
			 strcmp(config->httpdpassword, r->request.authPassword))) {
		debug(LOG_INFO, "Status page requested, forcing authentication");
		httpdForceAuthenticate(r, config->httpdrealm);
		return;
	}

	status = get_status_text();
	safe_asprintf(&buf, "<pre>%s</pre>", status);
	send_http_page(r, "WiFiDog Status", buf);
	free(buf);
	free(status);
}
/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request 
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
/*
void http_send_redirect_to_auth_back(request *r, char *urlFragment, char *text)
{
	char *protocol = NULL;
	int port = 80;
	t_auth_serv	*auth_server = get_auth_server();

	if (auth_server->authserv_use_ssl) {
		protocol = "https";
		port = auth_server->authserv_ssl_port;
	} else {
		protocol = "http";
		port = auth_server->authserv_cmshttp_port;
	}
			    		
	char *url = NULL;
	safe_asprintf(&url, "%s://%s:%d%s%s",
		protocol,
		auth_server->authserv_cmshostname,
		port,
		auth_server->authserv_path,
		urlFragment
	);
	http_send_redirect(r, url, text);
	free(url);	
}
*/
void http_send_redirect_to_auth(request *r, char *urlFragment, char *text)
{
	char *url = NULL;
	safe_asprintf(&url, "%s",urlFragment);
	http_send_redirect(r, url, text);
	free(url);	
}

/** @brief Sends a redirect to the web browser 
 * @param r The request 
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void http_send_redirect(request *r, char *url, char *text)
{
		char *message = NULL;
		char *header = NULL;
		char *response = NULL;
							/* Re-direct them to auth server */
		Ulog(ULOG_DEBUG, "Redirecting client browser to %s\n", url);
		safe_asprintf(&header, "Location: %s",
			url
		);
		if(text) {
			safe_asprintf(&response, "307 %s\n",
				text
			);	
		}
		else {
			safe_asprintf(&response, "307 %s\n",
				"Redirecting"
			);		
		}	
		httpdSetResponse(r, response);
		httpdAddHeader(r, header);
		free(response);
		free(header);	
		safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
		send_http_page(r, text ? text : "Redirection to message", message);
		free(message);
}

/*wf*/
void 
http_callback_weixin(httpd *webserver, request *r)
{
	t_client *client;
	char	*mac;
		if (!(mac = arp_get(r->clientAddr))) {
			/* We could not get their MAC address */
			debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
		} else {

			LOCK_CLIENT_LIST();		
			if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
				Ulog(ULOG_NOTICE, "[%s][%s]New client added\n",mac, r->clientAddr);
				client = client_list_append(r->clientAddr, mac, "d4df0de1");
			}
			fw_allow(r->clientAddr, mac, FW_MARK_KNOWN);
			client->isweixin = 1;
			client->weixin_timeout = 0;
			if(client->fw_connection_state != FW_MARK_KNOWN){
				client->fw_connection_state = FW_MARK_KNOWN;
				served_this_session++;
				httpd_sendwx(r);
			}else{
				httpd_ky_send200(r);
			}
			UNLOCK_CLIENT_LIST();
			free(mac);  //added by caosx 20160510
		}

}

void 
http_callback_auth(httpd *webserver, request *r)
{
	t_client	*client;
	httpVar * token;
	httpVar * csx_token;
	char * c_token;
	char	*mac;
	httpVar *logout = httpdGetVariableByName(r, "logout");
	csx_token = httpdGetVariableByName(r,"csx_token");
	//if ((token = httpdGetVariableByName(r, "token"))) {
	token = httpdGetVariableByName(r, "access_token");
	if (token || logout ) {// our key is access_token
		/* They supplied variable "token" */
		if (!(mac = arp_get(r->clientAddr))) {
			char *tokenbuf;
			s_config *config = config_get_config();
			/* We could not get their MAC address */
			debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			//send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
			safe_asprintf(&tokenbuf, "http://%s:9090%s/tokennosame.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port);
			http_send_redirect(r,tokenbuf,"Redirect to success");
			free(tokenbuf);
		} else {
			/* We have their MAC address */

			LOCK_CLIENT_LIST();
			
			if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
				char *tokenbuf;
				s_config *config = config_get_config();
				Ulog(ULOG_DEBUG, "error client for %s\n", r->clientAddr);
				//client_list_append(r->clientAddr, mac, token->value);
				//send_http_page(r, "auth-failure", "Failed to retrieve your MAC address");
				safe_asprintf(&tokenbuf, "http://%s:9090%s/tokennosame.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port);
				http_send_redirect(r,tokenbuf,"Redirect to success");
				free(tokenbuf);
			} else if (logout) {
			//} else if (0) {
			    t_authresponse  authresponse;
			    s_config *config = config_get_config();
			    //unsigned long long incoming = client->counters.incoming;
			    //unsigned long long outgoing = client->counters.outgoing;
			    //char *ip = safe_strdup(client->ip);
			    //char *urlFragment = NULL;
			    //t_auth_serv	*auth_server = get_auth_server();
			    				    	
			    fw_deny(client->ip, client->mac, client->fw_connection_state);
			    Ulog(ULOG_DEBUG, "Got logout from %s\n", client->ip);
			    client_list_delete(client);
			  
			    httpd_send200c(r,config->gw_id);  
			    /* Advertise the logout if we have an auth server */
			    /*if (config->auth_servers != NULL) {
					UNLOCK_CLIENT_LIST();
					auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT, ip, mac, token->value, 
									    incoming, outgoing, 0);
					LOCK_CLIENT_LIST();
					*/
					/* Re-direct them to auth server */
					/*debug(LOG_INFO, "Got manual logout from client ip %s, mac %s, token %s"
					"- redirecting them to logout message", client->ip, client->mac, client->token);
					safe_asprintf(&urlFragment, "%smessage=%s",
						auth_server->authserv_msg_script_path_fragment,
						GATEWAY_MESSAGE_ACCOUNT_LOGGED_OUT
					);
					http_send_redirect_to_auth(r, urlFragment, "Redirect to logout message");
					free(urlFragment);
					//UNLOCK_CLIENT_LIST();
			    }
			    free(ip);*/
 			}else{

				httpVar *type = NULL; type = httpdGetVariableByName(r, "type");if(type){debug(LOG_DEBUG, "type = %s", type->value);}
				int authtype = 0; if(type){client->type = atoi(type->value); authtype = client->type;}

				c_token = safe_strdup(client->token);

				if((strcmp(c_token,token->value) == 0) || (csx_token && (strcmp(c_token,csx_token->value) == 0))){
					
					client->isweixin = 0;//无论是否是微信认证，认证通过都需要置0
					httpVar *stadev = httpdGetVariableByName(r, "sta_dev");
					if(authtype){
						httpVar *authphone = httpdGetVariableByName(r, "cell_no");
						if(authphone){
							if(authphone->value){
								if(client->phone)
									free(client->phone);
                                	        		client->phone = safe_strdup(authphone->value);
							}
						}
						debug(LOG_INFO, "isweixin:%d", client->isweixin); 
						Ulog(ULOG_NOTICE, "[%s][%s]weixin auth success\n",client->mac,client->ip);
						//UNLOCK_CLIENT_LIST();
						httpd_send200(r);
					}else{
						httpVar *authphone = httpdGetVariableByName(r, "cell_no");
						if(authphone){
							if(authphone->value){
								if(client->phone)
									free(client->phone);
                                	        		client->phone = safe_strdup(authphone->value);
							}
						}
						if(client->fw_connection_state != FW_MARK_KNOWN){
							client->fw_connection_state = FW_MARK_KNOWN;
							served_this_session++;
						}
						client->counters.last_updated = time(NULL); //update time 
						fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
						Ulog(ULOG_NOTICE, "[%s][%s]phone auth success\n",client->mac,client->ip);
						//UNLOCK_CLIENT_LIST();
	
						char ssid_name[128]={0};
			                        char *ssid_id = get_ssid_id(mac,ssid_name);			
				                char *urlFragment = NULL;
						s_config *config = config_get_config();
						t_auth_serv *auth_server = get_auth_server();
				                safe_asprintf(&urlFragment, "%s?gw_id=%s&gw_address=%s&gw_port=%d&gw_mac=%s&mac=%s&ssid_id=%s",
				                        auth_server->authserv_portal_script_path_fragment,
				                        config->gw_id,
		                		        config->gw_address, //gw_address
		                        		config->gw_port,
		                        		config->gw_mac,
		                        		mac,
		                        		ssid_id);
		
                				http_send_redirect_to_auth(r, urlFragment, "Redirect to portal");
                				free(urlFragment);
						free(ssid_id);
					}
				}else{
					//UNLOCK_CLIENT_LIST();
					//token非法
					char token_tmp[64]={0};
					char *tokenbuf;
			    		s_config *config = config_get_config();

					strcpy(token_tmp,"Invalid token: ");
					strcat(token_tmp,token->value);
					Ulog(ULOG_NOTICE, "[%s][%s]token值%s非法(正确token：%s)\n",client->mac,client->ip,token->value,c_token);
					//send_http_page(r, "auth-failure", token_tmp);
					safe_asprintf(&tokenbuf, "http://%s:9090%s/tokennosame.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port);
					http_send_redirect(r,tokenbuf,"Redirect to success");
					free(tokenbuf);
				}
				free(c_token);
			}
			free(mac);
			UNLOCK_CLIENT_LIST();
		}
	} else {
		/* They did not supply variable "token" */
		send_http_page(r, "auth-failure", "Missing values");
	}
}

void 
http_callback_xhauth(httpd *webserver, request *r)
{
	t_client	*client;
	char	*mac;
	httpVar *action = httpdGetVariableByName(r, "action");
	if (action) {// our key is access_token
		/* They supplied variable "token" */
		if (!(mac = arp_get(r->clientAddr))) {
			char *tokenbuf;
			s_config *config = config_get_config();
			/* We could not get their MAC address */
			debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
			//send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
			safe_asprintf(&tokenbuf, "http://%s:9090%s/tokennosame.html?local_url=http://%s:%d",config->gw_address,config->gw_path,config->gw_address,config->gw_port);
			http_send_redirect(r,tokenbuf,"Redirect to success");
			free(tokenbuf);
		} else {
			/* We have their MAC address */
			httpVar *token = httpdGetVariableByName(r, "token");
			LOCK_CLIENT_LIST();
			if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
				s_config *config = config_get_config();
				Ulog(ULOG_DEBUG, "error client for %s\n", r->clientAddr);
				if(token)
					client = client_list_append(r->clientAddr, mac, token->value);
				else
					client = client_list_append(r->clientAddr, mac, "12345678");
			}

			if (strcmp(action->value,"logout") == 0) {
			    t_authresponse  authresponse;
			    s_config *config = config_get_config();

			    fw_deny(client->ip, client->mac, client->fw_connection_state);
			    Ulog(ULOG_DEBUG, "Got logout from %s\n", client->ip);
			    client_list_delete(client);
			  
			    httpd_send200c(r,config->gw_id);  
 			}else if (strcmp(action->value,"login") == 0){
				if(token){
					t_authresponse  authresponse;
					httpVar *authphone = httpdGetVariableByName(r, "cell_no");
					char *c_phone = NULL;
					if(authphone){
						if(authphone->value){
                        	      	        	client->phone = safe_strdup(authphone->value);
							c_phone = safe_strdup(authphone->value);
						}
					}

					UNLOCK_CLIENT_LIST();
					xhauth_server_request(&authresponse, REQUEST_TYPE_LOGOUT, r->clientAddr, mac,token->value,0, 0,0,c_phone); //向云平台请求认证
					free(c_phone);
					LOCK_CLIENT_LIST();
					
					if(authresponse.authcode == AUTH_ALLOWED){ 
						if(client->fw_connection_state != FW_MARK_KNOWN){
							client->fw_connection_state = FW_MARK_KNOWN;
							served_this_session++;
						}
						client->counters.last_updated = time(NULL); //update time 
						fw_allow(client->ip, client->mac, FW_MARK_KNOWN);
						Ulog(ULOG_NOTICE, "[%s][%s]token auth success\n",client->mac,client->ip);
						s_config *config = config_get_config();
			    			httpd_send200c(r,config->gw_id);  
					}else if(authresponse.authcode == AUTH_DENIED){
						Ulog(ULOG_NOTICE, "[%s][%s]token auth failed\n",client->mac,client->ip);
						httpd_send200c(r,"error:token auth failed");
					}else{
						Ulog(ULOG_NOTICE, "[%s][%s]认证服务器访问超时\n",client->mac,client->ip);
						httpd_send200c(r,"error:认证服务器访问超时");
					}
				}else{
					Ulog(ULOG_NOTICE, "[%s][%s]上线请求缺少token参数\n",client->mac,client->ip);
					httpd_send200c(r,"error:上线请求缺少token参数");
				}
			}else{
				Ulog(ULOG_NOTICE, "[%s][%s]参数action错误\n",client->mac,client->ip);
				httpd_send200c(r,"error：参数action错误");
			}
			free(mac);
			UNLOCK_CLIENT_LIST();
		}
	} else {
		Ulog(ULOG_NOTICE, "[%s][%s]Missing values\n",client->mac,client->ip);
		httpd_send200c(r,"error:Missing values");
	}
}

void substring(char *dest,char *src,int start,int end)  
{  
    int i=start;  
    if(start>strlen(src))return;  
    if(end>strlen(src))  
        end=strlen(src);  
    while(i<end)  
    {     
        dest[i-start]=src[i];  
        i++;  
    }  
    dest[i-start]='\0';  
    return;  
} 

void send_http_page(request *r, const char *title, const char* message)
{
    s_config	*config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;
    char dstnodeID[16]={0};

    fd=open(config->htmlmsgfile, O_RDONLY);
    if (fd==-1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info)==-1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }

    buffer=(char*)safe_malloc(stat_info.st_size+1);
    written=read(fd, buffer, stat_info.st_size);
    if (written==-1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written]=0;
    substring(dstnodeID,config->gw_id,strlen(config->gw_id)-8,strlen(config->gw_id));
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    if(dstnodeID[0])
    	httpdAddVariable(r, "nodeID", dstnodeID);
    else
    	httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}

