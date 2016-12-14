#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include "sem_util.h"
#include "log.h"
#include "conf.h"

#define SDCARD_LOG_DIR "/mnt/share/Wlog"
#define SDCARD_DIR "/mnt/share"
#define LOG_FILENAME "DOG"
#define LOG_SAVE_DAYS 7

SemHandl_t Handl_log;

int global_log_level;
int log_show_function = 1;
int log_show_pid = 1;
int log_show_file = 1;
int log_show_level = 1;
int log_show_date = 1;

FILE *log_stream = NULL;
char LOG_PATH[512];

int  log_day = 0;
volatile struct tm t_logold;

void log_set_level(int level)
{
	global_log_level = level;
}

static void log_fresh_fd(void)
{
    	struct  tm *tmnow,*rm_tmnow;
	time_t  tnow,rm_tnow;
	char rmlogcmd[128]={0};
	char rm_file_name[128]={0};
	int i;
	static int isfflag = 1;

	tnow = time(NULL);
	tmnow = localtime(&tnow);

	if(isfflag){
		t_logold.tm_mday = tmnow->tm_mday;
		t_logold.tm_mon = tmnow->tm_mon;
		t_logold.tm_year = tmnow->tm_year;
	}

    if(isfflag || (t_logold.tm_mday != tmnow->tm_mday) || (t_logold.tm_mon != tmnow->tm_mon) || (t_logold.tm_year != tmnow->tm_year))
    {//初次运行，或者天数更新了，则执行更新fd操作。
	t_logold.tm_mday = tmnow->tm_mday;
	t_logold.tm_mon = tmnow->tm_mon;
	t_logold.tm_year = tmnow->tm_year;

        if(!isfflag)
        {//天数更新了，则关闭原来的fd；
		if (log_stream && log_stream != stderr)
            		log_close();
        }

	if (!access(SDCARD_DIR,F_OK)){
        	log_day = tmnow->tm_mday;
        	sprintf(LOG_PATH,"%s/%04d%02d%02d-%s.log",
			SDCARD_LOG_DIR,
        	        tmnow->tm_year+1900, tmnow->tm_mon+1,tmnow->tm_mday,LOG_FILENAME);

		//今天向前推LOG_SAVE_DAYS天的日志保留，再向前推365天，查找倒数第7天与第365+7天之前的日志，若有日志则删除
		for(i=0;i<365;i++){
			rm_tnow = tnow - 24*60*60*(LOG_SAVE_DAYS+i);
			rm_tmnow = localtime(&rm_tnow);
		
			sprintf(rm_file_name,"%s/%04d%02d%02d-%s.log",SDCARD_LOG_DIR,rm_tmnow->tm_year+1900, rm_tmnow->tm_mon+1,rm_tmnow->tm_mday,LOG_FILENAME);
			if(!strcmp(rm_file_name,LOG_PATH)) break;
			if (access(rm_file_name,F_OK) == 0){
				sprintf(rmlogcmd,"rm -f %s",rm_file_name);
				system(rmlogcmd);           //删除LOG_SAVE_DAYS天前的日志
			}
		}

	        log_open(LOG_PATH);
	}else
		log_stream = stderr;

	if(isfflag)
		isfflag = 0;
    }

    return ;
}

int init_syslog(void)
{
    	char    cmd[128];

    	s_config *config = config_get_config();

    	log_set_level(config->debuglevel);
	memset(&t_logold,0,sizeof(t_logold));

	if (!access(SDCARD_DIR,F_OK)){
		if (access(SDCARD_LOG_DIR,F_OK))
		{
       			sprintf(cmd, "mkdir -p %s", SDCARD_LOG_DIR);
       			system(cmd);
       			sprintf(cmd, "chmod 777 %s", SDCARD_LOG_DIR);
       			system(cmd);
		}
	}

//	sprintf(cmd,"mkdir -p %s",SDCARD_LOG_DIR);
//	system(cmd);

	Handl_log = MakeSem();
	if(Handl_log == NULL)
		return -1;

    return 0;
}

/******************************************************************************
 *
 *  @brief                日志生成函数
 * 
 *  @param   level     :  日志信息等级
 *  @param   file      :  
 *  @param   line      ： 执行行号
 *  @param   funciton  :  调用函数名
 *  @param   format    :  日志信息正文，变长参数
 *
 ******************************************************************************/
void Ulog(int level, char *file, int line, const char *function, const char *format, ...)
{
    	SemWait(Handl_log);
    	log_fresh_fd();
	va_list ap;
	va_start(ap, format);


	if (!log_stream)
		log_stream = stderr;

	if (global_log_level >= level)
	{
		if (log_show_date)
			fprintf(log_stream, "%s", date_iso(NULL));
		if (log_show_level)
			fprintf(log_stream, " %2d", level);
		if (log_show_pid)
			fprintf(log_stream, " %5d", getpid());
		if (log_show_file)
			fprintf(log_stream, " %10s:%-4d", file, line);
		if (log_show_function && function)
			fprintf(log_stream, " %13s()", function);
		if (log_show_function || log_show_date || log_show_date || log_show_pid || log_show_file)
			fprintf(log_stream, ": ");
		vfprintf(log_stream, format, ap);
		fflush(log_stream);
        	SemRelease(Handl_log);

		if(log_stream != stderr){
			fprintf(stderr,"[%16s:%05d--%s]:",file,line,date_iso1(NULL));
    			vfprintf(stderr,format,ap);
		}
	}else{
        	SemRelease(Handl_log);
    	}

    	return ;
}

int log_open(char *filename)
{
	static char *saved_log_filename = NULL;

	if (log_stream && log_stream != stderr)
		log_close();

	if (filename == NULL && saved_log_filename)
	{
		filename = saved_log_filename;
	}

	if (filename)
	{
		if(saved_log_filename)
            		free(saved_log_filename);
		saved_log_filename = strdup(filename);
		log_stream = fopen(filename, "a+");
		if (!log_stream)
		{
			log_stream = stderr;
			return 0;
		}
		fseek(log_stream, 0, SEEK_END);
	}
	else
	{
		log_stream = stderr;
	}

	return 1;
}

int log_close()
{
	if (log_stream && log_stream != stderr)
	{
		fflush(log_stream);
		fclose(log_stream);
	}

	log_stream = stderr;
	return 1;
}

Date *date_now()
{
	time_t tt;
	Date *date;

	date = (Date *)malloc(sizeof(Date));
	tt = time(NULL);
	date->tm = localtime(&tt);

	return date;
}

void date_free(Date *date)
{
	free(date);
}

char *date_iso(Date *date)
{
	Date *tempdate;
	static char *buffer = NULL;

	tempdate = date;

	if (!tempdate)
		tempdate = date_now();

	if (!buffer) 
        buffer = (char *)malloc(20);

	sprintf(buffer, "%4d-%02d-%02d %02d:%02d:%02d", tempdate->tm->tm_year + 1900, tempdate->tm->tm_mon + 1, tempdate->tm->tm_mday,
	        tempdate->tm->tm_hour, tempdate->tm->tm_min, tempdate->tm->tm_sec);

	if (!date)
		date_free(tempdate);

	return buffer;
}

char *date_iso1(Date *date)
{
	Date *tempdate;
	static char *buffer = NULL;

	tempdate = date;

	if (!tempdate)
		tempdate = date_now();

	if (!buffer) 
        buffer = (char *)malloc(20);

	sprintf(buffer, "%02d:%02d:%02d:", tempdate->tm->tm_hour, tempdate->tm->tm_min, tempdate->tm->tm_sec);

	if (!date)
		date_free(tempdate);

	return buffer;
}

int log_get_level()
{
	return global_log_level;
}


