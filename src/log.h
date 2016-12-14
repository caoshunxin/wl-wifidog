
#ifndef __LOG_H__
#define __LOG_H__

#define ULOG_EMERG	    0, __FILE__, __LINE__, __FUNCTION__     //紧急状态（系统不可使用）（最高优先级）
#define ULOG_ALERT   	1, __FILE__, __LINE__, __FUNCTION__     //必须立即修复的状态
#define ULOG_CRIT	    2, __FILE__, __LINE__, __FUNCTION__     //严重状态（例如，硬设备出错）
#define ULOG_ERR 	    3, __FILE__, __LINE__, __FUNCTION__     //出错状态
#define ULOG_WARNING	    4, __FILE__, __LINE__, __FUNCTION__     //警告状态
#define ULOG_NOTICE	    5, __FILE__, __LINE__, __FUNCTION__     //正常，但重要的状态
#define ULOG_INFO	    6, __FILE__, __LINE__, __FUNCTION__     //信息性消息
#define ULOG_DEBUG	    7, __FILE__, __LINE__, __FUNCTION__     //调试消息（最低优先级）
//#define false		0
//#define true		!false
#define VALIDSTR(x)	(x != NULL && *x != 0)

typedef struct
{
    struct tm *tm;
}Date;

extern int log_show_function;
extern int log_show_pid;
extern int log_show_file;
extern int log_show_level;
extern int log_show_date;

int init_syslog(void);
extern void Ulog(int level, char *file, int line, const char *function, const char *format, ...);
void log_set_level(int level);
int  log_get_level();
int  log_open(char *filename);
int  log_close();
Date *date_now();
void date_free(Date *date);
char *date_iso(Date *date);
char *date_iso1(Date *date);

#endif

