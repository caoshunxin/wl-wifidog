
/******************************************************************************
 *
 *  @file   sem_util.c
 *
 *  @date   2016.04.08
 *
 *  @author 曹顺新
 *
 *  @brief  互斥量相关操作函数
 *
 ******************************************************************************/

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include "sem_util.h"

#define ERR(fmt, args...) fprintf(stderr, "sem_util::Error: " fmt, ## args)

/******************************************************

 *  @brief               互斥量初始化操作，该互斥量为动态分配。
 *
 *  @return    NULL   :  失败
 *             非空   :  成功
 *
 ******************************************************/
SemHandl_t MakeSem()
{
    SemHandl_t hndlSem = malloc(sizeof(pthread_mutex_t));
    if(hndlSem == NULL){
        ERR("%s,Not enough memory !\n",__func__);
        return NULL;
    }
    /*added by zjy*/
    pthread_mutexattr_t attr;
    if(pthread_mutexattr_init(&attr) != 0){
        ERR("%s,create mutex attribute error !\n",__func__);
        free(hndlSem);
        return NULL;
     }

    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    if( pthread_mutex_init((pthread_mutex_t*)hndlSem, &attr) != 0 )
    {
        ERR("%s,init faill !\n",__func__);
        free(hndlSem);
		pthread_mutexattr_destroy(&attr);
        return NULL;
    }

	pthread_mutexattr_destroy(&attr);
    return hndlSem;
}

/******************************************************************************

 *  @brief               对互斥量进行解锁操作
 *
 *  @return    -1     :  互斥量故障
 *             0      :  成功
 *             其他   :  解锁失败，返回错误编号。
 *
 ******************************************************************************/
int SemRelease(SemHandl_t hndlSem)
{
    if(hndlSem == NULL){
        ERR("%s,Invalid Semaphore handler !\n",__func__);
        return -1;
    }

    return pthread_mutex_unlock((pthread_mutex_t*)hndlSem);
}

/******************************************************************************

 *  @brief               对互斥量进行加锁操作
 *
 *  @return    -1     :  互斥量故障
 *             0      :  成功
 *             其他   :  加锁失败，返回错误编号。
 *
 ******************************************************************************/
int SemWait(SemHandl_t hndlSem)
{
    if(hndlSem == NULL){
        ERR("%s,Invalid Semaphore handler !\n",__func__);
        return -1;
    }

    return pthread_mutex_lock((pthread_mutex_t*)hndlSem);
}

/******************************************************************************

 *  @brief               互斥量为动态分配，需手动销毁。
 *
 *  @return    -1     :  互斥量故障
 *             0      :  成功
 *
 ******************************************************************************/
int DestroySem(SemHandl_t hndlSem)
{
    if(hndlSem == NULL){
        ERR("%s,Invalid Semaphore handler !\n",__func__);
        return -1;
    }
    pthread_mutex_lock((pthread_mutex_t*)hndlSem);
    pthread_mutex_unlock((pthread_mutex_t*)hndlSem);
    if( pthread_mutex_destroy((pthread_mutex_t*)hndlSem)!= 0 )
    {
        ERR("%s,Sem_kill faill !\n",__func__);
    }

    free(hndlSem);
    return 0;
}
