
/******************************************************************************
 *
 *  @file   sem_util.h
 *
 *  @date   2012.09.02
 *
 *  @author 李玮帆
 *
 *  @brief  互斥量相关操作函数
 *
 ******************************************************************************/

#ifndef __SEM_UTIL_H__
#define __SEM_UTIL_H__

typedef void* SemHandl_t;

SemHandl_t MakeSem();
int SemRelease(SemHandl_t hndlSem);
int SemWait(SemHandl_t hndlSem);
int DestroySem(SemHandl_t hndlSem);

#endif

