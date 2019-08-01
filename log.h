//
// Created by explorer on 7/18/19.
//

#ifndef SHDOWTOY_LOG_H
#define SHDOWTOY_LOG_H

#include <stdio.h>

#define LOG_DEBUG

#ifdef LOG_DEBUG
int
logger(const char *level, const char *pFile, const char *pFuncName, int iLineNumb, FILE *pLogHandle, const char *fmt,
       ...);
#else
#define logger(...)
#endif

#define INFO "info", __FILE__ , __FUNCTION__, __LINE__
#define WARN "warning", __FILE__ , __FUNCTION__, __LINE__
#define ERR "error", __FILE__ , __FUNCTION__, __LINE__
#define DEBUG "debug", __FILE__ , __FUNCTION__, __LINE__


#endif //SHDOWTOY_LOG_H
