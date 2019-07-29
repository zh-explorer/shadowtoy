//
// Created by explorer on 7/12/19.
//

#include "log.h"

#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>

#define STR_LEN_2048 2048

#ifdef LOG_DEBUG
int logger(const char *level, const char *pFile, const char *pFuncName, int iLineNumb, FILE *pLogHandle, const char *fmt, ...) {
    if (NULL == pLogHandle || NULL == pFile || '\0' == pFile[0] || NULL == pFuncName || '\0' == pFuncName[0])
        return -1;

    //写入日期、函数信息
    time_t timeSecs = time(NULL);
    struct tm *timeInfo = localtime(&timeSecs);
    char acTitle[STR_LEN_2048] = {0};
    snprintf(acTitle, sizeof(acTitle), "[%s] [%d%02d%02d/%02d:%02d:%02d] [%s] [%s:%d]", level,
             timeInfo->tm_year + 1900, timeInfo->tm_mon + 1, timeInfo->tm_mday,
             timeInfo->tm_hour, timeInfo->tm_min, timeInfo->tm_sec, pFile, pFuncName, iLineNumb);

    size_t iLen = strlen(acTitle);
    fwrite(acTitle, iLen, 1, pLogHandle);
    //写入日志
    fwrite("\t\t", 3, 1, pLogHandle);
    memset(acTitle, 0, sizeof(acTitle));
    va_list args;
    va_start(args, fmt);
    vsnprintf(acTitle, sizeof(acTitle), fmt, args);
    va_end(args);
    iLen = strlen(acTitle);
    fwrite(acTitle, iLen, 1, pLogHandle);
    fwrite("\n", 1, 1, pLogHandle);
    return 0;
}
#endif