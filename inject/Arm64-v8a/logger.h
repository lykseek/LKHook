#ifndef _LOGGER_H_
#define _LOGGER_H_

#ifdef _ANDROID_
#include <android/log.h>
#define LOG_TAG "TTT"
#endif

#ifdef DEBUG

#ifdef _ANDROID_
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI printf
#define LOGE printf
#endif

#else
#define LOGI(...) while(0)
#define LOGE(...) while(0)
#endif

#endif /* LOG_H_ */