#include <stdio.h>
#include <android/log.h>

#define LOG_TAG "example"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)


int entry()
{
	LOGI("Just a entry!\n");

	return 0;
}

void __attribute__ ((constructor)) load()
{
	entry();
}

