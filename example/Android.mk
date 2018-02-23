LOCAL_PATH := $(call my-dir)    
    
include $(CLEAR_VARS)    
  
# 编译生成的模块的名称  
LOCAL_MODULE := example    
  
# 需要被编译的源码文件   
LOCAL_SRC_FILES := 	example.c

# 支持log日志打印android/log.h里函数调用的需要  
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog    
			  
# 编译模块生成可执行文件   
include $(BUILD_SHARED_LIBRARY) 