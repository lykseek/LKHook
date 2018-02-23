LOCAL_PATH := $(call my-dir)    
    
include $(CLEAR_VARS)    
  
# 编译生成的模块的名称  
LOCAL_MODULE := inject    
  
# 需要被编译的源码文件   
LOCAL_SRC_FILES := 	inject.c\
					ptrace_utils.c\
					tools.c\
					elf_utils.c
			  
# 编译模块生成可执行文件   
include $(BUILD_EXECUTABLE) 