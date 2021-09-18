安全函数接口封装、编译工程已经完成，有几点需要大家注意：
1.删除原先代码中私自定义的安全函数。不允许私自封装安全函数，所有安全函数都已经封装到cm_security.h,通过编译选项ENABLE_SECURITY_FUNCTION启用。
cm_memcpy_s
snprintf
sprintf_s
snprintf_s
vsprintf_s
strncpy_s
strcpy_s
cm_strcat_s

2.原则上不允许使用微软提供安全函数。如果需要使用，需要保证编译路径都不包含cm_base.h头文件。否则会出现重复符号链接错误。

3.整改安全函数时，需要把cm_base.h放到整改C文件的第一行。

4.新增工程直接或间接依赖安全函数库，需要在VS工程和MAKEFILE增加 securec.h securectype.h头文件路径和libsecurec.so 动态库路径
pkg\library\platform\aes\include\security\securec.h
pkg\library\platform\aes\include\security\securectype.h
pkg/library/platform/aes/lib/suse11/libsecurec.so  

5.对于strcpy、strncpy、strcat、strncat、memcpy、memset使用高性能接口CM_STRCPY_SP/CM_STRNCPY_SP/CM_STRCAT_SP/CM_STRNCAT_SP/CM_MEMCPY_SP/CM_MEMSET_SP