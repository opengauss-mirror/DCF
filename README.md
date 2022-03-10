# Distributed Consensus Framework
分布式一致性框架


#### 一、工程说明
##### 1、编程语言：C
##### 2、编译工具：cmake或make，建议使用cmake
##### 3、目录说明：
-   DCF：主目录，CMakeLists.txt为主工程入口；
-   src:：源代码目录，按子目录划分模块解耦；
-   test：测试用例
-   build：工程构建脚本

#### 二、编译指导与工程构建
##### 概述
编译DCF需要dcf和binarylibs两个组件。
-   dcf：dcf的主要代码。可以从开源社区获取。
-   binarylibs：依赖的第三方开源软件，你可以直接编译openGauss-third_party代码获取，也可以从开源社区下载已经编译好的并上传的一个副本。
##### 操作系统和软件依赖要求
支持以下操作系统：
-   CentOS 7.6（x86）
-   openEuler-20.03-LTS<br>
适配其他系统，可参照openGauss数据库编译指导<br>
当前DCF依赖第三方软件有securec、lz4、zstd、openssl、cjson;
编译dcf依赖的第三方软件要求与编译opengauss对依赖的第三方软件要求一致。
##### 下载dcf
可以从开源社区下载dcf和openGauss-third_party。
可以通过以下网站获取编译好的binarylibs。
https://opengauss.obs.cn-south-1.myhuaweicloud.com/2.0.0/openGauss-third_party_binarylibs.tar.gz
##### 编译第三方软件
在编译dcf之前，需要先编译dcf依赖的开源及第三方软件。这些开源及第三方软件存储在openGauss-third_party代码仓库中，通常只需要构建一次。如果开源软件有更新，需要重新构建软件。<br>
用户也可以直接从binarylibs库中获取开源软件编译和构建的输出文件。
##### 代码编译
使用DCF/build/linux/opengauss/build.sh编译代码, 参数说明请见以下表格。<br>
| 选项 | 参数               | 说明                                   |
| ---  |:---              | :---                                   |
| -3rd | [binarylibs path] | 指定binarylibs路径。该路径必须是绝对路径。|
| -m | [version_mode] | 编译目标版本，Debug或者Release。默认Release|
| -t   | [build_tool]      | 指定编译工具，cmake或者make。默认cmake|

现在只需使用如下命令即可编译：<br>
[user@linux ]$ sh build.sh -3rd [binarylibs path] -m Release -t cmake<br>
完成编译后，动态库生成在DCF/output/lib目录中

##### （其他可选编译方式）仅拉取dcf依赖的第三方软件编译代码
###### 1、进入DCF/build/linux,编译开源第三方库，DCF依赖3rd库有securec、lz4、zstd、openssl。编译完生成lib和头文件在../DCF/library
        sh compile_opensource.sh
###### 2、进入DCF主目录,生成编译脚本
        cmake -DCMAKE_BUILD_TYPE=Debug -DUSE32BIT=OFF CMakeLists.txt
        cmake  -D CMAKE_BUILD_TYPE=Release -DUSE32BIT=OFF CMakeLists.txt
###### 3、make all -sj8
完成编译，动态库生成在DCF/lib目录中

#### 三、接口说明
##### 1、API列表

DCF角色定义：
typedef enum en_dcf_role {
    DCF_ROLE_UNKNOWN = 0,
    DCF_ROLE_LEADER,
    DCF_ROLE_FOLLOWER,
    DCF_ROLE_LOGGER,
    DCF_ROLE_PASSIVE,
    DCF_ROLE_PRE_CANDIDATE,
    DCF_ROLE_CANDIDATE,
    DCF_ROLE_CEIL,
} dcf_role_t;

- ___int dcf_set_param(const char *param_name, const char *param_value);___

功能说明：设置DCF配置参数
参数说明：param_name是需要设置的参数名称，param_value是需要设置的参数值。
          参数名称有以下类型：
		  "ELECTION_TIMEOUT"   --选举超时时间，单位ms
		  "HEARTBEAT_INTERVAL" --心跳间隔，单位ms
		  "RUN_MODE" --运行模式，ELECTION_AUTO或ELECTION_MANUAL
		  "INSTANCE_NAME" --实例名称
		  "DATA_PATH" --数据文件路径
		  "LOG_PATH"  --日志文件路径
		  "LOG_LEVEL" --最大日志级别"RUN_ERR|RUN_WAR|RUN_INF|DEBUG_ERR|DEBUG_WAR|DEBUG_INF|MEC|OPER|TRACE|PROFILE",
                                需要开启自定义级别,从上述字符串中选取并使用|分割;
                        默认级别"RUN_ERR|RUN_WAR|DEBUG_ERR|OPER"
                        若需要关闭日志打印，配置"NONE"
		  "LOG_BACKUP_FILE_COUNT" --日志备份文件数
		  "MAX_LOG_FILE_SIZE" --日志文件最大size，单位MB
		  "LOG_FILE_PERMISSION" --日志文件权限,权限不高于700
		  "LOG_PATH_PERMISSION" --日志路径权限,权限不高于700
		  "MEC_AGENT_THREAD_NUM" --通信agent线程数量
		  "MEC_REACTOR_THREAD_NUM" --通信reactor线程数量
		  "MEC_CHANNEL_NUM" --通信通道数量
		  "MEM_POOL_INIT_SIZE" --共用buddy pool的初始size
		  "MEM_POOL_MAX_SIZE"  --共用buddy pool的最大size
		  "COMPRESS_ALGORITHM" --通信压缩算法, 0:COMPRESS_NONE, 1:COMPRESS_ZSTD, 2:COMPRESS_LZ4
		  "COMPRESS_LEVEL" --压缩级别
		  "SOCKET_TIMEOUT"  --socket收发报文超时时间，单位ms
		  "CONNECT_TIMEOUT" --连接超时时间，单位ms
		  "REP_APPEND_THREAD_NUM" --leader节点发送日志的线程数
		  "MEC_FRAGMENT_SIZE" --通信消息buffer size
		  "STG_POOL_INIT_SIZE" --存储pool初始size
		  "STG_POOL_MAX_SIZE" --存储pool最大size，存储有读写两个pool，这里是单个pool的size
		  "MEC_POOL_MAX_SIZE" --通信pool最大size，通信有收发两个pool，这里是单个pool的size
		  "FLOW_CONTROL_CPU_THRESHOLD" -- CPU使用率超过此值时会对passive节点的日志同步进行流控，单位%
		  "FLOW_CONTROL_NET_QUEUE_MESSAGE_NUM_THRESHOLD" -- DCF发送日志队列中消息超过此值时会对passive节点的日志同步进行流控
		  "FLOW_CONTROL_DISK_RAWAIT_THRESHOLD" -- 磁盘读延时超过此值时会对passive节点的日志同步进行流控，单位us
          "DN_FLOW_CONTROL_RTO" -- DN流控参数，结合接口dcf_pause_rep使用
          "DN_FLOW_CONTROL_RPO" -- DN流控参数，结合接口dcf_pause_rep使用
          
- ___int dcf_get_param(const char *param_name, const char *param_value, unsigned int size);___

功能说明：设置DCF配置参数
参数说明：param_name是需要设置的参数名称，参数名称如dcf_set_param中参数param_name一致
        param_value是获取的参数值，需提前分配内存
        size是param_value的大小
          

- ___int dcf_register_after_writer(usr_cb_after_writer_t cb_func);___

功能说明：注册leader节点写入数据成功的回调函数
参数说明：回调函数形式如下，其中stream_id是分组编号，相同编号的组成一个一致性group;
          index是落盘日志的index; buf是落盘的日志buf; size是落盘的日志size;
		  key是落盘日志的key，可以唯一标识一条日志; error_no是错误码
         typedef int (*usr_cb_after_writer_t)(unsigned int stream_id, unsigned long long index,
                      const char *buf, unsigned int size, unsigned long long key, int error_no);

- ___int dcf_register_consensus_notify(usr_cb_consensus_notify_t cb_func);___

功能说明：注册follower节点写入数据成功的回调函数
参数说明：回调函数形式如下，参数解释同上
         typedef int (*usr_cb_consensus_notify_t)(unsigned int stream_id, unsigned long long index,
                      const char *buf, unsigned int size, unsigned long long key);

- ___int dcf_register_status_notify(usr_cb_status_notify_t cb_func);___

功能说明：注册节点角色变化的回调函数
参数说明：回调函数形式如下，new_role是节点新角色
         typedef int (*usr_cb_status_notify_t)(unsigned int stream_id, dcf_role_t new_role);

- ___int dcf_register_log_output(usr_cb_log_output_t cb_func);___

功能说明：注册日志输出的回调函数
参数说明：回调函数形式如下，log_type是日志类型，LOG_RUN、LOG_DEBUG等; log_level是日志级别，LEVEL_ERROR、LEVEL_WARN等;
          code_file_name是代码文件名，如__FILE__; code_line_num是代码行号，如__LINE__;
		  module_name是模块名，如"DCF"; format, ...是格式化字符串
         typedef void (*usr_cb_log_output_t)(int log_type, int log_level, const char *code_file_name,
                       unsigned int code_line_num, const char *module_name, const char *format, ...);

- ___int dcf_register_exception_report(usr_cb_exception_notify_t cb_func);___

功能说明：注册异常处理函数
参数说明：回调函数形式如下，dcf_exception_t异常类型，见dcf_interface.h中定义
              typedef int(*usr_cb_exception_notify_t)(unsigned int stream_id, dcf_exception_t exception);

- ___int dcf_register_election_notify(usr_cb_election_notify_t cb_func);___

功能说明：注册选举leader变化的回调函数
参数说明：回调函数形式如下，new_leader 是新主的nodeid
              typedef int (*usr_cb_election_notify_t)(unsigned int stream_id, unsigned int new_leader);

- ___int dcf_register_msg_proc(usr_cb_msg_proc_t cb_func);___

功能说明：注册选举leader变化的回调，follower调用函数
参数说明：回调函数形式如下，
              typedef int (*usr_cb_msg_proc_t)(unsigned int stream_id, unsigned int src_node_id, const char* msg,
                           unsigned int msg_size);

- ___int dcf_start(unsigned int node_id, const char *cfg_str);___

功能说明：启动工作线程
参数说明：node_id是节点id; cfg_str是集群节点列表，按照json字符串的格式进行配置，每个json item的配置信息包括stream_id/node_id/ip/port/role;
          例如三个节点"[{
            "stream_id":1,
            "node_id":1,
            "ip":"127.0.0.1",
            "port":1711,
            "role":"LEADER"
            },{
            "stream_id":1,
            "node_id":2,
            "ip":"127.0.0.1",
            "port":1712,
            "role":"FOLLOWER"
            },{
            "stream_id":1,
            "node_id":3,
            "ip":"127.0.0.1",
            "port":1713,
            "role":"FOLLOWER"
            }]"

- ___int dcf_write(unsigned int stream_id, const char* buffer, unsigned int length, unsigned long long key, unsigned long long *index);___

功能说明：写入数据，仅leader节点调用
参数说明：buffer是待写入数据的buffer; length是待写入数据的size; key是待写入数据的key，可以唯一标识一条日志; index是leader分配的日志index

- ___int dcf_universal_write(unsigned int stream_id, const char* buffer, unsigned int length, unsigned long long key, unsigned long long *index);___

功能说明：写入数据，可在任意节点调用，但性能不如dcf_write。
参数说明：buffer是待写入数据的buffer; length是待写入数据的size; key是待写入数据的key，可以唯一标识一条日志; index是leader分配的日志index

- ___int dcf_read(unsigned int stream_id, unsigned long long index, char *buffer, unsigned int length);___

功能说明：查询已写入的数据，成功返回实际读到的字节数，失败返回ERROR(-1)
参数说明：参考前述

- ___int dcf_stop();___

功能说明：停止工作线程
参数说明：

- ___int dcf_truncate(unsigned int stream_id, unsigned long long first_index_kept);___

功能说明：丢弃索引first_index_kept之前的日志
参数说明：first_index_kept是保留的第一个日志index

- ___int dcf_set_applied_index(unsigned int stream_id, unsigned long long index);___

功能说明：设置applied index,在函数dcf_start调用前调用
参数说明：index是日志index

- ___int dcf_get_cluster_min_applied_idx(unsigned int stream_id, unsigned long long* index);___

功能说明：获取集群所有节点最小的applied index
参数说明：*index是获取到的最小applied index

- ___int dcf_get_leader_last_index(unsigned int stream_id, unsigned long long* index);___

功能说明：查询leader节点的last index
参数说明：返回值index为last index

- ___int dcf_get_last_index(unsigned int stream_id, unsigned long long* index);___

功能说明：查询当前节点的last index
参数说明：返回值index为last index

- ___int dcf_get_node_last_disk_index(unsigned int stream_id, unsigned int node_id, unsigned long long* index);___

功能说明：获取node_id节点的last disk index，只可在leader调用。成功返回SUCCESS，失败返回ERROR
参数说明：*index为获取到的last disk index。

- ___int dcf_query_cluster_info(char* buffer, unsigned int length);___

功能说明：查询集群信息，streamlist、node等
参数说明：buffer是查询信息输出空间; length是最大输出长度; 函数返回值是实际输出长度
          例如三个节点的cluster查询信息：
          {
           "local_node_id":1,
           "stream_list":[{"stream_id":1,"local_node_id":1,"role":"FOLLOWER","term":3,"work_mode":0,
                           "applied_index":0,"commit_index":0,"first_index":1,"last_index":5733936,
                           "leader_id":3,"leader_ip":"127.0.0.1","leader_port":1713,
                           "nodes":[{"node_id":1,"ip":"127.0.0.1","port":1711,"role":"FOLLOWER"},
                                    {"node_id":2,"ip":"127.0.0.1","port":1712,"role":"FOLLOWER"},
                                    {"node_id":3,"ip":"127.0.0.1","port":1713,"role":"LEADER"}]
                         }]
         }

- ___int dcf_query_stream_info(unsigned int stream_id, char *buffer, unsigned int length);___

功能说明：查询stream信息
参数说明：stream_id是待查询stream的id; buffer是查询信息输出空间; length是最大输出长度; 函数返回值是实际输出长度
          例如三个节点的stream查询信息：
          {
           "stream_id":1,"local_node_id":3,"role":"FOLLOWER","term":2,"work_mode":0,
           "applied_index":0,"commit_index":0,"first_index":1,"last_index":0,
           "leader_id":2,"leader_ip":"127.0.0.1","leader_port":1712,
           "nodes":[{"node_id":1,"ip":"127.0.0.1","port":1711,"role":"FOLLOWER"},
                    {"node_id":2,"ip":"127.0.0.1","port":1712,"role":"LEADER"},
                    {"node_id":3,"ip":"127.0.0.1","port":1713,"role":"FOLLOWER"}]
          }

- ___int dcf_query_leader_info(unsigned int stream_id, char *ip, unsigned int ip_len, unsigned int *port, unsigned int *node_id);___

功能说明：查询leader信息
参数说明：ip是输出leader ip的buffer; ip_len是ip buffer长度; port输出leader的port; node_id输出leader的node_id

- ___int dcf_get_errorno();___

功能说明：获取错误码
参数说明：

- ___const char* dcf_get_error(int code);___

功能说明：获取错误信息
参数说明：code错误码

- ___const char *dcf_get_version();___

功能说明：获取版本信息
参数说明：

- ___int dcf_add_member(unsigned int stream_id, unsigned int node_id, const char *ip, unsigned int port, dcf_role_t role, unsigned int wait_timeout_ms);___

功能说明：添加节点，只可在leader调用。成功返回SUCCESS(0)，失败返回ERROR(-1)，超时返回TIMEOUT(1),超时最终也可能成功，可以重试。
参数说明：node_id是待添加节点id; ip是待添加节点ip; port是待添加节点port，调用者需保证port可用; role是待添加节点角色; wait_timeout_ms是超时时间，单位ms

- ___int dcf_remove_member(unsigned int stream_id, unsigned int node_id, unsigned int wait_timeout_ms);___

功能说明：删除节点，只可在leader调用。成功返回SUCCESS(0)，失败返回ERROR(-1)，超时返回TIMEOUT(1),超时最终也可能成功，可以重试。
参数说明：node_id是待删除节点id; wait_timeout_ms是超时时间，单位ms

- ___int dcf_change_member_role(unsigned int stream_id, unsigned int node_id, dcf_role_t new_role, unsigned int wait_timeout_ms);___

功能说明：改变节点角色，在leader调用可改变其他节点角色，非leader调用只能改变节点自身的角色。成功返回SUCCESS(0)，失败返回ERROR(-1)，超时返回TIMEOUT(1),超时最终也可能成功，可以重试。
参数说明：node_id为被修改角色节点id; new_role是节点新角色。

- ___int dcf_change_member(const char *change_str, unsigned int wait_timeout_ms);___

功能说明：改变节点属性，在leader调用可改变其他节点的role/group/priority等属性，非leader调用只能改变节点自身的属性，一次可改变一个或多个属性。成功返回SUCCESS(0)，失败返回ERROR(-1)，超时返回TIMEOUT(1),超时最终也可能成功，可以重试。
参数说明：change_str是需要修改的节点及属性列表，按照json字符串的格式进行配置，例如[{"stream_id":1,"node_id":1,"group":1,"priority":5,"role":"FOLLOWER"}]。

- ___int dcf_promote_leader(unsigned int stream_id, unsigned int node_id, unsigned int wait_timeout_ms);___

功能说明：推选指定节点为leader。在leader调用可推选其他节点，在follower节点调用只能推选自己。失败返回ERROR(-1)，成功返回SUCCESS(0)，返回SUCCESS仅代表推选命令下发成功，最终能否成功需要调用者查询。
参数说明：node_id为被推选节点id; wait_timeout_ms是超时时间，单位ms，为0表示不阻塞leader直接发起推选。

- ___int dcf_timeout_notify(unsigned int stream_id, unsigned int node_id);___

功能说明：外部触发超时
参数说明：stream_id≠0表示触发指定stream_id超时，stream_id=0表示触发所有stream_id超时

___int int dcf_set_work_mode(unsigned int stream_id, dcf_work_mode_t work_mode, unsigned int vote_num)；___

功能说明：设置运行模式（正常、少数派）
参数说明：work_mode为正常或少数派，如果是少数派模式，需指定票数。

- ___int dcf_query_statistics_info(char *buffer, unsigned int length);___

功能说明：获取统计信息，需要日志级别开启PROFILE。
参数说明：buffer是查询信息输出空间; length是最大输出长度

- ___int dcf_check_if_all_logs_applied(unsigned int stream_id, unsigned int *all_applied);___

功能说明：一般在节点升主时使用，检查当前欲升主节点的dcf日志是否都完成apply。调用成功返回SUCCESS，失败返回ERROR，调用成功后可从*all_applied获取结果。
参数说明：*all_applied为获取到的结果，0表示日志没有都完成apply，非0表示日志都完成apply。

- ___int dcf_send_msg(unsigned int stream_id, unsigned int dest_node_id, const char* msg, unsigned int msg_size);___

功能说明：用于节点间对指定节点发送消息。调用成功返回SUCCESS，失败返回ERROR。
参数说明：dest_node_id为指定节点，msg表示待发送的消息，msg_size表示消息大小。

- ___int dcf_broadcast_msg(unsigned int stream_id, const char* msg, unsigned int msg_size);___

功能说明：用于对除当前节点外所有节点广播发送消息。调用成功返回SUCCESS，失败返回ERROR。
参数说明：msg表示待发送的消息，msg_size表示消息大小。

- ___int dcf_pause_rep(unsigned int stream_id, unsigned int node_id, unsigned int time_us);___

功能说明：对指定节点暂停日志复制。调用成功返回SUCCESS，失败返回ERROR。
参数说明：node_id指定暂停的节点; time_us是暂停时间(不超过1s)，单位us。

- ___int dcf_demote_follower(unsigned int stream_id);___

功能说明：对主节点进行降备
参数说明：stream_id对应降备的stream。

- ___int dcf_get_last_commit_index(unsigned int stream_id, unsigned int is_consensus, unsigned long long* index);___

功能说明：获取最新 commit index 值
参数说明：stream_id对应群组id，默认为1; is_consensus，是否要求一致性(true, false); index，出参commit index。

- ___int dcf_get_current_term_and_role(unsigned int stream_id, unsigned long long* term, dcf_role_t* role);___

功能说明：获取自己当前的任期和角色信息。
参数说明：失败返回ERROR(-1)，成功返回SUCCESS(0)。返回SUCCESS时可以从出参term获取任期，从出参role获取角色。

- ___int int dcf_set_election_priority(unsigned int stream_id, unsigned long long priority);___

功能说明：设置节点的选举优先级。频繁调用该接口时内部有保护，1s内只能设置成功一次。
参数说明：priority是需要设置的优先级值。

- ___void dcf_set_timer(void *timer);___

功能说明：注册上层组件的timer给DCF使用，timer需要与DCF内部gs_timer_t结构一致，一般内部组件间使用。
参数说明：timer是上层组件timer地址。

##### 2、DEMO示例

```c{.line-num}

参见：DCF/test/test_main目录

```

#### 四、测试工程
##### 1、编译
##### 2、执行测试用例

待续...

#### 五、应用实例
##### 1、GaussDB(for openGauss)使能paxos特性实践
具体可参考：https://gitee.com/opengauss/blog/blob/master/content/zh/post/yanghaiyan/openGauss%E4%BD%BF%E8%83%BDpaxos%E7%89%B9%E6%80%A7%E5%AE%9E%E8%B7%B5.md