# Distributed Consensus Framework

Distributed Consensus Framework (DCF)

## 1. Project Description

### 1. Programming language: C

### 2. Compilation tool: CMake (recommended) or Make

### 3. Directories:

-   `DCF`: the main directory. The `CMakeLists.txt` file is the main project entry.
-   `src`: the source code directory, where modules are decoupled by subdirectory.
-   `test`: the test case
-   `build`: the project building script

## 2. Compilation Guide and Project Building

### Overview

DCF compilation requires two components: `dcf` and `binarylibs`.
-   `dcf`: the main code of DCF, which can be obtained from the open-source community.
-   `binarylibs`: third-party open-source software. Run code in `openGauss-third_party` to obtain it, or download the compiled software from the open-source community.

### OS and Software Dependencies

The following OSs are supported:
-   CentOS 7.6 (x86)
-   openEuler 20.03 LTS<br>
-   openEuler 22.03 LTS<br>
-   openEuler 24.03 LTS<br>
For details about how to adapt to other OSs, see the openGauss compilation guide.<br>
Currently, DCF depends on the following third-party software: SecureC, LZ4, zstd, OpenSSL, and cJSON.
The requirements for the third-party software on which DCF compilation depends are the same as those for compiling openGauss.

### Downloading DCF and Third-Party Software

DCF code: Clone the code from the [code repository](https://gitee.com/opengauss/DCF) to the local host.

Third-party software: openGauss maintains third-party software in the [software repository](https://gitee.com/opengauss/openGauss-third_party). Acquire the required third-party software in one of the following ways: 1. Download the compiled `openGauss-third_party` binary package. 2. Download the source code and compile it.

For details about how to download the compiled `openGauss-third_party` binary package, see the `README` file in the [software repository](https://gitee.com/opengauss/openGauss-third_party). The file provides the links for downloading the compiled `openGauss-third_party` binary package for different OSs and software versions. For example, for openEuler (x86) with GCC 10.3 or later, click [here](https://opengauss.obs.cn-south-1.myhuaweicloud.com/latest/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_x86_64.tar.gz) to download the latest compiled third-party software binary package.

If you want to compile the software by yourself, clone the entire [software repository](https://gitee.com/opengauss/openGauss-third_party) to the local host. Then, check the repository's README file and the `Compiling Third-Party Software` section in this document to learn the build process.

### Compiling Third-Party Software

Before compiling DCF, compile the open-source and third-party software on which DCF depends. Open-source and third-party software is stored in the `openGauss-third_party` code repository and usually needs to be built only once. If the open-source software is updated, you need to rebuild the software.<br>
Alternatively, obtain the compiled open-source software from `binarylibs`.

### Compiling Code

Use `DCF/build/linux/opengauss/build.sh` to compile the code. The following table describes the parameters.<br>

| Option| Parameter              | Description                                  |
| ---  |:---              | :---                                   |
| -3rd | [binarylibs path] | Specifies the `binarylibs` path, which must be an absolute path.|
| -m | [version_mode] | Specifies the target version to be compiled, which can be `Debug` or `Release` (default).|
| -t   | [build_tool]      | Specifies the compilation tool, which can be `cmake` (default) or `make`.|

Run the following command to perform compilation:<br>
`[user@linux ]$ sh build.sh -3rd [binarylibs path] -m Release -t cmake`<br>
After the compilation is complete, the dynamic library is generated under the `DCF/output/lib` directory.

## 3. API Description

### 1. APIs

DCF roles are defined as follows:
```
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
```

- ___int dcf_set_param(const char *param_name, const char *param_value);___

Function: setting DCF configuration parameters

Parameter description: `param_name` indicates the name of the parameter to be set. `param_value` indicates the value of the parameter to be set.
          The parameter names are as follows:

		  "ELECTION_TIMEOUT"   -- Election timeout interval, in milliseconds
		  "HEARTBEAT_INTERVAL" -- Heartbeat interval, in milliseconds
		  "RUN_MODE" -- Running mode, which can be ELECTION_AUTO or ELECTION_MANUAL
		  "INSTANCE_NAME" -- Instance name
		  "DATA_PATH" -- Data file path
		  "LOG_PATH" -- Log file path
		  "LOG_LEVEL" -- The maximum log level is "RUN_ERR|RUN_WAR|RUN_INF|DEBUG_ERR|DEBUG_WAR|DEBUG_INF|MEC|OPER|TRACE|PROFILE".
                                To customize the level, select values from the preceding character strings and separate them with vertical bars (|).
                        Default level: "RUN_ERR|RUN_WAR|DEBUG_ERR|OPER"
                        To disable log printing, set this parameter to "NONE".
		  "LOG_BACKUP_FILE_COUNT" -- Number of log backup files
		  "MAX_LOG_FILE_SIZE" -- Maximum size of a log file, in MB
		  "LOG_FILE_PERMISSION" -- Log file permission, which cannot be higher than 700
		  "LOG_PATH_PERMISSION" -- Log path permission, which cannot be higher than 700
		  "MEC_AGENT_THREAD_NUM" -- Number of communication agent threads
		  "MEC_REACTOR_THREAD_NUM" -- Number of communication reactor threads
		  "MEC_CHANNEL_NUM" -- Number of communication channels
		  "MEM_POOL_INIT_SIZE" -- Initial size of the shared buddy pool
		  "MEM_POOL_MAX_SIZE" -- Maximum size of the shared buddy pool
		  "COMPRESS_ALGORITHM" -- Communication compression algorithm. 0: COMPRESS_NONE; 1: COMPRESS_ZSTD; 2: COMPRESS_LZ4
		  "COMPRESS_LEVEL" -- Compression level
		  "SOCKET_TIMEOUT" -- Timeout interval for the socket to send and receive packets, in milliseconds
		  "CONNECT_TIMEOUT" -- Connection timeout interval, in milliseconds
		  "REP_APPEND_THREAD_NUM" -- Number of threads for the leader node to send logs
		  "MEC_FRAGMENT_SIZE" -- Communication message buffer size
		  "STG_POOL_INIT_SIZE" -- Initial size of the storage pool
		  "STG_POOL_MAX_SIZE" -- Maximum size of the storage pool. There are two storage pools: one for read and the other for write. This is the size of a single pool.
		  "MEC_POOL_MAX_SIZE" -- Maximum size of the communication pool. There are two communication pools: one for sending and the other for receiving. This is the size of a single pool.
		  "FLOW_CONTROL_CPU_THRESHOLD" -- If the CPU usage exceeds this value, flow control is performed on log synchronization of the passive node. The unit is %.
		  "FLOW_CONTROL_NET_QUEUE_MESSAGE_NUM_THRESHOLD" -- If the number of messages in the log queue sent by DCF exceeds this value, flow control is performed on log synchronization of the passive node.
		  "FLOW_CONTROL_DISK_RAWAIT_THRESHOLD" -- If the disk read latency exceeds this value, flow control is performed on log synchronization of the passive node. The unit is microsecond.
          "DN_FLOW_CONTROL_RTO" -- DN flow control parameter, which is used together with dcf_pause_rep.
          "DN_FLOW_CONTROL_RPO" -- DN flow control parameter, which is used together with dcf_pause_rep.
          
- ___int dcf_get_param(const char *param_name, const char *param_value, unsigned int size);___

Function: setting DCF configuration parameters

Parameter description: `param_name` indicates the name of the parameter to be set, which is the same as the value of `param_name in dcf_set_param`.
        `param_value` indicates the obtained parameter value. Memory must be allocated in advance.
        `size` indicates the size of `param_value`.
          

- ___int dcf_register_after_writer(usr_cb_after_writer_t cb_func);___

Function: registering the callback function when the leader node successfully writes data

Parameter description: The following shows an example. `stream_id` indicates the group ID. Groups with the same ID form a consistency group.
          `index` indicates the index of the flushed log. `buf` indicates the buffer of the flushed log. `size` indicates the size of the flushed log.
		  `key` indicates the key of the flushed log, which uniquely identifies a log. `error_no` indicates the error code.
```
         typedef int (*usr_cb_after_writer_t)(unsigned int stream_id, unsigned long long index,
                      const char *buf, unsigned int size, unsigned long long key, int error_no);
```

- ___int dcf_register_consensus_notify(usr_cb_consensus_notify_t cb_func);___

Function: registering the callback function when the follower node successfully writes data

Parameter description: The following shows an example. The parameter description is the same as above.
```
         typedef int (*usr_cb_consensus_notify_t)(unsigned int stream_id, unsigned long long index,
                      const char *buf, unsigned int size, unsigned long long key);
```

- ___int dcf_register_status_notify(usr_cb_status_notify_t cb_func);___

Function: registering the callback function for node role changes

Parameter description: The following shows an example. `new_role` indicates the new role of the node.
```
         typedef int (*usr_cb_status_notify_t)(unsigned int stream_id, dcf_role_t new_role);
```

- ___int dcf_register_log_output(usr_cb_log_output_t cb_func);___

Function: registering the callback function for log output

Parameter description: The following shows an example. `log_type` indicates the log type, such as `LOG_RUN` and `LOG_DEBUG`. `log_level` indicates the log level, such as `LEVEL_ERROR` and `LEVEL_WARN`.
          `code_file_name` indicates the code file name, for example, `__FILE__`. `code_line_num` indicates the code line number, for example, `__LINE__`.
		  `module_name` indicates the module name, for example, `DCF`. `format, ...` indicates the formatted string.
```
         typedef void (*usr_cb_log_output_t)(int log_type, int log_level, const char *code_file_name,
                       unsigned int code_line_num, const char *module_name, const char *format, ...);
```

- ___int dcf_register_exception_report(usr_cb_exception_notify_t cb_func);___

Function: registering the function for handling exceptions

Parameter description: The following shows an example. `dcf_exception_t` indicates the exception type. For details, see the definition in `dcf_interface.h`.
```
              typedef int(*usr_cb_exception_notify_t)(unsigned int stream_id, dcf_exception_t exception);
```

- ___int dcf_register_election_notify(usr_cb_election_notify_t cb_func);___

Function: registering the callback function for leader election changes

Parameter description: The following shows an example. `new_leader` indicates the node ID of the new leader node.
```
              typedef int (*usr_cb_election_notify_t)(unsigned int stream_id, unsigned int new_leader);
```

- ___int dcf_register_msg_proc(usr_cb_msg_proc_t cb_func);___

Function: registering the callback function for leader election changes, which is called by the follower

Parameter description: The following shows an example.
```
              typedef int (*usr_cb_msg_proc_t)(unsigned int stream_id, unsigned int src_node_id, const char* msg,
                           unsigned int msg_size);
```

- ___int dcf_start(unsigned int node_id, const char *cfg_str);___

Function: starting a working thread

Parameter description: `node_id` indicates the node ID. `cfg_str` indicates the cluster node list, which is configured in JSON string format. The configuration information of each JSON item includes `stream_id`, `node_id`, `ip`, `port`, and `role`.
          For example, if there are three nodes:
```
          "[{
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
```

- ___int dcf_write(unsigned int stream_id, const char* buffer, unsigned int length, unsigned long long key, unsigned long long *index);___

Function: writing data. It can be invoked only by the leader node.

Parameter description: `buffer` indicates the buffer of the data to be written. `length` indicates the size of the data to be written. `key` indicates the key of the data to be written, which uniquely identifies a log. `index` indicates the log index allocated by the leader.

- ___int dcf_universal_write(unsigned int stream_id, const char* buffer, unsigned int length, unsigned long long key, unsigned long long *index);___

Function: writing data. It can be invoked on any node, but the performance is not as good as `dcf_write`.

Parameter description: `buffer` indicates the buffer of the data to be written. `length` indicates the size of the data to be written. `key` indicates the key of the data to be written, which uniquely identifies a log. `index` indicates the log index allocated by the leader.

- ___int dcf_read(unsigned int stream_id, unsigned long long index, char *buffer, unsigned int length);___

Function: querying the written data. If the operation is successful, the number of read bytes is returned. If the operation fails, `ERROR(-1)` is returned.

Parameter description: See the preceding description.

- ___int dcf_stop();___

Function: stopping a working thread

Parameter description:

- ___int dcf_truncate(unsigned int stream_id, unsigned long long first_index_kept);___

Function: discarding logs that precede the `first_index_kept` index

Parameter description: `first_index_kept` is the index of the first log to be retained.

- ___int dcf_set_applied_index(unsigned int stream_id, unsigned long long index);___

Function: setting the `applied index`. It must be called before the `function dcf_start` is called.

Parameter description: `index` specifies the log index.

- ___int dcf_get_cluster_min_applied_idx(unsigned int stream_id, unsigned long long* index);___

Function: obtaining the minimum `applied index` of all nodes in a cluster

Parameter description: `*index` specifies the obtained minimum `applied index`.

- ___int dcf_get_leader_last_index(unsigned int stream_id, unsigned long long* index);___

Function: querying the `last index` of the leader node

Parameter description: The returned `index` is the last index.

- ___int dcf_get_last_index(unsigned int stream_id, unsigned long long* index);___

Function: querying the `last index` of the current node

Parameter description: The returned `index` is the last index.

- ___int dcf_get_node_last_disk_index(unsigned int stream_id, unsigned int node_id, unsigned long long* index);___

Function: obtaining the `last disk index` of the node specified by `node_id`. It can be invoked only on the leader node. If the operation is successful, `SUCCESS` is returned. If the operation fails, `ERROR` is returned.

Parameter description: `*index` specifies the obtained `last disk index`.

- ___int dcf_query_cluster_info(char* buffer, unsigned int length);___

Function: querying cluster information, such as `streamlist` and `node`

Parameter description: `buffer` specifies the output space for the query information. `length` specifies the maximum output length. The return value of the function is the actual output length.
          For example, if there are three nodes in the cluster:
```
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
```

- ___int dcf_query_stream_info(unsigned int stream_id, char *buffer, unsigned int length);___

Function: querying stream information

Parameter description: `stream_id` indicates the ID of the stream to be queried. `buffer` specifies the output space for the query information. `length` specifies the maximum output length. The return value of the function is the actual output length.
          For example, if there are three nodes in the stream:
```
          {
           "stream_id":1,"local_node_id":3,"role":"FOLLOWER","term":2,"work_mode":0,
           "applied_index":0,"commit_index":0,"first_index":1,"last_index":0,
           "leader_id":2,"leader_ip":"127.0.0.1","leader_port":1712,
           "nodes":[{"node_id":1,"ip":"127.0.0.1","port":1711,"role":"FOLLOWER"},
                    {"node_id":2,"ip":"127.0.0.1","port":1712,"role":"LEADER"},
                    {"node_id":3,"ip":"127.0.0.1","port":1713,"role":"FOLLOWER"}]
          }
```

- ___int dcf_query_leader_info(unsigned int stream_id, char *ip, unsigned int ip_len, unsigned int *port, unsigned int *node_id);___

Function: querying leader information

Parameter description: `ip` is the buffer for outputting the leader IP address. `ip_len` is the length of the IP address buffers. `port` is the port number of the leader. `node_id` is the node ID of the leader.

- ___int dcf_get_errorno();___

Function: obtaining error codes

Parameter description:

- ___const char* dcf_get_error(int code);___

Function: obtaining error information

Parameter description: `code` indicates the error code.

- ___const char *dcf_get_version();___

Function: obtaining version information

Parameter description:

- ___int dcf_add_member(unsigned int stream_id, unsigned int node_id, const char *ip, unsigned int port, dcf_role_t role, unsigned int wait_timeout_ms);___

Function: adding a node. It can be invoked only on the leader node. If the operation is successful, `SUCCESS(0)` is returned. If the operation fails, `ERROR(-1)` is returned. If the operation times out, `TIMEOUT(1)` is returned. The operation may still succeed after timeout. You can retry if necessary.

Parameter description: `node_id` indicates the ID of the node to be added. `ip` indicates the IP address of the node to be added. `port` indicates the port of the node to be added. The caller must ensure that the port is available. `role` indicates the role of the node to be added. `wait_timeout_ms` indicates the timeout interval, in milliseconds.

- ___int dcf_remove_member(unsigned int stream_id, unsigned int node_id, unsigned int wait_timeout_ms);___

Function: deleting a node. It can be invoked only on the leader node. If the operation is successful, `SUCCESS(0)` is returned. If the operation fails, `ERROR(-1)` is returned. If the operation times out, `TIMEOUT(1)` is returned. The operation may still succeed after timeout. You can retry if necessary.

Parameter description: `node_id` indicates the ID of the node to be deleted. `wait_timeout_ms` indicates the timeout interval, in milliseconds.

- ___int dcf_change_member_role(unsigned int stream_id, unsigned int node_id, dcf_role_t new_role, unsigned int wait_timeout_ms);___

Function: changing the role of a node. If this API is called on the leader node, the roles of other nodes can be changed. If this API is called on a non-leader node, only the role of the node itself can be changed. If the operation is successful, `SUCCESS(0)` is returned. If the operation fails, `ERROR(-1)` is returned. If the operation times out, `TIMEOUT(1)` is returned. The operation may still succeed after timeout. You can retry if necessary.

Parameter description: `node_id` indicates the ID of the node whose role is to be changed. `new_role` indicates the new role of the node.

- ___int dcf_change_member(const char *change_str, unsigned int wait_timeout_ms);___

Function: changing node attributes. If this API is called on the leader node, the attributes such as role, group, and priority of other nodes can be changed. If this API is called on a non-leader node, only the attributes of the node itself can be changed. One or more attributes can be changed at a time. If the operation is successful, `SUCCESS(0)` is returned. If the operation fails, `ERROR(-1)` is returned. If the operation times out, `TIMEOUT(1)` is returned. The operation may still succeed after timeout. You can retry if necessary.

Parameter description: `change_str` is the list of nodes and attributes to be changed. It is configured in JSON string format, for example, `[{"stream_id":1,"node_id":1,"group":1,"priority":5,"role":"FOLLOWER"}]`.

- ___int dcf_promote_leader(unsigned int stream_id, unsigned int node_id, unsigned int wait_timeout_ms);___

Function: electing a specified node as the leader. If this API is invoked on the leader node, other nodes can be elected. If this API is invoked on the follower node, only the current node can be elected. If the operation fails, `ERROR(-1)` is returned. If the operation is successful, `SUCCESS(0)` is returned. The returned `SUCCESS` only indicates that the election command is successfully delivered. The caller needs to query whether the election is successful.

Parameter description: `node_id` indicates the ID of the node to be elected. `wait_timeout_ms` indicates the timeout interval, in milliseconds. A value of `0` indicates that the leader initiates the election immediately without blocking.

- ___int dcf_timeout_notify(unsigned int stream_id, unsigned int node_id);___

Function: triggering an external timeout

Parameter description: `stream_id≠0` indicates that the timeout of a specified stream ID is triggered. `stream_id=0` indicates that the timeout of all stream IDs is triggered.

___int int dcf_set_work_mode(unsigned int stream_id, dcf_work_mode_t work_mode, unsigned int vote_num);___

Function: setting the running mode (`normal` or `minority`)

Parameter description: `work_mode` can be set to `normal` or `minority`. If it is set to `minority`, the number of votes must be specified.

- ___int dcf_query_statistics_info(char *buffer, unsigned int length);___

Function: obtaining statistics. The log level must be set to `PROFILE`.

Parameter description: `buffer` specifies the output space for the query information. `length` specifies the maximum output length.

- ___int dcf_check_if_all_logs_applied(unsigned int stream_id, unsigned int *all_applied);___

Function: verifying if all DCF logs have been applied. It is used when a node is promoted to the active node. If the call is successful, `SUCCESS` is returned. If the call fails, `ERROR` is returned. After the call is successful, you can obtain the result from `*all_applied`.

Parameter description: `*all_applied` indicates the obtained result. The value `0` indicates that not all logs have been applied. A non-zero value indicates that all logs have been applied.

- ___int dcf_send_msg(unsigned int stream_id, unsigned int dest_node_id, const char* msg, unsigned int msg_size);___

Function: sending messages to a specified node. If the operation is successful, `SUCCESS` is returned. If the operation fails, `ERROR` is returned.

Parameter description: `dest_node_id` indicates the specified node. `msg` indicates the message to be sent. `msg_size` indicates the message size.

- ___int dcf_broadcast_msg(unsigned int stream_id, const char* msg, unsigned int msg_size);___

Function: broadcasting messages to all nodes except the current node. If the operation is successful, `SUCCESS` is returned. If the operation fails, `ERROR` is returned.

Parameter description: `msg` indicates the message to be sent. `msg_size` indicates the message size.

- ___int dcf_pause_rep(unsigned int stream_id, unsigned int node_id, unsigned int time_us);___

Function: pausing log replication on a specified node. If the operation is successful, `SUCCESS` is returned. If the operation fails, `ERROR` is returned.

Parameter description: `node_id` specifies the node to be paused. `time_us` specifies the pause duration (no more than 1s), in microseconds.

- ___int dcf_demote_follower(unsigned int stream_id);___

Function: demoting the active node

Parameter description: `stream_id` indicates the stream to be demoted.

- ___int dcf_get_last_commit_index(unsigned int stream_id, unsigned int is_consensus, unsigned long long* index);___

Function: obtaining the latest `commit index` value

Parameter description: `stream_id` indicates the group ID, which defaults to `1`. `is_consensus` indicates whether consistency is required (`true` or `false`). `index` is the output parameter for the `commit index`.

- ___int dcf_get_current_term_and_role(unsigned int stream_id, unsigned long long* term, dcf_role_t* role);___

Function: obtaining the current term and role information

Parameter description: If the operation fails, `ERROR(-1)` is returned. If the operation is successful, `SUCCESS(0)` is returned. When `SUCCESS` is returned, check the `term` and `role` parameters.

- ___int int dcf_set_election_priority(unsigned int stream_id, unsigned long long priority);___

Function: setting the election priority of a node. To prevent instability, this operation is rate-limited. It can only succeed once per second.

Parameter description: `priority` indicates the priority to be set.

- ___void dcf_set_timer(void *timer);___

Function: registering the timer of the upper-layer component for DCF. The timer must be compatible with the internal `gs_timer_t structure`. This is typically used for internal component integration.

Parameter description: `timer` indicates the address of the upper-layer component's timer.

### 2. Demos

Reference: `DCF/test/test_main`

The `main` function in `test_main.c` contains two parameters: the node ID and a JSON string that contains the cluster configuration information. The parameter content and meaning are the same as those of the `dcf_start` API mentioned above.

In the following example, the executable file name is `test_main` after compilation.

```
# Node 1
./test_main 1 '[{"stream_id":1,"node_id":1,"ip":"127.0.0.1","port":1711,"role":"LEADER"},{"stream_id":1,"node_id":2,"ip":"127.0.0.1","port":1712,"role":"FOLLOWER"},{"stream_id":1,"node_id":3,"ip":"127.0.0.1","port":1713,"role":"FOLLOWER"}]'

# Node 2
./test_main 2 '[{"stream_id":1,"node_id":1,"ip":"127.0.0.1","port":1711,"role":"LEADER"},{"stream_id":1,"node_id":2,"ip":"127.0.0.1","port":1712,"role":"FOLLOWER"},{"stream_id":1,"node_id":3,"ip":"127.0.0.1","port":1713,"role":"FOLLOWER"}]'

# Node 3
./test_main 3 '[{"stream_id":1,"node_id":1,"ip":"127.0.0.1","port":1711,"role":"LEADER"},{"stream_id":1,"node_id":2,"ip":"127.0.0.1","port":1712,"role":"FOLLOWER"},{"stream_id":1,"node_id":3,"ip":"127.0.0.1","port":1713,"role":"FOLLOWER"}]'
```

## 4. Test Engineering

### 1. Compile

### 2. Run test cases

To be continued...

## 5. Use Cases

### 1. Enabling the Paxos feature for GaussDB(for openGauss)

For details, see https://gitee.com/opengauss/blog/blob/master/content/zh/post/yanghaiyan/openGauss %E4%BD%BF%E8%83%BDpaxos%E7%89%B9%E6%80%A7%E5%AE%9E%E8%B7%B5.md.
