/*
 * Copyright (c) 2021 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * dcf_word.c
 *
 *
 * IDENTIFICATION
 *    src/common/lexer/dcf_word.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_num.h"
#include "dcf_word.h"
#include "dcf_oper.h"
#include "ddes_lexer.h"

#ifdef __cplusplus
extern "C" {
#endif

// only for using constant string constructing a text struct
#define CONSTRUCT_TEXT(const_str) {(char *)(const_str), sizeof(const_str) - 1}

static key_word_t g_key_words[] = {
    { (uint32)KEY_WORD_ABORT,                    CM_TRUE,  CONSTRUCT_TEXT("abort") },
    { (uint32)KEY_WORD_ACCOUNT,                  CM_TRUE,  CONSTRUCT_TEXT("account") },
    { (uint32)KEY_WORD_ACTIVATE,                 CM_TRUE,  CONSTRUCT_TEXT("activate") },
    { (uint32)KEY_WORD_ACTIVE,                   CM_TRUE,  CONSTRUCT_TEXT("active") },
    { (uint32)KEY_WORD_ADD,                      CM_FALSE, CONSTRUCT_TEXT("add") },
    { (uint32)KEY_WORD_AFTER,                    CM_TRUE,  CONSTRUCT_TEXT("after") },
    { (uint32)KEY_WORD_ALL,                      CM_FALSE, CONSTRUCT_TEXT("all") },
    { (uint32)KEY_WORD_ALTER,                    CM_FALSE, CONSTRUCT_TEXT("alter") },
    { (uint32)KEY_WORD_ANALYZE,                  CM_TRUE,  CONSTRUCT_TEXT("analyze") },
    { (uint32)KEY_WORD_AND,                      CM_FALSE, CONSTRUCT_TEXT("and") },
    { (uint32)KEY_WORD_ANY,                      CM_FALSE, CONSTRUCT_TEXT("any") },
    { (uint32)KEY_WORD_APPENDONLY,               CM_TRUE,  CONSTRUCT_TEXT("appendonly") },
    { (uint32)KEY_WORD_ARCHIVELOG,               CM_TRUE,  CONSTRUCT_TEXT("archivelog") },
    { (uint32)KEY_WORD_AS,                       CM_FALSE, CONSTRUCT_TEXT("as") },
    { (uint32)KEY_WORD_ASC,                      CM_FALSE, CONSTRUCT_TEXT("asc") },
    { (uint32)KEY_WORD_ASYNC,                    CM_TRUE,  CONSTRUCT_TEXT("async") },
    { (uint32)KEY_WORD_AUDIT,                    CM_FALSE, CONSTRUCT_TEXT("audit") },
    { (uint32)KEY_WORD_AUTOALLOCATE,             CM_TRUE,  CONSTRUCT_TEXT("autoallocate") },
    { (uint32)KEY_WORD_AUTOEXTEND,               CM_TRUE,  CONSTRUCT_TEXT("autoextend") },
    { (uint32)KEY_WORD_AUTOMATIC,                CM_TRUE,  CONSTRUCT_TEXT("automatic") },
    { (uint32)KEY_WORD_AUTON_TRANS,              CM_TRUE,  CONSTRUCT_TEXT("autonomous_transaction") },
    { (uint32)KEY_WORD_AUTOOFFLINE,              CM_TRUE,  CONSTRUCT_TEXT("autooffline") },
    { (uint32)KEY_WORD_AUTOPURGE,                CM_TRUE,  CONSTRUCT_TEXT("autopurge") },
    { (uint32)KEY_WORD_AUTO_INCREMENT,           CM_TRUE,  CONSTRUCT_TEXT("auto_increment") },
    { (uint32)KEY_WORD_AVAILABILITY,             CM_TRUE,  CONSTRUCT_TEXT("availability") },
    { (uint32)KEY_WORD_BACKUP,                   CM_TRUE,  CONSTRUCT_TEXT("backup") },
    { (uint32)KEY_WORD_BEFORE,                   CM_TRUE,  CONSTRUCT_TEXT("before") },
    { (uint32)KEY_WORD_BEGIN,                    CM_TRUE,  CONSTRUCT_TEXT("begin") },
    { (uint32)KEY_WORD_BETWEEN,                  CM_FALSE, CONSTRUCT_TEXT("between") },
    { (uint32)KEY_WORD_BODY,                     CM_TRUE,  CONSTRUCT_TEXT("body") },
    { (uint32)KEY_WORD_BOTH,                     CM_TRUE,  CONSTRUCT_TEXT("both") }, /* for TRIM expression only */
    { (uint32)KEY_WORD_BUFFER,                   CM_TRUE,  CONSTRUCT_TEXT("buffer") },
    { (uint32)KEY_WORD_BUILD,                    CM_TRUE,  CONSTRUCT_TEXT("build") },
    { (uint32)KEY_WORD_BULK,                     CM_TRUE,  CONSTRUCT_TEXT("bulk") },
    { (uint32)KEY_WORD_BY,                       CM_FALSE, CONSTRUCT_TEXT("by") },
    { (uint32)KEY_WORD_CACHE,                    CM_TRUE,  CONSTRUCT_TEXT("cache") },
    { (uint32)KEY_WORD_CALL,                     CM_TRUE,  CONSTRUCT_TEXT("call") },
    { (uint32)KEY_WORD_CANCEL,                   CM_TRUE,  CONSTRUCT_TEXT("cancel") },
    { (uint32)KEY_WORD_CASCADE,                  CM_TRUE,  CONSTRUCT_TEXT("cascade") },
    { (uint32)KEY_WORD_CASCADED,                 CM_TRUE,  CONSTRUCT_TEXT("cascaded") },
    { (uint32)KEY_WORD_CASE,                     CM_FALSE, CONSTRUCT_TEXT("case") },
    { (uint32)KEY_WORD_CAST,                     CM_TRUE,  CONSTRUCT_TEXT("cast") },
    { (uint32)KEY_WORD_CATALOG,                  CM_TRUE,  CONSTRUCT_TEXT("catalog") },
    { (uint32)KEY_WORD_CHARACTER,                CM_TRUE,  CONSTRUCT_TEXT("character") },
    { (uint32)KEY_WORD_CHARSET,                  CM_TRUE,  CONSTRUCT_TEXT("charset") },
    { (uint32)KEY_WORD_CHECK,                    CM_FALSE, CONSTRUCT_TEXT("check") },
    { (uint32)KEY_WORD_CHECKPOINT,               CM_TRUE,  CONSTRUCT_TEXT("checkpoint") },
    { (uint32)KEY_WORD_CLOSE,                    CM_TRUE,  CONSTRUCT_TEXT("close") },
    { (uint32)KEY_WORD_COALESCE,                 CM_TRUE,  CONSTRUCT_TEXT("coalesce") },
    { (uint32)KEY_WORD_COLLATE,                  CM_TRUE,  CONSTRUCT_TEXT("collate") },
    { (uint32)KEY_WORD_COLUMN,                   CM_FALSE, CONSTRUCT_TEXT("column") },
    { (uint32)KEY_WORD_COLUMNS,                  CM_TRUE,  CONSTRUCT_TEXT("columns") },
    { (uint32)KEY_WORD_COLUMN_VALUE,             CM_TRUE,  CONSTRUCT_TEXT("column_value") },
    { (uint32)KEY_WORD_COMMENT,                  CM_TRUE,  CONSTRUCT_TEXT("comment") },
    { (uint32)KEY_WORD_COMMIT,                   CM_TRUE,  CONSTRUCT_TEXT("commit") },
    { (uint32)KEY_WORD_COMPRESS,                 CM_FALSE, CONSTRUCT_TEXT("compress") },
    { (uint32)KEY_WORD_CONFIG,                   CM_TRUE,  CONSTRUCT_TEXT("config") },
    { (uint32)KEY_WORD_CONNECT,                  CM_FALSE, CONSTRUCT_TEXT("connect") },
    { (uint32)KEY_WORD_CONSISTENCY,              CM_TRUE,  CONSTRUCT_TEXT("consistency") },
    { (uint32)KEY_WORD_CONSTRAINT,               CM_FALSE, CONSTRUCT_TEXT("constraint") },
    { (uint32)KEY_WORD_CONTENT,                  CM_TRUE,  CONSTRUCT_TEXT("content") },
    { (uint32)KEY_WORD_CONTINUE,                 CM_TRUE,  CONSTRUCT_TEXT("continue") },
    { (uint32)KEY_WORD_CONTROLFILE,              CM_TRUE,  CONSTRUCT_TEXT("controlfile") },
    { (uint32)KEY_WORD_CONVERT,                  CM_TRUE,  CONSTRUCT_TEXT("convert") },
    { (uint32)KEY_WORD_COPY,                     CM_TRUE,  CONSTRUCT_TEXT("copy") },
    { (uint32)KEY_WORD_CREATE,                   CM_FALSE, CONSTRUCT_TEXT("create") },
    { (uint32)KEY_WORD_CRMODE,                   CM_FALSE, CONSTRUCT_TEXT("crmode") },
    { (uint32)KEY_WORD_CROSS,                    CM_TRUE,  CONSTRUCT_TEXT("cross") },
    { (uint32)KEY_WORD_CTRLFILE,                 CM_TRUE,  CONSTRUCT_TEXT("ctrlfile") },
    { (uint32)KEY_WORD_CUMULATIVE,               CM_FALSE, CONSTRUCT_TEXT("cumulative") },
    { (uint32)KEY_WORD_CURRENT,                  CM_FALSE, CONSTRUCT_TEXT("current") },
    { (uint32)KEY_WORD_CURRVAL,                  CM_TRUE,  CONSTRUCT_TEXT("currval") },
    { (uint32)KEY_WORD_CURSOR,                   CM_TRUE,  CONSTRUCT_TEXT("cursor") },
    { (uint32)KEY_WORD_CYCLE,                    CM_TRUE,  CONSTRUCT_TEXT("cycle") },
    { (uint32)KEY_WORD_DATA,                     CM_TRUE,  CONSTRUCT_TEXT("data") },
    { (uint32)KEY_WORD_DATABASE,                 CM_TRUE,  CONSTRUCT_TEXT("database") },
    { (uint32)KEY_WORD_DATAFILE,                 CM_TRUE,  CONSTRUCT_TEXT("datafile") },
    { (uint32)KEY_WORD_DEBUG,                    CM_TRUE,  CONSTRUCT_TEXT("debug") },
    { (uint32)KEY_WORD_DECLARE,                  CM_TRUE,  CONSTRUCT_TEXT("declare") },
    { (uint32)KEY_WORD_DEFERRABLE,               CM_TRUE,  CONSTRUCT_TEXT("deferrable") },
    { (uint32)KEY_WORD_DELETE,                   CM_FALSE, CONSTRUCT_TEXT("delete") },
    { (uint32)KEY_WORD_DESC,                     CM_FALSE, CONSTRUCT_TEXT("desc") },
    { (uint32)KEY_WORD_DICTIONARY,               CM_TRUE,  CONSTRUCT_TEXT("dictionary") },
    { (uint32)KEY_WORD_DIRECTORY,                CM_TRUE,  CONSTRUCT_TEXT("directory") },
    { (uint32)KEY_WORD_DISABLE,                  CM_TRUE,  CONSTRUCT_TEXT("disable") },
    { (uint32)KEY_WORD_DISCARD,                  CM_TRUE,  CONSTRUCT_TEXT("discard") },
    { (uint32)KEY_WORD_DISCONNECT,               CM_TRUE,  CONSTRUCT_TEXT("disconnect") },
    { (uint32)KEY_WORD_DISTINCT,                 CM_FALSE, CONSTRUCT_TEXT("distinct") },
    { (uint32)KEY_WORD_DISTRIBUTE,               CM_TRUE,  CONSTRUCT_TEXT("distribute") },
    { (uint32)KEY_WORD_DO,                       CM_TRUE,  CONSTRUCT_TEXT("do") },
    { (uint32)KEY_WORD_DROP,                     CM_FALSE, CONSTRUCT_TEXT("drop") },
    { (uint32)KEY_WORD_DUMP,                     CM_TRUE,  CONSTRUCT_TEXT("dump") },
    { (uint32)KEY_WORD_DUPLICATE,                CM_TRUE,  CONSTRUCT_TEXT("duplicate") },
    { (uint32)KEY_WORD_ELSE,                     CM_FALSE, CONSTRUCT_TEXT("else") },
    { (uint32)KEY_WORD_ELSIF,                    CM_TRUE,  CONSTRUCT_TEXT("elsif") },
    { (uint32)KEY_WORD_ENABLE,                   CM_TRUE,  CONSTRUCT_TEXT("enable") },
    { (uint32)KEY_WORD_ENABLE_LOGIC_REPLICATION, CM_TRUE,  CONSTRUCT_TEXT("enable_logic_replication") },
    { (uint32)KEY_WORD_ENCRYPTION,               CM_TRUE,  CONSTRUCT_TEXT("encryption") },
    { (uint32)KEY_WORD_END,                      CM_TRUE,  CONSTRUCT_TEXT("end") },
    { (uint32)KEY_WORD_ERROR,                    CM_TRUE,  CONSTRUCT_TEXT("error") },
    { (uint32)KEY_WORD_ESCAPE,                   CM_TRUE,  CONSTRUCT_TEXT("escape") },
    { (uint32)KEY_WORD_EXCEPT,                   CM_FALSE,  CONSTRUCT_TEXT("except") },
    { (uint32)KEY_WORD_EXCEPTION,                CM_TRUE,  CONSTRUCT_TEXT("exception") },
    { (uint32)KEY_WORD_EXCLUDE,                  CM_TRUE,  CONSTRUCT_TEXT("exclude") },
    { (uint32)KEY_WORD_EXEC,                     CM_TRUE,  CONSTRUCT_TEXT("exec") },
    { (uint32)KEY_WORD_EXECUTE,                  CM_TRUE,  CONSTRUCT_TEXT("execute") },
    { (uint32)KEY_WORD_EXISTS,                   CM_FALSE, CONSTRUCT_TEXT("exists") },
    { (uint32)KEY_WORD_EXIT,                     CM_TRUE,  CONSTRUCT_TEXT("exit") },
    { (uint32)KEY_WORD_EXPLAIN,                  CM_TRUE,  CONSTRUCT_TEXT("explain") },
    { (uint32)KEY_WORD_EXTENT,                   CM_TRUE,  CONSTRUCT_TEXT("extent") },
    { (uint32)KEY_WORD_FAILOVER,                 CM_TRUE,  CONSTRUCT_TEXT("failover") },
    { (uint32)KEY_WORD_FETCH,                    CM_TRUE,  CONSTRUCT_TEXT("fetch") },
    { (uint32)KEY_WORD_FILE,                     CM_TRUE,  CONSTRUCT_TEXT("file") },
    { (uint32)KEY_WORD_FILETYPE,                 CM_TRUE,  CONSTRUCT_TEXT("filetype") },
    { (uint32)KEY_WORD_FINAL,                    CM_TRUE,  CONSTRUCT_TEXT("final") },
    { (uint32)KEY_WORD_FINISH,                   CM_TRUE,  CONSTRUCT_TEXT("finish") },
    { (uint32)KEY_WORD_FLASHBACK,                CM_TRUE,  CONSTRUCT_TEXT("flashback") },
    { (uint32)KEY_WORD_FLUSH,                    CM_TRUE,  CONSTRUCT_TEXT("flush") },
    { (uint32)KEY_WORD_FOR,                      CM_FALSE, CONSTRUCT_TEXT("for") },
    { (uint32)KEY_WORD_FORALL,                   CM_FALSE, CONSTRUCT_TEXT("forall") },
    { (uint32)KEY_WORD_FORCE,                    CM_TRUE,  CONSTRUCT_TEXT("force") },
    { (uint32)KEY_WORD_FOREIGN,                  CM_TRUE,  CONSTRUCT_TEXT("foreign") },
    { (uint32)KEY_WORD_FORMAT,                   CM_TRUE,  CONSTRUCT_TEXT("format") },
    { (uint32)KEY_WORD_FROM,                     CM_FALSE, CONSTRUCT_TEXT("from") },
    { (uint32)KEY_WORD_FULL,                     CM_TRUE,  CONSTRUCT_TEXT("full") },
    { (uint32)KEY_WORD_FUNCTION,                 CM_TRUE,  CONSTRUCT_TEXT("function") },
    { (uint32)KEY_WORD_GLOBAL,                   CM_TRUE,  CONSTRUCT_TEXT("global") },
    { (uint32)KEY_WORD_GOTO,                     CM_TRUE,  CONSTRUCT_TEXT("goto") },
    { (uint32)KEY_WORD_GRANT,                    CM_TRUE,  CONSTRUCT_TEXT("grant") },
    { (uint32)KEY_WORD_GROUP,                    CM_FALSE, CONSTRUCT_TEXT("group") },
    { (uint32)KEY_WORD_GROUPID,                  CM_TRUE,  CONSTRUCT_TEXT("groupid") },
    { (uint32)KEY_WORD_HASH,                     CM_TRUE,  CONSTRUCT_TEXT("hash") },
    { (uint32)KEY_WORD_HAVING,                   CM_FALSE, CONSTRUCT_TEXT("having") },
    { (uint32)KEY_WORD_IDENTIFIED,               CM_FALSE, CONSTRUCT_TEXT("identified") },
    { (uint32)KEY_WORD_IF,                       CM_TRUE,  CONSTRUCT_TEXT("if") },
    { (uint32)KEY_WORD_IGNORE,                   CM_TRUE,  CONSTRUCT_TEXT("ignore") },
    { (uint32)KEY_WORD_IN,                       CM_FALSE, CONSTRUCT_TEXT("in") },
    { (uint32)KEY_WORD_INCLUDE,                  CM_TRUE,  CONSTRUCT_TEXT("include") },
    { (uint32)KEY_WORD_INCLUDING,                CM_TRUE,  CONSTRUCT_TEXT("including") },
    { (uint32)KEY_WORD_INCREMENT,                CM_FALSE, CONSTRUCT_TEXT("increment") },
    { (uint32)KEY_WORD_INCREMENTAL,              CM_TRUE,  CONSTRUCT_TEXT("incremental") },
    { (uint32)KEY_WORD_INDEX,                    CM_FALSE, CONSTRUCT_TEXT("index") },
    { (uint32)KEY_WORD_INDEX_ASC,                CM_TRUE,  CONSTRUCT_TEXT("index_asc") },
    { (uint32)KEY_WORD_INDEX_DESC,               CM_TRUE,  CONSTRUCT_TEXT("index_desc") },
    { (uint32)KEY_WORD_INIT,                     CM_TRUE,  CONSTRUCT_TEXT("init") },
    { (uint32)KEY_WORD_INITIAL,                  CM_TRUE,  CONSTRUCT_TEXT("initial") },
    { (uint32)KEY_WORD_INITIALLY,                CM_TRUE,  CONSTRUCT_TEXT("initially") },
    { (uint32)KEY_WORD_INITRANS,                 CM_TRUE,  CONSTRUCT_TEXT("initrans") },
    { (uint32)KEY_WORD_INNER,                    CM_TRUE,  CONSTRUCT_TEXT("inner") },
    { (uint32)KEY_WORD_INSERT,                   CM_FALSE, CONSTRUCT_TEXT("insert") },
    { (uint32)KEY_WORD_INSTANCE,                 CM_TRUE,  CONSTRUCT_TEXT("instance") },
    { (uint32)KEY_WORD_INSTANTIABLE,             CM_TRUE,  CONSTRUCT_TEXT("instantiable") },
    { (uint32)KEY_WORD_INSTEAD,                  CM_TRUE,  CONSTRUCT_TEXT("instead") },
    { (uint32)KEY_WORD_INTERSECT,                CM_FALSE, CONSTRUCT_TEXT("intersect") },
    { (uint32)KEY_WORD_INTO,                     CM_FALSE, CONSTRUCT_TEXT("into") },
    { (uint32)KEY_WORD_INVALIDATE,               CM_TRUE,  CONSTRUCT_TEXT("invalidate") },
    { (uint32)KEY_WORD_IS,                       CM_FALSE, CONSTRUCT_TEXT("is") },
    { (uint32)KEY_WORD_IS_NOT,                   CM_TRUE,  CONSTRUCT_TEXT("isnot") },
    { (uint32)KEY_WORD_JOIN,                     CM_TRUE,  CONSTRUCT_TEXT("join") },
    { (uint32)KEY_WORD_JSON,                     CM_TRUE,  CONSTRUCT_TEXT("json") },
    { (uint32)KEY_WORD_KEEP,                     CM_TRUE,  CONSTRUCT_TEXT("keep") },
    { (uint32)KEY_WORD_KEY,                      CM_TRUE,  CONSTRUCT_TEXT("key") },
    { (uint32)KEY_WORD_KILL,                     CM_TRUE,  CONSTRUCT_TEXT("kill") },
    { (uint32)KEY_WORD_LANGUAGE,                 CM_TRUE,  CONSTRUCT_TEXT("language") },
    { (uint32)KEY_WORD_LEADING,                  CM_TRUE,  CONSTRUCT_TEXT("leading") }, /* for TRIM expression only */
    { (uint32)KEY_WORD_LEFT,                     CM_TRUE,  CONSTRUCT_TEXT("left") },
    { (uint32)KEY_WORD_LESS,                     CM_TRUE,  CONSTRUCT_TEXT("less") },
    { (uint32)KEY_WORD_LEVEL,                    CM_FALSE, CONSTRUCT_TEXT("level") },
    { (uint32)KEY_WORD_LIBRARY,                  CM_FALSE, CONSTRUCT_TEXT("library") },
    { (uint32)KEY_WORD_LIKE,                     CM_FALSE, CONSTRUCT_TEXT("like") },
    { (uint32)KEY_WORD_LIMIT,                    CM_TRUE,  CONSTRUCT_TEXT("limit") },
    { (uint32)KEY_WORD_LIST,                     CM_TRUE,  CONSTRUCT_TEXT("list") },
    { (uint32)KEY_WORD_LNNVL,                    CM_TRUE,  CONSTRUCT_TEXT("lnnvl") },
    { (uint32)KEY_WORD_LOAD,                     CM_TRUE,  CONSTRUCT_TEXT("load") },
    { (uint32)KEY_WORD_LOB,                      CM_TRUE,  CONSTRUCT_TEXT("lob") },
    { (uint32)KEY_WORD_LOCAL,                    CM_TRUE,  CONSTRUCT_TEXT("local") },
    { (uint32)KEY_WORD_LOCK,                     CM_FALSE, CONSTRUCT_TEXT("lock") },
    { (uint32)KEY_WORD_LOCK_WAIT,                CM_TRUE,  CONSTRUCT_TEXT("lock_wait") },
    { (uint32)KEY_WORD_LOG,                      CM_TRUE,  CONSTRUCT_TEXT("log") },
    { (uint32)KEY_WORD_LOGFILE,                  CM_TRUE,  CONSTRUCT_TEXT("logfile") },
    { (uint32)KEY_WORD_LOGGING,                  CM_TRUE,  CONSTRUCT_TEXT("logging") },
    { (uint32)KEY_WORD_LOGICAL,                  CM_TRUE,  CONSTRUCT_TEXT("logical") },
    { (uint32)KEY_WORD_LOOP,                     CM_TRUE,  CONSTRUCT_TEXT("loop") },
    { (uint32)KEY_WORD_MANAGED,                  CM_TRUE,  CONSTRUCT_TEXT("managed") },
    { (uint32)KEY_WORD_MAXIMIZE,                 CM_TRUE,  CONSTRUCT_TEXT("maximize") },
    { (uint32)KEY_WORD_MAXSIZE,                  CM_TRUE,  CONSTRUCT_TEXT("maxsize") },
    { (uint32)KEY_WORD_MAXTRANS,                 CM_TRUE,  CONSTRUCT_TEXT("maxtrans") },
    { (uint32)KEY_WORD_MAXVALUE,                 CM_TRUE,  CONSTRUCT_TEXT("maxvalue") },
    { (uint32)KEY_WORD_MEMBER,                   CM_TRUE,  CONSTRUCT_TEXT("member") },
    { (uint32)KEY_WORD_MEMORY,                   CM_TRUE,  CONSTRUCT_TEXT("memory") },
    { (uint32)KEY_WORD_MERGE,                    CM_TRUE,  CONSTRUCT_TEXT("merge") },
    { (uint32)KEY_WORD_MINUS,                    CM_FALSE, CONSTRUCT_TEXT("minus") },
    { (uint32)KEY_WORD_MINVALUE,                 CM_TRUE,  CONSTRUCT_TEXT("minvalue") },
    { (uint32)KEY_WORD_MODE,                     CM_TRUE,  CONSTRUCT_TEXT("mode") },
    { (uint32)KEY_WORD_MODIFY,                   CM_FALSE, CONSTRUCT_TEXT("modify") },
    { (uint32)KEY_WORD_MONITOR,                  CM_TRUE,  CONSTRUCT_TEXT("monitor") },
    { (uint32)KEY_WORD_MOUNT,                    CM_TRUE,  CONSTRUCT_TEXT("mount") },
    { (uint32)KEY_WORD_MOVE,                     CM_TRUE,  CONSTRUCT_TEXT("move") },
    { (uint32)KEY_WORD_NEXT,                     CM_TRUE,  CONSTRUCT_TEXT("next") },
    { (uint32)KEY_WORD_NEXTVAL,                  CM_TRUE,  CONSTRUCT_TEXT("nextval") },
    { (uint32)KEY_WORD_NOARCHIVELOG,             CM_TRUE,  CONSTRUCT_TEXT("noarchivelog") },
    { (uint32)KEY_WORD_NO_CACHE,                 CM_TRUE,  CONSTRUCT_TEXT("nocache") },
    { (uint32)KEY_WORD_NO_COMPRESS,              CM_FALSE, CONSTRUCT_TEXT("nocompress") },
    { (uint32)KEY_WORD_NO_CYCLE,                 CM_TRUE,  CONSTRUCT_TEXT("nocycle") },
    { (uint32)KEY_WORD_NODE,                     CM_TRUE,  CONSTRUCT_TEXT("node") },
    { (uint32)KEY_WORD_NO_LOGGING,               CM_TRUE,  CONSTRUCT_TEXT("nologging") },
    { (uint32)KEY_WORD_NO_MAXVALUE,              CM_TRUE,  CONSTRUCT_TEXT("nomaxvalue") },
    { (uint32)KEY_WORD_NO_MINVALUE,              CM_TRUE,  CONSTRUCT_TEXT("nominvalue") },
    { (uint32)KEY_WORD_NO_ORDER,                 CM_TRUE,  CONSTRUCT_TEXT("noorder") },
    { (uint32)KEY_WORD_NO_RELY,                  CM_TRUE,  CONSTRUCT_TEXT("norely") },
    { (uint32)KEY_WORD_NOT,                      CM_FALSE, CONSTRUCT_TEXT("not") },
    { (uint32)KEY_WORD_NO_VALIDATE,              CM_TRUE,  CONSTRUCT_TEXT("novalidate") },
    { (uint32)KEY_WORD_NOWAIT,                   CM_FALSE, CONSTRUCT_TEXT("nowait") },
    { (uint32)KEY_WORD_NULL,                     CM_FALSE, CONSTRUCT_TEXT("null") },
    { (uint32)KEY_WORD_NULLS,                    CM_TRUE,  CONSTRUCT_TEXT("nulls") },
    { (uint32)KEY_WORD_OF,                       CM_FALSE, CONSTRUCT_TEXT("of") },
    { (uint32)KEY_WORD_OFF,                      CM_TRUE,  CONSTRUCT_TEXT("off") },
    { (uint32)KEY_WORD_OFFLINE,                  CM_FALSE, CONSTRUCT_TEXT("offline") },
    { (uint32)KEY_WORD_OFFSET,                   CM_TRUE,  CONSTRUCT_TEXT("offset") },
    { (uint32)KEY_WORD_ON,                       CM_FALSE, CONSTRUCT_TEXT("on") },
    { (uint32)KEY_WORD_ONLINE,                   CM_FALSE, CONSTRUCT_TEXT("online") },
    { (uint32)KEY_WORD_ONLY,                     CM_TRUE,  CONSTRUCT_TEXT("only") },
    { (uint32)KEY_WORD_OPEN,                     CM_TRUE,  CONSTRUCT_TEXT("open") },
    { (uint32)KEY_WORD_OR,                       CM_FALSE, CONSTRUCT_TEXT("or") },
    { (uint32)KEY_WORD_ORDER,                    CM_FALSE, CONSTRUCT_TEXT("order") },
    { (uint32)KEY_WORD_ORGANIZATION,             CM_TRUE,  CONSTRUCT_TEXT("organization") },
    { (uint32)KEY_WORD_OUTER,                    CM_TRUE,  CONSTRUCT_TEXT("outer") },
    { (uint32)KEY_WORD_OVERRIDING,               CM_TRUE,  CONSTRUCT_TEXT("overriding") },
    { (uint32)KEY_WORD_PACKAGE,                  CM_TRUE,  CONSTRUCT_TEXT("package") },
    { (uint32)KEY_WORD_PARALLELISM,              CM_TRUE,  CONSTRUCT_TEXT("parallelism") },
    { (uint32)KEY_WORD_PARAM,                    CM_TRUE,  CONSTRUCT_TEXT("parameter") },
    { (uint32)KEY_WORD_PARTITION,                CM_TRUE,  CONSTRUCT_TEXT("partition") },
    { (uint32)KEY_WORD_PASSWORD,                 CM_TRUE,  CONSTRUCT_TEXT("password") },
    { (uint32)KEY_WORD_PATH,                     CM_TRUE,  CONSTRUCT_TEXT("path") },
    { (uint32)KEY_WORD_PCTFREE,                  CM_TRUE,  CONSTRUCT_TEXT("pctfree") },
    { (uint32)KEY_WORD_PERFORMANCE,              CM_TRUE,  CONSTRUCT_TEXT("performance") },
    { (uint32)KEY_WORD_PHYSICAL,                 CM_TRUE,  CONSTRUCT_TEXT("physical") },
    { (uint32)KEY_WORD_PIVOT,                    CM_TRUE,  CONSTRUCT_TEXT("pivot") },
    { (uint32)KEY_WORD_PLAN,                     CM_TRUE,  CONSTRUCT_TEXT("plan") },
    { (uint32)KEY_WORD_PRAGMA,                   CM_TRUE,  CONSTRUCT_TEXT("pragma") },
    { (uint32)KEY_WORD_PREPARE,                  CM_TRUE,  CONSTRUCT_TEXT("prepare") },
    { (uint32)KEY_WORD_PREPARED,                 CM_TRUE,  CONSTRUCT_TEXT("prepared") },
    { (uint32)KEY_WORD_PRESERVE,                 CM_TRUE,  CONSTRUCT_TEXT("preserve") },
    { (uint32)KEY_WORD_PRIMARY,                  CM_TRUE,  CONSTRUCT_TEXT("primary") },
    { (uint32)KEY_WORD_PRIOR,                    CM_TRUE,  CONSTRUCT_TEXT("prior") },
    { (uint32)KEY_WORD_PRIVILEGES,               CM_FALSE, CONSTRUCT_TEXT("privileges") },
    { (uint32)KEY_WORD_PROCEDURE,                CM_TRUE,  CONSTRUCT_TEXT("procedure") },
    { (uint32)KEY_WORD_PROFILE,                  CM_TRUE,  CONSTRUCT_TEXT("profile") },
    { (uint32)KEY_WORD_PROTECTION,               CM_TRUE,  CONSTRUCT_TEXT("protection") },
    { (uint32)KEY_WORD_PUBLIC,                   CM_FALSE, CONSTRUCT_TEXT("public") },
    { (uint32)KEY_WORD_PURGE,                    CM_TRUE,  CONSTRUCT_TEXT("purge") },
    { (uint32)KEY_WORD_QUERY,                    CM_TRUE,  CONSTRUCT_TEXT("query") },
    { (uint32)KEY_WORD_RAISE,                    CM_TRUE,  CONSTRUCT_TEXT("raise") },
    { (uint32)KEY_WORD_RANGE,                    CM_TRUE,  CONSTRUCT_TEXT("range") },
    { (uint32)KEY_WORD_READ,                     CM_TRUE,  CONSTRUCT_TEXT("read") },
    { (uint32)KEY_WORD_READ_ONLY,                CM_TRUE,  CONSTRUCT_TEXT("readonly") },
    { (uint32)KEY_WORD_READ_WRITE,               CM_TRUE,  CONSTRUCT_TEXT("readwrite") },
    { (uint32)KEY_WORD_REBUILD,                  CM_TRUE,  CONSTRUCT_TEXT("rebuild") },
    { (uint32)KEY_WORD_RECOVER,                  CM_TRUE,  CONSTRUCT_TEXT("recover") },
    { (uint32)KEY_WORD_RECYCLEBIN,               CM_TRUE,  CONSTRUCT_TEXT("recyclebin") },
    { (uint32)KEY_WORD_REDO,                     CM_TRUE,  CONSTRUCT_TEXT("redo") },
    { (uint32)KEY_WORD_REFERENCES,               CM_TRUE,  CONSTRUCT_TEXT("references") },
    { (uint32)KEY_WORD_REFRESH,                  CM_TRUE,  CONSTRUCT_TEXT("refresh") },
    { (uint32)KEY_WORD_REGEXP,                   CM_TRUE,  CONSTRUCT_TEXT("regexp") },
    { (uint32)KEY_WORD_REGEXP_LIKE,              CM_TRUE,  CONSTRUCT_TEXT("regexp_like") },
    { (uint32)KEY_WORD_REGISTER,                 CM_TRUE,  CONSTRUCT_TEXT("register") },
    { (uint32)KEY_WORD_RELEASE,                  CM_TRUE,  CONSTRUCT_TEXT("release") },
    { (uint32)KEY_WORD_RELOAD,                   CM_TRUE,  CONSTRUCT_TEXT("reload") },
    { (uint32)KEY_WORD_RELY,                     CM_TRUE,  CONSTRUCT_TEXT("rely") },
    { (uint32)KEY_WORD_RENAME,                   CM_FALSE, CONSTRUCT_TEXT("rename") },
    { (uint32)KEY_WORD_REPLACE,                  CM_TRUE,  CONSTRUCT_TEXT("replace") },
    { (uint32)KEY_WORD_RESET,                    CM_TRUE,  CONSTRUCT_TEXT("reset") },
    { (uint32)KEY_WORD_RESIZE,                   CM_TRUE,  CONSTRUCT_TEXT("resize") },
    { (uint32)KEY_WORD_RESTORE,                  CM_TRUE,  CONSTRUCT_TEXT("restore") },
    { (uint32)KEY_WORD_RESTRICT,                 CM_TRUE,  CONSTRUCT_TEXT("restrict") },
    { (uint32)KEY_WORD_RETURN,                   CM_TRUE,  CONSTRUCT_TEXT("return") },
    { (uint32)KEY_WORD_RETURNING,                CM_TRUE,  CONSTRUCT_TEXT("returning") },
    { (uint32)KEY_WORD_REUSE,                    CM_TRUE,  CONSTRUCT_TEXT("reuse") },
    { (uint32)KEY_WORD_REVOKE,                   CM_TRUE,  CONSTRUCT_TEXT("revoke") },
    { (uint32)KEY_WORD_RIGHT,                    CM_TRUE,  CONSTRUCT_TEXT("right") },
    { (uint32)KEY_WORD_ROLE,                     CM_TRUE,  CONSTRUCT_TEXT("role") },
    { (uint32)KEY_WORD_ROLLBACK,                 CM_TRUE,  CONSTRUCT_TEXT("rollback") },
    { (uint32)KEY_WORD_ROUTE,                    CM_TRUE,  CONSTRUCT_TEXT("route") },
    { (uint32)KEY_WORD_ROWS,                     CM_FALSE, CONSTRUCT_TEXT("rows") },
    { (uint32)KEY_WORD_SAVEPOINT,                CM_TRUE,  CONSTRUCT_TEXT("savepoint") },
    { (uint32)KEY_WORD_SCN,                      CM_TRUE,  CONSTRUCT_TEXT("scn") },
    { (uint32)KEY_WORD_SECONDARY,                CM_TRUE,  CONSTRUCT_TEXT("secondary") },
    { (uint32)KEY_WORD_SECTION,                  CM_TRUE,  CONSTRUCT_TEXT("section") },
    { (uint32)KEY_WORD_SELECT,                   CM_FALSE, CONSTRUCT_TEXT("select") },
    { (uint32)KEY_WORD_SEPARATOR,                CM_TRUE,  CONSTRUCT_TEXT("separator") },
    { (uint32)KEY_WORD_SEQUENCE,                 CM_TRUE,  CONSTRUCT_TEXT("sequence") },
    { (uint32)KEY_WORD_SERIALIZABLE,             CM_TRUE,  CONSTRUCT_TEXT("serializable") },
    { (uint32)KEY_WORD_SERVER,                   CM_TRUE,  CONSTRUCT_TEXT("server") },
    { (uint32)KEY_WORD_SESSION,                  CM_FALSE, CONSTRUCT_TEXT("session") },
    { (uint32)KEY_WORD_SET,                      CM_FALSE, CONSTRUCT_TEXT("set") },
    { (uint32)KEY_WORD_SHARE,                    CM_TRUE,  CONSTRUCT_TEXT("share") },
    { (uint32)KEY_WORD_SHOW,                     CM_TRUE,  CONSTRUCT_TEXT("show") },
    { (uint32)KEY_WORD_SHRINK,                   CM_TRUE,  CONSTRUCT_TEXT("shrink") },
    { (uint32)KEY_WORD_SHUTDOWN,                 CM_TRUE,  CONSTRUCT_TEXT("shutdown") },
#ifdef DB_DEBUG_VERSION
    { (uint32)KEY_WORD_SIGNAL,                   CM_TRUE, CONSTRUCT_TEXT("signal") },
#endif
    { (uint32)KEY_WORD_SIZE,                     CM_TRUE,  CONSTRUCT_TEXT("size") },
    { (uint32)KEY_WORD_SKIP,                     CM_TRUE,  CONSTRUCT_TEXT("skip") },
    { (uint32)KEY_WORD_SKIP_ADD_DROP_TABLE,      CM_TRUE,  CONSTRUCT_TEXT("skip_add_drop_table") },
    { (uint32)KEY_WORD_SKIP_COMMENTS,            CM_TRUE,  CONSTRUCT_TEXT("skip_comment") },
    { (uint32)KEY_WORD_SKIP_TRIGGERS,            CM_TRUE,  CONSTRUCT_TEXT("skip_triggers") },
    { (uint32)KEY_WORD_SKIP_QUOTE_NAMES,         CM_TRUE,  CONSTRUCT_TEXT("skip_quote_names") },
    { (uint32)KEY_WORD_SPACE,                    CM_TRUE,  CONSTRUCT_TEXT("space") },
    { (uint32)KEY_WORD_SPLIT,                    CM_TRUE,  CONSTRUCT_TEXT("split") },
    { (uint32)KEY_WORD_SPLIT_FACTOR,             CM_TRUE,  CONSTRUCT_TEXT("split_factor") },
    { (uint32)KEY_WORD_SQL_MAP,                  CM_FALSE, CONSTRUCT_TEXT("sql_map") },
    { (uint32)KEY_WORD_STANDARD,                 CM_TRUE,  CONSTRUCT_TEXT("standard") },
    { (uint32)KEY_WORD_STANDBY,                  CM_TRUE,  CONSTRUCT_TEXT("standby") },
    { (uint32)KEY_WORD_START,                    CM_FALSE, CONSTRUCT_TEXT("start") },
    { (uint32)KEY_WORD_STARTUP,                  CM_TRUE,  CONSTRUCT_TEXT("startup") },
    { (uint32)KEY_WORD_STATIC,                   CM_TRUE,  CONSTRUCT_TEXT("static") },
    { (uint32)KEY_WORD_STOP,                     CM_TRUE,  CONSTRUCT_TEXT("stop") },
    { (uint32)KEY_WORD_STORAGE,                  CM_TRUE,  CONSTRUCT_TEXT("storage") },
    { (uint32)KEY_WORD_SWAP,                     CM_TRUE,  CONSTRUCT_TEXT("swap") },
    { (uint32)KEY_WORD_SWITCH,                   CM_TRUE,  CONSTRUCT_TEXT("switch") },
    { (uint32)KEY_WORD_SWITCHOVER,               CM_TRUE,  CONSTRUCT_TEXT("switchover") },
#ifdef DB_DEBUG_VERSION
    { (uint32)KEY_WORD_SYNCPOINT,                CM_TRUE, CONSTRUCT_TEXT("syncpoint") },
#endif
    { (uint32)KEY_WORD_SYNONYM,                  CM_FALSE, CONSTRUCT_TEXT("synonym") },
    { (uint32)KEY_WORD_SYSAUX,                   CM_TRUE,  CONSTRUCT_TEXT("sysaux") },
    { (uint32)KEY_WORD_SYSTEM,                   CM_TRUE,  CONSTRUCT_TEXT("system") },
    { (uint32)KEY_WORD_TABLE,                    CM_FALSE, CONSTRUCT_TEXT("table") },
    { (uint32)KEY_WORD_TABLES,                   CM_TRUE,  CONSTRUCT_TEXT("tables") },
    { (uint32)KEY_WORD_TABLESPACE,               CM_TRUE,  CONSTRUCT_TEXT("tablespace") },
    { (uint32)KEY_WORD_TAG,                      CM_TRUE,  CONSTRUCT_TEXT("tag") },
    { (uint32)KEY_WORD_TEMP,                     CM_TRUE,  CONSTRUCT_TEXT("temp") },
    { (uint32)KEY_WORD_TEMPFILE,                 CM_TRUE,  CONSTRUCT_TEXT("tempfile") },
    { (uint32)KEY_WORD_TEMPORARY,                CM_TRUE,  CONSTRUCT_TEXT("temporary") },
    { (uint32)KEY_WORD_THAN,                     CM_TRUE,  CONSTRUCT_TEXT("than") },
    { (uint32)KEY_WORD_THEN,                     CM_FALSE, CONSTRUCT_TEXT("then") },
    { (uint32)KEY_WORD_THREAD,                   CM_TRUE,  CONSTRUCT_TEXT("thread") },
    { (uint32)KEY_WORD_TIMEOUT,                  CM_TRUE,  CONSTRUCT_TEXT("timeout") },
    { (uint32)KEY_WORD_TIMEZONE,                 CM_TRUE,  CONSTRUCT_TEXT("time_zone") },
    { (uint32)KEY_WORD_TO,                       CM_FALSE, CONSTRUCT_TEXT("to") },
    { (uint32)KEY_WORD_TRAILING,                 CM_TRUE,  CONSTRUCT_TEXT("trailing") }, /* for TRIM expression only */
    { (uint32)KEY_WORD_TRANSACTION,              CM_TRUE,  CONSTRUCT_TEXT("transaction") },
    { (uint32)KEY_WORD_TRIGGER,                  CM_FALSE, CONSTRUCT_TEXT("trigger") },
    { (uint32)KEY_WORD_TRUNCATE,                 CM_TRUE,  CONSTRUCT_TEXT("truncate") },
    { (uint32)KEY_WORD_TYPE,                     CM_TRUE,  CONSTRUCT_TEXT("type") },
    { (uint32)KEY_WORD_UNDO,                     CM_TRUE,  CONSTRUCT_TEXT("undo") },
    { (uint32)KEY_WORD_UNIFORM,                  CM_TRUE,  CONSTRUCT_TEXT("uniform") },
    { (uint32)KEY_WORD_UNION,                    CM_FALSE, CONSTRUCT_TEXT("union") },
    { (uint32)KEY_WORD_UNIQUE,                   CM_TRUE,  CONSTRUCT_TEXT("unique") },
    { (uint32)KEY_WORD_UNLIMITED,                CM_TRUE,  CONSTRUCT_TEXT("unlimited") },
    { (uint32)KEY_WORD_UNLOCK,                   CM_TRUE,  CONSTRUCT_TEXT("unlock") },
    { (uint32)KEY_WORD_UNPIVOT,                  CM_TRUE,  CONSTRUCT_TEXT("unpivot") },
    { (uint32)KEY_WORD_UNTIL,                    CM_TRUE,  CONSTRUCT_TEXT("until") },
    { (uint32)KEY_WORD_UNUSABLE,                 CM_TRUE,  CONSTRUCT_TEXT("unusable") },
    { (uint32)KEY_WORD_UPDATE,                   CM_FALSE, CONSTRUCT_TEXT("update") },
    { (uint32)KEY_WORD_USER,                     CM_FALSE, CONSTRUCT_TEXT("user") },
    { (uint32)KEY_WORD_USERS,                    CM_TRUE,  CONSTRUCT_TEXT("users") },
    { (uint32)KEY_WORD_USING,                    CM_TRUE,  CONSTRUCT_TEXT("using") },
    { (uint32)KEY_WORD_VALIDATE,                 CM_TRUE,  CONSTRUCT_TEXT("validate") },
    { (uint32)KEY_WORD_VALUES,                   CM_FALSE, CONSTRUCT_TEXT("values") },
    { (uint32)KEY_WORD_VIEW,                     CM_FALSE, CONSTRUCT_TEXT("view") },
    { (uint32)KEY_WORD_WAIT,                     CM_TRUE,  CONSTRUCT_TEXT("wait") },
    { (uint32)KEY_WORD_WHEN,                     CM_TRUE,  CONSTRUCT_TEXT("when") },
    { (uint32)KEY_WORD_WHERE,                    CM_FALSE, CONSTRUCT_TEXT("where") },
    { (uint32)KEY_WORD_WHILE,                    CM_FALSE, CONSTRUCT_TEXT("while") },
    { (uint32)KEY_WORD_WITH,                     CM_FALSE, CONSTRUCT_TEXT("with") },
};

#ifdef WIN32
static_assert(sizeof(g_key_words) / sizeof(key_word_t) == KEY_WORD_DUMB_END - KEY_WORD_0_UNKNOWN - 1,
              "Array g_key_words defined error");
#endif

/* datatype key words */
static datatype_word_t g_datatype_words[] = {
    { CONSTRUCT_TEXT("bigint"), DTYP_BIGINT, CM_TRUE, CM_TRUE },
    { CONSTRUCT_TEXT("binary"), DTYP_BINARY, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("binary_bigint"), DTYP_BINARY_BIGINT, CM_TRUE, CM_TRUE },
    { CONSTRUCT_TEXT("binary_double"), DTYP_BINARY_DOUBLE, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("binary_float"), DTYP_BINARY_FLOAT, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("binary_integer"), DTYP_BINARY_INTEGER, CM_TRUE, CM_TRUE },
    { CONSTRUCT_TEXT("binary_uint32"), DTYP_UINTEGER, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("blob"), DTYP_BLOB, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("bool"), DTYP_BOOLEAN, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("boolean"), DTYP_BOOLEAN, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("bpchar"), DTYP_CHAR, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("bytea"), DTYP_BLOB, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("char"), DTYP_CHAR, CM_FALSE, CM_FALSE },
    { CONSTRUCT_TEXT("character"), DTYP_CHAR, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("clob"), DTYP_CLOB, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("date"), DTYP_DATE, CM_FALSE, CM_FALSE },
    { CONSTRUCT_TEXT("datetime"), DTYP_DATE, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("decimal"), DTYP_DECIMAL, CM_FALSE, CM_FALSE },
    { CONSTRUCT_TEXT("double"), DTYP_DOUBLE, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("float"), DTYP_FLOAT, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("image"), DTYP_IMAGE, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("int"), DTYP_INTEGER, CM_TRUE, CM_TRUE },
    { CONSTRUCT_TEXT("integer"), DTYP_INTEGER, CM_FALSE, CM_TRUE },
    { CONSTRUCT_TEXT("interval"), DTYP_INTERVAL, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("long"), DTYP_CLOB, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("longblob"), DTYP_IMAGE, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("longtext"), DTYP_CLOB, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("mediumblob"), DTYP_IMAGE, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("nchar"), DTYP_NCHAR, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("number"), DTYP_NUMBER, CM_FALSE, CM_FALSE },
    { CONSTRUCT_TEXT("numeric"), DTYP_DECIMAL, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("nvarchar"), DTYP_NVARCHAR, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("nvarchar2"), DTYP_NVARCHAR, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("raw"), DTYP_RAW, CM_FALSE, CM_FALSE },
    { CONSTRUCT_TEXT("real"), DTYP_DOUBLE, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("serial"), DTYP_SERIAL, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("short"), DTYP_SMALLINT, CM_TRUE, CM_TRUE },
    { CONSTRUCT_TEXT("smallint"), DTYP_SMALLINT, CM_TRUE, CM_TRUE },
    { CONSTRUCT_TEXT("text"), DTYP_CLOB, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("timestamp"), DTYP_TIMESTAMP, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("tinyint"), DTYP_TINYINT, CM_TRUE, CM_TRUE },
    { CONSTRUCT_TEXT("ubigint"), DTYP_UBIGINT, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("uint"), DTYP_UINTEGER, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("uinteger"), DTYP_UINTEGER, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("ushort"), DTYP_USMALLINT, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("usmallint"), DTYP_USMALLINT, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("utinyint"), DTYP_UTINYINT, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("varbinary"), DTYP_VARBINARY, CM_TRUE, CM_FALSE },
    { CONSTRUCT_TEXT("varchar"), DTYP_VARCHAR, CM_FALSE, CM_FALSE },
    { CONSTRUCT_TEXT("varchar2"), DTYP_VARCHAR, CM_FALSE, CM_FALSE },
};

/* reserved keywords
 * **Note:** the reserved keywords must be arrange in alphabetically
 * ascending order for speeding the search process. */
static key_word_t g_reserved_words[] = {
    { (uint32)RES_WORD_COLUMN_VALUE,       CM_TRUE,  CONSTRUCT_TEXT("column_value") },
    { (uint32)RES_WORD_CONNECT_BY_ISCYCLE, CM_TRUE,  CONSTRUCT_TEXT("connect_by_iscycle") },
    { (uint32)RES_WORD_CONNECT_BY_ISLEAF,  CM_TRUE,  CONSTRUCT_TEXT("connect_by_isleaf") },
    { (uint32)RES_WORD_CURDATE,            CM_TRUE,  CONSTRUCT_TEXT("curdate") },
    { (uint32)RES_WORD_CURDATE,            CM_TRUE,  CONSTRUCT_TEXT("current_date") },
    { (uint32)RES_WORD_CURTIMESTAMP,       CM_TRUE,  CONSTRUCT_TEXT("current_timestamp") },
    { (uint32)RES_WORD_DATABASETZ,         CM_TRUE,  CONSTRUCT_TEXT("dbtimezone") },
    { (uint32)RES_WORD_DEFAULT,            CM_FALSE, CONSTRUCT_TEXT("default") },
    { (uint32)RES_WORD_DELETING,           CM_TRUE,  CONSTRUCT_TEXT("deleting") },
    { (uint32)RES_WORD_FALSE,              CM_FALSE, CONSTRUCT_TEXT("false") },
    { (uint32)RES_WORD_INSERTING,          CM_TRUE,  CONSTRUCT_TEXT("inserting") },
    { (uint32)RES_WORD_LEVEL,              CM_FALSE, CONSTRUCT_TEXT("level") },
    { (uint32)RES_WORD_LOCALTIMESTAMP,     CM_TRUE,  CONSTRUCT_TEXT("localtimestamp") },
    { (uint32)RES_WORD_SYSTIMESTAMP,       CM_TRUE,  CONSTRUCT_TEXT("now") },
    { (uint32)RES_WORD_NULL,               CM_FALSE, CONSTRUCT_TEXT("null") },
    { (uint32)RES_WORD_ROWID,              CM_FALSE, CONSTRUCT_TEXT("rowid") },
    { (uint32)RES_WORD_ROWNUM,             CM_FALSE, CONSTRUCT_TEXT("rownum") },
    { (uint32)RES_WORD_ROWSCN,             CM_FALSE, CONSTRUCT_TEXT("rowscn") },
    { (uint32)RES_WORD_SESSIONTZ,          CM_TRUE,  CONSTRUCT_TEXT("sessiontimezone") },
    { (uint32)RES_WORD_SYSDATE,            CM_FALSE, CONSTRUCT_TEXT("sysdate") },
    { (uint32)RES_WORD_SYSTIMESTAMP,       CM_TRUE,  CONSTRUCT_TEXT("systimestamp") },
    { (uint32)RES_WORD_TRUE,               CM_FALSE, CONSTRUCT_TEXT("true") },
    { (uint32)RES_WORD_UPDATING,           CM_TRUE,  CONSTRUCT_TEXT("updating") },
    { (uint32)RES_WORD_USER,               CM_FALSE, CONSTRUCT_TEXT("user") },
    { (uint32)RES_WORD_UTCTIMESTAMP,       CM_TRUE,  CONSTRUCT_TEXT("utc_timestamp") },
};

/* The unit of an interval. Its value defines its significance. The high
significant unit can not be parsed after low significant unit. */
typedef enum en_interval_unit {
    IU_NONE = 0x00000000,
    IU_MICROSECOND = 0x00000001,
    IU_MILLISECOND = 0x00000002,
    IU_SECOND = 0x00000004,
    IU_MINUTE = 0x00000008,
    IU_HOUR = 0x00000010,
    IU_DAY = 0x00000020,
    IU_WEEK = 0x00000040,
    IU_MONTH = 0x00000080,
    IU_QUARTER = 0x00000100,
    IU_YEAR = 0x00000200,
    IU_TIME = IU_SECOND | IU_MINUTE | IU_HOUR,
    IU_DS_INTERVAL = IU_DAY | IU_TIME,
    IU_YM_INTERVAL = IU_YEAR | IU_MONTH,
    IU_ALL = IU_YM_INTERVAL | IU_DS_INTERVAL,
} interval_unit_t;

static key_word_t g_datetime_unit_words[] = {
    { (uint32)IU_DAY,         CM_TRUE, CONSTRUCT_TEXT("DAY") },
    { (uint32)IU_HOUR,        CM_TRUE, CONSTRUCT_TEXT("HOUR") },
    { (uint32)IU_MICROSECOND, CM_TRUE, CONSTRUCT_TEXT("MICROSECOND") },
    { (uint32)IU_MINUTE,      CM_TRUE, CONSTRUCT_TEXT("MINUTE") },
    { (uint32)IU_MONTH,       CM_TRUE, CONSTRUCT_TEXT("MONTH") },
    { (uint32)IU_QUARTER,     CM_TRUE, CONSTRUCT_TEXT("QUARTER") },
    { (uint32)IU_SECOND,      CM_TRUE, CONSTRUCT_TEXT("SECOND") },
    { (uint32)IU_DAY,         CM_TRUE, CONSTRUCT_TEXT("SQL_TSI_DAY") },
    { (uint32)IU_MICROSECOND, CM_TRUE, CONSTRUCT_TEXT("SQL_TSI_FRAC_SECOND") },
    { (uint32)IU_HOUR,        CM_TRUE, CONSTRUCT_TEXT("SQL_TSI_HOUR") },
    { (uint32)IU_MINUTE,      CM_TRUE, CONSTRUCT_TEXT("SQL_TSI_MINUTE") },
    { (uint32)IU_MONTH,       CM_TRUE, CONSTRUCT_TEXT("SQL_TSI_MONTH") },
    { (uint32)IU_QUARTER,     CM_TRUE, CONSTRUCT_TEXT("SQL_TSI_QUARTER") },
    { (uint32)IU_SECOND,      CM_TRUE, CONSTRUCT_TEXT("SQL_TSI_SECOND") },
    { (uint32)IU_WEEK,        CM_TRUE, CONSTRUCT_TEXT("SQL_TSI_WEEK") },
    { (uint32)IU_YEAR,        CM_TRUE, CONSTRUCT_TEXT("SQL_TSI_YEAR") },
    { (uint32)IU_WEEK,        CM_TRUE, CONSTRUCT_TEXT("WEEK") },
    { (uint32)IU_YEAR,        CM_TRUE, CONSTRUCT_TEXT("YEAR") },
};

static key_word_t g_hint_key_words[] = {
    { (uint32)HINT_KEY_WORD_FULL,             CM_FALSE, CONSTRUCT_TEXT("full") },
    { (uint32)HINT_KEY_WORD_HASH_BUCKET_SIZE, CM_FALSE, CONSTRUCT_TEXT("hash_bucket_size") },
    { (uint32)HINT_KEY_WORD_INDEX,            CM_FALSE, CONSTRUCT_TEXT("index") },
    { (uint32)HINT_KEY_WORD_INDEX_ASC,        CM_FALSE, CONSTRUCT_TEXT("index_asc") },
    { (uint32)HINT_KEY_WORD_INDEX_DESC,       CM_FALSE, CONSTRUCT_TEXT("index_desc") },
    { (uint32)HINT_KEY_WORD_INDEX_FFS,        CM_FALSE, CONSTRUCT_TEXT("index_ffs") },
    { (uint32)HINT_KEY_WORD_LEADING,          CM_FALSE, CONSTRUCT_TEXT("leading") },
    { (uint32)HINT_KEY_WORD_NO_INDEX,         CM_FALSE, CONSTRUCT_TEXT("no_index") },
    { (uint32)HINT_KEY_WORD_NO_INDEX_FFS,     CM_FALSE, CONSTRUCT_TEXT("no_index_ffs") },
    { (uint32)HINT_KEY_WORD_ORDERED,          CM_FALSE, CONSTRUCT_TEXT("ordered") },
    { (uint32)HINT_KEY_WORD_PARALLEL,         CM_FALSE, CONSTRUCT_TEXT("parallel") },
    { (uint32)HINT_KEY_WORD_RULE,             CM_FALSE, CONSTRUCT_TEXT("rule") },
    { (uint32)HINT_KEY_WORD_THROW_DUPLICATE,  CM_FALSE, CONSTRUCT_TEXT("throw_duplicate") },
    { (uint32)HINT_KEY_WORD_USE_HASH,         CM_FALSE, CONSTRUCT_TEXT("use_hash") },
    { (uint32)HINT_KEY_WORD_USE_MERGE,        CM_FALSE, CONSTRUCT_TEXT("use_merge") },
    { (uint32)HINT_KEY_WORD_USE_NL,           CM_FALSE, CONSTRUCT_TEXT("use_nl") },
};

#define RESERVED_WORDS_COUNT (sizeof(g_reserved_words) / sizeof(key_word_t))
#define KEY_WORDS_COUNT      (sizeof(g_key_words) / sizeof(key_word_t))
#define DATATYPE_WORDS_COUNT (ELEMENT_COUNT(g_datatype_words))
#define HINT_KEY_WORDS_COUNT (sizeof(g_hint_key_words) / sizeof(key_word_t))

bool32 lex_match_subset(key_word_t *word_set, int32 count, word_t *word)
{
    int32 begin_pos, end_pos, mid_pos, cmp_result;
    key_word_t *cmp_word = NULL;

    begin_pos = 0;
    end_pos = count - 1;

    while (end_pos >= begin_pos) {
        mid_pos = (begin_pos + end_pos) / 2;
        cmp_word = &word_set[mid_pos];

        cmp_result = cm_compare_text_ins((text_t *)&word->text, &cmp_word->text);
        if (cmp_result == 0) {
            word->namable = (uint32)cmp_word->namable;
            word->id = (uint32)cmp_word->id;
            return CM_TRUE;
        } else if (cmp_result < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    return CM_FALSE;
}

bool32 lex_match_datetime_unit(word_t *word)
{
    return lex_match_subset(g_datetime_unit_words, ELEMENT_COUNT(g_datetime_unit_words), word);
}

const datatype_word_t *lex_match_datatype_words(const datatype_word_t *word_set, int32 count, const word_t *word)
{
    int32 begin_pos, end_pos, mid_pos, cmp_result;
    const datatype_word_t *cmp_word = NULL;

    begin_pos = 0;
    end_pos = count - 1;

    while (end_pos >= begin_pos) {
        mid_pos = (begin_pos + end_pos) / 2;
        cmp_word = &word_set[mid_pos];

        cmp_result = cm_compare_text_ins((text_t *)&word->text, &cmp_word->text);
        if (cmp_result == 0) {
            return cmp_word;
        } else if (cmp_result < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    return NULL;
}

bool32 lex_check_datatype(word_t *typword)
{
    return lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, typword) != NULL;
}

status_t lex_try_match_datatype(struct st_lex *lex, word_t *word, bool32 *matched)
{
    bool32 result = CM_FALSE;
    uint32 signed_flag;
    const datatype_word_t *dt_word = lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, word);

    if (dt_word == NULL) {
        *matched = CM_FALSE;
        return CM_SUCCESS;
    }

    word->type = WORD_TYPE_DATATYPE;

    /* special handling PG's datatype:
    * + character varying
    * + double precision */
    word->id = (uint32)dt_word->id;
    switch (dt_word->id) {
        case DTYP_CHAR:
            if (lex_try_fetch(lex, "varying", &result) != CM_SUCCESS) {
                return CM_ERROR;
            }
            if (result) {  // if `varying` is found, then the datatype is `VARCHAR`
                word->id = DTYP_VARCHAR;
            }
            break;
        case DTYP_DOUBLE:
            if (lex_try_fetch(lex, "precision", &result) != CM_SUCCESS) {
                return CM_ERROR;
            }
            break;

        case DTYP_TINYINT:
            CM_RETURN_IFERR(lex_try_fetch_1of2(lex, "SIGNED", "UNSIGNED", &signed_flag));
            if (signed_flag == 1) {
                word->id = DTYP_UTINYINT;
            }
            break;

        case DTYP_SMALLINT:
            CM_RETURN_IFERR(lex_try_fetch_1of2(lex, "SIGNED", "UNSIGNED", &signed_flag));
            if (signed_flag == 1) {
                word->id = DTYP_USMALLINT;
            }
            break;

        case DTYP_BIGINT:
            CM_RETURN_IFERR(lex_try_fetch_1of2(lex, "SIGNED", "UNSIGNED", &signed_flag));
            if (signed_flag == 1) {
                word->id = DTYP_UBIGINT;
            }
            break;

        case DTYP_INTEGER:
            CM_RETURN_IFERR(lex_try_fetch_1of2(lex, "SIGNED", "UNSIGNED", &signed_flag));
            if (signed_flag == 1) {
                word->id = DTYP_UINTEGER;
            }
            break;

        case DTYP_BINARY_INTEGER:
            CM_RETURN_IFERR(lex_try_fetch_1of2(lex, "SIGNED", "UNSIGNED", &signed_flag));
            if (signed_flag == 1) {
                word->id = DTYP_BINARY_UINTEGER;
            }
            break;

        case DTYP_BINARY_BIGINT:
            CM_RETURN_IFERR(lex_try_fetch_1of2(lex, "SIGNED", "UNSIGNED", &signed_flag));
            if (signed_flag == 1) {
                word->id = DTYP_BINARY_UBIGINT;
            }
            break;

        default:
            // DO NOTHING
            break;
    }
    *matched = CM_TRUE;

    return CM_SUCCESS;
}

status_t lex_match_keyword(struct st_lex *lex, word_t *word)
{
    lex->ext_flags = 0;
    if (SECUREC_UNLIKELY(lex->key_word_count != 0)) {  // match external key words only
        if (lex_match_subset((key_word_t *)lex->key_words, (int32)lex->key_word_count, word)) {
            word->type = WORD_TYPE_KEYWORD;
            lex->ext_flags = LEX_SINGLE_WORD | LEX_WITH_OWNER;
            return CM_SUCCESS;
        }
    }

    if (lex_match_subset((key_word_t *)g_reserved_words, RESERVED_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_RESERVED;
        return CM_SUCCESS;
    }

    if (lex_match_subset((key_word_t *)g_key_words, KEY_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_KEYWORD;
        if (word->id == KEY_WORD_PRIOR) {
            word->type = WORD_TYPE_OPERATOR;
            word->id = OPER_TYPE_PRIOR;
        }
        return CM_SUCCESS;
    }

    const datatype_word_t *dt_word = lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, word);
    if (dt_word != NULL) {
        word->type = WORD_TYPE_DATATYPE;
        word->id = (uint32)dt_word->id;
        word->namable = dt_word->namable;
        return CM_SUCCESS;
    }

    return CM_SUCCESS;
}

status_t lex_match_hint_keyword(struct st_lex *lex, word_t *word)
{
    if (lex_match_subset((key_word_t *)g_hint_key_words, HINT_KEY_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_HINT_KEYWORD;
    }

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
