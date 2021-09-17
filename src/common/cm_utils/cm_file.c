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
 * cm_file.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_utils/cm_file.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_file.h"
#include "cm_log.h"

#ifdef WIN32
#else
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define GS_WRITE_BUFFER_SIZE SIZE_M(2)

#define IS_DIR_SEPARATOR(c)	((c) == '/' || (c) == '\\')

/*
 * On Windows, a path may begin with "X:" or "//network/". Skip these and point to the effective start.
 */
#ifdef WIN32
static char *cm_skip_drive(const char *path)
{
    if (IS_DIR_SEPARATOR(path[0]) && IS_DIR_SEPARATOR(path[1])) {
        path += strlen("\\");
        while (*path && !IS_DIR_SEPARATOR(*path)) {
            path++;
        }
    } else if (isalpha((unsigned char)path[0]) && path[1] == ':') {
        path += strlen("X:");
    }
    return (char *)path;
}
#else
#define cm_skip_drive(path)	(path)
#endif

status_t cm_fsync_file(int32 file)
{
#ifndef WIN32
    if (fsync(file) != 0) {
        CM_THROW_ERROR(ERR_DATAFILE_FSYNC, errno);
        return CM_ERROR;
    }
#endif

    return CM_SUCCESS;
}

status_t cm_fdatasync_file(int32 file)
{
#ifndef WIN32
    if (fdatasync(file) != 0) {
        CM_THROW_ERROR(ERR_DATAFILE_FDATASYNC, errno);
        return CM_ERROR;
    }
#endif

    return CM_SUCCESS;
}

// file name could not include black space before string on windows, auto-remove it
status_t cm_open_file(const char *file_name, uint32 mode, int32 *file)
{
    uint32 perm = ((mode & O_CREAT) != 0) ? S_IRUSR | S_IWUSR : 0;

    if (strlen(file_name) > CM_MAX_FILE_NAME_LEN) {
        CM_THROW_ERROR(ERR_INVALID_FILE_NAME, file_name, (uint32)CM_MAX_FILE_NAME_LEN);
        return CM_ERROR;
    }

    *file = open(file_name, (int)mode, perm);

    if ((*file) == -1) {
        if ((mode & O_CREAT) != 0) {
            CM_THROW_ERROR(ERR_CREATE_FILE, file_name, errno);
        } else {
            CM_THROW_ERROR(ERR_OPEN_FILE, file_name, errno);
        }
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_chmod_file(uint32 perm, int32 fd)
{
#ifndef WIN32
    int32 err_no = fchmod(fd, perm);
    if (err_no != 0) {
        CM_THROW_ERROR(ERR_CREATE_FILE, "", err_no);
        return CM_ERROR;
    }
#endif  // !WIN32
    return CM_SUCCESS;
}

status_t cm_fopen(const char *filename, const char *mode, uint32 perm, FILE **fp)
{
    *fp = fopen(filename, mode);
    if (*fp == NULL) {
        CM_THROW_ERROR(ERR_OPEN_FILE, filename, errno);
        return CM_ERROR;
    }
#ifndef WIN32
    int32 err_no = fchmod(cm_fileno(*fp), perm);
    if (err_no != 0) {
        fclose(*fp);
        *fp = NULL;
        CM_THROW_ERROR(ERR_OPEN_FILE, filename, err_no);
        return CM_ERROR;
    }
#endif  // !WIN32

    return CM_SUCCESS;
}

status_t cm_create_file(const char *file_name, uint32 mode, int32 *file)
{
    return cm_open_file(file_name, mode | O_CREAT | O_TRUNC, file);
}

void cm_close_file(int32 file)
{
    int32 ret;

    if (file == -1) {
        return;
    }

    ret = close(file);
    if (ret != 0) {
        LOG_RUN_ERR("failed to close file with handle %d, error code %d", file, errno);
    }
}

status_t cm_read_file(int32 file, void *buf, int32 size, int32 *read_size)
{
    int32 total_size = 0;
    int32 curr_size;

    do {
        curr_size = read(file, (char *)buf + total_size, size);
        if (curr_size == -1) {
            CM_THROW_ERROR(ERR_READ_FILE, errno);
            return CM_ERROR;
        }
        size -= curr_size;
        total_size += curr_size;
    } while (size > 0 && curr_size > 0);

    if (read_size != NULL) {
        *read_size = total_size;
    }

    return CM_SUCCESS;
}

status_t cm_write_file(int32 file, const void *buf, int32 size)
{
    int32 write_size = 0;
    int32 try_times = 0;

    while (try_times < CM_WRITE_TRY_TIMES) {
        write_size = write(file, buf, size);
        if (write_size == 0) {
            cm_sleep(5);
            try_times++;
            continue;
        } else if (write_size == -1) {
            CM_THROW_ERROR(ERR_WRITE_FILE, errno);
            LOG_DEBUG_ERR("write file failed, errno = %d", errno);
            return CM_ERROR;
        } else {
            break;
        }
    }

    if (write_size != size) {
        CM_THROW_ERROR(ERR_WRITE_FILE_PART_FINISH, write_size, size);
        LOG_DEBUG_ERR("write file(part write) failed, errno = %d", errno);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_pread_file(int32 file, void *buf, int size, int64 offset, int32 *read_size)
{
#ifdef WIN32
    if (cm_seek_file(file, offset, SEEK_SET) != offset) {
        CM_THROW_ERROR(ERR_SEEK_FILE, offset, SEEK_SET, errno);
        return CM_ERROR;
    }

    if (cm_read_file(file, buf, size, read_size) != CM_SUCCESS) {
        return CM_ERROR;
    }
#else
    int32 curr_size;
    int32 total_size = 0;
    do {
        curr_size = pread64(file, (char *)buf + total_size, size, offset);
        if (curr_size == -1) {
            CM_THROW_ERROR(ERR_READ_FILE, errno);
            return CM_ERROR;
        }

        total_size += curr_size;
        offset += curr_size;
        size -= curr_size;
    } while (size > 0 && curr_size > 0);

    if (read_size != NULL) {
        *read_size = total_size;
    }
#endif
    return CM_SUCCESS;
}


status_t cm_pwrite_file(int32 file, const char *buf, int32 size, int64 offset)
{
#ifdef WIN32
    if (cm_seek_file(file, offset, SEEK_SET) != offset) {
        CM_THROW_ERROR(ERR_SEEK_FILE, offset, SEEK_SET, errno);
        return CM_ERROR;
    }

    if (cm_write_file(file, buf, size) != CM_SUCCESS) {
        return CM_ERROR;
    }
#else
    int32 write_size;
    int32 try_times = 0;

    while (try_times < CM_WRITE_TRY_TIMES) {
        write_size = pwrite64(file, buf, size, offset);
        if (write_size == 0) {
            cm_sleep(5);
            try_times++;
            continue;
        } else if (write_size == -1) {
            CM_THROW_ERROR(ERR_WRITE_FILE, errno);
            return CM_ERROR;
        } else {
            break;
        }
    }

    if (write_size != size) {
        CM_THROW_ERROR(ERR_WRITE_FILE_PART_FINISH, write_size, size);
        return CM_ERROR;
    }
#endif

    return CM_SUCCESS;
}

int64 cm_seek_file(int32 file, int64 offset, int32 origin)
{
    return (int64)lseek64(file, (off64_t)offset, origin);
}

status_t cm_check_file(const char *name, int64 size)
{
    int32 file;
    if (cm_open_file(name, O_BINARY | O_RDONLY, &file) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (size != cm_seek_file(file, 0, SEEK_END)) {
        cm_close_file(file);
        CM_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CM_ERROR;
    }

    cm_close_file(file);
    return CM_SUCCESS;
}

status_t cm_create_dir(const char *dir_name)
{
    if (make_dir(dir_name, S_IRWXU) != 0 && errno != EEXIST) {
        CM_THROW_ERROR(ERR_CREATE_DIR, dir_name, errno);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_rename_file(const char *src, const char *dst)
{
    if (rename(src, dst) != 0) {
        CM_THROW_ERROR(ERR_RENAME_FILE, src, dst, errno);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void cm_get_parent_dir(char *path, uint32 len)
{
    char *p = NULL;

    if (len == 0) {
        return;
    }

    path = cm_skip_drive(path);
    if (path[0] == '\0') {
        return;
    }

    /* Exclude trailing slash(es) */
    for (p = path + strlen(path) - 1; IS_DIR_SEPARATOR(*p) && p > path; p--) {
    }

    /* Exclude file name */
    for (; !IS_DIR_SEPARATOR(*p) && p > path; p--) {
    }

    /* If multiple slashes before directory name, remove 'em all */
    for (; p > path && IS_DIR_SEPARATOR(*(p - 1)); p--) {
    }

    /* Don't erase a leading slash */
    if (p == path && IS_DIR_SEPARATOR(*p)) {
        p++;
    }

    *p = '\0';
}

/* cm_fsync_file_ex: try to fsync a file */
static status_t cm_fsync_file_ex(const char *file, bool32 isdir)
{
    int32 flags = O_BINARY;
    flags |= (!isdir) ? O_RDWR : O_RDONLY;

    int32 fd = open(file, flags, 0);
    /* Some OSes don't allow to open directories (Windows returns EACCES), just ignore the error in that case. */
    if (fd < 0 && isdir && (errno == EISDIR || errno == EACCES)) {
        return CM_SUCCESS;
    } else if (fd < 0) {
        CM_THROW_ERROR(ERR_OPEN_FILE, file, errno);
        return CM_ERROR;
    }

    /* Some OSes don't allow us to fsync directories at all, just ignore those errors. */
    if (cm_fsync_file(fd) != CM_SUCCESS && !(isdir && (errno == EBADF || errno == EINVAL))) {
        close(fd);
        return CM_ERROR;
    }

    close(fd);
    return CM_SUCCESS;
}

/* cm_fsync_parent_path: try to fsync a directory */
static status_t cm_fsync_parent_path(const char *fname)
{
    char  parentpath[CM_FILE_NAME_BUFFER_SIZE] = {0};

    int32 ret = strncpy_s(parentpath, sizeof(parentpath), fname, strlen(fname));
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }

    cm_get_parent_dir(parentpath, (uint32)strlen(parentpath));
    if (strlen(parentpath) == 0) {
        parentpath[0] = '.';
        parentpath[1] = '\0';
    }

    if (cm_fsync_file_ex(parentpath, CM_TRUE) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_rename_file_durably(const char *src, const char *dst)
{
    /* First fsync the src file to ensure that they are properly persistent on disk. */
    if (cm_fsync_file_ex(src, CM_FALSE) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (rename(src, dst) != 0) {
        CM_THROW_ERROR(ERR_RENAME_FILE, src, dst, errno);
        return CM_ERROR;
    }

    /* To guarantee renaming the file is persistent, fsync the file with its new name. */
    if (cm_fsync_file_ex(dst, CM_FALSE) != CM_SUCCESS) {
        return CM_ERROR;
    }

    /* To guarantee containing directory is persistent too. */
    if (cm_fsync_parent_path(dst) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t cm_copy_file_ex(const char *src, const char *dst, char *buf, uint32 buffer_size, bool32 over_write)
{
    int32 src_file, dst_file, data_size;
    uint32 mode;

    if (cm_open_file(src, O_RDONLY | O_BINARY, &src_file) != CM_SUCCESS) {
        return CM_ERROR;
    }

    int64 file_size = cm_file_size(src_file);
    if (file_size < 0 || file_size > buffer_size) {
        cm_close_file(src_file);
        CM_THROW_ERROR(ERR_FILE_SIZE_MISMATCH, file_size, (uint64)buffer_size);
        return CM_ERROR;
    }

    if (cm_seek_file(src_file, 0, SEEK_SET) != 0) {
        cm_close_file(src_file);
        LOG_RUN_ERR("seek file failed :%s.", src);
        return CM_ERROR;
    }

    mode = over_write ? O_RDWR | O_BINARY | O_SYNC : O_RDWR | O_BINARY | O_EXCL | O_SYNC;

    if (cm_create_file(dst, mode, &dst_file) != CM_SUCCESS) {
        cm_close_file(src_file);
        return CM_ERROR;
    }

    if (cm_seek_file(dst_file, 0, SEEK_SET) != 0) {
        cm_close_file(src_file);
        cm_close_file(dst_file);
        LOG_RUN_ERR("seek file failed :%s.", dst);
        return CM_ERROR;
    }

    if (cm_read_file(src_file, buf, (int32)buffer_size, &data_size) != CM_SUCCESS) {
        cm_close_file(src_file);
        cm_close_file(dst_file);
        return CM_ERROR;
    }

    while (data_size > 0) {
        if (cm_write_file(dst_file, buf, data_size) != CM_SUCCESS) {
            cm_close_file(src_file);
            cm_close_file(dst_file);
            return CM_ERROR;
        }

        if (cm_read_file(src_file, buf, (int32)buffer_size, &data_size) != CM_SUCCESS) {
            cm_close_file(src_file);
            cm_close_file(dst_file);
            return CM_ERROR;
        }
    }

    cm_close_file(src_file);
    cm_close_file(dst_file);
    return CM_SUCCESS;
}

status_t cm_copy_file(const char *src, const char *dst, bool32 over_write)
{
    errno_t rc_memzero;

    char *buf = (char *)malloc(GS_WRITE_BUFFER_SIZE);
    if (buf == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_WRITE_BUFFER_SIZE, "copying file");
        return CM_ERROR;
    }
    rc_memzero = memset_sp(buf, (uint32)GS_WRITE_BUFFER_SIZE, 0, (uint32)GS_WRITE_BUFFER_SIZE);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(buf);
        CM_THROW_ERROR(ERR_RESET_MEMORY, "buf");
        return CM_ERROR;
    }
    status_t status = cm_copy_file_ex(src, dst, buf, GS_WRITE_BUFFER_SIZE, over_write);
    CM_FREE_PTR(buf);
    return status;
}

status_t cm_remove_file(const char *file_name)
{
    if (remove(file_name) != 0) {
        CM_THROW_ERROR(ERR_REMOVE_FILE, file_name, errno);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_unlink_file(const char *file_name)
{
    if (__unlink(file_name) != 0) {
        CM_THROW_ERROR(ERR_REMOVE_FILE, file_name, errno);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

bool32 cm_file_exist(const char *file_path)
{
    int32 ret;
#ifdef WIN32
    struct _stat stat_buf;
#else
    struct stat stat_buf;
#endif

#ifdef WIN32
    ret = _stat(file_path, &stat_buf);
#else
    ret = stat(file_path, &stat_buf);
#endif
    if (ret != 0) {
        return CM_FALSE;
    }

#ifdef WIN32
    if (_S_IFREG == (stat_buf.st_mode & _S_IFREG)) {
#else
    /* S_ISREG: judge whether it's a regular file or not by the flag */
    if (S_ISREG(stat_buf.st_mode)) {
#endif
        return CM_TRUE;
    }

    return CM_FALSE;
}

bool32 cm_dir_exist(const char *dir_path)
{
    int32 ret;
#ifdef WIN32
    struct _stat stat_buf;
#else
    struct stat stat_buf;
#endif

#ifdef WIN32
    ret = _stat(dir_path, &stat_buf);
#else
    ret = stat(dir_path, &stat_buf);
#endif
    if (ret != 0) {
        return CM_FALSE;
    }

#ifdef WIN32
    if (_S_IFDIR == (stat_buf.st_mode & _S_IFDIR)) {
#else
    /* S_ISREG: judge whether it's a directory or not by the flag */
    if (S_ISDIR(stat_buf.st_mode)) {
#endif
        return CM_TRUE;
    }

    return CM_FALSE;
}

void cm_trim_dir(const char *file_name, uint32 size, char *buf)
{
    int32 i;
    uint32 len;
    errno_t errcode = 0;

    len = (uint32)strlen(file_name);

    for (i = (int32)len; i >= 0; i--) {
        if (file_name[i] == '\\' || file_name[i] == '/') {
            break;
        }
    }

    if (i < 0) {
        errcode = strncpy_s(buf, (size_t)size, file_name, (size_t)len);
        if (errcode != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return;
        }
        return;
    }

    errcode = strncpy_s(buf, (size_t)size, file_name + i + 1, (size_t)(len - (uint32)i));
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }

    return;
}

void cm_trim_filename(const char *file_name, uint32 size, char *buf)
{
    int32 i;
    uint32 len;

    len = (uint32)strlen(file_name);
    errno_t errcode = strncpy_s(buf, (size_t)size, file_name, (size_t)len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
    len = (uint32)strlen(buf);

    for (i = (int32)len; i >= 0; i--) {
        if (buf[i] == '\\' || buf[i] == '/') {
            buf[i + 1] = '\0';
            break;
        }
    }
}

/*
 * trim serial character '\' or '/' in the right of home path
 * etc. transform /home/gauss/ to /home/gauss
 */
void cm_trim_home_path(char *home_path, uint32 len)
{
    int32 i;

    for (i = len - 1; i >= 0; i--) {
        if (home_path[i] == '\\' || home_path[i] == '/') {
            home_path[i] = '\0';
        } else {
            break;
        }
    }
}

status_t cm_access_file(const char *file_name, uint32 mode)
{
    if (access(file_name, mode) != 0) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

bool32 cm_filename_equal(const text_t *text, const char *str)
{
#ifdef WIN32
    return cm_text_str_equal_ins(text, str);
#else
    return cm_text_str_equal(text, str);
#endif /* WIN32 */
}

status_t cm_create_dir_ex(const char *dir_name)
{
    char dir[CM_MAX_PATH_LEN + 1];
    size_t dir_len = strlen(dir_name);
    uint32 i;

    errno_t errcode = strncpy_s(dir, (size_t)CM_MAX_PATH_LEN, dir_name, (size_t)dir_len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    if (dir[dir_len - 1] != '\\' && dir[dir_len - 1] != '/') {
        dir[dir_len] = '/';
        dir_len++;
        dir[dir_len] = '\0';
    }

    for (i = 0; i < dir_len; i++) {
        if (dir[i] == '\\' || dir[i] == '/') {
            if (i == 0) {
                continue;
            }

            dir[i] = '\0';
            if (cm_dir_exist(dir)) {
                dir[i] = '/';
                continue;
            }

            if (cm_create_dir(dir) != CM_SUCCESS) {
                return CM_ERROR;
            }
            dir[i] = '/';
        }
    }

    return CM_SUCCESS;
}

status_t cm_truncate_file(int32 fd, int64 offset)
{
#ifdef WIN32
    if (_chsize_s(fd, offset) != 0) {
#else
    if (ftruncate(fd, offset) != 0) {
#endif
        CM_THROW_ERROR(ERR_TRUNCATE_FILE, offset, errno);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cm_lock_fd(int32 fd)
{
#ifdef WIN32
    return CM_SUCCESS;
#else
    struct flock lk;

    lk.l_type = F_WRLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = lk.l_len = 0;

    if (fcntl(fd, F_SETLK, &lk) != 0) {
        CM_THROW_ERROR(ERR_LOCK_FILE, errno);
        return CM_ERROR;
    }

    return CM_SUCCESS;
#endif
}

// if val = 700, log_file_permissions is (S_IRUSR | S_IWUSR | S_IXUSR)
uint32 cm_file_permissions(uint16 val)
{
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;
    uint32 file_perm = 0;

    usr_perm = (val / 100) % 10;
    if (usr_perm & 1) {
        file_perm |= S_IXUSR;
    }

    if (usr_perm & 2) {
        file_perm |= S_IWUSR;
    }

    if (usr_perm & 4) {
        file_perm |= S_IRUSR;
    }

    grp_perm = (val / 10) % 10;
    if (grp_perm & 1) {
        file_perm |= S_IXGRP;
    }

    if (grp_perm & 2) {
        file_perm |= S_IWGRP;
    }

    if (grp_perm & 4) {
        file_perm |= S_IRGRP;
    }

    oth_perm = val % 10;
    if (oth_perm & 1) {
        file_perm |= S_IXOTH;
    }

    if (oth_perm & 2) {
        file_perm |= S_IWOTH;
    }

    if (oth_perm & 4) {
        file_perm |= S_IROTH;
    }
    return file_perm;
}

void cm_get_filesize(const char *filename, uint32 *filesize)
{
    struct stat statbuf;
    stat(filename, &statbuf);
    *filesize = statbuf.st_size;
}

#ifdef __cplusplus
}
#endif
