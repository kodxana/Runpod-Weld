/* Trusted Linux fixture helper: no payload, directory or symlink-target reads.
 * Static linking avoids accessing the image's executable/loader just to stat it.
 * Input: NUL-separated paths. Output: JSON lines with byte strings hex encoded. */
#define _GNU_SOURCE
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>

static void hex(const void *data, size_t size) {
    const unsigned char *bytes = data;
    for (size_t i = 0; i < size; i++) printf("%02x", bytes[i]);
}

int main(void) {
    struct entry { char *path; struct stat st; } *entries = NULL;
    size_t count = 0, capacity = 0;
    char *path = NULL;
    ssize_t length;
    while ((length = getdelim(&path, &capacity, '\0', stdin)) != -1) {
        if (length < 2 || path[length - 1] != '\0') return 2;
        struct entry *next = realloc(entries, (count + 1) * sizeof(*entries));
        if (!next) return 2;
        entries = next;
        entries[count].path = path;
        if (lstat(path, &entries[count].st)) { perror(path); return 2; }
        count++;
        path = NULL;
        capacity = 0;
    }
    free(path);
    if (ferror(stdin)) return 2;
    /* Capture every stat before any other observation. l*xattr never follows links. */
    for (size_t i = 0; i < count; i++) {
        struct stat *s = &entries[i].st;
        printf("{\"path_hex\":\""); hex(entries[i].path, strlen(entries[i].path));
        printf("\",\"mode\":%ju,\"uid\":%ju,\"gid\":%ju,"
               "\"atime_sec\":%jd,\"atime_nsec\":%ld,\"mtime_sec\":%jd,\"mtime_nsec\":%ld,"
               "\"ctime_sec\":%jd,\"ctime_nsec\":%ld,\"dev\":%ju,\"ino\":%ju,\"xattrs\":{",
               (uintmax_t)s->st_mode, (uintmax_t)s->st_uid, (uintmax_t)s->st_gid,
               (intmax_t)s->st_atim.tv_sec, s->st_atim.tv_nsec,
               (intmax_t)s->st_mtim.tv_sec, s->st_mtim.tv_nsec,
               (intmax_t)s->st_ctim.tv_sec, s->st_ctim.tv_nsec,
               (uintmax_t)s->st_dev, (uintmax_t)s->st_ino);
        char names[65536], value[65536];
        ssize_t size = llistxattr(entries[i].path, names, sizeof(names));
        if (size < 0) { perror("llistxattr"); return 2; }
        for (ssize_t offset = 0; offset < size;) {
            char *name = names + offset;
            ssize_t bytes = lgetxattr(entries[i].path, name, value, sizeof(value));
            if (bytes < 0) { perror("lgetxattr"); return 2; }
            if (offset) printf(",");
            printf("\""); hex(name, strlen(name)); printf("\":\"");
            hex(value, (size_t)bytes); printf("\"");
            offset += (ssize_t)strlen(name) + 1;
        }
        printf("}}\n");
        free(entries[i].path);
    }
    free(entries);
    return fflush(stdout) ? 2 : 0;
}
