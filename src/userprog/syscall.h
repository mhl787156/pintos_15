#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include <kernel/console.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/list.h"

void syscall_init (void);

/* SYSCALL FUNCTIONS */
//one argument
void sys_exit(int);
tid_t sys_exec(const char *);
int sys_wait(pid_t);
bool sys_remove(const char *);
int sys_open(const char *);
off_t sys_filesize(int);
off_t sys_tell(int);
void sys_close(int) ;
void sys_munmap(mapid_t);
void sys_chdir(const char *);
void sys_mkdir(const char *);
void sys_isdir(int);
void sys_inumber(int);

//two arguments
void sys_seek(int, unsigned);
mapid_t sys_mmap (int, void *);
bool sys_readdir (int fd, char name[READDIR_MAX_LEN + 1]);
bool sys_create(const char *, unsigned);

//three arguments
int sys_read(int, void *, unsigned);
int sys_write(int, const void *, unsigned);

/* HELPER FUNCTIONS */
struct fd_container *file_lookup(int);
void kill_fdc(struct fd_container *fdc);
bool fd_compare (const struct list_elem *,
                 const struct list_elem *, void *aux);

void is_safe_user_memory_access(void *);
void check_buffer(void *, unsigned);

/* GLOBAL VARIABLES */
int fd_counter;
struct lock file_lock;

#endif /* userprog/syscall.h */
