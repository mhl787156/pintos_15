#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include <kernel/console.h>
#include <list.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "vm/page.h"

/* SYSCALL HANDLER FUNCTIONS */
static void syscall_handler (struct intr_frame *);
void syscall_select(struct intr_frame *);
void syscall_arg0(void);
void syscall_arg1(struct intr_frame *,void *);
void syscall_arg2(struct intr_frame *,void *, void *);
void syscall_arg3(struct intr_frame *,void *, void *, void *);

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

/* GLOBAL VARIABLES */
struct lock file_lock;
int fd_counter;
int mm_counter;


/* ---------FILE START ----------*/

/* intialise syscall handler */
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock); //initialise file system lock
  fd_counter = 2; //initialise fd generator
  mm_counter = 2; //initialise mm generator
}

/* syscall handler. delegates calls */
static void
syscall_handler (struct intr_frame *f)
{
  // esp currently at the  top of the stack
  void *esp = f->esp;
  if(!is_user_vaddr(esp))
  {
    sys_exit(-1);
  }
  int e = *((int *)esp);
  //empty return register
  f->eax = 0;

  if(e == 0)
  {
    syscall_arg0();
    return;
  }

  void *arg0 = *((void **)(esp + 4));
  void *arg1 = *((void **)(esp + 8));
  void *arg2 = *((void **)(esp + 12));

  if(e == 8 || e == 9)
  {
    syscall_arg3(f, arg0, arg1, arg2);
    return;
  }

  if(e == 4 || e == 10
   ||e == 13|| e == 17)
  {
    syscall_arg2(f, arg0, arg1);
    return;
  }

  syscall_arg1(f, arg0);

}

/* function to deal with syscalls with no args */
void
syscall_arg0()
{
  //HALT
  shutdown_power_off(); //turns the thing off
}

/* function to deal with syscalls with one arg */
void
syscall_arg1(struct intr_frame *f, void *arg0)
{
  int *esp = f->esp;
  int e = *esp;
  void *return_val = NULL;

  if(!is_user_vaddr(arg0))
  {
    sys_exit(-1);
  }

  switch(e)
  {
    case SYS_EXIT:
      f->eax = (int) arg0;
      sys_exit((int) arg0);
      break;

    case SYS_EXEC:
      is_safe_user_memory_access(arg0);
      return_val = (void *) sys_exec((const char *) arg0);
      break;

    case SYS_WAIT:
      return_val = (void *) sys_wait((pid_t) arg0);
      break;

    case SYS_REMOVE:
      is_safe_user_memory_access(arg0);
      return_val = (void *) sys_remove((const char *) arg0);
      break;

    case SYS_OPEN:
      is_safe_user_memory_access(arg0);
      return_val = (void *) sys_open((const char *) arg0);
      break;

    case SYS_FILESIZE:
      return_val = (void *) sys_filesize((int) arg0);
      break;

    case SYS_TELL:
      return_val = (void *) sys_tell((int) arg0);
      break;

    case SYS_CLOSE:
      sys_close((int) arg0);
      break;

    case SYS_MUNMAP:
      sys_munmap((mapid_t) arg0);
      break;

    case SYS_CHDIR:
      is_safe_user_memory_access(arg0);
      sys_chdir((const char *) arg0);
      break;

    case SYS_MKDIR:
      is_safe_user_memory_access(arg0);
      sys_mkdir((const char *) arg0);
      break;

    case SYS_ISDIR:
      sys_isdir((int) arg0);
      break;

    case SYS_INUMBER:
      sys_inumber((int) arg0);
      break;
  }

  f->eax = (int) return_val;
}

/* function to deal with syscalls with two args */
void
syscall_arg2(struct intr_frame *f,void *arg0, void *arg1)
{
  int *esp = f->esp;
  int e = *esp;
  void *return_val = NULL;

  switch(e)
  {
    case SYS_CREATE:
      is_safe_user_memory_access(arg0);
      return_val = (void *) sys_create((const char *) arg0, (unsigned) arg1);
      break;

    case SYS_SEEK:
      sys_seek((int) arg0, (unsigned) arg1);
      break;

    case SYS_MMAP:
      is_safe_user_memory_access(arg1);
      return_val = (void *) sys_mmap((int) arg0, (void *) arg1);
      break;

    case SYS_READDIR:
      return_val = (void *) sys_readdir((int) arg0, (char *) arg1);
      break;
  }
  f->eax = (int) return_val;
}


/* Translates a System call with three arguments,
 * This includes:
 * SYS_READ, SYS_WRITE */
void
syscall_arg3(struct intr_frame *f,void *arg0, void *arg1, void *arg2)
{

  int *esp = f->esp;
  int e = *esp;
  void *return_val = NULL;

  is_safe_user_memory_access(arg1);

  // In both cases:
  // typeof(arg0) is int
  // typeof(arg1) is void * buffer
  // typeof(arg2) is unsigned

  int fd = (int) arg0;
  void *buffer =  arg1;
  unsigned size = (unsigned) arg2;

  is_safe_user_memory_access(buffer);

  switch(e)
  {
    case SYS_READ :
      return_val = (void *) sys_read(fd, buffer, size);
      break;

    case SYS_WRITE:
      return_val = (void *) sys_write(fd, buffer, size);
      break;
  }

  f->eax = (int) return_val;

}

/* Exits current process */
void
sys_exit(int exit_code)
{
  // f->eax = exit_code;
  struct thread *curr = thread_current();
  curr->exit_code = exit_code;

  /* allow writes to executable's file again */
  if(!lock_held_by_current_thread(&file_lock)) lock_acquire(&file_lock);
  file_close(curr->open_file);
  lock_release(&file_lock);

  /* Kills the current process's supplemental page table */
  struct hash *spt = curr->spt;
  if (spt != NULL)
  {
    curr->spt = NULL;
    destroy_spt (spt);
  }

  /* call kill_fdc() on all fd_containers in current thread's fds
     to release memory */
  struct list *fds = &(thread_current ()->fds);
  struct list_elem *it;
  it = list_begin(fds);
  while(it != list_end(fds))
  {
    struct fd_container *fdc = list_entry(it, struct fd_container, elem);
    it = list_next(it);
    kill_fdc(fdc);
  }

  //ensure thread is not holding file system lock
  if(lock_held_by_current_thread(&file_lock))
  {
    lock_release(&file_lock);
  }

  printf("%s: exit(%d)\n", curr->name, exit_code);
  thread_exit();
}

/* Runs executable with arguments specified in file
 * starts a child process of the current process
 * returns Tid on success else -1 */
tid_t
sys_exec(const char *name)
{
  tid_t tid = process_execute(name);

  //Return value
  return tid;
}

/* waits for process marked by given pid.
 * returns process exit value */
int
sys_wait(pid_t pid)
{
  return process_wait(pid);
}

/* remove given file from the file system.
 * returns true if possible, false otherwise */
bool
sys_remove(const char *name)
{
  lock_acquire(&file_lock);
  bool ret_val = filesys_remove(name);
  lock_release(&file_lock);
  return ret_val;
}

/* opens file called name.
 * returns unique file descriptor, -1 if file could not be opened */
int
sys_open(const char *name)
{

  if (name == NULL)
  {
    sys_exit(-1);
  }

  //open file
  lock_acquire(&file_lock);
  struct file *file = filesys_open(name);
  lock_release(&file_lock);

  if (file == NULL)
  {
    return -1; //if file could not be opened
  }

  //initialise new fd container
  struct fd_container *new_fd = (struct fd_container *)malloc(sizeof(struct fd_container));
  ASSERT(new_fd != NULL);
  new_fd->fd = fd_counter;
  new_fd->mid = 0;
  new_fd->addr = NULL;
  new_fd->file = file;

  off_t fl = file_length(file);
  size_t num_pages = fl / PGSIZE;
  num_pages += fl % PGSIZE == 0 ? 0 : 1 ;
  new_fd->file_size = num_pages;
  new_fd->file_size_bytes = fl;

  lock_acquire(&file_lock);
  fd_counter++;
  lock_release(&file_lock);


  /*add file to file descriptor list*/
  struct list *fds = &(thread_current ()->fds);
  list_push_back(fds, &new_fd->elem);

  return new_fd->fd;
}

/* comparison function for inserting into the list of file descriptors */
bool
fd_compare (const struct list_elem *a,
            const struct list_elem *b, void *aux UNUSED)
{
  struct fd_container *fda = list_entry(a, struct fd_container, elem);
  struct fd_container *fdb = list_entry(b, struct fd_container, elem);

  return (fda->fd) > (fdb->fd);
}

/* find fd container with given descriptor.
 * return NULL if file not found */
struct fd_container *
file_lookup(int fd)
{
  struct list *fds = &(thread_current ()->fds);
  struct list_elem *it;

  //search for file
  for (it = list_begin(fds); it != list_end(fds); it = list_next(it))
  {
    struct fd_container *fdc = list_entry(it, struct fd_container, elem);

    if (fdc->fd == fd)
    {
      //return file descriptor container
      return fdc;
    } else if (fdc->fd > fd)
    {
      break;
    }
  }
  return NULL;
}

/* reads length of file specified by the given descriptor
 * returns -1 if file not found */
off_t
sys_filesize(int fd)
{
  struct fd_container *fdc = file_lookup(fd);
  if (fdc != NULL)
  {
    lock_acquire(&file_lock);
    off_t ret_val = file_length(fdc->file);
    lock_release(&file_lock);
    return ret_val;
  }
  return -1;
}

/* returns current position in file referred to by given
 * descriptor in terms of bytes from the start of
 * the file. returns -1 if file cannot be found*/
off_t
sys_tell(int fd)
{
  struct fd_container *fdc = file_lookup(fd);
  if (fdc != NULL)
  {
    lock_acquire(&file_lock);
    off_t ret_val = file_tell(fdc->file);
    lock_acquire(&file_lock);
    return ret_val;
  }
  return -1;
}

/* closes the file specified by the given descriptor */
void
sys_close(int fd)
{
  struct fd_container *fdc = file_lookup(fd);
  fdc->fd = 0;
  if(fdc->mid == 0)
  {
    // Only kill fdc if not still mmapped
    kill_fdc(fdc);
  }
}

/* closes file associated with given fd_container and frees memory */
void
kill_fdc(struct fd_container *fdc)
{
  if (fdc != NULL)
  {
    lock_acquire(&file_lock);
    file_close(fdc->file);
    lock_release(&file_lock);

    //remove from list and free memory
    list_remove(&fdc->elem);
    free(fdc);
  }
}


mapid_t
sys_mmap (int fd, void *addr)
{
  // If not page aligned
  if(addr == 0 || fd == 0 || fd == 1 || (int) addr % PGSIZE != 0)
  {
    return -1;
  }

  /* Get the fd container */
  struct fd_container *fdc = get_fd_container(fd);
  if(fdc == NULL)
  {
    return -1;
  }

  if(fdc->file_size == 0)
  {
    return -1;
  }


  struct thread *curr = thread_current();
  void *addr_ = addr;


  /* Check for memory overlap */
  size_t i;
  for(i = 0; i < fdc->file_size; i++)
  {
    if(is_mmap(curr->spt, addr) || is_stack(curr->spt, addr)
            || pagedir_get_page(curr->pagedir, addr) != NULL)
    {
      return -1;
    }
    addr_ += PGSIZE;
  }

  /* Set the fd counter's mmap fields */
  fdc->mid = mm_counter;
  fdc->addr = addr;
  lock_acquire(&file_lock);
  mm_counter++;
  lock_release(&file_lock);

  /* Set the addresses from addr till addr + file_length
     and create and set those pages to be mmaps */
  for(i = 0; i < fdc->file_size; i++)
  {
    set_is_mmap(curr->spt, addr, fdc);
    addr += PGSIZE;
  }
  return fdc->mid;
}

void
sys_munmap(mapid_t mapid)
{
  struct fd_container *fdc = get_fd_container_mm(mapid);
  if(fdc == NULL) sys_exit(-1);

  void *addr = fdc->addr;

  struct thread *curr = thread_current();

  size_t i;
  for(i = 0; i < fdc->file_size; i++)
  {
    addr = addr + (PGSIZE * i);
    set_not_mmap(curr->spt, addr);
    free_and_destroy_spt_elem(curr->spt, addr);
  }
  fdc->mid = 0;
  fdc->addr = NULL;

  if(fdc->fd == 0)
  {
    // If file has been 'closed' close the fd_container as well
    kill_fdc(fdc);
  }
}

void
sys_chdir(const char *dir)
{
  //TODO TASK 3
}

bool sys_readdir (int fd, char name[READDIR_MAX_LEN + 1])
{
  //TODO Task 3
}

void
sys_mkdir(const char *dir)
{
  //TODO TASK 3
}

void
sys_isdir(int fd)
{
  //TODO TASK 3
}

void
sys_inumber(int fd)
{
  //TODO TASK 3
}


/* moves current position in file referred to by
 * given descriptor to position given by offset */
void
sys_seek(int fd, unsigned offset)
{
  struct fd_container *fdc = file_lookup(fd);
  if (fdc != NULL)
  {
    lock_acquire(&file_lock);
    file_seek(fdc->file, (off_t) offset);
    lock_release(&file_lock);
  }
}

/* create a new file in the file system with
 * starting size given by unsigned size */
bool
sys_create(const char *name, unsigned size)
{
  if (name == NULL)
  {
    sys_exit(-1);
  }
  lock_acquire(&file_lock);
  bool ret_val = filesys_create(name, (off_t) size);
  lock_release(&file_lock);
  return ret_val;
}

/* reads from file given by fd. returns number of bytes read,
 * -1 if none read and not EOF */
int
sys_read(int fd, void *buffer, unsigned size)
{
  check_buffer(buffer, size);

  //read from STDIN
  if (fd == 0)
  {
    char *buffer = (char *) buffer;
    unsigned i;
    for (i = 1; i <= size; i++)
    {
      *buffer = (char) input_getc();
      buffer++;
    }
    return i;
  }

  //read from file
  struct fd_container *fdc = file_lookup(fd);
  if (fdc != NULL)
  {
    int ret_val;

    if(fdc->mid != 0)
    {
      /* Memory Mapped file, need to check for loading*/
      void *addr = fdc->addr;
      off_t offset = file_tell(fdc->file);
      memcpy(buffer, addr+offset, size);
      ret_val = size;
    }
    else{
      lock_acquire(&file_lock);
      ret_val = file_read(fdc->file, buffer, size);
      lock_release(&file_lock);
    }

    return ret_val;
  }
  return -1; //return -1 if file not found
}

/* writes to file given by fd. returns number of bytes written */
int
sys_write(int fd, const void *buffer, unsigned size)
{
  check_buffer(buffer, size);
  //write to console
  if (fd == 1)
  {
    //TODO : break up large buffers
    putbuf((const char *) buffer, (size_t) size);
    return size;
  }
  //write to file
  struct fd_container *fdc = file_lookup(fd);
  if (fdc != NULL)
  {
    int ret_val;

    /* Memory Mapped file, need to check for loading*/
    if(fdc->mid != 0)
    {
      void *addr = fdc->addr;
      off_t offset = file_tell(fdc->file);
      memcpy(addr+offset, buffer, size);
      ret_val = size;
    }
    else
    {
      lock_acquire(&file_lock);
      ret_val = file_write(fdc->file, buffer, size);
      lock_release(&file_lock);
    }

    return ret_val;
  }
  return 0; //return 0 if file not found
}

/* checks that the given buffer only spans user memory */
void
check_buffer(void *buffer, unsigned size)
{
  //checks that every page increment of the buffer is in user memory
  void *offset_check;
  void *buffer_end = buffer + size - 1;
  for (offset_check = buffer + PGSIZE;
       offset_check < buffer_end;
       offset_check += PGSIZE)
  {
    is_safe_user_memory_access(offset_check);
  }
  is_safe_user_memory_access(buffer_end);
}


void
is_safe_user_memory_access(void *buffer)
{
  if (buffer == NULL)
  {
    return;
  }

  //Check that buffer pointer is in user space
  //Check that the memory is mapped
  if(is_user_vaddr(buffer))
  {
    return;
  }

  // should break here
  sys_exit(-1);
}
