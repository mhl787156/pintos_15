#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "synch.h"

typedef int mapid_t;

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* Maximum Stack size */
#define MAX_STACK_PAGES 2000            /* Maximum Stack is 8MB */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and timer.c */
    int64_t wake_up_time;      /* Time expected to wake up since OS booted */
    struct list_elem sleep_elem;        /* List Element for thead sleep*/
    struct semaphore sleep_sema;        /* Blocks thread when sleeping */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    struct lock spt_lock;               /* Lock on access to the SPT */
    struct hash *spt;                   /* Supplemental page table */

    struct list fds;                    /* list of open file descriptors */
    struct file *open_file;             /* thread's process file.
                                           kept open to prevent writes */
    size_t stack_size;                  /* Size of the stack in pages */

    //Fields as a parent
    struct list children;               /* Children of the current thread */
    tid_t waiting_on;                   /* The Process that the parent is waiting for */

    //Fields as a child
    struct thread *parent;              /* The thread that spawned this thread */
    int exit_code;                      /* exit code of the thread. */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* Container for elements of the file descriptor list */
struct fd_container
{
  int fd;                //file descriptor, 0 if closed
  mapid_t mid;           //Memory Mapped ID, 0 for not mapped, >2 if mapped
  void *addr;            //Address of mm if mm
  struct file *file;     //pointer to file
  size_t file_size;      //file_size in pages (rounded up)
  size_t file_size_bytes;//file_size in bytes
  struct list_elem elem; //list elem
};

/* Contained for a child process */
struct child_process
{
  tid_t child_tid;
  struct thread *child_thread;
  struct list_elem child_elem;
  struct semaphore process_wait_sema; /* Semaphore for process_wait */
  bool isdead;
  bool process_wait_called;
  int exit_code;
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
struct thread *thread_from_tid(tid_t);
struct child_process *thread_child_tid(struct thread *,tid_t);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* filesystem helpers */
struct fd_container *get_fd_container(int);
struct fd_container *get_fd_container_mm(mapid_t);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
