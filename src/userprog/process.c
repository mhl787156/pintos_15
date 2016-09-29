#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

struct init_proc
{
  char *exec_name;
  char *args;
  struct file* file;
  struct semaphore exec_sema;
  struct semaphore child_sema;
  bool load_success;
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy, *fn_copy_2;
  char *first, *rest;
  tid_t tid;



  /* Make a copy of FILE_NAME.
  Otherwise there's a race between the caller and load(). */
  fn_copy = frame_get_frame();
  fn_copy_2 = frame_get_frame();
  struct init_proc *ip = (struct init_proc *)malloc(sizeof(struct init_proc));
  if (fn_copy == NULL || fn_copy_2 == NULL
                || ip == NULL || strlen(file_name) >= (PGSIZE/2))
  {
    return TID_ERROR;
  }

  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (fn_copy_2, file_name, PGSIZE);
  first = strtok_r(fn_copy_2, " ", &rest);
  ip->exec_name = first;
  ip->args = fn_copy;
  ip->load_success = false;
  sema_init(&ip->exec_sema, 0);
  sema_init(&ip->child_sema, 0);


  /* Check if the file 'first' exists in the pintos directory */
  /* also open process's file and deny writes */
  lock_acquire(&file_lock);
  struct file *file = filesys_open(first);
  lock_release(&file_lock);
  if(file == NULL){
    return TID_ERROR;
  }
  file_deny_write(file);
  ip->file = file;


  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (first, PRI_DEFAULT, start_process, ip);

  /* If thread creation failed, destroy all allocated memory */
  if (tid == TID_ERROR ){
    frame_free_frame (fn_copy);
    frame_free_frame(fn_copy_2);
    free(ip);
    return TID_ERROR;
  }

  /* Block parent to allow child to set up */
  sema_down(&ip->exec_sema);

  /* Detect load success, if load failed, return fail
    and let child exit itself, freeing its own data */
  if (!ip->load_success)
  {
    sema_up(&ip->child_sema);
    return TID_ERROR;
  }


  /*If thread creation successful,
    Add child to parent.*/
  struct thread *curr = thread_current();
  struct thread *child = thread_from_tid(tid);

  struct child_process *child_struct
      = (struct child_process *)malloc(sizeof(struct child_process));

  if (child_struct == NULL){
    sys_exit(-1);
  }

  child_struct->child_tid = tid;
  child_struct->child_thread = child;
  child_struct->isdead = false;
  child_struct->process_wait_called = false;
  child_struct->exit_code = -1;

  child->parent = curr;
  list_push_front(&curr->children, &child_struct->child_elem);

  /* Release the child after parents' child set up */
  sema_up(&ip->child_sema);

  return tid;
}

/* Internal representation of argc and argv */
struct args {
  int argc;
  struct list *argv;
};

/* A single argv element */
struct aelem{
  struct list_elem argv_elem;
  char *word;
  int len;
};

struct args *parse_arguments(void *arguments);
void *push_args_stack(void *esp, struct args *a);

/* Parse arguments given on the command line and
 * parse them into the list argv in arguments */
struct args *
parse_arguments(void *arguments)
{
  struct args *a = frame_get_frame();
  struct list *argv = (struct list *)malloc(sizeof(struct list));
  if(a == NULL || argv == NULL)
  {
    sys_exit(-1);
  }
  a->argc = 0;

  list_init(argv);

  char *word, *sep, *brk;
  sep = " ";

  for(word = strtok_r(arguments,sep, &brk);
  	  word != NULL;
  	  word = strtok_r(NULL, sep, &brk))
  {
    struct aelem *elem = malloc(sizeof(struct aelem));
    if(elem == NULL)
    {
      sys_exit(-1);
    }
    elem->word = word;
    elem->len = strlen(word) + 1;
    list_push_front(argv, elem);
    a->argc++;
  }
  a->argv = argv;

  return a;
}

/* Takes an internal args struct and pushes them onto the stack
 * Then pushes the rest of the arguments on as detailed in the
 * specification */
void *
push_args_stack(void *esp, struct args *a)
{
  int bytesize = 4;
  int esp_offsets = 0;
  struct list_elem *it;
  int i = 0;

  //Start by pushing actual arguments onto stack
  //const char *arg_pointer_list[a->argc];
  char **arg_pointer_list = (char **) malloc(a->argc * sizeof(char *));
  if(arg_pointer_list == NULL){
    sys_exit(-1);
  }

  it = list_begin(a->argv);
  while(it != list_end(a->argv)){

    struct aelem *elem = list_entry(it, struct aelem, argv_elem);

    esp -= elem->len;
    esp_offsets += elem->len;
    memcpy((char *) esp, elem->word, elem->len);

    arg_pointer_list[i] = esp;

    i++;
    it = list_remove(it);

    free(elem);
  }
  //word-align padding
  while(esp_offsets % 4 != 0){
    esp_offsets+=1;
    esp -= 1;
    char *nullval = "\0";
    memcpy((char *) esp, nullval, strlen(nullval));
  }
  //Null sentinal
  esp-=4;
  char *nullsent = "\0\0\0\0";
  memcpy((char *) esp, nullsent, strlen(nullsent));

  //Push address to arguments in reverse order.
  for(i = 0; i < a->argc; i++)
  {

    esp -= bytesize;
    char *addr = arg_pointer_list[i];
    memcpy((char *)esp, &addr, bytesize);
  }
  free(arg_pointer_list);

  //Push address of array of addresses of arguments
  char *prevaddr = esp;
  esp-=bytesize;
  memcpy((char *) esp, &prevaddr, bytesize);

  //Argc
  esp-=bytesize;
  memcpy((char *) esp, &a->argc, bytesize);

  //Return address
  esp-=bytesize;
  int retaddr = 0;
  memcpy((char *) esp, &retaddr, bytesize);

  //Free the list
  frame_free_frame(a);

  //return the new stack pointer
  return esp;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *ip_)
{
  struct init_proc *ip = (struct init_proc *) ip_;

  char *file_name = ip->args;
  char *first = ip->exec_name;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  lock_acquire(&file_lock);
  success = load (first, &if_.eip, &if_.esp);
  lock_release(&file_lock);

  /* Tell the parent of load success/failure and wait for
     Parent to finish its set up */
  ip->load_success = success;
  thread_current()-> open_file = ip->file;
  sema_up(&ip->exec_sema);
  sema_down(&ip->child_sema);
  free(ip);

  /* Safely parse command line arguments and push to stack*/
  if(success)
  {
    struct semaphore sema;
    sema_init(&sema, 1);
    sema_down(&sema);
    struct args *arguments;
    arguments = parse_arguments(file_name);
    if_.esp = push_args_stack(if_.esp, arguments);
    sema_up(&sema);
  }

  frame_free_frame (file_name);
  frame_free_frame(first);

  /* If load failed, quit. */
  if(!success)
  {
    sys_exit(-1);
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{

  struct thread *curr  = thread_current();


  /* Attempts to find thread child_tid in the current threads
    children list */
  struct child_process *child = thread_child_tid(curr, child_tid);

  /* If child_tid does not exist, or child is not the current threads child
     return -1 */
  if(child == NULL)
  {
    return -1;
  }


  /* If process_wait has already been called on this child
     or the child is already dead.
     return -1 */
  if(child->process_wait_called || child->isdead)
  {
    return child->exit_code;
  }
  child->process_wait_called = true;

  /* Otherwise
     Block current thread
     Run until child_tid has finished
     Record and return child_tid exit code. */
  do
  {
    curr->waiting_on = child_tid;
    sema_init(&child->process_wait_sema,0);
    sema_down(&child->process_wait_sema);
  } while(!child->isdead);

  /* Sema_up occurs in threads/thread.c
     in thread_exit of the child thread */
  list_remove(&child->child_elem);
  int ec = child -> exit_code;
  free(child);
  return ec;
}


/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();

  /* When a process exits it should be sets the child thread as dead*/
  struct thread* parent = cur->parent;
  if(parent != NULL)
  {
    struct child_process *cp = thread_child_tid(parent, cur->tid);
    cp->isdead = true;
    cp->exit_code = cur->exit_code;
    cur->parent = NULL;
    if(parent->status == THREAD_BLOCKED
                && parent->waiting_on == cp->child_tid){
      parent->waiting_on = TID_ERROR;
      sema_up(&cp->process_wait_sema);
    }
  }


  enum intr_level ol = intr_disable();
  /* Kill the processes existing children if wait was not called on them */
  struct list_elem *it = list_end(&cur->children);
  while(it != list_end(&cur->children))
  {
    struct child_process *cp = list_entry(it, struct child_process, child_elem);
    /* If the child is still alive, we must set its parent field to NULL */
    if(!cp->isdead || cp->child_thread != NULL)
    {
      cp->child_thread->parent = NULL;
    }
    it = list_remove(it);
  }
  intr_set_level(ol);

  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  /* Intialise supplemental page table */
  t->spt = init_spt ();
  if (t->pagedir == NULL || t->spt == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

// static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {

      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;



      /* Get a page of memory. */
      uint8_t *kpage = frame_get_frame();
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          frame_free_frame (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          frame_free_frame (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = frame_get_frame();
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
      {
        *esp = PHYS_BASE;
        set_is_stack(thread_current()->spt, esp);
      }
      else
        frame_free_frame(kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with frame_get_frame().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
