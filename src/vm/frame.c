#include "vm/frame.h"
#include <hash.h>
#include <inttypes.h>
#include <limits.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "devices/block.h"
#include "vm/page.h"
#include "vm/swap.h"


/* Global Frame Table */
struct hash frame_table;

/* Struct of the frame table */
struct frame
{
  struct hash_elem hash_elem;
  void *paddr;                 /* page address */
  void *faddr;                 /* frame address */
  tid_t tid;                   /* process that this page belongs to */
  struct thread *thread;       /* replacement for tid */
  bool second_chance_bit;      /* Bit that is set on second chance */
};

size_t max_table_size;         /* max table size */
size_t current_num_entries;    /* keep record of num of entries */
struct lock table_lock;        /* lock for the frame table */

unsigned frame_hash (const struct hash_elem *f_, void *aux UNUSED);
bool frame_less (const struct hash_elem *a_,
                      const struct hash_elem *b_, void *aux UNUSED);
void *evict_frame(void);
struct frame *ft_find_frame(void *);


#define ISFULL (current_num_entries >= max_table_size)

/* Init the frame table */
void
frame_init()
{
  bool res = hash_init (&frame_table, frame_hash, frame_less, NULL);
  max_table_size = num_user_pages;
  current_num_entries = 0;
  lock_init(&table_lock);
}

/* Returns the paddr from palloc, puts this frame into frame table hash map
   If the palloc returns NULL then evicts the page in a frame and remaps the
   paddr and return paddr */
void *
frame_get_frame()
{
  lock_acquire(&table_lock);
  struct frame *frame = NULL;
  void *paddr = palloc_get_page(PAL_USER);
  if(paddr == NULL)
  {
    /* Frame table full, must evict, reassigns the swapped frame*/
    void *faddr = evict_frame();
    paddr = palloc_get_page(PAL_USER);
    ASSERT(paddr != NULL);
    frame = ft_find_frame(paddr);
    ASSERT(frame != NULL);

    //paddr already set.
    frame->faddr = faddr;
    frame->thread = thread_current();
    frame->tid = frame->thread->tid;
    frame->second_chance_bit = false;
  }
  else
  {
    /* New frame */
    frame = (struct frame *) malloc(sizeof(struct frame));
    ASSERT(frame != NULL);

    frame->paddr = paddr;
    frame->faddr = paddr;
    frame->thread = thread_current();
    frame->tid = frame->thread->tid;
    frame->second_chance_bit = false;

    if(hash_insert(&frame_table, &frame->hash_elem) != NULL)
    {
      PANIC("PHYSICAL ADDRESS ALREADY ALLOCATED");
    }
  }

  current_num_entries += 1;
  lock_release(&table_lock);

  return paddr;
}

/* Takes a paddr given from the user,
   and palloc_free_page's it */
void
frame_free_frame(void *paddr)
{
  lock_acquire(&table_lock);
  struct frame *f = ft_find_frame(paddr);
  if(f == NULL)
  {
    lock_release(&table_lock);
    return;
  }
  hash_delete(&frame_table, &f->hash_elem);
  palloc_free_page(paddr);
  free(f);
  current_num_entries -= 1;
  lock_release(&table_lock);
  return;
}

/* Sets the frame in the frame table's second chance to true
  returns true if successful, false, if the frame is not allocated */
bool
set_second_chance_bit(void *paddr) {
  lock_acquire(&table_lock);
  struct frame *curr = ft_find_frame(paddr);
  if(curr == NULL)
  {
    lock_release(&table_lock);
    return false;
  }
  curr->second_chance_bit = true;
  lock_release(&table_lock);
  return true;
}


/* Second Chance Algorithm...
   If Frame table is full, we must evict frames for new frames
   Removes the evicted page from the pagedtable
   Assumes that access to frame table is safe */
void *
evict_frame()
{
  void *evicted_frame = NULL;
  static struct hash_iterator it;
  hash_first(&it, &frame_table);
  while(true)
  {
    struct frame *f = hash_entry( hash_cur(&it), struct frame, hash_elem);
    // If second chance bit has not been set
    // i.e. first time this frame has been considered yet.
    if(f->second_chance_bit)
    {
      f->second_chance_bit = false;
      continue;
    }
    // If second chance bit has already been set
    // i.e. this frame has already been considered once.
    else
    {
      struct thread *curr = f->thread;

      // Check if page is mmaped
      struct fd_container *fdc = get_mmap_container(curr->spt, f->paddr);
      if(fdc != NULL)
      {
        if(pagedir_is_dirty(curr->pagedir, f->paddr))
        {
          // Write the page back to file system
          mmap_write_page_back_to_file(fdc, f->paddr);
        }
      }
      else
      {
        // If not any of the above, its then ready for swap
        block_sector_t sector = move_to_swap(f->paddr);
        // update supplemental page table
        set_swap_address(curr->spt,f->paddr,sector);
      }

      // palloc free the now swapped page of this frame
      palloc_free_page(f->paddr);
      // save evicted frame to return
      evicted_frame = f->faddr;

      break;
    }

    //loop round table if end is reached
    if(!hash_next(&it)) hash_first(&it, &frame_table);
  }
  current_num_entries -= 1;
  return evicted_frame;
}

void
mmap_write_page_back_to_file(struct fd_container *fdc, void *paddr)
{
  // Get the offset from the file of the page
  off_t offset = paddr - fdc->addr;

  // Write the page back to file
  if(offset != (fdc->file_size * PGSIZE))
  {
    // If address is last page
    size_t num_bytes_remaining = fdc->file_size_bytes * PGSIZE;
    file_write_at(fdc->file, paddr, num_bytes_remaining, offset);
  }
  else
  {
    file_write_at(fdc->file, paddr, PGSIZE, offset);
  }

  // Reset the dirty bit
  pagedir_set_dirty(thread_current()->pagedir, paddr, false);
}

/* Returns the page containing the given virtual address,
or a null pointer if no such page exists.
Must be called in a safe context*/
struct frame *
ft_find_frame(void *paddr)
{
  struct frame f;
  struct hash_elem *e;
  f.paddr = paddr;

  e = hash_find (&frame_table, &f.hash_elem);
  return e != NULL ? hash_entry (e, struct frame, hash_elem) : NULL;
}

/* Returns a hash value for frame f. */
unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED)
{
  const struct frame *f = hash_entry (f_, struct frame, hash_elem);
  return hash_bytes (&f->paddr, sizeof(f->paddr));
}

/* Returns true if page a precedes page b. */
bool
frame_less (const struct hash_elem *a_, const struct hash_elem *b_,
void *aux UNUSED)
{
  const struct frame *a = hash_entry (a_, struct frame, hash_elem);
  const struct frame *b = hash_entry (b_, struct frame, hash_elem);
  return a->paddr < b->paddr;
}
