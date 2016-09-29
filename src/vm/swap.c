#include "vm/swap.h"
#include <hash.h>
#include <inttypes.h>
#include <limits.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bitmap.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

/* Bitmap representing the swap table */
struct block *swap_device;
struct bitmap *swap_table;
size_t table_size; // maximum number of pages that can be stored on disk

/* Safety table access lock */
static struct lock swap_lock;

#define SECTORS_PER_PAGE 8

/* typdef for the block read/ write functions */
typedef void (*block_func)(struct block*, block_sector_t, void *);

/* Helper functions */
block_sector_t get_free_page(void);
void *block_swap(block_sector_t, void *, block_func);


/* Initiate the swap table to map the swap*/
void
swap_init()
{
  swap_device = block_get_role(BLOCK_SWAP);
  ASSERT(swap_device != NULL);
  block_sector_t num_sectors = block_size(swap_device);
  table_size = num_sectors / SECTORS_PER_PAGE;
  InvalidSwapNum = table_size + 10;
  swap_table = bitmap_create(table_size);
  ASSERT(swap_table != NULL);
  bitmap_set_all(swap_table, false);
  lock_init(&swap_lock);
}

/* Write a page to swap from 1st to 8th sector
   Returns true if successful, false otherwise, paddr assumed to be
   page aligned */
block_sector_t
move_to_swap(void *paddr)
{
  lock_acquire(&swap_lock);

  ASSERT(swap_table != NULL);

  block_sector_t index = get_free_page();
  bitmap_set(swap_table, index, true);

  lock_release(&swap_table);
  
  block_swap(index, paddr, block_write);

  return index;
}

/* Read a page from swap
   from 1st to 8th sector into given vaddr*/
void *
get_from_swap(void *vaddr, block_sector_t index)
{
  lock_acquire(&swap_lock);

  bitmap_set(swap_table, index, false);

  lock_release(&swap_table);

  return block_swap(index, vaddr, block_read);
}

/* Generalising the block read and write functions */
void *
block_swap(block_sector_t index, void *vaddr, block_func func)
{
  block_sector_t phys_index = index * SECTORS_PER_PAGE;
  size_t i;
  void *o_vaddr = vaddr;
  for(i = 0 ; i < SECTORS_PER_PAGE ; i++)
  {
    size_t s_index = phys_index + i;
    func(swap_device, s_index, vaddr);
    vaddr = vaddr +  BLOCK_SECTOR_SIZE;
  }
  return o_vaddr;
}

/* Get the first page in swap that is free
   Panic's the kernel if no value exists */
block_sector_t
get_free_page()
{
  size_t i;
  for(i = 0; i < table_size; i++)
  {
    if(!bitmap_test(swap_table, i))
    {
      return i;
    }
  }
  PANIC("SWAP IS FULL");
}
