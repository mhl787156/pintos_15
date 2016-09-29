#ifndef PAGE_H
#define PAGE_H

#include <stdbool.h>
#include <hash.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "devices/block.h"
#include "vm/swap.h"

/* Functions for management of the supplemental page table.
 * Allows checking if a given vaddr is swapped (and if so
 * whereabeouts), is part of the stack or part of a mmap'd file.
 */

struct spt_elem
{
  void *vaddr;                  /*Virtual address*/

  block_sector_t swap_address;  /* location of page in the swap partition */

  bool is_swapped;              /* bool indicating swap status */
  bool is_stack;                /* bool indicating stack status */

  bool is_mmap;                 /* bool indicating mmap status */
  struct fd_container *fdc;     /* pointer to container if its mmaped */

  struct hash_elem hash_elem;   /* hash elem for storage in hash table */
};

struct hash * init_spt(void);
void destroy_spt(struct hash *);
void destroy_spt_elem(struct hash_elem *, void *);

block_sector_t get_swap_address(struct hash *, void *);
struct fd_container *get_mmap_container(struct hash *, void *);
bool is_swapped(struct hash *, void *);
bool is_stack(struct hash *, void *);
bool is_mmap(struct hash *, void *);

void set_swap_address(struct hash *, void *, block_sector_t);
void set_is_swapped(struct hash *, void *);
void set_is_stack(struct hash *, void *);
void set_is_mmap(struct hash *, void *, struct fd_container *);

void set_not_swapped(struct hash *, void *);
void set_not_stack(struct hash *, void *);
void set_not_mmap(struct hash *, void *);

struct spt_elem * spt_find_or_insert(struct hash *, void *);

unsigned spt_hash(const struct hash_elem *, void *);
bool spt_less(const struct hash_elem *, const struct hash_elem *, void *);

#endif
