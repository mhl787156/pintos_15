#include "vm/page.h"
#include "userprog/pagedir.h"

/* Initialises a new supplemental page table
 */
struct hash *
init_spt(void)
{
  struct hash *spt = malloc(sizeof(struct hash));
  ASSERT(spt != NULL);
  hash_init (spt, spt_hash, spt_less, NULL);
  return spt;
}

/* Destroys given supplemental page table, freeing memory
 */
void
destroy_spt(struct hash *spt)
{
  hash_destroy(spt, destroy_spt_elem);
  free(spt);
}

/* Removes the entry from the hash table_lock
   then frees the entry */
void
free_and_destroy_spt_elem(struct hash *spt, void *vaddr)
{
  struct spt_elem *entry = spt_find_or_insert(spt, vaddr);
  struct hash_elem *he = hash_delete(spt, &entry->hash_elem);
  ASSERT(he != NULL);
  free(entry);
}

/* Destroys the entry associated with given hash_elem,
 * freeing memory
 */
void destroy_spt_elem(struct hash_elem *hash_elem, void *aux UNUSED)
{
  struct spt_elem *elem = hash_entry(hash_elem, struct spt_elem, hash_elem);
  if(elem->is_mmap)
  {
    mmap_write_page_back_to_file(elem->fdc, elem->vaddr);
  }
  free(elem);
}

/* Finds where the page of the given virtual address
 * is stored on the disk. Returns -1 if the page isn't
 * in the swap partition.
 */
block_sector_t
get_swap_address(struct hash *spt, void *vaddr)
{
  struct spt_elem *entry = spt_find_or_insert(spt, vaddr);
  return entry->is_swapped ? entry->swap_address : InvalidSwapNum;
}

/* Finds where the mmaped page of the given virtual address
 * is stored on the disk. Returns NULL if the page isn't
 * in the swap partition.
 */
struct fd_container *
get_mmap_container(struct hash *spt, void *vaddr)
{
  struct spt_elem *entry = spt_find_or_insert(spt, vaddr);
  return entry->is_mmap ? entry->fdc : NULL;
}

/* Checks if the page of the given virtual address
 * is in the swap partition.
 */
bool
is_swapped(struct hash *spt, void *vaddr)
{
  return spt_find_or_insert(spt, vaddr)->is_swapped;
}

/* Checks if the page of the given virtual address
 * is a stack page.
 */
bool
is_stack(struct hash *spt, void *vaddr)
{
  return spt_find_or_insert(spt, vaddr)->is_stack;
}

/* Checks if the page of the given virtual address
 * is part of a mmap'd file.
 */
bool
is_mmap(struct hash *spt, void *vaddr)
{
  return spt_find_or_insert(spt, vaddr)->is_mmap;
}

/* Sets the swap address of the page of the given
 * virtual address to the given block_sector_t.
 */
void
set_swap_address(struct hash *spt, void *vaddr, block_sector_t swpaddr)
{
  struct spt_elem *spt_entry = spt_find_or_insert(spt, vaddr);
  spt_entry->is_swapped = true;
  spt_entry->swap_address = swpaddr;
}

/* Sets the page of the given virtual address
 * to be considered as  located in the swap partition.
 */
void
set_is_swapped(struct hash *spt, void *vaddr)
{
  spt_find_or_insert(spt, vaddr)->is_swapped = true;
}

/* Sets the page of the given virtual address
 * to be treated as a page on the stack.
 */
void
set_is_stack(struct hash *spt, void *vaddr)
{
  spt_find_or_insert(spt, vaddr)->is_stack = true;
}

/* Sets the page of the given virtual address
 * to be treated as a page of a mmap'd file
 */
void
set_is_mmap(struct hash *spt, void *vaddr, struct fd_container *fdc)
{
  struct spt_elem *se = spt_find_or_insert(spt, vaddr);
  se->is_mmap = true;
  se->fdc = fdc;
}

/* Indicates that the page of the given virtual
 * address is not located in the swap partition
 */
void
set_not_swapped(struct hash *spt, void *vaddr)
{
  struct spt_elem *elem = spt_find_or_insert(spt, vaddr);
  elem->is_swapped = false;
  elem->swap_address = 0;
}

/* Sets the page of the given virtual address
 * to NOT be considered as a page on the stack
 */
void
set_not_stack(struct hash *spt, void *vaddr)
{
  spt_find_or_insert(spt, vaddr)->is_stack = false;
}

/* Sets the page of the given virtual address
 * to NOT be considered as a page of a mmap'd file
 */
void
set_not_mmap(struct hash *spt, void *vaddr)
{
  struct spt_elem *elem = spt_find_or_insert(spt, vaddr);
  if(pagedir_is_dirty(thread_current()->pagedir, vaddr))
  {
    mmap_write_page_back_to_file(elem->fdc, vaddr);
  }
  elem->is_mmap = false;
  elem->fdc = NULL;
}

/* Looks up a given virtual addrzess in the supplemental
 * page table. If an entry does not exist, create a new
 * empty one.
 */
struct spt_elem *
spt_find_or_insert(struct hash *spt, void *vaddr)
{
  vaddr = pg_round_down(vaddr); //discards offset
  struct spt_elem entry_check;
  entry_check.vaddr = vaddr;
  struct thread *curr = thread_current();

  if(!lock_held_by_current_thread(&curr->spt_lock)) lock_acquire(&curr->spt_lock);
  struct hash_elem *result = hash_find(spt, &entry_check.hash_elem);
  lock_release(&curr->spt_lock);

  if (result == NULL)
  {
    struct spt_elem *entry;
    entry = (struct size *)malloc(sizeof(struct spt_elem));
    ASSERT(entry != NULL);
    entry->vaddr = vaddr;
    entry->swap_address = InvalidSwapNum;
    entry->is_swapped = false;
    entry->is_stack = false;
    entry->is_mmap = false;
    entry->fdc = NULL;

    lock_acquire(&curr->spt_lock);
    hash_insert(spt, &entry->hash_elem);
    lock_release(&curr->spt_lock);

    return entry;
  }
  return hash_entry(result, struct spt_elem, hash_elem);
}

/* Returns a hash value for spt entry E. */
unsigned
spt_hash(const struct hash_elem *e_, void *aux UNUSED)
{
  const struct spt_elem *e = hash_entry (e_, struct spt_elem, hash_elem);
  return hash_bytes (&e->vaddr, sizeof(e->vaddr));
}

/* Returns true if spt entry a precedes spt entry b. */
bool
spt_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct spt_elem *a = hash_entry (a_, struct spt_elem, hash_elem);
  const struct spt_elem *b = hash_entry (b_, struct spt_elem, hash_elem);
  return a->vaddr < b->vaddr;
}
