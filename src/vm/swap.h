#ifndef SWAP_H
#define SWAP_H

#include <stdbool.h>
#include "devices/block.h"

void swap_init(void);
block_sector_t move_to_swap(void *);
void * get_from_swap(void *, block_sector_t);

block_sector_t InvalidSwapNum;

#endif
