#ifndef FRAME_H
#define FRAME_H

#include <stdbool.h>
#include "threads/thread.h"

void frame_init(void);
void *frame_get_frame(void);
void frame_free_frame(void *);

bool set_second_chance_bit(void *);
void mmap_write_page_back_to_file(struct fd_container *, void *);



#endif
