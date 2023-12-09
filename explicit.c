/*
Name: Tim Jing
Explicit heap allocator implementation for malloc, free, and realloc. Maintains a doubly-linked list
of free blocks for faster search. Support in-place realloc and coalescing.
*/
#include "./allocator.h"
#include "./debug_break.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// How many bytes are printed per line in dump_heap
#define BYTES_PER_LINE 64

// Struct to maintain header information
typedef struct header {
    size_t payload_size;
} header;

// Struct to maintain pointers information
typedef struct pointers {
    header *prev;
    header *next;
} pointers;

// Global variables maintained for explicit heap allocator function
static void *segment_start;
static void *segment_end;
static size_t segment_size;
static size_t nused;
static size_t num_free;
header *first_free;

// Function declarations for helper functions
bool occupied(header *cur_header);
size_t payload_val(header *cur_header);
header *payload_to_header(void *payload);
header *next_free_header(header *cur_header);
size_t roundup(size_t sz, size_t mult);
pointers *header_to_pointers(header *cur_header);
header *next_order_header(header *cur_header);

/*
Main functions for explicit allocator implementation
*/

/* 
Init function to define begin and end of heap. Does bounds checking to ensure
there is enough room and sets global variables. 
*/
bool myinit(void *heap_start, size_t heap_size) {
    if (heap_size < sizeof(header) + sizeof(pointers)) {  // Minimum payload is sizeof(pointers)
        return false;
    }
    segment_start = heap_start;
    segment_size = heap_size;
    segment_end = (char *)segment_start + segment_size;

    first_free = (header *)segment_start;
    first_free->payload_size = heap_size - sizeof(header);

    pointers *initial_pointers = (pointers *)((char *)segment_start + sizeof(header));
    initial_pointers->prev = NULL;
    initial_pointers->next = NULL;

    num_free = 1;
    nused = 0;
    return true;
}

/* 
Helper function that finds the best free block available, or NULL if none is found.
Best is defined as payload size greater than needed, but minimizing the difference.
*/
header *find_best_fit(size_t needed, size_t *difference) {
    size_t min_val = SIZE_MAX;
    header *traverse = first_free;
    header *to_return = NULL;
    while (traverse) {
        size_t payload_size = payload_val(traverse);
        if (payload_size >= needed && payload_size < min_val && !occupied(traverse)) {
            min_val = payload_size;
            to_return = traverse;
            if (payload_size == needed) {  // Already best free spot we can find
                break;
            }
        }
        traverse = next_free_header(traverse);
    }

    *difference = min_val - needed;
    return to_return;
}

/* 
Helper function that takes a pointer to a free header and removes it from the
free linked list.
*/
void splice_out(header *to_remove) {
    pointers *cur_pointers = header_to_pointers(to_remove);
    if (cur_pointers->next) {
        pointers *next_pointers = header_to_pointers(cur_pointers->next);
        next_pointers->prev = cur_pointers->prev;
    }

    if (cur_pointers->prev) {
        pointers *prev_pointers = header_to_pointers(cur_pointers->prev);
        prev_pointers->next = cur_pointers->next;
    }

    if (first_free == to_remove) {
        first_free = cur_pointers->next;
        if (first_free) {
            header_to_pointers(first_free)->prev = NULL;
        } 
    }
    num_free -= 1;
}

/* 
Helper function that inserts a free block and adds it to the linked list if necessary 
based on how much of the payload is actually needed.
*/
void insert_block(header* cur_block, size_t difference, size_t needed) {
    if (difference >= sizeof(header) + sizeof(pointers)) {
        header *new_block = (header *)((char *)cur_block + sizeof(header) + needed);
        pointers *new__pointers = header_to_pointers(new_block);

        new_block->payload_size = difference - sizeof(header);
        new__pointers->prev = NULL;
        new__pointers->next = first_free;
        if (first_free) {
            header_to_pointers(first_free)->prev = new_block;
        }  
        first_free = new_block;

        cur_block->payload_size = needed + 1;
        num_free += 1;
    } else {
        cur_block->payload_size += 1;
        nused += difference;  // Accounts for the padding in the block
    }
}

/*
Malloc implementation that takes a requested_size and returns a pointer to the
allocated heap address, or NULL if none is found. 0 or invalid requests receive NULL.
*/
void *mymalloc(size_t requested_size) {
    if (requested_size <= 0 || requested_size > MAX_REQUEST_SIZE) {
        return NULL;
    }

    size_t needed = roundup(requested_size, ALIGNMENT);
    size_t zero = 0;
    size_t *difference = &zero;
    header *loc = find_best_fit(needed, difference);
    if (!loc) {
        return NULL;
    }

    splice_out(loc);
    insert_block(loc, *difference, needed);
    nused += (needed + sizeof(header));
    return (char *)loc + sizeof(header);
}

/*
Helper function that checks if the immediate right neighboring header is free
and combines the two.
*/
bool coalesce(header *cur_header) {
    header *right_header = next_order_header(cur_header);
    if (!right_header) {
        return false;
    }

    if (!occupied(right_header)) {
        splice_out(right_header);
        cur_header->payload_size += (payload_val(right_header) + sizeof(header));
        return true;
    }
    return false;
}

/*
Free implementation that frees the given pointer, adding it back into the linked list.
It attempts to coalesce its immedaite right neighbor.
*/
void myfree(void *ptr) {
    if (!ptr) {
        return;
    }
    header *cur_header = payload_to_header(ptr);
    cur_header->payload_size -= 1;
    nused -= (payload_val(cur_header) + sizeof(header));
    coalesce(cur_header);
    
    pointers *cur_pointers = header_to_pointers(cur_header);
    cur_pointers->next = first_free;
    cur_pointers->prev = NULL;
    if (first_free) {
        header_to_pointers(first_free)->prev = cur_header;
    }
    first_free = cur_header;
    num_free += 1;
}

/*
Realloc implementation that supports in-place realloc. If NULL is provided, behavior is like
normal malloc. If no realloc pointer is found, NULL is returned. Realloc attempts to coalesce
as many free blocks to the right as possible no matter if in-place occurs or not.
*/
void *myrealloc(void *old_ptr, size_t new_size) {
    if (!old_ptr) {
        return mymalloc(new_size);
    }
    header *old_header = payload_to_header(old_ptr);
    size_t initial_payload = payload_val(old_header);
    size_t needed = roundup(new_size, ALIGNMENT);

    while (coalesce(old_header)) {    // Coalesce as much as possible
    }
    
    if (needed <= payload_val(old_header)) {   // Case 1: In-place realloc
        old_header->payload_size -= 1;
        insert_block(old_header, payload_val(old_header) - needed, needed);
        nused -= initial_payload;
        nused += needed;
        return old_ptr;
    } else {   // Case 2: New malloc required
        void *new_loc = mymalloc(new_size);
        if (!new_loc) {
            return NULL;
        }

        memcpy(new_loc, old_ptr, initial_payload);
        myfree(old_ptr);
        nused += (payload_val(old_header) - initial_payload);  // Accounts for over subtraction when coalesce occurs
        return new_loc;
    }
}

/*
HELPER FUNCTIONS: Useful functions for explicit allocator implementation
*/

// Determines if the current header is free or occupied (used)
bool occupied(header *cur_header) {
    size_t occupied = cur_header->payload_size & 0x1;
    return occupied == 1;
}

// Extracts the payload size regardless of occupied status
size_t payload_val(header *cur_header) {
    size_t mask = SIZE_MAX - 1;
    return cur_header->payload_size & mask;
}

// Pointer arithmetic to go from payload to header
header *payload_to_header(void *payload) {
    return (header *)((char *)payload - sizeof(header));
}

// Pointer arithmetic to go from header to pointers
pointers *header_to_pointers(header *cur_header) {
    return (pointers *)((char *)cur_header + sizeof(header));
}

// Jump to the next header in the free linked list
header *next_free_header(header *cur_header) {
    pointers *cur_pointers = header_to_pointers(cur_header);
    return cur_pointers->next;
}

// Jump to the next neighboring header to the right
header *next_order_header(header *cur_header) {
    size_t payload_size = payload_val(cur_header);
    header *next = (header *)((char *)cur_header + payload_size + sizeof(header));
    return (next < (header *)segment_end) ? next : NULL;
}

// Roundup sz to the nearest multiple. If the value is less than the minimum payload size,
// the minimum payload size is returned.
size_t roundup(size_t sz, size_t mult) {
    size_t to_return = (sz + mult - 1) & ~(mult - 1);
    return (to_return < sizeof(pointers)) ? sizeof(pointers) : to_return;
}

/*
HELPER FUNCTIONS: Testing and Debugging
*/

/*
Helper function that validates whether the internal state of the heap is correct. Conducts checks
on alignment, amount of free blocks, bytes used, payload sizing, etc.
*/
bool validate_heap() {
    header *traverse = (header *)segment_start;
    header *follower = NULL;
    size_t used_count = 0;
    while (traverse) {
        size_t payload_size = payload_val(traverse);
        if (payload_size % ALIGNMENT != 0) {  // Check all headers are properly aligned
            breakpoint();
            return false;
        }
        if (occupied(traverse)) { 
            used_count += (payload_size + sizeof(header));
        }
        follower = traverse;    
        traverse = next_order_header(traverse);
    }

    // Check headers are perfectly sized
    if ((char *)follower + payload_val(follower) + sizeof(header) != segment_end) { 
        breakpoint();
        return false;
    }

    if (used_count != nused) {   // Check used payload is correct
        breakpoint();
        return false;
    }

    traverse = first_free;
    size_t free_counter = 0;
    while (traverse) {
        free_counter += 1;
        if (occupied(traverse)) {   // Check no used nodes in free list
            breakpoint();
            return false;
        }
        traverse = next_free_header(traverse);
    }

    if (free_counter != num_free) {   // Check number of free nodes is correct
        breakpoint();
        return false;
    }
    return true;
}

/* Function: dump_heap
 * -------------------
 * This function prints out the the block contents of the heap.  It is not
 * called anywhere, but is a useful helper function to call from gdb when
 * tracing through programs.  It prints out the total range of the heap, and
 * information about each block within it.
 */
void dump_heap() {
    printf("Heap segment starts at address %p, ends at %p. %lu bytes currently used.\n", segment_start, segment_end,
            nused);
    header *traverse = (header *)segment_start;
    while (traverse) {
        size_t payload_size = payload_val(traverse);
        if (occupied(traverse)) {
            printf("Header: %ld Used \n", payload_size);
            /*
            Comment this following section in in order to print out the stored values in each used block
            */

            // for (size_t i = 0; i < payload_size; i++) {
            //     unsigned char *cur = (unsigned char *)traverse + sizeof(header) + i;
            //     if (i % BYTES_PER_LINE == 0) {
            //         printf("\n%p: ", cur);
            //     }
            //     printf("%02x ", *cur);
            // }
        } else {
            printf("Header: %ld Free \n", payload_size);
        }
        traverse = next_order_header(traverse);
    }
}
