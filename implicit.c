/*
Name: Tim Jing
Implicit heap allocator implementation for malloc, free, and realloc. Headers are used to store
payload size. No explicit list of free blocks is maintained. Does not support in-place realloc or
coalescing.
*/

#include "./allocator.h"
#include "./debug_break.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// How many bytes are printed per line in dump_heap
#define BYTES_PER_LINE 64

// Global variables maintained for implicit heap allocator function
static void *segment_start;
static void *segment_end;
static size_t segment_size;
static size_t nused;

// Struct to maintain header information
typedef struct header {
    size_t payload_size;
} header;

// Function declarations for helper functions
bool occupied(header *cur_header);
size_t payload_val(header *cur_header);
header *payload_to_header(void *payload);
header *next_header(header *cur_header);
size_t roundup(size_t sz, size_t mult);

/*
Main functions for implicit allocator implementation
*/

/* 
Init function to define begin and end of heap. Does bounds checking to ensure
there is enough room and sets global variables. 
*/
bool myinit(void *heap_start, size_t heap_size) {
    if (heap_size < sizeof(header) + ALIGNMENT) {
        return false;
    }
    segment_start = heap_start;
    segment_size = heap_size;
    segment_end = (char *)segment_start + segment_size;

    header *initial_header = (header *)segment_start;
    initial_header->payload_size = heap_size - sizeof(header);
    nused = 0;
    return true;
}

/* 
Helper function that finds the best free block available, or NULL if none is found.
Best is defined as payload size greater than needed, but minimizing the difference.
*/
header *find_best_fit(size_t needed, size_t *difference) {
    size_t min_val = SIZE_MAX;
    header *traverse = (header *)segment_start;
    header *to_return = NULL;
    while (traverse != NULL) {
        size_t payload_size = payload_val(traverse);
        if (!occupied(traverse) && payload_size >= needed && payload_size < min_val) {
            min_val = payload_size;
            to_return = traverse;
            if (payload_size == needed) {  // Already best free spot we can find
                break;
            }
        }
        traverse = next_header(traverse);
    }
    *difference = min_val - needed;
    return to_return;
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

    nused += (needed + sizeof(header));
    if (*difference >= sizeof(header) + ALIGNMENT) {
        header *new_block = (header *)((char *)loc + sizeof(header) + needed);
        new_block->payload_size = *difference - sizeof(header);
        loc->payload_size = needed + 1;
    } else {
        loc->payload_size += 1;
        nused += *difference;
    }
    
    return (char *)loc + sizeof(header);
}

/*
Free implementation that frees the given pointer, adding it back into the linked list.
It does not attempt to coalesce its immedaite right neighbor.
*/
void myfree(void *ptr) {
    if (!ptr) {
        return;
    }
    header *cur = payload_to_header(ptr);
    cur->payload_size -= 1;
    nused -= (cur->payload_size + sizeof(header));
}

/*
Realloc implementation that doesn't support in-place realloc. If NULL is provided, behavior is like
normal malloc. If no realloc pointer is found, NULL is returned
*/
void *myrealloc(void *old_ptr, size_t new_size) {
    void *new_loc = mymalloc(new_size);
    if (!new_loc) {
        return NULL;
    }
    if (!old_ptr) {
        return new_loc;
    }

    header *new_header = payload_to_header(new_loc);
    memcpy(new_loc, old_ptr, payload_val(new_header));
    myfree(old_ptr);
    return new_loc;
}

/*
HELPER FUNCTIONS: Useful functions for implicit allocator implementation
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

// Jump to the next neighboring header to the right
header *next_header(header *cur_header) {
    size_t payload_size = payload_val(cur_header);
    header *next = (header *)((char *)cur_header + payload_size + sizeof(header));
    return (next < (header *)segment_end) ? next : NULL;
}

// Roundup sz to the nearest mult 
size_t roundup(size_t sz, size_t mult) {
    return (sz + mult - 1) & ~(mult - 1);
}

/*
HELPER FUNCTIONS: Testing and Debugging
*/

/*
Helper function that validates whether the internal state of the heap is correct. Conducts checks
on alignment, bytes used, payload sizing, etc.
*/
bool validate_heap() {
    header *traverse = (header *)segment_start;
    header *follower = NULL;
    size_t used_count = 0;
    while (traverse != NULL) {
        size_t payload_size = payload_val(traverse);
        if (payload_size % ALIGNMENT != 0) {  // Check all headers are properly aligned
            breakpoint();
            return false;
        }
        if (occupied(traverse)) { 
            used_count += (payload_size + sizeof(header));
        }
        follower = traverse;    
        traverse = next_header(traverse);
    }

    // Check headers are perfectly sized
    if ((char *)follower + payload_val(follower) + sizeof(header) != segment_end) {
        breakpoint();
        return false;
    }

    if (used_count != nused) {  // Check used payload is correct
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
    printf("Heap segment starts at address %p, ends at %p. %lu bytes currently used.\n", segment_start,
            segment_end, nused);
    header *traverse = (header *)segment_start;
    while (traverse != NULL) {
        size_t payload_size = payload_val(traverse);
        if (occupied(traverse)) {
            printf("Header: %ld Used\n", payload_size);
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
        traverse = next_header(traverse);
    }
}