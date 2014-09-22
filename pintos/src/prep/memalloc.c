#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <list.h>
#include "memalloc.h"

/*
 * This header file describes the public interface of the first-fit 
 * memory allocator.
 */

/* Initialize a pthread lock with default attributes. */
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

bool check_address(const struct list_elem *a, const struct list_elem *b, void *aux);

/* Initialize memory allocator to use 'length' 
 * bytes of memory at 'base'. 
 */
struct list free_list;

void mem_init(uint8_t *base, size_t length) {

    list_init(&free_list);

    struct free_block *fbp;
    fbp = (struct free_block *) base;

    struct list_elem elem;
    fbp->elem = elem;
    fbp->length = length;
    list_push_back(&free_list, &fbp->elem);
}

/* Allocate 'length' bytes of memory. */
void *mem_alloc(size_t length) {

    struct list_elem *e;
    struct free_block *fbp;
    void *fbp_end = NULL, *ubp = NULL;

    long bytes_left = 0, actual_length = 0;

    /* Length must be greater than the free_block header - used_block header. 
     * Since the used_block header is still accounted for in the length.
     */
    long min_length = sizeof(struct free_block) - sizeof(struct used_block);

    if (length < min_length) {

         length = min_length;
    }

    /* By prepending the used_block header, account for the header space. */
    actual_length = sizeof(struct used_block) + length;

    pthread_mutex_lock(&mutex);

    for (e = list_begin (&free_list); e != list_end (&free_list); e = list_next (e)) {
	
	fbp = list_entry(e, struct free_block, elem);

	/* If there is space, initialize the used block and update free block length. 
	 * Else there is not enough space, and return NULL.  
	 */
	if (actual_length <= fbp->length) {

	    bytes_left = fbp->length - actual_length;

	    if (bytes_left < (long)(sizeof(struct free_block))) {

		length += bytes_left;
		actual_length = (long)sizeof(struct used_block) + length;
		list_remove(e);
	    }

	    fbp_end = (void *)((size_t)fbp + (size_t)fbp->length);
	    ubp = (void *)(fbp_end - actual_length);
	    fbp->length = (size_t)fbp->length - actual_length;

	    ((struct used_block *)ubp)->length = length;

	    pthread_mutex_unlock(&mutex);

	    return ((struct used_block *)ubp)->data;
        }
    }
    
    pthread_mutex_unlock(&mutex);

    return NULL;
}

/* Free the requested memory. */
void mem_free(void *ptr) {
    
    struct list_elem *e, *free_elem;
    struct free_block *fbp;
    void *left = NULL;
    void *right = NULL;
    long freed_space = 0;

    void *ubp = ptr - sizeof(struct used_block);

    freed_space = (long)sizeof(struct used_block) + (long)((struct used_block *)ubp)->length;

    pthread_mutex_lock(&mutex);

    /* Iterates through list until we find left and right of the used block. */
    for (e = list_begin (&free_list); e != list_end (&free_list); e = list_next (e)) {

        fbp = list_entry(e, struct free_block, elem);

        if (ubp == ((struct free_block *)fbp)->length + (void *)fbp) {

            left = fbp;
        }

        if (fbp == (void *)(((struct used_block *)ubp)->length + ptr)) {

            right = fbp;
            free_elem = e;
        }
    }

    if (left == NULL && right == NULL) {

        struct list_elem e;
        fbp = (struct free_block *)ubp;

        fbp->length = freed_space;
        fbp->elem = e;

        list_insert_ordered(&free_list, &(fbp->elem), check_address, NULL);
    }

    else if (left != NULL && right == NULL) {

        ((struct free_block *)left)->length += freed_space;
    }

    else if (left == NULL && right != NULL) {

        struct list_elem e;
        fbp = (struct free_block *) ubp;

        fbp->length = ((struct free_block *)right)->length + freed_space;
        fbp->elem = e;
        list_insert_ordered(&free_list, &(fbp->elem), check_address, NULL);
        list_remove(free_elem);
    }
    else {

        ((struct free_block *)left)->length += (freed_space + ((struct free_block *)right)->length);
        list_remove(free_elem);
    }

    pthread_mutex_unlock(&mutex);
}

bool check_address(const struct list_elem *a, const struct list_elem *b, void *aux) {

    if ((long)a == (long)b) {

	return 0;
    }
    else if((long)a < (long) b) {

	return -1;
    }
    else {

	return 1;
    }
}

/* Return the number of elements in the free list. */
size_t mem_sizeof_free_list(void) {

    return list_size(&free_list);
}

