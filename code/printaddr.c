/**
 * Call instrumentation for e9patch to print out addresses of
 * all instrumented instructions.
 *
 * Should be copied into the folder e9patch/example,
 * and compiled with ./e9compile.sh example/printaddr.c
 *
 **/

#include "stdlib.c"

struct addr_s {
    void *content;
    struct addr_s *next;
};
typedef struct addr_s ADDR;

static ADDR *trace_head = NULL;
static ADDR *trace_tail = NULL;

/**
 * Usage: call entry(addr)@printaddr
 **/
void entry(const void *addr) {
    ADDR *new_node = (ADDR *)malloc(sizeof(ADDR));
    // new_node should be new tail
    new_node->content = addr;
    new_node->next = NULL;
    if (!trace_head) {
        trace_head = new_node;
        trace_tail = new_node;
    } else {
        trace_tail->next = new_node;
        trace_tail = new_node;
    }
}

// print out trace to stderr
void fini(void) {
    for (ADDR *tmp = trace_head; tmp != NULL; tmp = tmp->next)
        fprintf(stderr, "%p\n", tmp->content);
    }
}
