#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define POOL_SIZE 64

struct Block {
  struct Block *next;
  int payload;
};

static struct Block *free_list = NULL;
static int alloc_count = 0;
static int free_count = 0;

static struct Block *pool_alloc(void) {
  struct Block *b;
  if (free_list) {
    b = free_list;
    free_list = free_list->next;
  } else {
    b = (struct Block *)malloc(sizeof(struct Block));
  }
  ++alloc_count;
  b->next = NULL;
  return b;
}

static void pool_free(struct Block *b) {
  if (!b)
    return;
  b->next = free_list;
  free_list = b;
  ++free_count;
}

static struct Block *make_chain(int n) {
  struct Block *head = NULL;
  for (int i = 0; i < n; ++i) {
    struct Block *b = pool_alloc();
    b->payload = (i + 1) * (i + 2);
    b->next = head;
    head = b;
  }
  return head;
}

static int sum_chain(struct Block *head) {
  int s = 0;
  for (struct Block *p = head; p; p = p->next)
    s += p->payload;
  return s;
}

static void release_chain(struct Block *head) {
  while (head) {
    struct Block *next = head->next;
    pool_free(head);
    head = next;
  }
}

static int churn(int rounds, int chain_len) {
  int acc = 0;
  for (int r = 0; r < rounds; ++r) {
    struct Block *c = make_chain(chain_len);
    acc += sum_chain(c);
    release_chain(c);
  }
  return acc;
}

static int slab_count(struct Block *head) {
  int n = 0;
  for (struct Block *p = head; p; p = p->next)
    ++n;
  return n;
}

int main(void) {
  struct Block *c1 = make_chain(5);
  struct Block *c2 = make_chain(3);
  int s1 = sum_chain(c1);
  int s2 = sum_chain(c2);
  release_chain(c1);
  release_chain(c2);

  int churned = churn(4, 6);

  int pooled = 0;
  for (struct Block *p = free_list; p; p = p->next)
    ++pooled;

  printf("alloc:%d:%d:%d:%d:%d\n", s1, s2, churned, alloc_count, pooled);
  return 0;
}
