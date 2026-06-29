#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static int sum_stride(int *p, int n, int stride) {
  int s = 0;
  int *q = p;
  for (int i = 0; i < n; ++i) {
    s += *q;
    q += stride;
  }
  return s;
}

static int matrix_trace(int *base, int rows, int cols) {
  int s = 0;
  for (int i = 0; i < rows && i < cols; ++i)
    s += *(base + (size_t)i * cols + i);
  return s;
}

static int indirect_walk(int **arr, int n) {
  int s = 0;
  int **p = arr;
  for (int i = 0; i < n; ++i) {
    s += **p;
    ++p;
  }
  return s;
}

struct Node {
  int value;
  struct Node *next;
};

static struct Node *build_list(int n, int *buf) {
  struct Node *head = NULL;
  for (int i = n - 1; i >= 0; --i) {
    struct Node *node = (struct Node *)malloc(sizeof(struct Node));
    node->value = buf[i];
    node->next = head;
    head = node;
  }
  return head;
}

static int traverse_free(struct Node *head) {
  int s = 0;
  struct Node *p = head;
  while (p) {
    s = s * 7 + p->value;
    struct Node *next = p->next;
    free(p);
    p = next;
  }
  return s;
}

static int cast_alias(uint32_t *bytes, int n) {
  uint8_t *as_bytes = (uint8_t *)bytes;
  int s = 0;
  for (int i = 0; i < n; ++i)
    s += as_bytes[i];
  return s;
}

int main(void) {
  int data[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  int stride_sum = sum_stride(data, 4, 3);
  int trace = matrix_trace(data, 3, 4);

  int a = 10, b = 20, c = 30;
  int *ptrs[3] = {&a, &b, &c};
  int walk = indirect_walk(ptrs, 3);

  int list_buf[5] = {5, 4, 3, 2, 1};
  struct Node *head = build_list(5, list_buf);
  int list_val = traverse_free(head);

  uint32_t word = 0x01020304;
  int alias = cast_alias(&word, 4);

  printf("ptrs:%d:%d:%d:%d:%d\n", stride_sum, trace, walk, list_val, alias);
  return 0;
}
