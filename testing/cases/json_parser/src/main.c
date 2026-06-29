#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const char *DOC =
    "{\"name\":\"taokari\",\"version\":42,\"flags\":[true,false,null],"
    "\"nested\":{\"a\":1,\"b\":2.5},\"items\":[1,2,3,4,5],\"ok\":true}";

static const char *p;

static void skip_ws(void) {
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    ++p;
}

struct Stats {
  int objects;
  int arrays;
  int strings;
  int numbers;
  int bools;
  int nulls;
  uint32_t number_sum;
};

static void parse_value(struct Stats *s);

static void parse_string(struct Stats *s) {
  ++p;
  while (*p && *p != '"') {
    if (*p == '\\' && p[1])
      ++p;
    ++p;
  }
  if (*p == '"')
    ++p;
  ++s->strings;
}

static void parse_number(struct Stats *s) {
  uint32_t int_part = 0;
  int neg = 0;
  if (*p == '-') { neg = 1; ++p; }
  while (*p >= '0' && *p <= '9') {
    int_part = int_part * 10 + (uint32_t)(*p - '0');
    ++p;
  }
  if (*p == '.') {
    ++p;
    while (*p >= '0' && *p <= '9')
      ++p;
  }
  if (*p == 'e' || *p == 'E') {
    ++p;
    if (*p == '+' || *p == '-')
      ++p;
    while (*p >= '0' && *p <= '9')
      ++p;
  }
  s->number_sum += neg ? -((int)int_part) : int_part;
  ++s->numbers;
}

static void parse_array(struct Stats *s) {
  ++p;
  ++s->arrays;
  skip_ws();
  if (*p == ']') { ++p; return; }
  for (;;) {
    parse_value(s);
    skip_ws();
    if (*p == ',') { ++p; skip_ws(); continue; }
    if (*p == ']') { ++p; return; }
    return;
  }
}

static void parse_object(struct Stats *s) {
  ++p;
  ++s->objects;
  skip_ws();
  if (*p == '}') { ++p; return; }
  for (;;) {
    skip_ws();
    parse_string(s);
    skip_ws();
    if (*p == ':') ++p;
    skip_ws();
    parse_value(s);
    skip_ws();
    if (*p == ',') { ++p; continue; }
    if (*p == '}') { ++p; return; }
    return;
  }
}

static void parse_value(struct Stats *s) {
  skip_ws();
  char c = *p;
  if (c == '{') parse_object(s);
  else if (c == '[') parse_array(s);
  else if (c == '"') parse_string(s);
  else if (c == '-' || (c >= '0' && c <= '9')) parse_number(s);
  else if (strncmp(p, "true", 4) == 0) { p += 4; ++s->bools; }
  else if (strncmp(p, "false", 5) == 0) { p += 5; ++s->bools; }
  else if (strncmp(p, "null", 4) == 0) { p += 4; ++s->nulls; }
}

int main(void) {
  p = DOC;
  struct Stats s = {0, 0, 0, 0, 0, 0, 0};
  parse_value(&s);
  printf("json:%d:%d:%d:%d:%d:%d:%u\n",
         s.objects, s.arrays, s.strings, s.numbers,
         s.bools, s.nulls, s.number_sum);
  return 0;
}
