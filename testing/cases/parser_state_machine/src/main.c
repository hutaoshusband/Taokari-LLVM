#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const char *INPUT = "(1+2)*3-(4-5)*6+7";

static const char *p;

static void reset(const char *s) { p = s; }

static int peek(void) { return *p ? *p : -1; }
static int next(void) { return *p ? *p++ : -1; }
static void skip_ws(void) { while (*p == ' ' || *p == '\t') ++p; }

static int parse_expr(void);

static int parse_number(void) {
  skip_ws();
  int v = 0;
  while (*p >= '0' && *p <= '9') {
    v = v * 10 + (*p - '0');
    ++p;
  }
  return v;
}

static int parse_factor(void) {
  skip_ws();
  if (peek() == '(') {
    next();
    int v = parse_expr();
    if (peek() == ')')
      next();
    return v;
  }
  return parse_number();
}

static int parse_term(void) {
  int v = parse_factor();
  for (;;) {
    skip_ws();
    int c = peek();
    if (c == '*') { next(); v *= parse_factor(); }
    else if (c == '/') { next(); int d = parse_factor(); v = d ? v / d : 0; }
    else break;
  }
  return v;
}

static int parse_expr(void) {
  int v = parse_term();
  for (;;) {
    skip_ws();
    int c = peek();
    if (c == '+') { next(); v += parse_term(); }
    else if (c == '-') { next(); v -= parse_term(); }
    else break;
  }
  return v;
}

enum State { S_START, S_SIGN, S_INT, S_FRAC, S_EXP_SIGN, S_EXP, S_DONE, S_ERR };

static int number_state_machine(const char *s) {
  enum State st = S_START;
  int seen_digit = 0;
  for (const char *q = s; *q; ++q) {
    char c = *q;
    switch (st) {
      case S_START:
        if (c == '+' || c == '-') st = S_SIGN;
        else if (c >= '0' && c <= '9') { st = S_INT; seen_digit = 1; }
        else return 0;
        break;
      case S_SIGN:
        if (c >= '0' && c <= '9') { st = S_INT; seen_digit = 1; }
        else return 0;
        break;
      case S_INT:
        if (c >= '0' && c <= '9') seen_digit = 1;
        else if (c == '.') st = S_FRAC;
        else if (c == 'e' || c == 'E') st = S_EXP_SIGN;
        else return seen_digit ? -1 : 0;
        break;
      case S_FRAC:
        if (c >= '0' && c <= '9') seen_digit = 1;
        else if (c == 'e' || c == 'E') st = S_EXP_SIGN;
        else return seen_digit ? -1 : 0;
        break;
      case S_EXP_SIGN:
        if (c == '+' || c == '-') st = S_EXP;
        else if (c >= '0' && c <= '9') { st = S_EXP; seen_digit = 1; }
        else return 0;
        break;
      case S_EXP:
        if (c >= '0' && c <= '9') seen_digit = 1;
        else return seen_digit ? -1 : 0;
        break;
      default: return 0;
    }
  }
  return seen_digit ? 1 : 0;
}

int main(void) {
  reset(INPUT);
  int result = parse_expr();
  int valid_full = number_state_machine("-12.5e3");
  int valid_int = number_state_machine("42");
  int invalid = number_state_machine("3.5.5");
  int partial = number_state_machine("3.5x");
  printf("parser:%d:%d:%d:%d:%d\n", result, valid_full, valid_int, invalid, partial);
  return 0;
}
