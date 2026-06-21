// Control-flow & loop fixture.
// Exercises nested if/switch/for/while/do-while, break/continue/goto/return
// and the comma operator, plus recursive factorial and a recursive binary
// tree built with malloc. The switch dispatch, the goto re-entry and the
// recursive calls all become indirect branches / flattened state machines
// under the obfuscator, which is what this case stresses.
//
// Target: Flattening, IndirectBranch, LegacyLowerSwitch, BCF opaque
// predicates around every branch.
#include <cstdint>
#include <cstdio>
#include <cstdlib>

__declspec(noinline) int64_t factorial(int n) {
  if (n <= 1) return 1;
  return static_cast<int64_t>(n) * factorial(n - 1);
}

__declspec(noinline) int switch_dispatch(int v) {
  int acc = 0;
  for (int i = 0; i < 5; ++i) {
    switch ((v + i) % 6) {
    case 0: acc += 1; break;
    case 1: acc += 2; continue;  // skip post-increment branch
    case 2: acc += 4; break;
    case 3: acc += 8; break;
    case 4: acc -= 1; break;
    default: acc += 16; break;
    }
    acc ^= 0x55;
  }
  return acc;
}

__declspec(noinline) int loop_break_continue(int n) {
  int sum = 0;
  for (int i = 0; i < n; ++i) {
    if (i % 7 == 0) continue;
    if (i == 23) break;
    sum += i, sum ^= 0x33;  // comma operator in expression
  }
  return sum;
}

__declspec(noinline) int while_dowhile(int seed) {
  int a = seed;
  int rounds = 0;
  while (a > 1) {
    if (a & 1) a = 3 * a + 1;
    else a >>= 1;
    ++rounds;
    if (rounds > 1000) return -1;
  }
  // do/while with a goto escape hatch in the middle.
  int b = seed;
  int prod = 1;
start:
  if (b <= 0) goto done;
  do {
    prod *= (b & 3) + 1;
    b -= 2;
  } while (b > 0);
done:
  return rounds * 1000 + prod;
}

struct Node {
  int value;
  Node *left;
  Node *right;
};

__declspec(noinline) Node *make_node(int v) {
  Node *n = static_cast<Node *>(malloc(sizeof(Node)));
  n->value = v;
  n->left = n->right = nullptr;
  return n;
}

__declspec(noinline) Node *insert(Node *root, int v) {
  if (!root) return make_node(v);
  if (v < root->value) root->left = insert(root->left, v);
  else if (v > root->value) root->right = insert(root->right, v);
  return root;
}

__declspec(noinline) int inorder_sum(const Node *root) {
  if (!root) return 0;
  return inorder_sum(root->left) + root->value + inorder_sum(root->right);
}

__declspec(noinline) void free_tree(Node *root) {
  if (!root) return;
  free_tree(root->left);
  free_tree(root->right);
  free(root);
}

int main() {
  int64_t f = factorial(10);          // 3628800
  int sw = switch_dispatch(11);
  int lb = loop_break_continue(40);
  int wd = while_dowhile(27);

  // Build a small BST from non-trivially-ordered keys so the recursive
  // insert/inorder path is exercised on every obfuscation axis.
  int keys[] = {50, 30, 70, 20, 40, 60, 80, 10, 35, 65};
  Node *root = nullptr;
  for (int k : keys) root = insert(root, k);
  int tree_sum = inorder_sum(root);
  free_tree(root);

  std::printf("ctrlflow:%lld:%d:%d:%d:%d\n",
              static_cast<long long>(f), sw, lb, wd, tree_sum);
  return 0;
}
