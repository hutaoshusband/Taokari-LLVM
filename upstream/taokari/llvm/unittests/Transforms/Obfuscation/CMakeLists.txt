set(LLVM_LINK_COMPONENTS
  Core
  Obfuscation
  Support
  )

add_llvm_unittest(ObfuscationTests
  OpaquePredicateTest.cpp
  )
