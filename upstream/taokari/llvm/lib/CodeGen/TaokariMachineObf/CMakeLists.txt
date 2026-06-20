add_llvm_component_library(LLVMTaokariMachineObf
  TaokariMachineObf.cpp

  COMPONENT_NAME
  TaokariMachineObf

  ADDITIONAL_HEADER_DIRS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/CodeGen

  DEPENDS
  intrinsics_gen

  LINK_COMPONENTS
  CodeGen
  CodeGenTypes
  Core
  MC
  Support
  Target
  TargetParser
  )
