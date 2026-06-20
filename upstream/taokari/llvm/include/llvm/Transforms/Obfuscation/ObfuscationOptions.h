#ifndef OBFUSCATION_OBFUSCATIONOPTIONS_H
#define OBFUSCATION_OBFUSCATIONOPTIONS_H

#include "llvm/Support/YAMLParser.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/ADT/SmallString.h"


namespace llvm {

SmallVector<std::string> readAnnotate(Function *f);

class ObfOpt {
protected:
  uint32_t    Enabled : 1;
  uint32_t    Level   : 3;
  std::string AttributeName;
  uint32_t    MaxInsts = 0;
  uint32_t    MaxBlocks = 0;
  uint32_t    MaxAllocas = 0;
  // 101 means unset; valid configured probability is 0..100.
  uint32_t    Probability = 101;
  uint32_t    LoopCount = 0;
  // Minimum bit-width of a constant worth encrypting. Constants narrower
  // than this are skipped (cheap, low-value, blows up code size). 0 = use
  // the pass's built-in floor (currently 8 bits).
  uint32_t    MinConstSize = 0;

public:
  ObfOpt(bool enable, uint32_t level, const std::string &attributeName) {
    this->Enabled = enable;
    this->Level = std::min<uint32_t>(level, 4);
    this->AttributeName = attributeName;
  }

  ObfOpt(const std::string &attributeName) {
    this->Enabled = false;
    this->Level = 0;
    this->AttributeName = attributeName;
  }

  void readOpt(const cl::opt<bool> &enableOpt) {
    if (enableOpt.getNumOccurrences()) {
      Enabled = enableOpt.getValue();
    }
  }

  void readOpt(const cl::opt<bool> &    enableOpt,
               const cl::opt<uint32_t> &levelOpt) {
    readOpt(enableOpt);
    if (levelOpt.getNumOccurrences()) {
      setLevel(levelOpt.getValue());
    }
  }

  void setEnable(bool enabled) {
    this->Enabled = enabled;
  }

  void setLevel(uint32_t level) {
    this->Level = std::min<uint32_t>(level, 4);
  }

  bool isEnabled() const {
    return this->Enabled;
  }

  uint32_t level() const {
    return this->Level;
  }

  void setMaxInsts(uint32_t maxInsts) {
    this->MaxInsts = maxInsts;
  }

  uint32_t maxInsts() const {
    return this->MaxInsts;
  }

  void setMaxBlocks(uint32_t maxBlocks) {
    this->MaxBlocks = maxBlocks;
  }

  uint32_t maxBlocks() const {
    return this->MaxBlocks;
  }

  void setMaxAllocas(uint32_t maxAllocas) {
    this->MaxAllocas = maxAllocas;
  }

  uint32_t maxAllocas() const {
    return this->MaxAllocas;
  }

  void setProbability(uint32_t probability) {
    this->Probability = std::min<uint32_t>(probability, 100);
  }

  uint32_t probability() const {
    return this->Probability;
  }

  void setLoopCount(uint32_t loopCount) {
    this->LoopCount = loopCount;
  }

  uint32_t loopCount() const {
    return this->LoopCount;
  }

  void setMinConstSize(uint32_t minConstSize) {
    this->MinConstSize = minConstSize;
  }

  uint32_t minConstSize() const {
    return this->MinConstSize;
  }

  const std::string &attributeName() const {
    return this->AttributeName;
  }

  ObfOpt none() const {
    return ObfOpt{false, 0, this->attributeName()};
  }

};

class ObfuscationOptions {
protected:
  std::shared_ptr<ObfOpt> IndBrOpt = nullptr;
  std::shared_ptr<ObfOpt> ICallOpt = nullptr;
  std::shared_ptr<ObfOpt> IndGvOpt = nullptr;
  std::shared_ptr<ObfOpt> FlaOpt = nullptr;
  std::shared_ptr<ObfOpt> CseOpt = nullptr;
  std::shared_ptr<ObfOpt> CieOpt = nullptr;
  std::shared_ptr<ObfOpt> CfeOpt = nullptr;
  std::shared_ptr<ObfOpt> BcfOpt = nullptr;
  std::shared_ptr<ObfOpt> RttiOpt = nullptr;

  SmallString<32> RandomSeed;

public:
  SmallVector<std::shared_ptr<ObfOpt>> getAllOpt() const {
    SmallVector<std::shared_ptr<ObfOpt>, 9> allOpt;
    allOpt.push_back(IndBrOpt);
    allOpt.push_back(ICallOpt);
    allOpt.push_back(IndGvOpt);
    allOpt.push_back(FlaOpt);
    allOpt.push_back(CseOpt);
    allOpt.push_back(CieOpt);
    allOpt.push_back(CfeOpt);
    allOpt.push_back(BcfOpt);
    allOpt.push_back(RttiOpt);
    return allOpt;
  }

  ObfuscationOptions(const std::shared_ptr<ObfOpt> &indBrOpt,
                     const std::shared_ptr<ObfOpt> &iCallOpt,
                     const std::shared_ptr<ObfOpt> &indGvOpt,
                     const std::shared_ptr<ObfOpt> &flaOpt,
                     const std::shared_ptr<ObfOpt> &cseOpt,
                     const std::shared_ptr<ObfOpt> &cieOpt,
                     const std::shared_ptr<ObfOpt> &cfeOpt,
                     const std::shared_ptr<ObfOpt> &bcfOpt,
                     const std::shared_ptr<ObfOpt> &rttiOpt) {
    this->IndBrOpt = indBrOpt;
    this->ICallOpt = iCallOpt;
    this->IndGvOpt = indGvOpt;
    this->FlaOpt = flaOpt;
    this->CseOpt = cseOpt;
    this->CieOpt = cieOpt;
    this->CfeOpt = cfeOpt;
    this->BcfOpt = bcfOpt;
    this->RttiOpt = rttiOpt;
  }

  ObfuscationOptions() : ObfuscationOptions{
                           std::make_shared<ObfOpt>("indbr"),
                           std::make_shared<ObfOpt>("icall"),
                           std::make_shared<ObfOpt>("indgv"),
                           std::make_shared<ObfOpt>("fla"),
                           std::make_shared<ObfOpt>("cse"),
                           std::make_shared<ObfOpt>("cie"),
                           std::make_shared<ObfOpt>("cfe"),
                           std::make_shared<ObfOpt>("bcf"),
                           std::make_shared<ObfOpt>("rtti")
                       } {}

  auto indBrOpt() const {
    return IndBrOpt;
  }

  auto iCallOpt() const {
    return ICallOpt;
  }

  auto indGvOpt() const {
    return IndGvOpt;
  }

  auto flaOpt() const {
    return FlaOpt;
  }

  auto cseOpt() const {
    return CseOpt;
  }

  auto cieOpt() const {
    return CieOpt;
  }

  auto cfeOpt() const {
    return CfeOpt;
  }

  auto bcfOpt() const {
    return BcfOpt;
  }

  auto rttiOpt() const {
    return RttiOpt;
  }

  auto &randomSeed() {
    return RandomSeed;
  }

  static std::shared_ptr<ObfuscationOptions> readConfigFile(
      const Twine &FileName);

  static ObfOpt toObfuscate(const std::shared_ptr<ObfOpt> &option, Function *f);

};

}

#endif
