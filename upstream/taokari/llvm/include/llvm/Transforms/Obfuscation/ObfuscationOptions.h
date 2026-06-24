#ifndef OBFUSCATION_OBFUSCATIONOPTIONS_H
#define OBFUSCATION_OBFUSCATIONOPTIONS_H

#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/YAMLParser.h"

#include <utility>
#include <vector>

namespace llvm {

SmallVector<std::string> readAnnotate(Function *f);

class ObfOpt {
protected:
  uint32_t Enabled : 1;
  uint32_t Level : 3;
  std::string AttributeName;
  uint32_t MaxInsts = 0;
  uint32_t MaxBlocks = 0;
  uint32_t MaxAllocas = 0;
  // 101 means unset; valid configured probability is 0..100.
  uint32_t Probability = 101;
  uint32_t FunctionProbability = 101;
  uint32_t LoopCount = 0;
  // Minimum bit-width of a constant worth encrypting. Constants narrower
  // than this are skipped (cheap, low-value, blows up code size). 0 = use
  // the pass's built-in floor (currently 8 bits).
  uint32_t MinConstSize = 0;
  uint32_t MinStringLength = 0;
  std::vector<std::string> SkipStrings;
  uint32_t StringLocalStackDecrypt = 0;
  uint32_t StringHeapDecrypt = 0;
  uint32_t StringReencryptAfterUse = 0;
  uint32_t VolatileSeed = 1;
  uint32_t ConstDecryptorMBA = 0;
  uint32_t ReleaseStrip = 0;
  uint32_t RandomizeSections = 0;
  std::vector<std::string> ExportAllowlist;
  // StringEncryption Fortress (L3) knobs. Each is an independent bit so the
  // JSON profile can compose them; the pass only fires them when cse.level>=3.
  uint32_t StringDecryptorMBA = 0;       // MBA in shared decrypt loop
  uint32_t StringDecryptorFlattening = 0;// flatten the shared decryptor body
  uint32_t StringDecryptorIndirectCall = 0; // route decryptor call via page tbl
  uint32_t StringShardedPool = 0;        // split encrypted pool across N globals
  uint32_t StringFakePools = 0;          // emit junk-only decoy pools
  uint32_t StringPageTableAccess = 0;    // look up pool ptr via indgv page tbl
  uint32_t StringDelayedDecrypt = 0;     // decrypt-on-touch, scrub before ret

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

  void readOpt(const cl::opt<bool> &enableOpt,
               const cl::opt<uint32_t> &levelOpt) {
    readOpt(enableOpt);
    if (levelOpt.getNumOccurrences()) {
      setLevel(levelOpt.getValue());
    }
  }

  void setEnable(bool enabled) { this->Enabled = enabled; }

  void setLevel(uint32_t level) { this->Level = std::min<uint32_t>(level, 4); }

  bool isEnabled() const { return this->Enabled; }

  uint32_t level() const { return this->Level; }

  void setMaxInsts(uint32_t maxInsts) { this->MaxInsts = maxInsts; }

  uint32_t maxInsts() const { return this->MaxInsts; }

  void setMaxBlocks(uint32_t maxBlocks) { this->MaxBlocks = maxBlocks; }

  uint32_t maxBlocks() const { return this->MaxBlocks; }

  void setMaxAllocas(uint32_t maxAllocas) { this->MaxAllocas = maxAllocas; }

  uint32_t maxAllocas() const { return this->MaxAllocas; }

  void setProbability(uint32_t probability) {
    this->Probability = probability <= 100 ? probability : 101;
  }

  uint32_t probability() const { return this->Probability; }

  void setFunctionProbability(uint32_t probability) {
    this->FunctionProbability = probability <= 100 ? probability : 101;
  }

  uint32_t functionProbability() const { return this->FunctionProbability; }

  void setLoopCount(uint32_t loopCount) { this->LoopCount = loopCount; }

  uint32_t loopCount() const { return this->LoopCount; }

  void setMinConstSize(uint32_t minConstSize) {
    this->MinConstSize = minConstSize;
  }

  uint32_t minConstSize() const { return this->MinConstSize; }

  void setMinStringLength(uint32_t minStringLength) {
    this->MinStringLength = minStringLength;
  }

  uint32_t minStringLength() const { return this->MinStringLength; }

  void setSkipStrings(std::vector<std::string> skipStrings) {
    this->SkipStrings = std::move(skipStrings);
  }

  const std::vector<std::string> &skipStrings() const {
    return this->SkipStrings;
  }

  void setStringLocalStackDecrypt(bool localStackDecrypt) {
    this->StringLocalStackDecrypt = localStackDecrypt;
  }

  bool stringLocalStackDecrypt() const {
    return this->StringLocalStackDecrypt;
  }

  void setStringHeapDecrypt(bool heapDecrypt) {
    this->StringHeapDecrypt = heapDecrypt;
  }

  bool stringHeapDecrypt() const { return this->StringHeapDecrypt; }

  void setStringReencryptAfterUse(bool reencryptAfterUse) {
    this->StringReencryptAfterUse = reencryptAfterUse;
  }

  bool stringReencryptAfterUse() const {
    return this->StringReencryptAfterUse;
  }

  void setVolatileSeed(bool volatileSeed) { this->VolatileSeed = volatileSeed; }

  bool volatileSeed() const { return this->VolatileSeed; }

  void setConstDecryptorMBA(bool constDecryptorMBA) {
    this->ConstDecryptorMBA = constDecryptorMBA;
  }

  bool constDecryptorMBA() const { return this->ConstDecryptorMBA; }

  void setReleaseStrip(bool releaseStrip) { this->ReleaseStrip = releaseStrip; }

  bool releaseStrip() const { return this->ReleaseStrip; }

  void setRandomizeSections(bool randomizeSections) {
    this->RandomizeSections = randomizeSections;
  }

  bool randomizeSections() const { return this->RandomizeSections; }

  void setExportAllowlist(std::vector<std::string> exportAllowlist) {
    this->ExportAllowlist = std::move(exportAllowlist);
  }

  const std::vector<std::string> &exportAllowlist() const {
    return this->ExportAllowlist;
  }

#define TAOKARI_STRING_L3_ACCESSOR(Camel, Lower)                              \
  void setString##Camel(bool V) { this->String##Camel = V; }                   \
  bool string##Camel() const { return this->String##Camel; }
  TAOKARI_STRING_L3_ACCESSOR(DecryptorMBA, decryptorMba)
  TAOKARI_STRING_L3_ACCESSOR(DecryptorFlattening, decryptorFlattening)
  TAOKARI_STRING_L3_ACCESSOR(DecryptorIndirectCall, decryptorIndirectCall)
  TAOKARI_STRING_L3_ACCESSOR(ShardedPool, shardedPool)
  TAOKARI_STRING_L3_ACCESSOR(FakePools, fakePools)
  TAOKARI_STRING_L3_ACCESSOR(PageTableAccess, pageTableAccess)
  TAOKARI_STRING_L3_ACCESSOR(DelayedDecrypt, delayedDecrypt)
#undef TAOKARI_STRING_L3_ACCESSOR

  const std::string &attributeName() const { return this->AttributeName; }

  ObfOpt none() const {
    ObfOpt Result{false, 0, this->attributeName()};
    Result.setMaxInsts(MaxInsts);
    Result.setMaxBlocks(MaxBlocks);
    Result.setMaxAllocas(MaxAllocas);
    Result.setProbability(Probability);
    Result.setFunctionProbability(FunctionProbability);
    Result.setLoopCount(LoopCount);
    Result.setMinConstSize(MinConstSize);
    Result.setMinStringLength(MinStringLength);
    Result.setSkipStrings(SkipStrings);
    Result.setStringLocalStackDecrypt(StringLocalStackDecrypt);
    Result.setStringHeapDecrypt(StringHeapDecrypt);
    Result.setStringReencryptAfterUse(StringReencryptAfterUse);
    Result.setVolatileSeed(VolatileSeed);
    Result.setConstDecryptorMBA(ConstDecryptorMBA);
    Result.setReleaseStrip(ReleaseStrip);
    Result.setRandomizeSections(RandomizeSections);
    Result.setExportAllowlist(ExportAllowlist);
    Result.setStringDecryptorMBA(StringDecryptorMBA);
    Result.setStringDecryptorFlattening(StringDecryptorFlattening);
    Result.setStringDecryptorIndirectCall(StringDecryptorIndirectCall);
    Result.setStringShardedPool(StringShardedPool);
    Result.setStringFakePools(StringFakePools);
    Result.setStringPageTableAccess(StringPageTableAccess);
    Result.setStringDelayedDecrypt(StringDelayedDecrypt);
    return Result;
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
  std::shared_ptr<ObfOpt> MbaOpt = nullptr;
  std::shared_ptr<ObfOpt> OutlineOpt = nullptr;
  std::shared_ptr<ObfOpt> RttiOpt = nullptr;
  std::shared_ptr<ObfOpt> MetaOpt = nullptr;
  std::shared_ptr<ObfOpt> VmpOpt = nullptr;

  SmallString<32> RandomSeed;

public:
  SmallVector<std::shared_ptr<ObfOpt>> getAllOpt() const {
    SmallVector<std::shared_ptr<ObfOpt>, 10> allOpt;
    allOpt.push_back(IndBrOpt);
    allOpt.push_back(ICallOpt);
    allOpt.push_back(IndGvOpt);
    allOpt.push_back(FlaOpt);
    allOpt.push_back(CseOpt);
    allOpt.push_back(CieOpt);
    allOpt.push_back(CfeOpt);
    allOpt.push_back(BcfOpt);
    allOpt.push_back(MbaOpt);
    allOpt.push_back(OutlineOpt);
    allOpt.push_back(RttiOpt);
    allOpt.push_back(MetaOpt);
    allOpt.push_back(VmpOpt);
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
                     const std::shared_ptr<ObfOpt> &mbaOpt,
                     const std::shared_ptr<ObfOpt> &outlineOpt,
                     const std::shared_ptr<ObfOpt> &rttiOpt,
                     const std::shared_ptr<ObfOpt> &metaOpt,
                     const std::shared_ptr<ObfOpt> &vmpOpt) {
    this->IndBrOpt = indBrOpt;
    this->ICallOpt = iCallOpt;
    this->IndGvOpt = indGvOpt;
    this->FlaOpt = flaOpt;
    this->CseOpt = cseOpt;
    this->CieOpt = cieOpt;
    this->CfeOpt = cfeOpt;
    this->BcfOpt = bcfOpt;
    this->MbaOpt = mbaOpt;
    this->OutlineOpt = outlineOpt;
    this->RttiOpt = rttiOpt;
    this->MetaOpt = metaOpt;
    this->VmpOpt = vmpOpt;
  }

  ObfuscationOptions()
      : ObfuscationOptions{std::make_shared<ObfOpt>("indbr"),
                           std::make_shared<ObfOpt>("icall"),
                           std::make_shared<ObfOpt>("indgv"),
                           std::make_shared<ObfOpt>("fla"),
                           std::make_shared<ObfOpt>("cse"),
                           std::make_shared<ObfOpt>("cie"),
                           std::make_shared<ObfOpt>("cfe"),
                           std::make_shared<ObfOpt>("bcf"),
                           std::make_shared<ObfOpt>("mba"),
                           std::make_shared<ObfOpt>("outline"),
                           std::make_shared<ObfOpt>("rtti"),
                           std::make_shared<ObfOpt>("meta"),
                           std::make_shared<ObfOpt>("vmp")} {}

  auto indBrOpt() const { return IndBrOpt; }

  auto iCallOpt() const { return ICallOpt; }

  auto indGvOpt() const { return IndGvOpt; }

  auto flaOpt() const { return FlaOpt; }

  auto cseOpt() const { return CseOpt; }

  auto cieOpt() const { return CieOpt; }

  auto cfeOpt() const { return CfeOpt; }

  auto bcfOpt() const { return BcfOpt; }

  auto mbaOpt() const { return MbaOpt; }

  auto outlineOpt() const { return OutlineOpt; }

  auto rttiOpt() const { return RttiOpt; }

  auto metaOpt() const { return MetaOpt; }

  auto vmpOpt() const { return VmpOpt; }

  auto &randomSeed() { return RandomSeed; }

  static std::shared_ptr<ObfuscationOptions>
  readConfigFile(const Twine &FileName);

  static ObfOpt toObfuscate(const std::shared_ptr<ObfOpt> &option, Function *f);
};

} // namespace llvm

#endif
