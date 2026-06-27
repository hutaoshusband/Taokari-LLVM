#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"

using namespace llvm;

namespace llvm {

static void reportConfigError(const Twine &FileName, const Twine &Message) {
  report_fatal_error("Taokari config error in " + FileName + ": " + Message);
}

SmallVector<std::string> readAnnotate(Function *f) {
  SmallVector<std::string> annotations;

  auto *Annotations =
      f->getParent()->getGlobalVariable("llvm.global.annotations");
  auto *C = dyn_cast_or_null<Constant>(Annotations);
  if (!C || C->getNumOperands() != 1)
    return annotations;

  C = cast<Constant>(C->getOperand(0));

  // Iterate over all entries in C and attach !annotation metadata to suitable
  // entries.
  for (auto &Op : C->operands()) {
    // Look at the operands to check if we can use the entry to generate
    // !annotation metadata.
    auto *OpC = dyn_cast<ConstantStruct>(&Op);
    if (!OpC || OpC->getNumOperands() < 2)
      continue;
    auto *Fn = dyn_cast<Function>(OpC->getOperand(0)->stripPointerCasts());
    if (Fn != f)
      continue;
    auto *StrC = dyn_cast<GlobalValue>(OpC->getOperand(1)->stripPointerCasts());
    if (!StrC)
      continue;
    auto *StrData = dyn_cast<ConstantDataSequential>(StrC->getOperand(0));
    if (!StrData)
      continue;
    annotations.emplace_back(StrData->getAsString());
  }
  return annotations;
}

std::shared_ptr<ObfuscationOptions>
ObfuscationOptions::readConfigFile(const Twine &FileName) {

  std::shared_ptr<ObfuscationOptions> result =
      std::make_shared<ObfuscationOptions>();
  if (FileName.str().empty()) {
    return result;
  }
  if (!sys::fs::exists(FileName)) {
    reportConfigError(FileName, "file does not exist");
  }

  auto BufOrErr = MemoryBuffer::getFileOrSTDIN(FileName);
  if (const auto ErrCode = BufOrErr.getError()) {
    reportConfigError(FileName, "cannot read file: " + ErrCode.message());
  }

  const auto &buf = *BufOrErr.get();
  llvm::SourceMgr sm;

  auto jsonRoot = json::parse(buf.getBuffer());
  if (!jsonRoot) {
    reportConfigError(FileName,
                      "invalid JSON: " + toString(jsonRoot.takeError()));
  }
  auto rootObj = jsonRoot->getAsObject();
  if (!rootObj) {
    reportConfigError(FileName, "JSON root must be an object");
  }

  auto procObj =
      [&FileName](const std::shared_ptr<ObfOpt> &obfOpt,
                  const detail::DenseMapPair<json::ObjectKey, json::Value> &obj)
      -> bool {
    auto procOptValue = [&FileName](const std::shared_ptr<ObfOpt> &obfOpt,
                                    const json::Value &value) {
      auto optObj = value.getAsObject();
      if (!optObj) {
        reportConfigError(FileName,
                          obfOpt->attributeName() + " must be an object");
      }
      if (const auto *enableValue = optObj->get("enable")) {
        auto enable = enableValue->getAsBoolean();
        if (!enable) {
          reportConfigError(FileName, obfOpt->attributeName() +
                                          ".enable must be boolean");
        }
        obfOpt->setEnable(*enable);
      }
      if (const auto *levelValue = optObj->get("level")) {
        auto level = levelValue->getAsInteger();
        if (!level) {
          reportConfigError(FileName,
                            obfOpt->attributeName() + ".level must be integer");
        }
        obfOpt->setLevel(static_cast<uint32_t>(*level));
      }
      if (const auto *maxInstsValue = optObj->get("maxInsts")) {
        auto maxInsts = maxInstsValue->getAsInteger();
        if (!maxInsts || *maxInsts < 0) {
          reportConfigError(FileName,
                            obfOpt->attributeName() +
                                ".maxInsts must be non-negative integer");
        }
        obfOpt->setMaxInsts(static_cast<uint32_t>(*maxInsts));
      }
      if (const auto *maxBlocksValue = optObj->get("maxBlocks")) {
        auto maxBlocks = maxBlocksValue->getAsInteger();
        if (!maxBlocks || *maxBlocks < 0) {
          reportConfigError(FileName,
                            obfOpt->attributeName() +
                                ".maxBlocks must be non-negative integer");
        }
        obfOpt->setMaxBlocks(static_cast<uint32_t>(*maxBlocks));
      }
      if (const auto *maxAllocasValue = optObj->get("maxAllocas")) {
        auto maxAllocas = maxAllocasValue->getAsInteger();
        if (!maxAllocas || *maxAllocas < 0) {
          reportConfigError(FileName,
                            obfOpt->attributeName() +
                                ".maxAllocas must be non-negative integer");
        }
        obfOpt->setMaxAllocas(static_cast<uint32_t>(*maxAllocas));
      }
      if (const auto *probabilityValue = optObj->get("probability")) {
        auto probability = probabilityValue->getAsInteger();
        if (!probability || *probability < 0 || *probability > 100) {
          reportConfigError(FileName,
                            obfOpt->attributeName() +
                                ".probability must be integer from 0 to 100");
        }
        obfOpt->setProbability(static_cast<uint32_t>(*probability));
      }
      if (const auto *probabilityValue = optObj->get("functionProbability")) {
        auto probability = probabilityValue->getAsInteger();
        if (!probability || *probability < 0 || *probability > 100) {
          reportConfigError(
              FileName, obfOpt->attributeName() +
                            ".functionProbability must be integer from 0 to 100");
        }
        obfOpt->setFunctionProbability(static_cast<uint32_t>(*probability));
      }
      if (const auto *loopCountValue = optObj->get("loopCount")) {
        auto loopCount = loopCountValue->getAsInteger();
        if (!loopCount || *loopCount < 0) {
          reportConfigError(FileName,
                            obfOpt->attributeName() +
                                ".loopCount must be non-negative integer");
        }
        obfOpt->setLoopCount(static_cast<uint32_t>(*loopCount));
      }
      if (const auto *minConstSizeValue = optObj->get("minConstSize")) {
        auto minConstSize = minConstSizeValue->getAsInteger();
        if (!minConstSize || *minConstSize < 0) {
          reportConfigError(FileName,
                            obfOpt->attributeName() +
                                ".minConstSize must be non-negative integer");
        }
        obfOpt->setMinConstSize(static_cast<uint32_t>(*minConstSize));
      }
      if (const auto *minStringLengthValue = optObj->get("minStringLength")) {
        auto minStringLength = minStringLengthValue->getAsInteger();
        if (!minStringLength || *minStringLength < 0) {
          reportConfigError(
              FileName, obfOpt->attributeName() +
                            ".minStringLength must be non-negative integer");
        }
        obfOpt->setMinStringLength(static_cast<uint32_t>(*minStringLength));
      }
      if (const auto *skipStringsValue = optObj->get("skipStrings")) {
        auto skipStringsArray = skipStringsValue->getAsArray();
        if (!skipStringsArray) {
          reportConfigError(FileName,
                            obfOpt->attributeName() +
                                ".skipStrings must be an array of strings");
        }
        std::vector<std::string> skipStrings;
        for (const auto &skipStringValue : *skipStringsArray) {
          auto skipString = skipStringValue.getAsString();
          if (!skipString) {
            reportConfigError(FileName,
                              obfOpt->attributeName() +
                                  ".skipStrings must be an array of strings");
          }
          skipStrings.emplace_back(skipString->str());
        }
        obfOpt->setSkipStrings(std::move(skipStrings));
      }
      if (const auto *localStackValue = optObj->get("localStackDecrypt")) {
        auto localStack = localStackValue->getAsBoolean();
        if (!localStack) {
          reportConfigError(FileName, obfOpt->attributeName() +
                                          ".localStackDecrypt must be boolean");
        }
        obfOpt->setStringLocalStackDecrypt(*localStack);
      }
      if (const auto *heapDecryptValue = optObj->get("heapDecrypt")) {
        auto heapDecrypt = heapDecryptValue->getAsBoolean();
        if (!heapDecrypt) {
          reportConfigError(FileName, obfOpt->attributeName() +
                                          ".heapDecrypt must be boolean");
        }
        obfOpt->setStringHeapDecrypt(*heapDecrypt);
      }
      if (const auto *reencryptValue = optObj->get("reencryptAfterUse")) {
        auto reencrypt = reencryptValue->getAsBoolean();
        if (!reencrypt) {
          reportConfigError(FileName, obfOpt->attributeName() +
                                          ".reencryptAfterUse must be boolean");
        }
        obfOpt->setStringReencryptAfterUse(*reencrypt);
      }
      if (const auto *volatileSeedValue = optObj->get("volatileSeed")) {
        auto volatileSeed = volatileSeedValue->getAsBoolean();
        if (!volatileSeed) {
          reportConfigError(FileName, obfOpt->attributeName() +
                                          ".volatileSeed must be boolean");
        }
        obfOpt->setVolatileSeed(*volatileSeed);
      }
      if (const auto *decryptorMbaValue = optObj->get("decryptorMba")) {
        auto decryptorMba = decryptorMbaValue->getAsBoolean();
        if (!decryptorMba) {
          reportConfigError(FileName, obfOpt->attributeName() +
                                          ".decryptorMba must be boolean");
        }
        obfOpt->setConstDecryptorMBA(*decryptorMba);
      }
      if (const auto *releaseStripValue = optObj->get("releaseStrip")) {
        auto releaseStrip = releaseStripValue->getAsBoolean();
        if (!releaseStrip) {
          reportConfigError(FileName, obfOpt->attributeName() +
                                          ".releaseStrip must be boolean");
        }
        obfOpt->setReleaseStrip(*releaseStrip);
      }
      if (const auto *randomizeSectionsValue =
              optObj->get("randomizeSections")) {
        auto randomizeSections = randomizeSectionsValue->getAsBoolean();
        if (!randomizeSections) {
          reportConfigError(FileName, obfOpt->attributeName() +
                                          ".randomizeSections must be boolean");
        }
        obfOpt->setRandomizeSections(*randomizeSections);
      }
      if (const auto *allowlistValue = optObj->get("exportAllowlist")) {
        auto allowlistArray = allowlistValue->getAsArray();
        if (!allowlistArray) {
          reportConfigError(FileName, obfOpt->attributeName() +
                                          ".exportAllowlist must be array");
        }
        std::vector<std::string> allowlist;
        for (const auto &allowlistItem : *allowlistArray) {
          auto name = allowlistItem.getAsString();
          if (!name) {
            reportConfigError(FileName, obfOpt->attributeName() +
                                            ".exportAllowlist must be strings");
          }
          allowlist.emplace_back(name->str());
        }
        obfOpt->setExportAllowlist(std::move(allowlist));
      }
      auto readStringL3Bool = [&](const char *Key,
                                  void (ObfOpt::*Setter)(bool)) {
        if (const auto *V = optObj->get(Key)) {
          auto B = V->getAsBoolean();
          if (!B) {
            reportConfigError(FileName, obfOpt->attributeName() + Twine(".") +
                                            Key + " must be boolean");
          }
          ((*obfOpt).*Setter)(*B);
        }
      };
      readStringL3Bool("stringDecryptorMBA", &ObfOpt::setStringDecryptorMBA);
      readStringL3Bool("stringDecryptorFlattening",
                       &ObfOpt::setStringDecryptorFlattening);
      readStringL3Bool("stringDecryptorIndirectCall",
                       &ObfOpt::setStringDecryptorIndirectCall);
      readStringL3Bool("stringShardedPool", &ObfOpt::setStringShardedPool);
      readStringL3Bool("stringFakePools", &ObfOpt::setStringFakePools);
      readStringL3Bool("stringPageTableAccess",
                       &ObfOpt::setStringPageTableAccess);
      readStringL3Bool("stringDelayedDecrypt",
                       &ObfOpt::setStringDelayedDecrypt);

      // Validate keys: warn on unknown keys inside this pass's config
      // object so typos surface instead of silently being ignored. The
      // set is the union of all keys read above across every pass; a
      // pass that does not consume a given key simply ignores the
      // warning target.
      static const StringSet<> KnownKeys = {
          "enable",          "level",
          "maxInsts",        "maxBlocks",
          "maxAllocas",      "probability",
          "functionProbability",
          "loopCount",       "minConstSize",
          "minStringLength", "skipStrings",
          "localStackDecrypt",
          "heapDecrypt",     "reencryptAfterUse",
          "volatileSeed",    "decryptorMba",
          "releaseStrip",    "randomizeSections",
          "exportAllowlist",
          "stringDecryptorMBA",
          "stringDecryptorFlattening",
          "stringDecryptorIndirectCall",
          "stringShardedPool",
          "stringFakePools",
          "stringPageTableAccess",
          "stringDelayedDecrypt"};
      for (const auto &KV : *optObj) {
        if (!KnownKeys.contains(KV.getFirst())) {
          llvm::errs() << "warning: unknown taokari config key: "
                       << obfOpt->attributeName() << "."
                       << KV.getFirst().str() << '\n';
        }
      }
    };

    std::string key = obj.getFirst().str();
    auto &value = obj.getSecond();

    if (key == obfOpt->attributeName()) {
      procOptValue(obfOpt, value);
      return true;
    }
    return false;
  };

  SmallVector<std::shared_ptr<ObfOpt>> allOpt = result->getAllOpt();
  for (auto &obj : *rootObj) {
    if (obj.getFirst().str() == "randomSeed") {
      if (auto objStr = obj.getSecond().getAsString()) {
        const auto &seedStr = objStr.value();
        auto &seed = result->randomSeed();
        seed = seedStr;
        seed.resize(32, 0);
      } else {
        reportConfigError(FileName, "randomSeed must be string");
      }
      continue;
    }
    if (obj.getFirst().str() == "vm") {
      auto *VmObj = obj.getSecond().getAsObject();
      if (!VmObj) {
        reportConfigError(FileName, "vm must be an object");
      }
      if (const auto *AntiTraceValue = VmObj->get("anti_trace")) {
        auto AntiTrace = AntiTraceValue->getAsString();
        if (!AntiTrace) {
          reportConfigError(FileName, "vm.anti_trace must be string");
        }
        if (*AntiTrace == "off") {
          result->setVmpAntiTraceMode(1);
        } else if (*AntiTrace == "light") {
          result->setVmpAntiTraceMode(2);
        } else if (*AntiTrace == "strong") {
          result->setVmpAntiTraceMode(3);
        } else {
          reportConfigError(FileName,
                            "vm.anti_trace must be off, light or strong");
        }
      }
      for (const auto &KV : *VmObj) {
        if (KV.getFirst() != "anti_trace") {
          llvm::errs() << "warning: unknown taokari config key: vm."
                       << KV.getFirst().str() << '\n';
        }
      }
      continue;
    }
    bool objHit = false;
    for (auto &opt : allOpt) {
      if ((objHit = procObj(opt, obj))) {
        break;
      }
    }
    if (!objHit) {
      llvm::errs() << "warning: unknown hikari config node: "
                   << obj.getFirst().str() << '\n';
    }
  }
  return result;
}

ObfOpt ObfuscationOptions::toObfuscate(const std::shared_ptr<ObfOpt> &option,
                                       Function *f) {
  const auto attrEnable = "+" + option->attributeName();
  const auto attrDisable = "-" + option->attributeName();
  const auto attrLevel = "^" + option->attributeName();
  ObfOpt result = option->none();
  if (f->isDeclaration()) {
    return result;
  }

  if (f->hasAvailableExternallyLinkage() != 0) {
    return result;
  }

  bool annotationEnableFound = false;
  bool annotationDisableFound = false;

  auto annotations = readAnnotate(f);
  int levelSet = 0;
  if (!annotations.empty()) {
    for (const auto &annotation : annotations) {
      if (annotation.find(attrDisable) != std::string::npos) {
        result.setEnable(false);
        annotationDisableFound = true;
      }
      if (annotation.find(attrEnable) != std::string::npos) {
        result.setEnable(true);
        annotationEnableFound = true;
      }
      if (const auto levelPos = annotation.find(attrLevel);
          levelPos != std::string::npos) {
        if (annotation.find(attrLevel, levelPos + 1) != std::string::npos) {
          f->getContext().diagnose(DiagnosticInfoUnsupported{
              *f, f->getName() + " has multiple annotations for setting " +
                      result.attributeName() +
                      " factors, What are you the fucking want to do?"});
          return result.none();
        }
        int32_t level = -1;
        const auto equalPos = annotation.find('=', levelPos + 1);
        if (equalPos == std::string::npos) {
          f->getContext().diagnose(DiagnosticInfoUnsupported{
              *f, f->getName() + ": " + annotation +
                      " missing equal sign, sample: " + attrLevel + " = 0"});
          return result.none();
        }

        for (size_t i = levelPos + attrLevel.length(); i < equalPos; ++i) {
          if (annotation[i] == ' ') {
            continue;
          }
          f->getContext().diagnose(DiagnosticInfoUnsupported{
              *f, f->getName() + ": " + annotation +
                      " unexpected characters, sample: " + attrLevel + " = 0"});
          return result.none();
        }

        for (size_t i = equalPos + 1; i < annotation.length(); ++i) {
          if (annotation[i] == ' ') {
            continue;
          }
          level = annotation[i] - '0';
          if (level < 0 || level > 9) {
            f->getContext().diagnose(DiagnosticInfoUnsupported{
                *f, f->getName() + ": " + annotation +
                        " unexpected character: " + std::string{annotation[i]} +
                        ", sample: " + attrLevel + " = 0"});
            return result.none();
          }
          break;
        }
        if (level == -1) {
          f->getContext().diagnose(DiagnosticInfoUnsupported{
              *f, f->getName() + ": " + annotation +
                      " level value not found, sample: " + attrLevel + " = 0"});
          return result.none();
        }

        ++levelSet;
        result.setLevel(level);
      }
    }
  }

  if (annotationDisableFound && annotationEnableFound) {
    f->getContext().diagnose(DiagnosticInfoUnsupported{
        *f, f->getName() + " having both enable annotation and disable "
                           "annotation, What are you the fucking want to do?"});
    return result.none();
  }

  if (levelSet > 1) {
    f->getContext().diagnose(DiagnosticInfoUnsupported{
        *f, f->getName() + " has multiple annotations for setting " +
                result.attributeName() +
                " factors, What are you the fucking want to do?"});
    return result.none();
  }

  if (!annotationDisableFound && !annotationEnableFound) {
    result.setEnable(option->isEnabled());
  }
  if (!levelSet) {
    result.setLevel(option->level());
  }
  result.setProbability(option->probability());
  result.setFunctionProbability(option->functionProbability());
  result.setLoopCount(option->loopCount());
  result.setMaxInsts(option->maxInsts());
  result.setMaxBlocks(option->maxBlocks());
  result.setMaxAllocas(option->maxAllocas());
  result.setMinConstSize(option->minConstSize());
  result.setMinStringLength(option->minStringLength());
  result.setSkipStrings(option->skipStrings());
  result.setStringLocalStackDecrypt(option->stringLocalStackDecrypt());
  result.setStringHeapDecrypt(option->stringHeapDecrypt());
  result.setStringReencryptAfterUse(option->stringReencryptAfterUse());
  result.setVolatileSeed(option->volatileSeed());
  result.setConstDecryptorMBA(option->constDecryptorMBA());
  result.setReleaseStrip(option->releaseStrip());
  result.setRandomizeSections(option->randomizeSections());
  result.setExportAllowlist(option->exportAllowlist());
  result.setStringDecryptorMBA(option->stringDecryptorMBA());
  result.setStringDecryptorFlattening(option->stringDecryptorFlattening());
  result.setStringDecryptorIndirectCall(option->stringDecryptorIndirectCall());
  result.setStringShardedPool(option->stringShardedPool());
  result.setStringFakePools(option->stringFakePools());
  result.setStringPageTableAccess(option->stringPageTableAccess());
  result.setStringDelayedDecrypt(option->stringDelayedDecrypt());

  if (option->attributeName() == "vmp" && !annotations.empty()) {
    const std::string BudgetToken = "vmp-budget=";
    for (const auto &annotation : annotations) {
      auto pos = annotation.find(BudgetToken);
      if (pos == std::string::npos)
        continue;
      auto digits = pos + BudgetToken.size();
      uint32_t value = 0;
      bool any = false;
      for (; digits < annotation.size() && annotation[digits] >= '0' &&
             annotation[digits] <= '9';
           ++digits) {
        value = value * 10 + static_cast<uint32_t>(annotation[digits] - '0');
        any = true;
      }
      if (!any) {
        f->getContext().diagnose(DiagnosticInfoUnsupported{
            *f, f->getName() + ": vmp-budget= needs a non-negative integer "
                               "(sample: vmp-budget=4096)"});
        return result.none();
      }
      result.setVmpBudget(value);
    }
  }

  return result;
}

} // namespace llvm
