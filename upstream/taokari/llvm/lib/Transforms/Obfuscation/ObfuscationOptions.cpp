#include "llvm/Transforms/Obfuscation/ObfuscationOptions.h"
#include "llvm/ADT/SmallString.h"
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
  return result;
}

} // namespace llvm
