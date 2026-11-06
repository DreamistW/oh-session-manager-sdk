#include "ohcrypto_probe.h"

#include <CryptoArchitectureKit/crypto_architecture_kit.h>
#include <CryptoArchitectureKit/crypto_key_agreement.h>
#include <hilog/log.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace homoxterm {
namespace {

constexpr unsigned int HOMOX_LOG_DOMAIN = 0xD003201;
constexpr const char *HOMOX_LOG_TAG = "HomoxNativeGate";

template<typename Operation>
void RunGateStep(const char *name, Operation operation)
{
    OH_LOG_Print(LOG_APP, LOG_INFO, HOMOX_LOG_DOMAIN, HOMOX_LOG_TAG,
        "BEGIN %{public}s", name);
    operation();
    OH_LOG_Print(LOG_APP, LOG_INFO, HOMOX_LOG_DOMAIN, HOMOX_LOG_TAG,
        "END %{public}s", name);
}

class GateReport {
public:
    void Pass(const std::string &name)
    {
        lines_.push_back("PASS " + name);
    }

    void Fail(const std::string &name, OH_Crypto_ErrCode code)
    {
        passed_ = false;
        lines_.push_back("FAIL " + name + " code=" + std::to_string(static_cast<int>(code)));
    }

    void Fail(const std::string &name, const std::string &reason)
    {
        passed_ = false;
        lines_.push_back("FAIL " + name + " " + reason);
    }

    std::string Finish() const
    {
        std::ostringstream out;
        out << (passed_ ? "OHCRYPTO_GATE_PASS" : "OHCRYPTO_GATE_FAIL");
        for (const std::string &line : lines_) {
            out << '\n' << line;
        }
        return out.str();
    }

private:
    bool passed_ = true;
    std::vector<std::string> lines_;
};

Crypto_DataBlob View(const uint8_t *data, size_t len)
{
    return {const_cast<uint8_t *>(data), len};
}

Crypto_DataBlob View(const std::string &text)
{
    return View(reinterpret_cast<const uint8_t *>(text.data()), text.size());
}

bool Equal(const Crypto_DataBlob &blob, const uint8_t *expected, size_t expectedLen)
{
    return blob.len == expectedLen && std::memcmp(blob.data, expected, expectedLen) == 0;
}

std::vector<uint8_t> Hex(const char *hex)
{
    std::vector<uint8_t> bytes;
    const size_t length = std::strlen(hex);
    bytes.reserve(length / 2);
    auto nibble = [](char value) -> uint8_t {
        if (value >= '0' && value <= '9') {
            return static_cast<uint8_t>(value - '0');
        }
        if (value >= 'a' && value <= 'f') {
            return static_cast<uint8_t>(value - 'a' + 10);
        }
        return static_cast<uint8_t>(value - 'A' + 10);
    };
    for (size_t index = 0; index + 1 < length; index += 2) {
        bytes.push_back(static_cast<uint8_t>((nibble(hex[index]) << 4U) | nibble(hex[index + 1])));
    }
    return bytes;
}

void TestDigest(GateReport &report, const char *algorithm, const char *expectedHex)
{
    OH_CryptoDigest *digest = nullptr;
    Crypto_DataBlob output {nullptr, 0};
    const std::string input = "abc";
    Crypto_DataBlob inputBlob = View(input);
    OH_Crypto_ErrCode code = OH_CryptoDigest_Create(algorithm, &digest);
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoDigest_Update(digest, &inputBlob);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoDigest_Final(digest, &output);
    }
    const std::vector<uint8_t> expected = Hex(expectedHex);
    const std::string name = std::string("digest-") + algorithm;
    if (code == CRYPTO_SUCCESS && Equal(output, expected.data(), expected.size())) {
        report.Pass(name);
    } else if (code != CRYPTO_SUCCESS) {
        report.Fail(name, code);
    } else {
        report.Fail(name, "vector-mismatch");
    }
    OH_Crypto_FreeDataBlob(&output);
    OH_DigestCrypto_Destroy(digest);
}

void TestHmac(GateReport &report, const char *algorithm, const char *expectedHex)
{
    OH_CryptoSymKeyGenerator *generator = nullptr;
    OH_CryptoSymKey *key = nullptr;
    OH_CryptoMac *mac = nullptr;
    Crypto_DataBlob output {nullptr, 0};
    const size_t keyLength = std::strcmp(algorithm, "SHA512") == 0 ? 64 : 32;
    std::vector<uint8_t> keyBytes(keyLength);
    for (size_t index = 0; index < keyBytes.size(); ++index) {
        keyBytes[index] = static_cast<uint8_t>(index);
    }
    const std::string input = "The quick brown fox jumps over the lazy dog";
    const std::string keyAlgorithm = std::string("HMAC|") + algorithm;
    Crypto_DataBlob keyBlob = View(keyBytes.data(), keyBytes.size());
    Crypto_DataBlob inputBlob = View(input);
    Crypto_DataBlob algorithmBlob = View(reinterpret_cast<const uint8_t *>(algorithm), std::strlen(algorithm));
    OH_Crypto_ErrCode code = OH_CryptoSymKeyGenerator_Create(keyAlgorithm.c_str(), &generator);
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymKeyGenerator_Convert(generator, &keyBlob, &key);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoMac_Create("HMAC", &mac);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoMac_SetParam(mac, CRYPTO_MAC_DIGEST_NAME_STR, &algorithmBlob);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoMac_Init(mac, key);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoMac_Update(mac, &inputBlob);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoMac_Final(mac, &output);
    }
    const std::vector<uint8_t> expected = Hex(expectedHex);
    const std::string name = std::string("hmac-") + algorithm;
    if (code == CRYPTO_SUCCESS && Equal(output, expected.data(), expected.size())) {
        report.Pass(name);
    } else if (code != CRYPTO_SUCCESS) {
        report.Fail(name, code);
    } else {
        report.Fail(name, "vector-mismatch");
    }
    OH_Crypto_FreeDataBlob(&output);
    OH_CryptoMac_Destroy(mac);
    OH_CryptoSymKey_Destroy(key);
    OH_CryptoSymKeyGenerator_Destroy(generator);
}

void TestAesCtr(GateReport &report)
{
    const std::vector<uint8_t> keyBytes = Hex("2b7e151628aed2a6abf7158809cf4f3c");
    const std::vector<uint8_t> ivBytes = Hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const std::vector<uint8_t> plain = Hex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710");
    const std::vector<uint8_t> expected = Hex(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee");
    OH_CryptoSymKeyGenerator *generator = nullptr;
    OH_CryptoSymKey *key = nullptr;
    OH_CryptoSymCipherParams *params = nullptr;
    OH_CryptoSymCipher *cipher = nullptr;
    Crypto_DataBlob keyBlob = View(keyBytes.data(), keyBytes.size());
    Crypto_DataBlob ivBlob = View(ivBytes.data(), ivBytes.size());
    std::vector<uint8_t> actual;
    OH_Crypto_ErrCode code = OH_CryptoSymKeyGenerator_Create("AES128", &generator);
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymKeyGenerator_Convert(generator, &keyBlob, &key);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymCipherParams_Create(&params);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymCipherParams_SetParam(params, CRYPTO_IV_DATABLOB, &ivBlob);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymCipher_Create("AES128|CTR|NoPadding", &cipher);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymCipher_Init(cipher, CRYPTO_ENCRYPT_MODE, key, params);
    }
    for (size_t offset = 0; code == CRYPTO_SUCCESS && offset < plain.size(); offset += 16) {
        Crypto_DataBlob input = View(plain.data() + offset, 16);
        Crypto_DataBlob output {nullptr, 0};
        code = OH_CryptoSymCipher_Update(cipher, &input, &output);
        if (code == CRYPTO_SUCCESS) {
            actual.insert(actual.end(), output.data, output.data + output.len);
        }
        OH_Crypto_FreeDataBlob(&output);
    }
    Crypto_DataBlob finalOutput {nullptr, 0};
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSymCipher_Final(cipher, nullptr, &finalOutput);
        if (code == CRYPTO_SUCCESS) {
            actual.insert(actual.end(), finalOutput.data, finalOutput.data + finalOutput.len);
        }
    }
    if (code == CRYPTO_SUCCESS && actual == expected) {
        report.Pass("aes128-ctr-segmented");
    } else if (code != CRYPTO_SUCCESS) {
        report.Fail("aes128-ctr-segmented", code);
    } else {
        report.Fail("aes128-ctr-segmented", "vector-mismatch");
    }
    OH_Crypto_FreeDataBlob(&finalOutput);
    OH_CryptoSymCipher_Destroy(cipher);
    OH_CryptoSymCipherParams_Destroy(params);
    OH_CryptoSymKey_Destroy(key);
    OH_CryptoSymKeyGenerator_Destroy(generator);
}

void TestAgreement(GateReport &report, const char *algorithm)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_CryptoKeyPair *first = nullptr;
    OH_CryptoKeyPair *second = nullptr;
    OH_CryptoKeyAgreement *agreement = nullptr;
    Crypto_DataBlob firstSecret {nullptr, 0};
    Crypto_DataBlob secondSecret {nullptr, 0};
    OH_Crypto_ErrCode code = OH_CryptoAsymKeyGenerator_Create(algorithm, &generator);
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGenerator_Generate(generator, &first);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGenerator_Generate(generator, &second);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoKeyAgreement_Create(algorithm, &agreement);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoKeyAgreement_GenerateSecret(agreement, OH_CryptoKeyPair_GetPrivKey(first),
            OH_CryptoKeyPair_GetPubKey(second), &firstSecret);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoKeyAgreement_GenerateSecret(agreement, OH_CryptoKeyPair_GetPrivKey(second),
            OH_CryptoKeyPair_GetPubKey(first), &secondSecret);
    }
    const std::string name = std::string("agreement-") + algorithm;
    if (code == CRYPTO_SUCCESS && firstSecret.len > 0 &&
        Equal(firstSecret, secondSecret.data, secondSecret.len)) {
        report.Pass(name);
    } else if (code != CRYPTO_SUCCESS) {
        report.Fail(name, code);
    } else {
        report.Fail(name, "secret-mismatch");
    }
    OH_Crypto_FreeDataBlob(&firstSecret);
    OH_Crypto_FreeDataBlob(&secondSecret);
    OH_CryptoKeyAgreement_Destroy(agreement);
    OH_CryptoKeyPair_Destroy(first);
    OH_CryptoKeyPair_Destroy(second);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

void TestRawX25519(GateReport &report)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_CryptoKeyPair *original = nullptr;
    OH_CryptoAsymKeySpec *privateSpec = nullptr;
    OH_CryptoAsymKeySpec *publicSpec = nullptr;
    OH_CryptoAsymKeyGeneratorWithSpec *privateGenerator = nullptr;
    OH_CryptoAsymKeyGeneratorWithSpec *publicGenerator = nullptr;
    OH_CryptoKeyPair *privatePair = nullptr;
    OH_CryptoKeyPair *publicPair = nullptr;
    OH_CryptoKeyAgreement *agreement = nullptr;
    Crypto_DataBlob privateRaw {nullptr, 0};
    Crypto_DataBlob publicRaw {nullptr, 0};
    Crypto_DataBlob shared {nullptr, 0};
    OH_Crypto_ErrCode code = OH_CryptoAsymKeyGenerator_Create("X25519", &generator);
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGenerator_Generate(generator, &original);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoPrivKey_GetParam(OH_CryptoKeyPair_GetPrivKey(original),
            CRYPTO_X25519_SK_DATABLOB, &privateRaw);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoPubKey_GetParam(OH_CryptoKeyPair_GetPubKey(original),
            CRYPTO_X25519_PK_DATABLOB, &publicRaw);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_Create("X25519", CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC, &privateSpec);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(privateSpec, CRYPTO_X25519_SK_DATABLOB, &privateRaw);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_Create(privateSpec, &privateGenerator);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(privateGenerator, &privatePair);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_Create("X25519", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, &publicSpec);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(publicSpec, CRYPTO_X25519_PK_DATABLOB, &publicRaw);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_Create(publicSpec, &publicGenerator);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(publicGenerator, &publicPair);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoKeyAgreement_Create("X25519", &agreement);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoKeyAgreement_GenerateSecret(agreement,
            OH_CryptoKeyPair_GetPrivKey(privatePair), OH_CryptoKeyPair_GetPubKey(publicPair), &shared);
    }
    if (code == CRYPTO_SUCCESS && privateRaw.len == 32 && publicRaw.len == 32 && shared.len == 32) {
        report.Pass("x25519-raw-key-roundtrip");
    } else if (code != CRYPTO_SUCCESS) {
        report.Fail("x25519-raw-key-roundtrip", code);
    } else {
        report.Fail("x25519-raw-key-roundtrip", "wrong-length");
    }
    OH_Crypto_FreeDataBlob(&shared);
    OH_Crypto_FreeDataBlob(&publicRaw);
    OH_Crypto_FreeDataBlob(&privateRaw);
    OH_CryptoKeyAgreement_Destroy(agreement);
    OH_CryptoKeyPair_Destroy(publicPair);
    OH_CryptoKeyPair_Destroy(privatePair);
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(publicGenerator);
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(privateGenerator);
    OH_CryptoAsymKeySpec_Destroy(publicSpec);
    OH_CryptoAsymKeySpec_Destroy(privateSpec);
    OH_CryptoKeyPair_Destroy(original);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

OH_Crypto_ErrCode ComputeRawX25519(const std::vector<uint8_t> &privateBytes,
    const std::vector<uint8_t> &publicBytes, std::vector<uint8_t> &secret)
{
    Crypto_DataBlob privateRaw = View(privateBytes.data(), privateBytes.size());
    Crypto_DataBlob publicRaw = View(publicBytes.data(), publicBytes.size());
    OH_CryptoAsymKeySpec *privateSpec = nullptr;
    OH_CryptoAsymKeySpec *publicSpec = nullptr;
    OH_CryptoAsymKeyGeneratorWithSpec *privateGenerator = nullptr;
    OH_CryptoAsymKeyGeneratorWithSpec *publicGenerator = nullptr;
    OH_CryptoKeyPair *privatePair = nullptr;
    OH_CryptoKeyPair *publicPair = nullptr;
    OH_CryptoKeyAgreement *agreement = nullptr;
    Crypto_DataBlob shared {nullptr, 0};
    OH_Crypto_ErrCode code = OH_CryptoAsymKeySpec_Create(
        "X25519", CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC, &privateSpec);
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(privateSpec, CRYPTO_X25519_SK_DATABLOB, &privateRaw);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_Create(privateSpec, &privateGenerator);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(privateGenerator, &privatePair);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_Create(
            "X25519", CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC, &publicSpec);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(publicSpec, CRYPTO_X25519_PK_DATABLOB, &publicRaw);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_Create(publicSpec, &publicGenerator);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(publicGenerator, &publicPair);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoKeyAgreement_Create("X25519", &agreement);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoKeyAgreement_GenerateSecret(agreement,
            OH_CryptoKeyPair_GetPrivKey(privatePair), OH_CryptoKeyPair_GetPubKey(publicPair), &shared);
    }
    if (code == CRYPTO_SUCCESS) {
        secret.assign(shared.data, shared.data + shared.len);
    }
    OH_Crypto_FreeDataBlob(&shared);
    OH_CryptoKeyAgreement_Destroy(agreement);
    OH_CryptoKeyPair_Destroy(publicPair);
    OH_CryptoKeyPair_Destroy(privatePair);
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(publicGenerator);
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(privateGenerator);
    OH_CryptoAsymKeySpec_Destroy(publicSpec);
    OH_CryptoAsymKeySpec_Destroy(privateSpec);
    return code;
}

void TestX25519Rfc7748(GateReport &report)
{
    const std::vector<uint8_t> alicePrivate = Hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const std::vector<uint8_t> bobPublic = Hex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const std::vector<uint8_t> expected = Hex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    std::vector<uint8_t> reversedPrivate(alicePrivate.rbegin(), alicePrivate.rend());
    std::vector<uint8_t> reversedPublic(bobPublic.rbegin(), bobPublic.rend());
    std::vector<uint8_t> secret;
    OH_Crypto_ErrCode code = ComputeRawX25519(alicePrivate, bobPublic, secret);
    if (code == CRYPTO_SUCCESS && secret == expected) {
        report.Pass("x25519-rfc7748-vector");
        return;
    }
    struct Variant {
        const char *name;
        const std::vector<uint8_t> *privateBytes;
        const std::vector<uint8_t> *publicBytes;
    };
    const std::array<Variant, 3> variants {{
        {"reverse-private", &reversedPrivate, &bobPublic},
        {"reverse-public", &alicePrivate, &reversedPublic},
        {"reverse-private-public", &reversedPrivate, &reversedPublic}
    }};
    for (const Variant &variant : variants) {
        secret.clear();
        code = ComputeRawX25519(*variant.privateBytes, *variant.publicBytes, secret);
        if (code == CRYPTO_SUCCESS && secret == expected) {
            if (std::strcmp(variant.name, "reverse-private-public") == 0) {
                report.Pass("x25519-rfc7748-vector-reverse-boundary");
            } else {
                report.Fail("x25519-rfc7748-vector", std::string("unexpected-") + variant.name);
            }
            return;
        }
        if (code == CRYPTO_SUCCESS && secret.size() == expected.size() &&
            std::equal(secret.begin(), secret.end(), expected.rbegin())) {
            report.Fail("x25519-rfc7748-vector",
                std::string("requires-") + variant.name + "-and-reverse-output");
            return;
        }
    }
    if (code != CRYPTO_SUCCESS) {
        report.Fail("x25519-rfc7748-vector", code);
    } else {
        report.Fail("x25519-rfc7748-vector", "no-simple-byte-order-mapping");
    }
}

OH_Crypto_ErrCode SignAndVerifyPair(OH_CryptoKeyPair *signingPair,
    OH_CryptoKeyPair *verificationPair, const char *algorithm)
{
    OH_CryptoSign *sign = nullptr;
    OH_CryptoVerify *verify = nullptr;
    Crypto_DataBlob signature {nullptr, 0};
    const std::string message = "HomoXterm-raw-key-spec";
    Crypto_DataBlob messageBlob = View(message);
    OH_Crypto_ErrCode code = OH_CryptoSign_Create(algorithm, &sign);
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Init(sign, OH_CryptoKeyPair_GetPrivKey(signingPair));
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Final(sign, &messageBlob, &signature);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoVerify_Create(algorithm, &verify);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoVerify_Init(verify, OH_CryptoKeyPair_GetPubKey(verificationPair));
    }
    if (code == CRYPTO_SUCCESS) {
        const bool verified = OH_CryptoVerify_Final(verify, &messageBlob, &signature);
        if (!verified) {
            code = CRYPTO_OPERTION_ERROR;
        }
    }
    OH_Crypto_FreeDataBlob(&signature);
    OH_CryptoVerify_Destroy(verify);
    OH_CryptoSign_Destroy(sign);
    return code;
}

void TestRawPrivateKeySpecs(GateReport &report)
{
    OH_CryptoAsymKeyGenerator *rsaGenerator = nullptr;
    OH_CryptoKeyPair *rsaOriginal = nullptr;
    OH_CryptoAsymKeySpec *rsaSpec = nullptr;
    OH_CryptoAsymKeyGeneratorWithSpec *rsaSpecGenerator = nullptr;
    OH_CryptoKeyPair *rsaImported = nullptr;
    Crypto_DataBlob n {nullptr, 0};
    Crypto_DataBlob e {nullptr, 0};
    Crypto_DataBlob d {nullptr, 0};
    OH_Crypto_ErrCode code = OH_CryptoAsymKeyGenerator_Create("RSA2048", &rsaGenerator);
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGenerator_Generate(rsaGenerator, &rsaOriginal);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoPubKey_GetParam(OH_CryptoKeyPair_GetPubKey(rsaOriginal), CRYPTO_RSA_N_DATABLOB, &n);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoPubKey_GetParam(OH_CryptoKeyPair_GetPubKey(rsaOriginal), CRYPTO_RSA_E_DATABLOB, &e);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoPrivKey_GetParam(OH_CryptoKeyPair_GetPrivKey(rsaOriginal), CRYPTO_RSA_D_DATABLOB, &d);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_Create("RSA", CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, &rsaSpec);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(rsaSpec, CRYPTO_RSA_N_DATABLOB, &n);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(rsaSpec, CRYPTO_RSA_E_DATABLOB, &e);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeySpec_SetParam(rsaSpec, CRYPTO_RSA_D_DATABLOB, &d);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_Create(rsaSpec, &rsaSpecGenerator);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(rsaSpecGenerator, &rsaImported);
    }
    if (code == CRYPTO_SUCCESS) {
        code = SignAndVerifyPair(rsaImported, rsaOriginal, "RSA|PKCS1|SHA256");
    }
    if (code == CRYPTO_SUCCESS) {
        report.Pass("raw-private-spec-RSA");
    } else {
        report.Fail("raw-private-spec-RSA", code);
    }
    OH_Crypto_FreeDataBlob(&d);
    OH_Crypto_FreeDataBlob(&e);
    OH_Crypto_FreeDataBlob(&n);
    OH_CryptoKeyPair_Destroy(rsaImported);
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(rsaSpecGenerator);
    OH_CryptoAsymKeySpec_Destroy(rsaSpec);
    OH_CryptoKeyPair_Destroy(rsaOriginal);
    OH_CryptoAsymKeyGenerator_Destroy(rsaGenerator);

    OH_CryptoAsymKeyGenerator *eccGenerator = nullptr;
    OH_CryptoKeyPair *eccOriginal = nullptr;
    OH_CryptoAsymKeySpec *eccSpec = nullptr;
    OH_CryptoAsymKeySpec *eccCommon = nullptr;
    OH_CryptoAsymKeyGeneratorWithSpec *eccSpecGenerator = nullptr;
    OH_CryptoKeyPair *eccImported = nullptr;
    Crypto_DataBlob x {nullptr, 0};
    Crypto_DataBlob y {nullptr, 0};
    Crypto_DataBlob sk {nullptr, 0};
    code = OH_CryptoAsymKeyGenerator_Create("ECC256", &eccGenerator);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoAsymKeyGenerator_Generate(eccGenerator, &eccOriginal);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoPubKey_GetParam(OH_CryptoKeyPair_GetPubKey(eccOriginal), CRYPTO_ECC_PK_X_DATABLOB, &x);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoPubKey_GetParam(OH_CryptoKeyPair_GetPubKey(eccOriginal), CRYPTO_ECC_PK_Y_DATABLOB, &y);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoPrivKey_GetParam(OH_CryptoKeyPair_GetPrivKey(eccOriginal), CRYPTO_ECC_SK_DATABLOB, &sk);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoAsymKeySpec_Create("ECC", CRYPTO_ASYM_KEY_KEY_PAIR_SPEC, &eccSpec);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoAsymKeySpec_GenEcCommonParamsSpec("NID_X9_62_prime256v1", &eccCommon);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoAsymKeySpec_SetCommonParamsSpec(eccSpec, eccCommon);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoAsymKeySpec_SetParam(eccSpec, CRYPTO_ECC_PK_X_DATABLOB, &x);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoAsymKeySpec_SetParam(eccSpec, CRYPTO_ECC_PK_Y_DATABLOB, &y);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoAsymKeySpec_SetParam(eccSpec, CRYPTO_ECC_SK_DATABLOB, &sk);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoAsymKeyGeneratorWithSpec_Create(eccSpec, &eccSpecGenerator);
    if (code == CRYPTO_SUCCESS) code = OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(eccSpecGenerator, &eccImported);
    if (code == CRYPTO_SUCCESS) code = SignAndVerifyPair(eccImported, eccOriginal, "ECC|SHA256");
    if (code == CRYPTO_SUCCESS) report.Pass("raw-private-spec-ECC256");
    else report.Fail("raw-private-spec-ECC256", code);
    OH_Crypto_FreeDataBlob(&sk);
    OH_Crypto_FreeDataBlob(&y);
    OH_Crypto_FreeDataBlob(&x);
    OH_CryptoKeyPair_Destroy(eccImported);
    OH_CryptoAsymKeyGeneratorWithSpec_Destroy(eccSpecGenerator);
    OH_CryptoAsymKeySpec_Destroy(eccCommon);
    OH_CryptoAsymKeySpec_Destroy(eccSpec);
    OH_CryptoKeyPair_Destroy(eccOriginal);
    OH_CryptoAsymKeyGenerator_Destroy(eccGenerator);

    OH_CryptoAsymKeyGenerator *edGenerator = nullptr;
    OH_CryptoKeyPair *edImported = nullptr;
    code = OH_CryptoAsymKeyGenerator_Create("Ed25519", &edGenerator);
    const std::array<uint8_t, 12> edPublicPrefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
        0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
    const std::array<uint8_t, 16> edPrivatePrefix = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30,
        0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20};
    const std::vector<uint8_t> edPublicRaw = Hex(
        "0dbfc2aaac30ef831521c7b322e9fd321d656e7c77730f50cbdbd8ced5b1d8d0");
    std::vector<uint8_t> edPrivateRaw = Hex(
        "f172a607b4ff8438363fa0deb764ab5c1a443ff09917ad449e1e5014f40fce92");
    std::vector<uint8_t> edPublicDer(edPublicPrefix.begin(), edPublicPrefix.end());
    std::vector<uint8_t> edPrivateDer(edPrivatePrefix.begin(), edPrivatePrefix.end());
    if (code == CRYPTO_SUCCESS) {
        edPublicDer.insert(edPublicDer.end(), edPublicRaw.begin(), edPublicRaw.end());
        edPrivateDer.insert(edPrivateDer.end(), edPrivateRaw.begin(), edPrivateRaw.end());
        Crypto_DataBlob edPublicBlob = View(edPublicDer.data(), edPublicDer.size());
        Crypto_DataBlob edPrivateBlob = View(edPrivateDer.data(), edPrivateDer.size());
        code = OH_CryptoAsymKeyGenerator_Convert(edGenerator, CRYPTO_DER, &edPublicBlob,
            &edPrivateBlob, &edImported);
    }
    if (code == CRYPTO_SUCCESS) code = SignAndVerifyPair(edImported, edImported, "Ed25519");
    if (code == CRYPTO_SUCCESS) report.Pass("openssh-components-Ed25519");
    else report.Fail("openssh-components-Ed25519", code);
    std::fill(edPrivateDer.begin(), edPrivateDer.end(), 0);
    std::fill(edPrivateRaw.begin(), edPrivateRaw.end(), 0);
    OH_CryptoKeyPair_Destroy(edImported);
    OH_CryptoAsymKeyGenerator_Destroy(edGenerator);
}

void TestSignAndImport(GateReport &report, const char *keyAlgorithm, const char *signAlgorithm,
    const char *verifyAlgorithm)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_CryptoKeyPair *imported = nullptr;
    OH_CryptoSign *sign = nullptr;
    OH_CryptoVerify *verify = nullptr;
    OH_CryptoSign *importedSign = nullptr;
    OH_CryptoVerify *importedVerify = nullptr;
    Crypto_DataBlob signature {nullptr, 0};
    Crypto_DataBlob importedSignature {nullptr, 0};
    Crypto_DataBlob publicDer {nullptr, 0};
    Crypto_DataBlob privateDer {nullptr, 0};
    std::vector<uint8_t> externalPublicDer;
    std::vector<uint8_t> externalPrivateDer;
    const std::string message = "HomoXterm-CryptoFramework-gate";
    Crypto_DataBlob messageBlob = View(message);
    OH_Crypto_ErrCode keyCode = OH_CryptoAsymKeyGenerator_Create(keyAlgorithm, &generator);
    if (keyCode == CRYPTO_SUCCESS) {
        keyCode = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    }
    OH_Crypto_ErrCode signCode = keyCode;
    if (signCode == CRYPTO_SUCCESS) {
        signCode = OH_CryptoSign_Create(signAlgorithm, &sign);
    }
    if (signCode == CRYPTO_SUCCESS) {
        signCode = OH_CryptoSign_Init(sign, OH_CryptoKeyPair_GetPrivKey(keyPair));
    }
    if (signCode == CRYPTO_SUCCESS) {
        signCode = OH_CryptoSign_Final(sign, &messageBlob, &signature);
    }
    if (signCode == CRYPTO_SUCCESS) {
        signCode = OH_CryptoVerify_Create(verifyAlgorithm, &verify);
    }
    if (signCode == CRYPTO_SUCCESS) {
        signCode = OH_CryptoVerify_Init(verify, OH_CryptoKeyPair_GetPubKey(keyPair));
    }
    bool verified = false;
    if (signCode == CRYPTO_SUCCESS) {
        verified = OH_CryptoVerify_Final(verify, &messageBlob, &signature);
        if (!verified) {
            signCode = CRYPTO_OPERTION_ERROR;
        }
    }
    const std::string signName = std::string("sign-") + keyAlgorithm;
    if (signCode == CRYPTO_SUCCESS && verified) {
        report.Pass(signName);
    } else {
        report.Fail(signName, signCode);
    }

    const bool isEd25519 = std::strcmp(keyAlgorithm, "Ed25519") == 0;
    OH_Crypto_ErrCode importCode = keyCode;
    if (importCode == CRYPTO_SUCCESS && isEd25519) {
        // OpenSSL-generated X.509 public key and PKCS#8 private key from the HarmonyOS CryptoFramework FAQ.
        externalPublicDer = Hex(
            "302a300506032b65700321000dbfc2aaac30ef831521c7b322e9fd321d656e7c77730f50cbdbd8ced5b1d8d0");
        externalPrivateDer = Hex(
            "302e020100300506032b657004220420f172a607b4ff8438363fa0deb764ab5c1a443ff09917ad449e1e5014f40fce92");
        publicDer = View(externalPublicDer.data(), externalPublicDer.size());
        privateDer = View(externalPrivateDer.data(), externalPrivateDer.size());
    } else if (importCode == CRYPTO_SUCCESS) {
        importCode = OH_CryptoPrivKey_Encode(OH_CryptoKeyPair_GetPrivKey(keyPair), CRYPTO_DER, "PKCS8", nullptr,
            &privateDer);
    }
    if (importCode == CRYPTO_SUCCESS) {
        Crypto_DataBlob *publicInput = publicDer.len == 0 ? nullptr : &publicDer;
        importCode = OH_CryptoAsymKeyGenerator_Convert(generator, CRYPTO_DER, publicInput, &privateDer, &imported);
    }
    if (importCode == CRYPTO_SUCCESS) {
        importCode = OH_CryptoSign_Create(signAlgorithm, &importedSign);
    }
    if (importCode == CRYPTO_SUCCESS) {
        importCode = OH_CryptoSign_Init(importedSign, OH_CryptoKeyPair_GetPrivKey(imported));
    }
    if (importCode == CRYPTO_SUCCESS) {
        importCode = OH_CryptoSign_Final(importedSign, &messageBlob, &importedSignature);
    }
    if (importCode == CRYPTO_SUCCESS) {
        importCode = OH_CryptoVerify_Create(verifyAlgorithm, &importedVerify);
    }
    if (importCode == CRYPTO_SUCCESS) {
        importCode = OH_CryptoVerify_Init(importedVerify, OH_CryptoKeyPair_GetPubKey(imported));
    }
    bool importedVerified = false;
    if (importCode == CRYPTO_SUCCESS) {
        importedVerified = OH_CryptoVerify_Final(importedVerify, &messageBlob, &importedSignature);
    }
    const std::string importName = std::string("import-pkcs8-") + keyAlgorithm;
    if (importCode == CRYPTO_SUCCESS && imported != nullptr && importedVerified) {
        report.Pass(importName);
    } else if (importCode != CRYPTO_SUCCESS) {
        report.Fail(importName, importCode);
    } else {
        report.Fail(importName, "verify-false");
    }
    OH_Crypto_FreeDataBlob(&signature);
    OH_Crypto_FreeDataBlob(&importedSignature);
    if (!isEd25519) {
        OH_Crypto_FreeDataBlob(&publicDer);
        OH_Crypto_FreeDataBlob(&privateDer);
    }
    OH_CryptoVerify_Destroy(importedVerify);
    OH_CryptoSign_Destroy(importedSign);
    OH_CryptoVerify_Destroy(verify);
    OH_CryptoSign_Destroy(sign);
    OH_CryptoKeyPair_Destroy(imported);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

void TestPrehashedSign(GateReport &report, const char *name, const char *keyAlgorithm,
    const char *digestAlgorithm, const char *onlySignAlgorithm, const char *verifyAlgorithm)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_CryptoDigest *digest = nullptr;
    OH_CryptoSign *sign = nullptr;
    OH_CryptoVerify *verify = nullptr;
    Crypto_DataBlob hash {nullptr, 0};
    Crypto_DataBlob signature {nullptr, 0};
    const std::string message = "HomoXterm-SSH-prehashed-signature";
    Crypto_DataBlob messageBlob = View(message);
    OH_Crypto_ErrCode code = OH_CryptoAsymKeyGenerator_Create(keyAlgorithm, &generator);
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoDigest_Create(digestAlgorithm, &digest);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoDigest_Update(digest, &messageBlob);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoDigest_Final(digest, &hash);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Create(onlySignAlgorithm, &sign);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Init(sign, OH_CryptoKeyPair_GetPrivKey(keyPair));
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoSign_Final(sign, &hash, &signature);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoVerify_Create(verifyAlgorithm, &verify);
    }
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoVerify_Init(verify, OH_CryptoKeyPair_GetPubKey(keyPair));
    }
    bool verified = false;
    if (code == CRYPTO_SUCCESS) {
        verified = OH_CryptoVerify_Final(verify, &messageBlob, &signature);
    }
    if (code == CRYPTO_SUCCESS && verified) {
        report.Pass(name);
    } else if (code != CRYPTO_SUCCESS) {
        report.Fail(name, code);
    } else {
        report.Fail(name, "verify-false");
    }
    OH_Crypto_FreeDataBlob(&signature);
    OH_Crypto_FreeDataBlob(&hash);
    OH_CryptoVerify_Destroy(verify);
    OH_CryptoSign_Destroy(sign);
    OH_DigestCrypto_Destroy(digest);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

void TestRandom(GateReport &report)
{
    OH_CryptoRand *random = nullptr;
    Crypto_DataBlob output {nullptr, 0};
    OH_Crypto_ErrCode code = OH_CryptoRand_Create(&random);
    if (code == CRYPTO_SUCCESS) {
        code = OH_CryptoRand_GenerateRandom(random, 32, &output);
    }
    const bool nonzero = output.data != nullptr && output.len == 32 &&
        std::any_of(output.data, output.data + output.len, [](uint8_t value) { return value != 0; });
    if (code == CRYPTO_SUCCESS && nonzero) {
        report.Pass("secure-random");
    } else if (code != CRYPTO_SUCCESS) {
        report.Fail("secure-random", code);
    } else {
        report.Fail("secure-random", "all-zero-or-wrong-length");
    }
    OH_Crypto_FreeDataBlob(&output);
    OH_CryptoRand_Destroy(random);
}

} // namespace

std::string RunOhCryptoCompatibilityGate()
{
    GateReport report;
    RunGateStep("digest-SHA256", [&]() {
        TestDigest(report, "SHA256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    });
    RunGateStep("digest-SHA512", [&]() {
        TestDigest(report, "SHA512",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    });
    RunGateStep("hmac-SHA256", [&]() {
        TestHmac(report, "SHA256", "f87ad256151fc7b4c5dffa4adb3ebe911a8eeb8a8ebdee3c2a4a8e5f5ec02c32");
    });
    RunGateStep("hmac-SHA512", [&]() {
        TestHmac(report, "SHA512",
            "8ef6fa91d810afa6546adf7bc2428273c116e0cb5578620462606659f08f78e9"
            "e27f2dee70c0ddb1a890c2c1b6f9c02766388e1fdb7d9b90fd9f46ede1fd8390");
    });
    RunGateStep("aes128-ctr-segmented", [&]() { TestAesCtr(report); });
    RunGateStep("secure-random", [&]() { TestRandom(report); });
    RunGateStep("agreement-X25519", [&]() { TestAgreement(report, "X25519"); });
    RunGateStep("x25519-raw-key-roundtrip", [&]() { TestRawX25519(report); });
    RunGateStep("x25519-rfc7748-vector", [&]() { TestX25519Rfc7748(report); });
    RunGateStep("raw-private-key-specs", [&]() { TestRawPrivateKeySpecs(report); });
    RunGateStep("agreement-ECC256", [&]() { TestAgreement(report, "ECC256"); });
    RunGateStep("agreement-ECC384", [&]() { TestAgreement(report, "ECC384"); });
    RunGateStep("agreement-ECC521", [&]() { TestAgreement(report, "ECC521"); });
    RunGateStep("agreement-DH_modp2048", [&]() { TestAgreement(report, "DH_modp2048"); });
    RunGateStep("agreement-DH_modp4096", [&]() { TestAgreement(report, "DH_modp4096"); });
    RunGateStep("agreement-DH_modp8192", [&]() { TestAgreement(report, "DH_modp8192"); });
    RunGateStep("sign-import-RSA2048", [&]() {
        TestSignAndImport(report, "RSA2048", "RSA|PKCS1|SHA256", "RSA|PKCS1|SHA256");
    });
    RunGateStep("sign-import-ECC256", [&]() {
        TestSignAndImport(report, "ECC256", "ECC|SHA256", "ECC|SHA256");
    });
    RunGateStep("sign-import-ECC384", [&]() {
        TestSignAndImport(report, "ECC384", "ECC|SHA384", "ECC|SHA384");
    });
    RunGateStep("sign-import-ECC521", [&]() {
        TestSignAndImport(report, "ECC521", "ECC|SHA512", "ECC|SHA512");
    });
    RunGateStep("sign-import-Ed25519", [&]() {
        TestSignAndImport(report, "Ed25519", "Ed25519", "Ed25519");
    });
    RunGateStep("ssh-prehashed-rsa-sha2-256", [&]() {
        TestPrehashedSign(report, "ssh-prehashed-rsa-sha2-256", "RSA2048", "SHA256",
            "RSA|PKCS1|SHA256|OnlySign", "RSA|PKCS1|SHA256");
    });
    RunGateStep("ssh-prehashed-rsa-sha2-512", [&]() {
        TestPrehashedSign(report, "ssh-prehashed-rsa-sha2-512", "RSA2048", "SHA512",
            "RSA|PKCS1|SHA512|OnlySign", "RSA|PKCS1|SHA512");
    });
    RunGateStep("ssh-prehashed-ecdsa-p256", [&]() {
        TestPrehashedSign(report, "ssh-prehashed-ecdsa-p256", "ECC256", "SHA256",
            "ECC|SHA256|OnlySign", "ECC|SHA256");
    });
    return report.Finish();
}

} // namespace homoxterm
