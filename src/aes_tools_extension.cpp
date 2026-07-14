#define DUCKDB_EXTENSION_MAIN

#include "aes_tools_extension.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include <openssl/evp.h>

#include <string>
#include <vector>

// -----------------------------------------------------------------------------
// AES-128-ECB/PKCS5Padding + Hex scalar functions for DuckDB, compatible with
// Hutool's `SecureUtil.aes(keyBytes).encryptHex(...)` and `decryptStr(...)`.
//
//   aes_encrypt(plaintext VARCHAR, key VARCHAR) -> ciphertext_hex VARCHAR
//   aes_decrypt(ciphertext_hex VARCHAR, key VARCHAR) -> plaintext VARCHAR
//
// The externally supplied key must be exactly 16 UTF-8 bytes, matching
// `key.getBytes(StandardCharsets.UTF_8)` on the Java side.
// -----------------------------------------------------------------------------

namespace duckdb {

// ------------------------- Hex helpers -------------------------

static std::string HexEncode(const unsigned char *data, size_t len) {
	static const char kHex[] = "0123456789abcdef";
	std::string out(len * 2, '\0');
	for (size_t i = 0; i < len; i++) {
		out[i * 2] = kHex[data[i] >> 4];
		out[i * 2 + 1] = kHex[data[i] & 0x0F];
	}
	return out;
}

static unsigned char HexValue(char c) {
	if (c >= '0' && c <= '9') {
		return static_cast<unsigned char>(c - '0');
	}
	if (c >= 'a' && c <= 'f') {
		return static_cast<unsigned char>(c - 'a' + 10);
	}
	if (c >= 'A' && c <= 'F') {
		return static_cast<unsigned char>(c - 'A' + 10);
	}
	throw InvalidInputException("aes_decrypt: ciphertext contains a non-hex character");
}

static std::vector<unsigned char> HexDecode(const std::string &input) {
	std::vector<unsigned char> out(input.size() / 2);
	for (size_t i = 0; i < out.size(); i++) {
		out[i] = static_cast<unsigned char>((HexValue(input[i * 2]) << 4) | HexValue(input[i * 2 + 1]));
	}
	return out;
}

// ------------------------- AES-128-ECB core -------------------------

static std::vector<unsigned char> ParseKey(const std::string &key, const char *function_name) {
	if (key.size() != 16) {
		throw InvalidInputException("%s: key must be exactly 16 UTF-8 bytes (got %d bytes)", function_name,
		                            static_cast<int>(key.size()));
	}
	return std::vector<unsigned char>(key.begin(), key.end());
}

static std::string AesEcbEncryptRaw(const std::vector<unsigned char> &key, const std::string &plaintext) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw InternalException("aes_encrypt: failed to allocate cipher context");
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw InvalidInputException("aes_encrypt: cipher init failed");
	}

	// EVP PKCS padding is enabled by default; for AES it is byte-compatible with
	// PKCS5Padding.
	std::vector<unsigned char> out(plaintext.size() + static_cast<size_t>(EVP_CIPHER_CTX_block_size(ctx)));
	int len1 = 0;
	int len2 = 0;
	if (EVP_EncryptUpdate(ctx, out.data(), &len1, reinterpret_cast<const unsigned char *>(plaintext.data()),
	                      static_cast<int>(plaintext.size())) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw InvalidInputException("aes_encrypt: encryption failed");
	}
	if (EVP_EncryptFinal_ex(ctx, out.data() + len1, &len2) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw InvalidInputException("aes_encrypt: padding/finalization failed");
	}
	EVP_CIPHER_CTX_free(ctx);

	return HexEncode(out.data(), static_cast<size_t>(len1 + len2));
}

static std::string AesEcbDecryptRaw(const std::vector<unsigned char> &key, const std::string &ciphertext_hex) {
	if (ciphertext_hex.empty()) {
		throw InvalidInputException("aes_decrypt: ciphertext must not be empty");
	}
	if (ciphertext_hex.size() % 32 != 0) {
		throw InvalidInputException("aes_decrypt: ciphertext Hex length must be a "
		                            "multiple of 32 characters");
	}
	auto cipher_bytes = HexDecode(ciphertext_hex);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw InternalException("aes_decrypt: failed to allocate cipher context");
	}
	if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw InvalidInputException("aes_decrypt: cipher init failed");
	}

	std::vector<unsigned char> out(cipher_bytes.size() + static_cast<size_t>(EVP_CIPHER_CTX_block_size(ctx)));
	int len1 = 0;
	int len2 = 0;
	if (EVP_DecryptUpdate(ctx, out.data(), &len1, cipher_bytes.data(), static_cast<int>(cipher_bytes.size())) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw InvalidInputException("aes_decrypt: decryption failed");
	}
	if (EVP_DecryptFinal_ex(ctx, out.data() + len1, &len2) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw InvalidInputException("aes_decrypt: decryption failed; key is "
		                            "incorrect or ciphertext is corrupted");
	}
	EVP_CIPHER_CTX_free(ctx);

	return std::string(reinterpret_cast<char *>(out.data()), static_cast<size_t>(len1 + len2));
}

// ------------------------- Scalar function glue -------------------------

static void AesEncryptFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &plain_vec = args.data[0];
	auto &key_vec = args.data[1];
	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    plain_vec, key_vec, result, args.size(), [&](string_t plaintext, string_t key_value) -> string_t {
		    auto key = ParseKey(key_value.GetString(), "aes_encrypt");
		    auto cipher_hex = AesEcbEncryptRaw(key, plaintext.GetString());
		    return StringVector::AddString(result, cipher_hex);
	    });
}

static void AesDecryptFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &cipher_vec = args.data[0];
	auto &key_vec = args.data[1];
	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    cipher_vec, key_vec, result, args.size(), [&](string_t ciphertext_hex, string_t key_value) -> string_t {
		    auto key = ParseKey(key_value.GetString(), "aes_decrypt");
		    auto plain = AesEcbDecryptRaw(key, ciphertext_hex.GetString());
		    return StringVector::AddString(result, plain);
	    });
}

static void LoadInternal(ExtensionLoader &loader) {
	auto aes_encrypt_fun = ScalarFunction("aes_encrypt", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                      LogicalType::VARCHAR, AesEncryptFun);
	loader.RegisterFunction(aes_encrypt_fun);

	auto aes_decrypt_fun = ScalarFunction("aes_decrypt", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                      LogicalType::VARCHAR, AesDecryptFun);
	loader.RegisterFunction(aes_decrypt_fun);
}

void AesToolsExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string AesToolsExtension::Name() {
	return "aes_tools";
}

std::string AesToolsExtension::Version() const {
#ifdef EXT_VERSION_AES_TOOLS
	return EXT_VERSION_AES_TOOLS;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(aes_tools, loader) {
	duckdb::LoadInternal(loader);
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
