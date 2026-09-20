#pragma once

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/function/scalar_function.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace duckdb {

static constexpr unsigned char GCM_VERSION = 0x01;
static constexpr size_t GCM_NONCE_SIZE = 12;
static constexpr size_t GCM_TAG_SIZE = 16;
static constexpr size_t GCM_HEADER_SIZE = 1 + GCM_NONCE_SIZE;
using GcmContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

static std::vector<unsigned char> GcmBase64Decode(const std::string &value, const char *function_name) {
	if (value.empty() || value.size() % 4 || value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
		throw InvalidInputException("%s: invalid Base64 input", function_name);
	}
	size_t padding = value.back() == '=' ? 1 : 0;
	if (value.size() > 1 && value[value.size() - 2] == '=') {
		padding++;
	}
	for (size_t i = 0; i < value.size() - padding; i++) {
		char c = value[i];
		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/')) {
			throw InvalidInputException("%s: invalid Base64 input", function_name);
		}
	}
	std::vector<unsigned char> decoded(value.size() / 4 * 3);
	int n = EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char *>(value.data()),
	                        static_cast<int>(value.size()));
	if (n < 0 || static_cast<size_t>(n) < padding) {
		throw InvalidInputException("%s: invalid Base64 input", function_name);
	}
	decoded.resize(static_cast<size_t>(n) - padding);
	std::string canonical((decoded.size() + 2) / 3 * 4 + 1, '\0');
	EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&canonical[0]), decoded.data(), static_cast<int>(decoded.size()));
	canonical.pop_back();
	if (canonical != value) {
		throw InvalidInputException("%s: invalid Base64 input", function_name);
	}
	return decoded;
}

static std::string GcmBase64Encode(const std::string &value) {
	if (value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
		throw InvalidInputException("aes_gcm_encrypt_base64: input is too large");
	}
	std::string result((value.size() + 2) / 3 * 4 + 1, '\0');
	EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&result[0]),
	                reinterpret_cast<const unsigned char *>(value.data()), static_cast<int>(value.size()));
	result.pop_back();
	return result;
}

static std::vector<unsigned char> GcmKey(const std::string &base64, const char *function_name) {
	auto key = GcmBase64Decode(base64, function_name);
	if (key.size() != 32) {
		throw InvalidInputException("%s: key must decode to exactly 32 bytes (got %d bytes)", function_name,
		                            static_cast<int>(key.size()));
	}
	return key;
}

static std::string GcmEncrypt(const std::string &plaintext, const std::vector<unsigned char> &key) {
	if (plaintext.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
		throw InvalidInputException("aes_gcm_encrypt: plaintext is too large");
	}
	unsigned char nonce[GCM_NONCE_SIZE];
	if (RAND_bytes(nonce, static_cast<int>(GCM_NONCE_SIZE)) != 1) {
		throw InternalException("aes_gcm_encrypt: nonce generation failed");
	}
	GcmContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
	    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(GCM_NONCE_SIZE), nullptr) != 1 ||
	    EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce) != 1) {
		throw InternalException("aes_gcm_encrypt: cipher initialization failed");
	}
	std::string result(GCM_HEADER_SIZE + plaintext.size() + GCM_TAG_SIZE, '\0');
	result[0] = static_cast<char>(GCM_VERSION);
	std::copy(nonce, nonce + GCM_NONCE_SIZE, result.begin() + 1);
	int written = 0;
	int final_written = 0;
	if (EVP_EncryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(&result[GCM_HEADER_SIZE]), &written,
	                      reinterpret_cast<const unsigned char *>(plaintext.data()),
	                      static_cast<int>(plaintext.size())) != 1 ||
	    EVP_EncryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(&result[GCM_HEADER_SIZE + written]),
	                        &final_written) != 1 ||
	    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(GCM_TAG_SIZE),
	                        &result[GCM_HEADER_SIZE + written + final_written]) != 1) {
		throw InternalException("aes_gcm_encrypt: encryption failed");
	}
	result.resize(GCM_HEADER_SIZE + static_cast<size_t>(written + final_written) + GCM_TAG_SIZE);
	return result;
}

static std::string GcmDecryptPayload(const std::string &data, size_t nonce_offset,
                                     const std::vector<unsigned char> &key, const char *function_name) {
	size_t header_size = nonce_offset + GCM_NONCE_SIZE;
	if (data.size() < header_size + GCM_TAG_SIZE) {
		throw InvalidInputException("%s: ciphertext is too short", function_name);
	}
	size_t cipher_size = data.size() - header_size - GCM_TAG_SIZE;
	if (cipher_size > static_cast<size_t>(std::numeric_limits<int>::max())) {
		throw InvalidInputException("%s: ciphertext is too large", function_name);
	}
	GcmContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
	    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(GCM_NONCE_SIZE), nullptr) != 1 ||
	    EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
	                       reinterpret_cast<const unsigned char *>(data.data() + nonce_offset)) != 1) {
		throw InternalException("%s: cipher initialization failed", function_name);
	}
	std::string plaintext(cipher_size + GCM_TAG_SIZE, '\0');
	int written = 0;
	int final_written = 0;
	if (EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(&plaintext[0]), &written,
	                      reinterpret_cast<const unsigned char *>(data.data() + header_size),
	                      static_cast<int>(cipher_size)) != 1 ||
	    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(GCM_TAG_SIZE),
	                        const_cast<char *>(data.data() + data.size() - GCM_TAG_SIZE)) != 1 ||
	    EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(&plaintext[written]), &final_written) != 1) {
		throw InvalidInputException("%s: authentication failed; key or ciphertext is incorrect", function_name);
	}
	plaintext.resize(static_cast<size_t>(written + final_written));
	return plaintext;
}

static std::string GcmDecryptVersioned(const std::string &data, const std::vector<unsigned char> &key,
                                       const char *function_name) {
	if (data.empty() || static_cast<unsigned char>(data[0]) != GCM_VERSION) {
		throw InvalidInputException("%s: unsupported ciphertext version (expected 0x01)", function_name);
	}
	return GcmDecryptPayload(data, 1, key, function_name);
}

static std::string GcmDecryptText(const std::string &value, const std::vector<unsigned char> &key,
                                  const char *function_name) {
	auto decoded = GcmBase64Decode(value, function_name);
	std::string data(reinterpret_cast<const char *>(decoded.data()), decoded.size());
	if (!data.empty() && static_cast<unsigned char>(data[0]) == GCM_VERSION) {
		try {
			return GcmDecryptVersioned(data, key, function_name);
		} catch (const InvalidInputException &) {
			// A legacy nonce can coincidentally start with the version byte.
		}
	}
	return GcmDecryptPayload(data, 0, key, function_name);
}

static std::string GcmDecryptBlob(const std::string &data, const std::vector<unsigned char> &key) {
	if (!data.empty() && static_cast<unsigned char>(data[0]) == GCM_VERSION) {
		return GcmDecryptVersioned(data, key, "aes_gcm_decrypt");
	}
	if (data.empty() || !((data[0] >= 'A' && data[0] <= 'Z') || (data[0] >= 'a' && data[0] <= 'z') ||
	                      (data[0] >= '0' && data[0] <= '9') || data[0] == '+' || data[0] == '/')) {
		throw InvalidInputException("aes_gcm_decrypt: unsupported ciphertext version (expected 0x01)");
	}
	// Java decryptFromBytes also accepts historical Base64 text stored in a binary column.
	return GcmDecryptText(data, key, "aes_gcm_decrypt");
}

static void GcmEncryptBlobFun(DataChunk &args, ExpressionState &state, Vector &result) {
	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    args.data[0], args.data[1], result, args.size(), [&](string_t plaintext, string_t key_base64) -> string_t {
		    return StringVector::AddString(
		        result, GcmEncrypt(plaintext.GetString(), GcmKey(key_base64.GetString(), "aes_gcm_encrypt")));
	    });
}

static void GcmDecryptBlobFun(DataChunk &args, ExpressionState &state, Vector &result) {
	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    args.data[0], args.data[1], result, args.size(), [&](string_t ciphertext, string_t key_base64) -> string_t {
		    return StringVector::AddString(
		        result, GcmDecryptBlob(ciphertext.GetString(), GcmKey(key_base64.GetString(), "aes_gcm_decrypt")));
	    });
}

static void GcmEncryptTextFun(DataChunk &args, ExpressionState &state, Vector &result) {
	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    args.data[0], args.data[1], result, args.size(), [&](string_t plaintext, string_t key_base64) -> string_t {
		    return StringVector::AddString(
		        result, GcmBase64Encode(GcmEncrypt(plaintext.GetString(),
		                                           GcmKey(key_base64.GetString(), "aes_gcm_encrypt_base64"))));
	    });
}

static void GcmDecryptTextFun(DataChunk &args, ExpressionState &state, Vector &result) {
	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    args.data[0], args.data[1], result, args.size(), [&](string_t ciphertext, string_t key_base64) -> string_t {
		    return StringVector::AddString(
		        result, GcmDecryptText(ciphertext.GetString(), GcmKey(key_base64.GetString(), "aes_gcm_decrypt_base64"),
		                               "aes_gcm_decrypt_base64"));
	    });
}

static void RegisterAesGcmFunctions(ExtensionLoader &loader) {
	loader.RegisterFunction(ScalarFunction("aes_gcm_encrypt", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                       LogicalType::BLOB, GcmEncryptBlobFun));
	loader.RegisterFunction(ScalarFunction("aes_gcm_decrypt", {LogicalType::BLOB, LogicalType::VARCHAR},
	                                       LogicalType::VARCHAR, GcmDecryptBlobFun));
	loader.RegisterFunction(ScalarFunction("aes_gcm_encrypt_base64", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                       LogicalType::VARCHAR, GcmEncryptTextFun));
	loader.RegisterFunction(ScalarFunction("aes_gcm_decrypt_base64", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                       LogicalType::VARCHAR, GcmDecryptTextFun));
}

} // namespace duckdb
