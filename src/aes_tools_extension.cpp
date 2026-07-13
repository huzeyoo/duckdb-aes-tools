#define DUCKDB_EXTENSION_MAIN

#include "aes_tools_extension.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include <openssl/evp.h>
#include <openssl/err.h>

#include <string>
#include <vector>

// -----------------------------------------------------------------------------
// AES-ECB/PKCS5Padding + Base64 scalar functions for DuckDB, compatible with
// Java's `Cipher.getInstance("AES")` default behaviour (AES/ECB/PKCS5Padding).
//
//   aes_encrypt(plaintext VARCHAR, key_base64 VARCHAR) -> ciphertext_base64 VARCHAR
//   aes_decrypt(ciphertext_base64 VARCHAR, key_base64 VARCHAR) -> plaintext VARCHAR
//
// The key must be the RAW AES key bytes (16/24/32 bytes for AES-128/192/256),
// base64-encoded. This is NOT the seed string fed into Java's KeyGenerator —
// it is the actual SecretKey.getEncoded() bytes. Extract that once from your
// Java code and pass its Base64 form into these functions.
// -----------------------------------------------------------------------------

namespace duckdb {

// ------------------------- Base64 helpers -------------------------

static const char kB64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                "abcdefghijklmnopqrstuvwxyz"
                                "0123456789+/";

static std::string Base64Encode(const unsigned char *data, size_t len) {
	std::string out;
	out.reserve(((len + 2) / 3) * 4);
	size_t i = 0;
	while (i + 3 <= len) {
		unsigned int n = (static_cast<unsigned int>(data[i]) << 16) | (static_cast<unsigned int>(data[i + 1]) << 8) |
		                 static_cast<unsigned int>(data[i + 2]);
		out += kB64Table[(n >> 18) & 0x3F];
		out += kB64Table[(n >> 12) & 0x3F];
		out += kB64Table[(n >> 6) & 0x3F];
		out += kB64Table[n & 0x3F];
		i += 3;
	}
	size_t rem = len - i;
	if (rem == 1) {
		unsigned int n = static_cast<unsigned int>(data[i]) << 16;
		out += kB64Table[(n >> 18) & 0x3F];
		out += kB64Table[(n >> 12) & 0x3F];
		out += "==";
	} else if (rem == 2) {
		unsigned int n = (static_cast<unsigned int>(data[i]) << 16) | (static_cast<unsigned int>(data[i + 1]) << 8);
		out += kB64Table[(n >> 18) & 0x3F];
		out += kB64Table[(n >> 12) & 0x3F];
		out += kB64Table[(n >> 6) & 0x3F];
		out += "=";
	}
	return out;
}

static int B64Val(unsigned char c) {
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	if (c == '+') {
		return 62;
	}
	if (c == '/') {
		return 63;
	}
	return -1;
}

static std::vector<unsigned char> Base64Decode(const std::string &in) {
	if (in.empty()) {
		return {};
	}
	if (in.size() % 4 != 0) {
		throw InvalidInputException("Invalid Base64 input: length must be a multiple of 4");
	}

	size_t padding = 0;
	if (in.back() == '=') {
		padding++;
	}
	if (in.size() >= 2 && in[in.size() - 2] == '=') {
		padding++;
	}
	for (size_t i = 0; i < in.size() - padding; i++) {
		if (B64Val(static_cast<unsigned char>(in[i])) < 0) {
			throw InvalidInputException("Invalid Base64 input: invalid character at position %d", static_cast<int>(i));
		}
	}
	for (size_t i = in.size() - padding; i < in.size(); i++) {
		if (in[i] != '=') {
			throw InvalidInputException("Invalid Base64 input: invalid padding");
		}
	}
	if ((padding == 1 && B64Val(static_cast<unsigned char>(in[in.size() - 2])) < 0) ||
	    (padding == 2 && B64Val(static_cast<unsigned char>(in[in.size() - 3])) < 0)) {
		throw InvalidInputException("Invalid Base64 input: invalid padding");
	}

	std::vector<unsigned char> out;
	out.reserve((in.size() / 4) * 3 - padding);
	for (size_t i = 0; i < in.size(); i += 4) {
		const auto d0 = static_cast<unsigned int>(B64Val(static_cast<unsigned char>(in[i])));
		const auto d1 = static_cast<unsigned int>(B64Val(static_cast<unsigned char>(in[i + 1])));
		out.push_back(static_cast<unsigned char>((d0 << 2) | (d1 >> 4)));
		if (in[i + 2] != '=') {
			const auto d2 = static_cast<unsigned int>(B64Val(static_cast<unsigned char>(in[i + 2])));
			out.push_back(static_cast<unsigned char>((d1 << 4) | (d2 >> 2)));
			if (in[i + 3] != '=') {
				const auto d3 = static_cast<unsigned int>(B64Val(static_cast<unsigned char>(in[i + 3])));
				out.push_back(static_cast<unsigned char>((d2 << 6) | d3));
			}
		}
	}
	// Require the canonical encoding emitted by Java's Base64 encoder.
	if ((padding == 1 && (B64Val(static_cast<unsigned char>(in[in.size() - 2])) & 0x03) != 0) ||
	    (padding == 2 && (B64Val(static_cast<unsigned char>(in[in.size() - 3])) & 0x0F) != 0)) {
		throw InvalidInputException("Invalid Base64 input: non-zero trailing bits");
	}
	return out;
}

// ------------------------- AES-ECB core -------------------------

static const EVP_CIPHER *PickEcbCipher(size_t key_len) {
	switch (key_len) {
	case 16:
		return EVP_aes_128_ecb();
	case 24:
		return EVP_aes_192_ecb();
	case 32:
		return EVP_aes_256_ecb();
	default:
		throw InvalidInputException("AES key must decode to 16, 24 or 32 raw bytes (got %d bytes). "
		                            "Make sure you are passing the Base64 of the actual SecretKey bytes, "
		                            "not the seed/passphrase string.",
		                            static_cast<int>(key_len));
	}
}

static std::string AesEcbEncryptRaw(const std::vector<unsigned char> &key, const std::string &plaintext) {
	const EVP_CIPHER *cipher = PickEcbCipher(key.size());

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw InternalException("aes_encrypt: failed to allocate cipher context");
	}
	if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw InvalidInputException("aes_encrypt: cipher init failed");
	}
	// PKCS padding is enabled by default in OpenSSL EVP (matches Java's PKCS5Padding for AES).
	std::vector<unsigned char> out(plaintext.size() + static_cast<size_t>(EVP_CIPHER_CTX_block_size(ctx)));
	int len1 = 0, len2 = 0;
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

	return Base64Encode(out.data(), static_cast<size_t>(len1 + len2));
}

static std::string AesEcbDecryptRaw(const std::vector<unsigned char> &key, const std::string &ciphertext_b64) {
	auto cipher_bytes = Base64Decode(ciphertext_b64);
	if (cipher_bytes.empty()) {
		throw InvalidInputException("aes_decrypt: ciphertext must not be empty");
	}
	if (cipher_bytes.size() % 16 != 0) {
		throw InvalidInputException("aes_decrypt: ciphertext length must be a multiple of the AES block size");
	}

	const EVP_CIPHER *cipher = PickEcbCipher(key.size());

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw InternalException("aes_decrypt: failed to allocate cipher context");
	}
	if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw InvalidInputException("aes_decrypt: cipher init failed");
	}
	std::vector<unsigned char> out(cipher_bytes.size() + static_cast<size_t>(EVP_CIPHER_CTX_block_size(ctx)));
	int len1 = 0, len2 = 0;
	if (EVP_DecryptUpdate(ctx, out.data(), &len1, cipher_bytes.data(), static_cast<int>(cipher_bytes.size())) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw InvalidInputException("aes_decrypt: decryption failed (malformed ciphertext?)");
	}
	if (EVP_DecryptFinal_ex(ctx, out.data() + len1, &len2) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw InvalidInputException("aes_decrypt: padding check failed - wrong key or corrupted/truncated ciphertext");
	}
	EVP_CIPHER_CTX_free(ctx);

	return std::string(reinterpret_cast<char *>(out.data()), static_cast<size_t>(len1 + len2));
}

// ------------------------- Scalar function glue -------------------------

static void AesEncryptFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &plain_vec = args.data[0];
	auto &key_vec = args.data[1];
	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    plain_vec, key_vec, result, args.size(), [&](string_t plaintext, string_t key_b64) -> string_t {
		    auto key = Base64Decode(key_b64.GetString());
		    auto cipher_b64 = AesEcbEncryptRaw(key, plaintext.GetString());
		    return StringVector::AddString(result, cipher_b64);
	    });
}

static void AesDecryptFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &cipher_vec = args.data[0];
	auto &key_vec = args.data[1];
	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    cipher_vec, key_vec, result, args.size(), [&](string_t ciphertext_b64, string_t key_b64) -> string_t {
		    auto key = Base64Decode(key_b64.GetString());
		    auto plain = AesEcbDecryptRaw(key, ciphertext_b64.GetString());
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
