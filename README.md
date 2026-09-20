# aes_tools

`aes_tools` is a DuckDB extension that provides Hutool-compatible AES encryption and decryption functions.

## Functions

```sql
aes_encrypt(plaintext VARCHAR, key VARCHAR) -> VARCHAR
aes_decrypt(ciphertext_hex VARCHAR, key VARCHAR) -> VARCHAR
```

The implementation uses:

- AES-128 in ECB mode
- PKCS5Padding (byte-compatible with OpenSSL's PKCS7 padding for AES)
- lowercase Hex ciphertext
- a caller-supplied key that must be exactly 16 bytes after UTF-8 encoding

It is compatible with the following Hutool usage:

```java
byte[] key = "1234567891234567".getBytes(StandardCharsets.UTF_8);

String encrypted = SecureUtil.aes(key)
        .encryptHex(value, StandardCharsets.UTF_8);

String decrypted = SecureUtil.aes(key)
        .decryptStr(encrypted, StandardCharsets.UTF_8);
```

The key length is validated in bytes, not characters. A key containing multibyte UTF-8 characters may therefore be fewer than 16 characters while still occupying 16 bytes.

## Error handling

Except for DuckDB's normal `NULL` propagation, encryption and decryption errors are raised as DuckDB errors. This includes invalid key length, malformed Hex input, invalid block length, incorrect keys, and corrupted ciphertext.

Callers can choose their own fallback behavior with DuckDB's `TRY` expression:

```sql
-- Strict: stop the query when decryption fails.
SELECT aes_decrypt(encrypted_value, '1234567891234567');

-- Convert a row-level error to NULL.
SELECT TRY(aes_decrypt(encrypted_value, '1234567891234567'));

-- Explicitly preserve historical plaintext when decryption fails.
SELECT COALESCE(
    TRY(aes_decrypt(value, '1234567891234567')),
    value
);
```

Error messages never include the key, plaintext, or complete ciphertext.

## Example

```sql
SELECT aes_encrypt('root', '1234567891234567');
-- bf7d6502bed67bfcf4ad9828eeb35f5f

SELECT aes_decrypt(
    'bf7d6502bed67bfcf4ad9828eeb35f5f',
    '1234567891234567'
);
-- root
```

## Building

Initialize the submodules first:

```shell
git submodule update --init --recursive
```

OpenSSL development files must be available to CMake. Then build the release extension:

```shell
GEN=ninja make release
```

The loadable extension is generated at:

```text
build/release/extension/aes_tools/aes_tools.duckdb_extension
```

The DuckDB CLI produced by this repository links `aes_tools` statically, so its functions are immediately available:

```shell
./build/release/duckdb
```

To test the loadable artifact with a compatible DuckDB v1.4.5 CLI, enable unsigned extensions and load it explicitly:

```shell
duckdb -unsigned
```

```sql
LOAD 'build/release/extension/aes_tools/aes_tools.duckdb_extension';
```

## Development checks

Run these checks before committing:

```shell
make format-check
make tidy-check
make test
git diff --check
git status --short
```

The SQLLogicTests cover fixed Java/Hutool-compatible vectors, Unicode and empty-string round trips, `NULL` propagation, `TRY` behavior, invalid key lengths, malformed input, and incorrect-key failures.

## AES-256-GCM functions

The following additional functions interoperate with `AesGcmCrypto.java`; the AES-128-ECB functions above are unchanged:

```sql
aes_gcm_encrypt(plaintext VARCHAR, key_base64 VARCHAR) -> BLOB
aes_gcm_decrypt(ciphertext BLOB, key_base64 VARCHAR) -> VARCHAR
aes_gcm_encrypt_base64(plaintext VARCHAR, key_base64 VARCHAR) -> VARCHAR
aes_gcm_decrypt_base64(ciphertext_base64 VARCHAR, key_base64 VARCHAR) -> VARCHAR
```

The external key is standard Base64 of exactly 32 raw bytes. It is not a UTF-8 passphrase. For example, `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=` represents a **test-only** key of 32 zero bytes; use a securely generated key in production.

The binary format matches `encryptToBytes`: `version 0x01 (1 byte) + random nonce (12 bytes) + ciphertext + authentication tag (16 bytes)`. The Base64 encryptor encodes those entire versioned bytes, matching the deprecated Java `encrypt(String)` method and the `VARCHAR` branch of `AesGcmStringTypeHandler`. Encryption uses a fresh random nonce, so ciphertext differs on every call.

```sql
-- For VARBINARY / BLOB columns:
SELECT aes_gcm_decrypt(
    aes_gcm_encrypt('hello', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
);

-- For VARCHAR columns containing Base64 text:
SELECT aes_gcm_decrypt_base64(
    aes_gcm_encrypt_base64('hello', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
);
```

`aes_gcm_decrypt_base64` also accepts the historical unversioned `Base64(nonce + ciphertext + tag)` format. The BLOB decryptor also accepts historical Base64 text stored as UTF-8 bytes in a binary column, matching `decryptFromBytes`.

Unlike Java's `decryptFromBytes`, these SQL decryptors do **not** silently return unrecognized input as plaintext. Malformed Base64, unsupported version, bad key length, and authentication failure raise errors. Callers can opt into a fallback explicitly with `TRY(...)` or `COALESCE(TRY(...), original_value)`. `NULL` inputs propagate to `NULL`.

## Security note

ECB mode is deterministic and does not provide authentication. Identical plaintext blocks produce identical ciphertext blocks, and a wrong key can very rarely produce valid padding by chance. This extension uses ECB only for compatibility with existing Hutool-encrypted data. For new security-sensitive designs, prefer an authenticated mode such as AES-GCM.

## DuckDB compatibility

This repository currently targets DuckDB v1.4.5. DuckDB extensions use internal C++ APIs and must be rebuilt—and may require source changes—when upgrading DuckDB.
