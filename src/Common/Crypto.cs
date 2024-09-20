// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace PasswordManagerAccess.Common
{
    internal static class Crypto
    {
        //
        // Random
        //

        public static byte[] RandomBytes(int size)
        {
            var bytes = new byte[size];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        public static string RandomHex(int length)
        {
            if (length % 2 != 0)
                throw new InternalErrorException("length must be multiple of 2");

            return RandomBytes(length / 2).ToHex();
        }

        public static uint RandomUInt32()
        {
            return BitConverter.ToUInt32(RandomBytes(sizeof(uint)), 0);
        }

        //
        // CRC32
        //

        // This is a table-less implementation of CRC32 algorithm as described here
        // https://github.com/Michaelangel007/crc32. On that page it's referred as
        // "Formulaic "Normal" CRC32". This version seems to do more computation than
        // a table version. This is intentional, since we don't do a lot of CRC32
        // computation in this library and we rather save memory than a few cycles.
        public static uint Crc32(byte[] bytes)
        {
            uint crc = 0xFFFF_FFFF;
            foreach (var c in bytes)
            {
                crc ^= (uint)c.ReverseBits() << 24;
                for (var bit = 0; bit < 8; bit++)
                {
                    if ((crc & 0x8000_0000) != 0)
                        crc = (crc << 1) ^ 0x04C1_1DB7;
                    else
                        crc <<= 1;
                }
            }

            return (~crc).ReverseBits();
        }

        //
        // MD5
        //

        public static byte[] Md5(string message)
        {
            return Md5(message.ToBytes());
        }

        public static byte[] Md5(byte[] message)
        {
            return Md5(message, 0, message.Length);
        }

        public static byte[] Md5(byte[] message, int start, int size)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(message, start, size);
        }

        public static byte[] Md5(ReadOnlySpan<byte> message)
        {
            // TODO: On modern frameworks it's possible to use Span based Crypto API
            return Md5(message.ToArray());
        }

        //
        // SHA-1
        //

        public static byte[] Sha1(string message)
        {
            return Sha1(message.ToBytes());
        }

        public static byte[] Sha1(byte[] message)
        {
            return Sha1(message, 0, message.Length);
        }

        public static byte[] Sha1(byte[] message, int start, int size)
        {
            using var sha = SHA1.Create();
            return sha.ComputeHash(message, start, size);
        }

        public static byte[] Sha1(ReadOnlySpan<byte> message)
        {
            // TODO: On modern frameworks it's possible to use Span based Crypto API
            return Sha1(message.ToArray());
        }

        //
        // SHA-256
        //

        public static byte[] Sha256(string message)
        {
            return Sha256(message.ToBytes());
        }

        public static byte[] Sha256(byte[] message)
        {
            return Sha256(message, 0, message.Length);
        }

        public static byte[] Sha256(byte[] message, int start, int size)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(message, start, size);
        }

        public static byte[] Sha256(ReadOnlySpan<byte> message)
        {
            // TODO: On modern frameworks it's possible to use Span based Crypto API
            return Sha256(message.ToArray());
        }

        //
        // SHA-512
        //

        public static byte[] Sha512(string message)
        {
            return Sha512(message.ToBytes());
        }

        public static byte[] Sha512(byte[] message)
        {
            return Sha512(message, 0, message.Length);
        }

        public static byte[] Sha512(byte[] message, int start, int size)
        {
            using var sha = SHA512.Create();
            return sha.ComputeHash(message, start, size);
        }

        public static byte[] Sha512(ReadOnlySpan<byte> message)
        {
            // TODO: On modern frameworks it's possible to use Span based Crypto API
            return Sha512(message.ToArray());
        }

        //
        // HMAC
        //

        public static byte[] HmacSha256(byte[] key, string message)
        {
            return HmacSha256(key, message.ToBytes());
        }

        public static byte[] HmacSha256(byte[] key, byte[] message)
        {
            return HmacSha256(key, message, 0, message.Length);
        }

        public static byte[] HmacSha256(byte[] key, byte[] message, int start, int size)
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(message, start, size);
        }

        public static byte[] HmacSha256(byte[] key, ReadOnlySpan<byte> message)
        {
            // TODO: On modern frameworks it's possible to use Span based Crypto API
            return HmacSha256(key, message.ToArray());
        }

        //
        // PBKDF2
        //

        public static byte[] Pbkdf2Sha1(string password, byte[] salt, int iterations, int byteCount)
        {
            return Pbkdf2.GenerateSha1(password.ToBytes(), salt, iterations, byteCount);
        }

        public static byte[] Pbkdf2Sha256(string password, byte[] salt, int iterations, int byteCount)
        {
            return Pbkdf2.GenerateSha256(password.ToBytes(), salt, iterations, byteCount);
        }

        public static byte[] Pbkdf2Sha512(string password, byte[] salt, int iterations, int byteCount)
        {
            return Pbkdf2.GenerateSha512(password.ToBytes(), salt, iterations, byteCount);
        }

        //
        // AES
        //

        //
        // ECB
        //

        public static byte[] DecryptAes256Ecb(byte[] ciphertext, byte[] iv, byte[] key, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            return DecryptAes256(ciphertext, iv, key, CipherMode.ECB, paddingMode);
        }

        public static byte[] DecryptAes256EcbNoPadding(byte[] ciphertext, byte[] iv, byte[] key)
        {
            return DecryptAes256Ecb(ciphertext, iv, key, PaddingMode.None);
        }

        public static byte[] EncryptAes256Ecb(byte[] plaintext, byte[] iv, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return EncryptAes256(plaintext, iv, key, CipherMode.ECB, padding);
        }

        public static byte[] EncryptAes256EcbNoPadding(byte[] plaintext, byte[] iv, byte[] key)
        {
            return EncryptAes256Ecb(plaintext, iv, key, PaddingMode.None);
        }

        //
        // CBC
        //

        public static byte[] DecryptAes256Cbc(byte[] ciphertext, byte[] iv, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return DecryptAes256(ciphertext, iv, key, CipherMode.CBC, padding);
        }

        public static byte[] DecryptAes256CbcNoPadding(byte[] ciphertext, byte[] iv, byte[] key)
        {
            return DecryptAes256Cbc(ciphertext, iv, key, PaddingMode.None);
        }

        public static byte[] EncryptAes256Cbc(byte[] plaintext, byte[] iv, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return EncryptAes256(plaintext, iv, key, CipherMode.CBC, padding);
        }

        public static byte[] EncryptAes256CbcNoPadding(byte[] plaintext, byte[] iv, byte[] key)
        {
            return EncryptAes256Cbc(plaintext, iv, key, PaddingMode.None);
        }

        //
        // Generic
        //

        public static byte[] DecryptAes256(byte[] ciphertext, byte[] iv, byte[] key, CipherMode cipherMode, PaddingMode padding)
        {
            return CryptAes256(ciphertext, iv, key, cipherMode, padding, aes => aes.CreateDecryptor());
        }

        public static byte[] EncryptAes256(byte[] plaintext, byte[] iv, byte[] key, CipherMode cipherMode, PaddingMode padding)
        {
            return CryptAes256(plaintext, iv, key, cipherMode, padding, aes => aes.CreateEncryptor());
        }

        private static byte[] CryptAes256(
            byte[] text,
            byte[] iv,
            byte[] key,
            CipherMode cipherMode,
            PaddingMode padding,
            Func<SymmetricAlgorithm, ICryptoTransform> createCryptor
        )
        {
            static CryptoException MakeError(Exception e) => new CryptoException("AES decryption failed", e);

            try
            {
                using var aes = Aes.Create();
                aes.KeySize = 256;
                aes.Key = key;
                aes.Mode = cipherMode;
                aes.IV = iv;
                aes.Padding = padding;

                // TOOD: Look into performance of this thing. Sometimes there's a lot of these
                // operations happening while the vault is being open. This is epecially true for
                // large vaults with tousands of items in them. There's a lot of (unnecessary)
                // temporary objects and memory copying here!
                using var cryptor = createCryptor(aes);
                using var inputStream = new MemoryStream(text, false);
                using var cryptoStream = new CryptoStream(inputStream, cryptor, CryptoStreamMode.Read);

                // Here we use quite a small buffer, since most of the time the encrypted data is
                // quite short.
                //
                // TODO: See if it makes sense to base the buffer size on the input size. Definitely
                // it doesn't make sense to have a buffer that is lager than the input.
                return cryptoStream.ReadAll(256);
            }
            catch (CryptographicException e)
            {
                throw MakeError(e);
            }
            // This should not be needed. But due to some bug in Mono the CryptographicException is not getting
            // thrown on all occasions, sometimes we get ArgumentException instead.
            catch (ArgumentException e)
            {
                throw MakeError(e);
            }
        }

        //
        // XChaCha20Poly1305
        //

        internal static byte[] DecryptXChaCha20Poly1305(byte[] ciphertext, byte[] nonce, byte[] key)
        {
            if (ciphertext.Length < 16)
                throw new InternalErrorException($"Ciphertext must be at least 16 bytes long, got {ciphertext.Length}");

            var xChaCha20 = new XChaCha20(key, nonce);

            // Skip 64 bytes advancing the counter to 1.
            // TODO: We're relying on the internal implementation details here. Not so good.
            //       Introduce a [X]ChaCha20.SetCounter method to set it explicitly.
            var polyKey = new byte[32]; // TODO: Temp alloc, replace with stackalloc
            xChaCha20.ProcessBytes(polyKey, 0, 32, polyKey, 0);
            var discard = new byte[32]; // TODO: Temp alloc, replace with stackalloc
            xChaCha20.ProcessBytes(discard, 0, 32, discard, 0);

            // Verify the Poly1305 tag.
            var length = ciphertext.Length - 16;
            var blockLength = length / Poly1305.BlockSize * Poly1305.BlockSize;
            Span<byte> block = stackalloc byte[Poly1305.BlockSize];

            var poly = new Poly1305(polyKey);

            // TODO: Update the tag with associated data.

            // Ciphertext
            poly.Update(ciphertext.AsSpan().Slice(0, blockLength));

            // Pad the last block with zeroes
            if (length > blockLength)
            {
                block.Fill(0);
                ciphertext.AsSpan().Slice(blockLength, length - blockLength).CopyTo(block);
                poly.Update(block);
            }

            // Write lengths
            Unsafe.WriteUnaligned(ref block[0], 0UL);
            Unsafe.WriteUnaligned(ref block[8], (ulong)length);
            poly.Update(block);

            poly.Finish(block);

            if (!AreEqual(block, ciphertext.AsRoSpan().Slice(length, 16)))
                throw new CryptoException("Tag doesn't match, the data is corrupted or the key is incorrect");

            var plaintext = new byte[length];
            xChaCha20.ProcessBytes(ciphertext, 0, length, plaintext, 0);

            return plaintext;
        }

        //
        // RSA
        //

        public static byte[] DecryptRsaPkcs1(byte[] ciphertext, RSAParameters privateKey)
        {
            // PKCS1 is supported on all platforms
            return DecryptRsaSystemCryptography(ciphertext, privateKey, RSAEncryptionPadding.Pkcs1);
        }

        public static byte[] DecryptRsaSha1(byte[] ciphertext, RSAParameters privateKey)
        {
            // OAEP-SHA1 is supported on all platforms
            return DecryptRsaSystemCryptography(ciphertext, privateKey, RSAEncryptionPadding.OaepSHA1);
        }

        public static byte[] DecryptRsaSha256(byte[] ciphertext, RSAParameters privateKey)
        {
            // OAEP-SHA256 support is very messy

            // 1. The easiest case is .NET 6+. RSA.Create() supports this out of the box on all platforms.
            return DecryptRsaSystemCryptography(ciphertext, privateKey, RSAEncryptionPadding.OaepSHA256);
        }

        internal static byte[] DecryptRsaSystemCryptography(byte[] ciphertext, RSAParameters privateKey, RSAEncryptionPadding padding)
        {
            using var rsa = RSA.Create();
            return DecryptRsaSystemCryptography(ciphertext, rsa, privateKey, padding);
        }

        internal static byte[] DecryptRsaSystemCryptography(byte[] ciphertext, RSA rsa, RSAParameters privateKey, RSAEncryptionPadding padding)
        {
            try
            {
                rsa.ImportParameters(RestoreLeadingZeros(privateKey));
                return rsa.Decrypt(ciphertext, padding);
            }
            catch (CryptographicException e)
            {
                throw new CryptoException("RSA decryption failed", e);
            }
        }

        // Sometimes we see the numbers with too few bits, which is normal BTW. The .NET is very
        // picky about that and it requires us to add the leading zeros to have the exact length.
        // The exact length is not really known so we're trying to guess it from the numbers
        // themselves. This doesn't seem to be a problem on .NET Core, it only fails on Windows
        // with .NET Framework 4+. This operation is fairly cheap when all the lengths are ok and
        // there are no unnecessary allocations happening in that case.
        internal static RSAParameters RestoreLeadingZeros(RSAParameters parameters)
        {
            var bytes = GuessKeyBitLength(parameters) / 8;
            return new RSAParameters()
            {
                Exponent = parameters.Exponent,
                Modulus = PrepadWithZeros(parameters.Modulus, bytes),
                P = PrepadWithZeros(parameters.P, bytes / 2),
                Q = PrepadWithZeros(parameters.Q, bytes / 2),
                DP = PrepadWithZeros(parameters.DP, bytes / 2),
                DQ = PrepadWithZeros(parameters.DQ, bytes / 2),
                InverseQ = PrepadWithZeros(parameters.InverseQ, bytes / 2),
                D = PrepadWithZeros(parameters.D, bytes),
            };
        }

        internal static int GuessKeyBitLength(RSAParameters parameters)
        {
            var bits = parameters.Modulus.Length * 8;

            foreach (var i in SupportedRsaBits)
                if (bits <= i && bits > i * 3 / 4)
                    return i;

            throw new UnsupportedFeatureException($"{bits}-bit RSA encryption mode is not supported");
        }

        internal static byte[] PrepadWithZeros(byte[] bytes, int desiredLength)
        {
            var length = bytes.Length;

            if (length == desiredLength)
                return bytes;

            if (length < desiredLength)
            {
                var padded = new byte[desiredLength];
                Array.Copy(bytes, 0, padded, desiredLength - length, length);
                return padded;
            }

            throw new InternalErrorException("The input array is too long to be padded");
        }

        private static readonly int[] SupportedRsaBits = { 1024, 2048, 4096 };

        //
        // Misc
        //

        // TODO: Benchmark this against simple indexed version and enable unsafe if it's worth it
        public static bool AreEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length)
                return false;

            if (a.Length == 0)
                return true;

            var s = 0;
#if HAVE_UNSAFE
            unsafe
            {
                fixed (byte* ap = a)
                fixed (byte* bp = b)
                {
                    var ai = ap;
                    var bi = bp;
                    for (var i = 0; i < a.Length; i++)
                    {
                        s |= *ai ^ *bi;
                        ai += 1;
                        bi += 1;
                    }
                }
            }
#else
            for (var i = 0; i < a.Length; i++)
                s |= a[i] ^ b[i];
#endif

            return s == 0;
        }
    }
}
