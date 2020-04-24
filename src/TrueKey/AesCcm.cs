// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.TrueKey
{
    // TODO: The implementation is not very efficient. There are a few temporary arrays allocated here and there.
    //       This should be done in a pre-allocated buffer via Span.
    static class AesCcm
    {
        public static byte[] Encrypt(byte[] key, byte[] plaintext, byte[] iv, byte[] adata, int tagLength)
        {
            var ivLength = iv.Length;
            if (ivLength < 7)
                throw new InternalErrorException ("IV must be at least 7 bytes long");

            var inputLengthLength = ComputeLengthLength(plaintext.Length);
            if (inputLengthLength < 15 - ivLength)
                inputLengthLength = 15 - ivLength;
            iv = iv.Take(15 - inputLengthLength).ToArray();

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using var cryptor = aes.CreateEncryptor();
            var tag = ComputeTag(cryptor, plaintext, iv, adata, tagLength, inputLengthLength);
            var ctr = ApplyCtr(cryptor, plaintext, iv, tag, tagLength, inputLengthLength);

            return ctr.Text.Concat(ctr.Tag.Take(tagLength)).ToArray();
        }

        // TODO: Factor out shared code between Encrypt and Decrypt!
        // TODO: Validate parameters better!
        public static byte[] Decrypt(byte[] key, byte[] ciphertext, byte[] iv, byte[] adata, int tagLength)
        {
            var ivLength = iv.Length;
            if (ivLength < 7)
                throw new InternalErrorException ("IV must be at least 7 bytes long");

            var plaintextLength = ciphertext.Length - tagLength;
            var ciphertextOnly = ciphertext.Take(plaintextLength).ToArray();

            var tag = new byte[16];
            Array.Copy(ciphertext, plaintextLength, tag, 0, tagLength);

            var inputLengthLength = ComputeLengthLength(plaintextLength);
            if (inputLengthLength < 15 - ivLength)
                inputLengthLength = 15 - ivLength;
            iv = iv.Take(15 - inputLengthLength).ToArray();

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using var encryptor = aes.CreateEncryptor();
            var plaintextWithTag = ApplyCtr(encryptor, ciphertextOnly, iv, tag, tagLength, inputLengthLength);
            var expectedTag = ComputeTag(encryptor, plaintextWithTag.Text, iv, adata, tagLength, inputLengthLength);

            var expectedTagBytes = expectedTag.Take(tagLength);
            var actualTagBytes = plaintextWithTag.Tag.Take(tagLength);

            if (!actualTagBytes.SequenceEqual(expectedTagBytes))
                throw new InternalErrorException ("CCM tag doesn't match");

            return plaintextWithTag.Text;
        }

        private static byte[] ComputeTag(ICryptoTransform encryptor,
                                         byte[] plaintext,
                                         byte[] iv,
                                         byte[] adata,
                                         int tagLength,
                                         int plaintextLengthLength)
        {
            if (tagLength % 2 != 0 || tagLength < 4 || tagLength > 16)
                throw new InternalErrorException ("Tag must be 4, 8, 10, 12, 14 or 16 bytes long");

            // flags + iv + plaintext-length
            var flags = (adata.Length > 0 ? 0x40 : 0) | ((tagLength - 2) << 2) | (plaintextLengthLength - 1);

            // Flags are at 0
            var tag = new byte[16];
            tag[0] = (byte) flags;

            // IV starts at 1
            var ivLength = Math.Min(iv.Length, 15 - plaintextLengthLength);
            for (var i = 0; i < ivLength; i++)
                tag[i + 1] = iv[i];

            // Append plaintext length
            for (var i = 0; i < plaintextLengthLength; ++i)
                tag[15 - i] = (byte) (plaintext.Length >> i * 8);

            var outputBuffer = new byte[16];
            encryptor.TransformBlock(tag, 0, 16, outputBuffer, 0);
            outputBuffer.CopyTo(tag, 0);

            var adataLength = adata.Length;
            if (adataLength > 0)
            {
                var adataWithLength = EncodeAdataLength(adataLength).Concat(adata).ToArray();
                var adataWithLengthSize = adataWithLength.Length;
                for (var offset = 0; offset < adataWithLengthSize; offset += 16)
                {
                    var blockSize = Math.Min(16, adataWithLengthSize - offset);
                    for (var i = 0; i < blockSize; i++)
                        tag[i] ^= adataWithLength[offset + i];

                    encryptor.TransformBlock(tag, 0, 16, outputBuffer, 0);
                    outputBuffer.CopyTo(tag, 0);
                }
            }

            var plaintextSize = plaintext.Length;
            for (var offset = 0; offset < plaintextSize; offset += 16)
            {
                var blockSize = Math.Min(16, plaintextSize - offset);
                for (var i = 0; i < blockSize; i++)
                    tag[i] ^= plaintext[offset + i];

                encryptor.TransformBlock(tag, 0, 16, outputBuffer, 0);
                outputBuffer.CopyTo(tag, 0);
            }

            return tag;
        }

        private static (byte[] Text, byte[] Tag) ApplyCtr(ICryptoTransform encryptor,
                                                          byte[] plaintext,
                                                          byte[] iv,
                                                          byte[] tag,
                                                          int tagLength,
                                                          int plaintextLengthLength)
        {
            // plaintextLength + iv
            var ctr = new byte[16];
            ctr[0] = (byte) (plaintextLengthLength - 1);

            // IV starts at 1
            var ivLength = Math.Min(iv.Length, 15 - plaintextLengthLength);
            for (var i = 0; i < ivLength; i++)
                ctr[i + 1] = iv[i];

            // Encrypt the tag
            var encryptedTag = new byte[16];
            encryptor.TransformBlock(ctr, 0, 16, encryptedTag, 0);

            for (var i = 0; i < 16; i++)
                encryptedTag[i] ^= tag[i];

            // Encrypt the plaintext
            var plaintextSize = plaintext.Length;
            var ciphertext = new byte[plaintextSize];
            var block = new byte[16];
            for (var offset = 0; offset < plaintextSize; offset += 16)
            {
                if (ctr[15]++ == 255) // TODO: Test on a really long input!
                    if (ctr[14]++ == 255)
                        if (ctr[13]++ == 255)
                            ctr[12]++;

                encryptor.TransformBlock(ctr, 0, 16, block, 0);
                var blockSize = Math.Min(16, plaintextSize - offset);
                for (var i = 0; i < blockSize; i++)
                    ciphertext[offset + i] = (byte) (block[i] ^ plaintext[offset + i]);
            }

            return (ciphertext, encryptedTag);
        }

        internal static int ComputeLengthLength(int plaintextLength)
        {
            var lengthLength = 2;
            while (lengthLength < 4 && (plaintextLength >> (8 * lengthLength)) > 0)
                ++lengthLength;

            return lengthLength;
        }

        internal static byte[] EncodeAdataLength(int length)
        {
            if (length <= 0)
                throw new InternalErrorException ("Adata length must be positive");

            if (length < 0xfeff) // 16 bit
                return new byte[] {(byte)(length >> 8), (byte)length};

            return new byte[] {0xff, 0xfe, (byte)(length >> 24),
                                           (byte)(length >> 16),
                                           (byte)(length >>  8),
                                           (byte)(length      )};
        }
    }
}
