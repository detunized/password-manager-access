// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;

namespace PasswordManagerAccess.TrueKey
{
    static class AesCcm
    {
        public static byte[] Encrypt(byte[] key, byte[] plaintext, byte[] iv, byte[] adata, int tagLength)
        {
            return Encrypt(new SjclAes(key), plaintext, iv, adata, tagLength);
        }

        public static byte[] Decrypt(byte[] key, byte[] ciphertext, byte[] iv, byte[] adata, int tagLength)
        {
            return Decrypt(new SjclAes(key), ciphertext, iv, adata, tagLength);
        }

        // TODO: Parametrize on cipher!
        private static byte[] Encrypt(SjclAes aes, byte[] plaintext, byte[] iv, byte[] adata, int tagLength)
        {
            var ivLength = iv.Length;
            if (ivLength < 7)
                throw new CryptoException("IV must be at least 7 bytes long");

            var inputLengthLength = ComputeLengthLength(plaintext.Length);
            if (inputLengthLength < 15 - ivLength)
                inputLengthLength = 15 - ivLength;
            iv = iv.Take(15 - inputLengthLength).ToArray();

            var tag = ComputeTag(aes, plaintext, iv, adata, tagLength, inputLengthLength);
            var ciphertextTag = ApplyCtr(aes, plaintext, iv, tag, tagLength, inputLengthLength);

            return ciphertextTag.Text.Concat(ciphertextTag.Tag.ToBytes().Take(tagLength)).ToArray();
        }

        // TODO: Parametrize on cipher!
        // TODO: Factor out shared code between Encrypt and Decrypt!
        // TODO: Validate parameters better!
        private static byte[] Decrypt(SjclAes aes, byte[] ciphertext, byte[] iv, byte[] adata, int tagLength)
        {
            var ivLength = iv.Length;
            if (ivLength < 7)
                throw new CryptoException("IV must be at least 7 bytes long");

            var plaintextLength = ciphertext.Length - tagLength;
            var ciphertextOnly = ciphertext.Take(plaintextLength).ToArray();
            var tag = new SjclQuad(ciphertext, plaintextLength);

            var inputLengthLength = ComputeLengthLength(plaintextLength);
            if (inputLengthLength < 15 - ivLength)
                inputLengthLength = 15 - ivLength;
            iv = iv.Take(15 - inputLengthLength).ToArray();

            var plaintextWithTag = ApplyCtr(aes, ciphertextOnly, iv, tag, tagLength, inputLengthLength);
            var expectedTag = ComputeTag(aes, plaintextWithTag.Text, iv, adata, tagLength, inputLengthLength);

            var expectedTagBytes = expectedTag.ToBytes().Take(tagLength);
            var actualTagBytes = plaintextWithTag.Tag.ToBytes().Take(tagLength);

            if (!actualTagBytes.SequenceEqual(expectedTagBytes))
                throw new CryptoException("CCM tag doesn't match");

            return plaintextWithTag.Text;
        }

        internal static SjclQuad ComputeTag(SjclAes aes, byte[] plaintext, byte[] iv, byte[] adata, int tagLength, int plaintextLengthLength)
        {
            if (tagLength % 2 != 0 || tagLength < 4 || tagLength > 16)
                throw new CryptoException("Tag must be 4, 8, 10, 12, 14 or 16 bytes long");

            // flags + iv + plaintext-length
            var tag = new SjclQuad(iv, -1);
            var flags = (adata.Length > 0 ? 0x40 : 0) | ((tagLength - 2) << 2) | (plaintextLengthLength - 1);
            tag.SetByte(0, (byte)flags);

            // Append plaintext length
            for (var i = 0; i < plaintextLengthLength; ++i)
                tag.SetByte(15 - i, (byte)(plaintext.Length >> i * 8));

            tag = aes.Encrypt(tag);

            var adataLength = adata.Length;
            if (adataLength > 0)
            {

                var adataWithLength = EncodeAdataLength(adataLength).Concat(adata).ToArray();
                for (var i = 0; i < adataWithLength.Length; i += 16)
                    tag = aes.Encrypt(tag ^ new SjclQuad(adataWithLength, i));
            }

            for (var i = 0; i < plaintext.Length; i += 16)
                tag = aes.Encrypt(tag ^ new SjclQuad(plaintext, i));

            return tag;
        }

        internal struct CtrResult
        {
            public CtrResult(byte[] text, SjclQuad tag)
            {
                Text = text;
                Tag = tag;
            }

            public readonly byte[] Text;
            public readonly SjclQuad Tag;
        }

        internal static CtrResult ApplyCtr(SjclAes aes, byte[] plaintext, byte[] iv, SjclQuad tag, int tagLength, int plaintextLengthLength)
        {
            // plaintextLength + iv
            var ctr = new SjclQuad(iv, -1);
            ctr.SetByte(0, (byte)(plaintextLengthLength - 1));

            // Encrypt the tag
            var encryptedTag = tag ^ aes.Encrypt(ctr);

            // Encrypt the plaintext
            var ciphertext = new byte[plaintext.Length];
            for (var i = 0; i < plaintext.Length; i += 16)
            {
                ++ctr.D;
                var block = new SjclQuad(plaintext, i) ^ aes.Encrypt(ctr);
                Array.Copy(block.ToBytes(), 0, ciphertext, i, Math.Min(16, plaintext.Length - i));
            }

            return new CtrResult(ciphertext, encryptedTag);
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
                throw new CryptoException("Adata length must be positive");

            if (length < 0xfeff) // 16 bit
                return new byte[] {(byte)(length >> 8), (byte)length};

            return new byte[] {0xff, 0xfe, (byte)(length >> 24),
                                           (byte)(length >> 16),
                                           (byte)(length >>  8),
                                           (byte)(length      )};
        }
    }
}
