// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using PasswordManagerAccess.Common;

// TODO: Here and everywhere else in Bitwarden: remove System.Exceptions

namespace PasswordManagerAccess.Bitwarden
{
    internal enum CipherMode
    {
        // Symmetric
        Aes256Cbc = 0,
        Aes128CbcHmacSha256 = 1,
        Aes256CbcHmacSha256 = 2,

        // Asymmetric
        Rsa2048OaepSha256 = 3,
        Rsa2048OaepSha1 = 4,

        // RSA/HMAC modes seem to be deprecated (why?)
        Rsa2048OaepSha256HmacSha256 = 5,
        Rsa2048OaepSha1HmacSha256 = 6,
    }

    internal class CipherString
    {
        public readonly CipherMode Mode;
        public readonly byte[] Iv;
        public readonly byte[] Ciphertext;
        public readonly byte[] Mac;

        public static CipherString Parse(string encoded)
        {
            CipherMode mode;
            string encrypted;

            var onDot = encoded.Split('.');
            switch (onDot.Length)
            {
            case 1:
                mode = CipherMode.Aes256Cbc;
                encrypted = onDot[0];
                break;
            case 2:
                mode = ParseCipherMode(onDot[0]);
                encrypted = onDot[1];
                break;
            default:
                throw MakeError("Invalid/unsupported cipher string format");
            }

            string iv = "";
            string ciphertext;
            string mac = "";

            var onPipe = encrypted.Split('|');
            switch (onPipe.Length)
            {
            case 1:
                ciphertext = onPipe[0];
                break;
            case 2:
                iv = onPipe[0];
                ciphertext = onPipe[1];
                break;
            case 3:
                iv = onPipe[0];
                ciphertext = onPipe[1];
                mac = onPipe[2];
                break;
            default:
                throw MakeError("Invalid/unsupported cipher string format");
            }

            return new CipherString(mode, iv.Decode64(), ciphertext.Decode64(), mac.Decode64());
        }

        public CipherString(CipherMode mode, byte[] iv, byte[] ciphertext, byte[] mac)
        {
            Validate(mode, iv, ciphertext, mac);

            Mode = mode;
            Iv = iv;
            Ciphertext = ciphertext;
            Mac = mac;
        }

        public byte[] Decrypt(byte[] key)
        {
            switch (Mode)
            {
            case CipherMode.Aes256Cbc:
                return DecryptAes256Cbc(key);
            case CipherMode.Aes128CbcHmacSha256:
                return DecryptAes128CbcHmacSha256(key);
            case CipherMode.Aes256CbcHmacSha256:
                return DecryptAes256CbcHmacSha256(key);
            case CipherMode.Rsa2048OaepSha256:
                return DecryptRsa2048OaepSha256(key);
            case CipherMode.Rsa2048OaepSha1:
                return DecryptRsa2048OaepSha1(key);
            case CipherMode.Rsa2048OaepSha256HmacSha256:
                return DecryptRsa2048OaepSha256HmacSha256(key);
            case CipherMode.Rsa2048OaepSha1HmacSha256:
                return DecryptRsa2048OaepSha1HmacSha256(key);
            default:
                throw new InvalidOperationException($"Invalid cipher mode: {Mode}");
            }
        }

        //
        // Private
        //

        private static CipherMode ParseCipherMode(string s)
        {
            switch (s)
            {
            case "0":
                return CipherMode.Aes256Cbc;
            case "1":
                return CipherMode.Aes128CbcHmacSha256;
            case "2":
                return CipherMode.Aes256CbcHmacSha256;
            case "3":
                return CipherMode.Rsa2048OaepSha256;
            case "4":
                return CipherMode.Rsa2048OaepSha1;
            case "5":
                return CipherMode.Rsa2048OaepSha256HmacSha256;
            case "6":
                return CipherMode.Rsa2048OaepSha1HmacSha256;
            }

            throw MakeError($"Invalid/unsupported cipher mode: {s}");
        }

        private static void Validate(CipherMode mode, byte[] iv, byte[] ciphertext, byte[] mac)
        {
            if (iv == null || ciphertext == null || mac == null)
                throw MakeError("IV, ciphertext and MAC must not be null");

            switch (mode)
            {
            case CipherMode.Aes256Cbc:
                ValidateAesIv(iv);
                if (mac.Length != 0)
                    throw MakeError("MAC is not supported in AES-256-CBC mode");
                break;
            case CipherMode.Aes128CbcHmacSha256:
            case CipherMode.Aes256CbcHmacSha256:
                ValidateAesIv(iv);
                if (mac.Length != 32)
                    throw MakeError($"MAC must be 32 bytes long, got {mac.Length}");
                break;
            case CipherMode.Rsa2048OaepSha256:
            case CipherMode.Rsa2048OaepSha1:
                if (iv.Length != 0)
                    throw MakeError("IV is not supported in RSA modes");
                if (ciphertext.Length != 256)
                    throw MakeError($"Ciphertext must be 256 bytes long, got {ciphertext.Length}");
                if (mac.Length != 0)
                    throw MakeError("MAC is not supported in unsigned RSA modes");
                break;
            case CipherMode.Rsa2048OaepSha256HmacSha256:
            case CipherMode.Rsa2048OaepSha1HmacSha256:
                if (iv.Length != 0)
                    throw MakeError("IV is not supported in RSA modes");
                if (ciphertext.Length != 256)
                    throw MakeError($"Ciphertext must be 256 bytes long, got {ciphertext.Length}");
                if (mac.Length != 32)
                    throw MakeError($"MAC must be 32 bytes long, got {mac.Length}");
                break;
            default:
                throw MakeError("Invalid cipher mode");
            }
        }

        private static void ValidateAesIv(byte[] iv)
        {
            if (iv.Length != 16)
                throw MakeError($"IV must be 16 bytes long in AES modes, got {iv.Length}");
        }

        private static InternalErrorException MakeError(string message)
        {
            return new InternalErrorException(message);
        }

        private byte[] DecryptAes256Cbc(byte[] key)
        {
            if (key.Length != 32)
                throw new InvalidOperationException($"Key must be 32 bytes long, got {key.Length}");

            return Crypto.DecryptAes256(Ciphertext, Iv, key);
        }

        private byte[] DecryptAes128CbcHmacSha256(byte[] key)
        {
            throw new UnsupportedFeatureException("AES-128-CBC-HMAC-SHA-256 is not supported");
        }

        private byte[] DecryptAes256CbcHmacSha256(byte[] key)
        {
            if (key.Length == 32)
                key = Crypto.ExpandKey(key);

            if (key.Length != 64)
                throw new InvalidOperationException($"Key must be 64 bytes long, got {key.Length}");

            // First 32 bytes is the encryption key and the next 32 bytes is the MAC key
            var encKey = key.Take(32).ToArray();
            var macKey = key.Skip(32).Take(32).ToArray();

            // Encrypt-then-MAC scheme
            var mac = Crypto.Hmac(macKey, Iv.Concat(Ciphertext).ToArray());
            if (!mac.SequenceEqual(Mac))
                throw new CryptoException("MAC doesn't match. The vault is most likely corrupted.");

            return Crypto.DecryptAes256(Ciphertext, Iv, encKey);
        }

        private byte[] DecryptRsa2048OaepSha256(byte[] key)
        {
            if (Ciphertext.Length != 256)
                throw new InvalidOperationException($"Ciphertext must be 256 bytes long, got {Ciphertext.Length}");

            return Crypto.DecryptRsaSha256(Ciphertext, key);
        }

        private byte[] DecryptRsa2048OaepSha1(byte[] key)
        {
            if (Ciphertext.Length != 256)
                throw new InvalidOperationException($"Ciphertext must be 256 bytes long, got {Ciphertext.Length}");

            return Crypto.DecryptRsaSha1(Ciphertext, key);
        }

        private byte[] DecryptRsa2048OaepSha256HmacSha256(byte[] key)
        {
            // The original code ignores the MAC
            return DecryptRsa2048OaepSha256(key);
        }

        private byte[] DecryptRsa2048OaepSha1HmacSha256(byte[] key)
        {
            // The original code ignores the MAC
            return DecryptRsa2048OaepSha1(key);
        }
    }
}
