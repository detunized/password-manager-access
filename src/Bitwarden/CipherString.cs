// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using PasswordManagerAccess.Common;

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
            string[] onPipe;

            var onDot = encoded.Split('.');
            switch (onDot.Length)
            {
                case 1:
                    onPipe = onDot[0].Split('|');
                    mode = onPipe.Length == 3 ? CipherMode.Aes128CbcHmacSha256 : CipherMode.Aes256Cbc;
                    break;
                case 2:
                    onPipe = onDot[1].Split('|');
                    mode = ParseCipherMode(onDot[0]);
                    break;
                default:
                    throw MakeError("Invalid/unsupported cipher string format");
            }

            string iv = "";
            string ciphertext;
            string mac = "";

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

        // Special forced RSA parsing mode. The original implementation treats RSA strings
        // differently in some contexts and ignores some data.
        public static CipherString ParseRsa(string encoded)
        {
            CipherMode mode;
            string ciphertext;
            byte[] mac;

            var onDot = encoded.Split('.');
            switch (onDot.Length)
            {
                case 1:
                    mode = CipherMode.Rsa2048OaepSha256;
                    ciphertext = onDot[0];
                    break;
                case 2:
                    mode = ParseCipherMode(onDot[0]);
                    ciphertext = onDot[1].Split('|')[0];
                    break;
                default:
                    throw MakeError("Invalid/unsupported cipher string format");
            }

            // The mac is ignored in the original implementation and we only keep it to pass the validation.
            mac = mode switch
            {
                CipherMode.Rsa2048OaepSha256 => new byte[0],
                CipherMode.Rsa2048OaepSha1 => new byte[0],
                CipherMode.Rsa2048OaepSha256HmacSha256 => new byte[32],
                CipherMode.Rsa2048OaepSha1HmacSha256 => new byte[32],
                _ => throw MakeError("Invalid RSA cipher string format"),
            };

            return new CipherString(mode, new byte[0], ciphertext.Decode64(), mac);
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
            return Mode switch
            {
                CipherMode.Aes256Cbc => DecryptAes256Cbc(key),
                CipherMode.Aes128CbcHmacSha256 => DecryptAes128CbcHmacSha256(key),
                CipherMode.Aes256CbcHmacSha256 => DecryptAes256CbcHmacSha256(key),
                CipherMode.Rsa2048OaepSha256 => DecryptRsa2048OaepSha256(key),
                CipherMode.Rsa2048OaepSha1 => DecryptRsa2048OaepSha1(key),
                CipherMode.Rsa2048OaepSha256HmacSha256 => DecryptRsa2048OaepSha256HmacSha256(key),
                CipherMode.Rsa2048OaepSha1HmacSha256 => DecryptRsa2048OaepSha1HmacSha256(key),
                _ => throw MakeError($"Invalid cipher mode: {Mode}"),
            };
        }

        //
        // Private
        //

        private static CipherMode ParseCipherMode(string s)
        {
            return s switch
            {
                "0" => CipherMode.Aes256Cbc,
                "1" => CipherMode.Aes128CbcHmacSha256,
                "2" => CipherMode.Aes256CbcHmacSha256,
                "3" => CipherMode.Rsa2048OaepSha256,
                "4" => CipherMode.Rsa2048OaepSha1,
                "5" => CipherMode.Rsa2048OaepSha256HmacSha256,
                "6" => CipherMode.Rsa2048OaepSha1HmacSha256,
                _ => throw MakeError($"Invalid/unsupported cipher mode: {s}"),
            };
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
                throw MakeError($"Key must be 32 bytes long, got {key.Length}");

            return Crypto.DecryptAes256Cbc(Ciphertext, Iv, key);
        }

        private byte[] DecryptAes128CbcHmacSha256(byte[] key)
        {
            throw new UnsupportedFeatureException("AES-128-CBC-HMAC-SHA-256 is not supported");
        }

        private byte[] DecryptAes256CbcHmacSha256(byte[] key)
        {
            if (key.Length == 32)
                key = Util.ExpandKey(key);

            if (key.Length != 64)
                throw MakeError($"Key must be 64 bytes long, got {key.Length}");

            // First 32 bytes is the encryption key and the next 32 bytes is the MAC key
            var encKey = key.Take(32).ToArray();
            var macKey = key.Skip(32).Take(32).ToArray();

            // Encrypt-then-MAC scheme
            var mac = Crypto.HmacSha256(macKey, Iv.Concat(Ciphertext).ToArray());
            if (!mac.SequenceEqual(Mac))
                throw new CryptoException("MAC doesn't match. The vault is most likely corrupted.");

            return Crypto.DecryptAes256Cbc(Ciphertext, Iv, encKey);
        }

        private byte[] DecryptRsa2048OaepSha256(byte[] key)
        {
            if (Ciphertext.Length != 256)
                throw MakeError($"Ciphertext must be 256 bytes long, got {Ciphertext.Length}");

            return Util.DecryptRsaSha256(Ciphertext, key);
        }

        private byte[] DecryptRsa2048OaepSha1(byte[] key)
        {
            if (Ciphertext.Length != 256)
                throw MakeError($"Ciphertext must be 256 bytes long, got {Ciphertext.Length}");

            return Util.DecryptRsaSha1(Ciphertext, key);
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
