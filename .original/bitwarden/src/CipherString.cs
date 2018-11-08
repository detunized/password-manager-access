// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Diagnostics.Contracts;
using System.Linq;

namespace Bitwarden
{
    internal enum CipherMode
    {
        Aes256Cbc = 0,
        Aes128CbcHmacSha256 = 1,
        Aes256CbcHmacSha256 = 2,
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

            string iv;
            string ciphertext;
            string mac = "";

            var onPipe = encrypted.Split('|');
            switch (onPipe.Length)
            {
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
            default:
                throw new InvalidOperationException("Invalid cipher mode");
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
            }

            throw MakeError(string.Format("Invalid/unsupported cipher mode: '{0}'", s));
        }

        private static void Validate(CipherMode mode, byte[] iv, byte[] ciphertext, byte[] mac)
        {
            if (iv == null || iv.Length != 16)
                throw MakeError("IV must be 16 bytes long");

            if (ciphertext == null)
                throw MakeError("Ciphertext must not be null");

            switch (mode)
            {
            case CipherMode.Aes256Cbc:
                if (mac != null && mac.Length != 0)
                    throw MakeError("MAC is not supported in AES-256-CBC mode");
                break;
            case CipherMode.Aes128CbcHmacSha256:
            case CipherMode.Aes256CbcHmacSha256:
                if (mac == null || mac.Length != 32)
                    throw MakeError("MAC must be 32 bytes long");
                break;
            default:
                throw MakeError("Invalid cipher mode");
            }
        }

        private static ClientException MakeError(string message)
        {
            return new ClientException(ClientException.FailureReason.InvalidFormat, message);
        }

        private byte[] DecryptAes256Cbc(byte[] key)
        {
            Contract.Requires(Mode == CipherMode.Aes256Cbc);

            if (key.Length != 32)
                throw new InvalidOperationException("Invalid key size");

            return Crypto.DecryptAes256(Ciphertext, Iv, key);
        }

        private byte[] DecryptAes128CbcHmacSha256(byte[] key)
        {
            Contract.Requires(Mode == CipherMode.Aes128CbcHmacSha256);

            throw new ClientException(ClientException.FailureReason.UnsupportedFeature,
                                      "AES-128-CBC-HMAC-SHA-256 is not supported");
        }

        private byte[] DecryptAes256CbcHmacSha256(byte[] key)
        {
            Contract.Requires(Mode == CipherMode.Aes256CbcHmacSha256);

            if (key.Length == 32)
                key = Crypto.ExpandKey(key);

            if (key.Length != 64)
                throw new InvalidOperationException("Invalid key size");

            // TODO: Verify the MAC
            return Crypto.DecryptAes256(Ciphertext, Iv, key.Take(32).ToArray());
        }
    }
}
