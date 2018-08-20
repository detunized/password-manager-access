// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;

namespace OPVault
{
    // TODO: Performance might be an issue here. There's a lot of small temporary objects in this code.
    //       For small vaults it wouldn't worth the effort to make it more efficient. On big vaults this
    //       could cause problems when decrypting everything at once. Profile this and verify.
    internal static class Opdata01
    {
        public static byte[] Decrypt(string blobBase64, KeyMac key)
        {
            return Decrypt(blobBase64.Decode64(), key);
        }

        public static byte[] Decrypt(byte[] blob, KeyMac key)
        {
            if (blob.Length < 64)
                throw CurruptedError("too short");

            using (var io = new BinaryReader(new MemoryStream(blob)))
            {
                var magic = io.ReadBytes(8);
                if (!magic.SequenceEqual("opdata01".ToBytes()))
                    throw CurruptedError("invalid signature");

                // TODO: Sloppy! Assume 2G should be enough.
                // TODO: Should be little endian! This will not work on big endian platform!
                var length = (int)io.ReadInt64();
                var iv = io.ReadBytes(16);
                var padding = 16 - length % 16;

                if (blob.Length != 32 + padding + length + 32)
                    throw CurruptedError("invalid length");

                var ciphertext = io.ReadBytes(padding + length);
                var storedTag = io.ReadBytes(32);

                // Rewind and reread everything to the tag
                io.BaseStream.Seek(0, SeekOrigin.Begin);
                var hashedContent = io.ReadBytes(32 + padding + length);

                var computedTag = Crypto.Hmac(hashedContent, key);
                if (!computedTag.SequenceEqual(storedTag))
                    throw CurruptedError("tag doesn't match");

                var plaintext = Crypto.DecryptAes(ciphertext, iv, key);
                return plaintext.Skip(padding).Take(length).ToArray();
            }
        }

        private static ParseException CurruptedError(string message)
        {
            return new ParseException(ParseException.FailureReason.Corrupted,
                                      string.Format("Opdata01 container is corrupted: {0}", message));
        }
    }
}
