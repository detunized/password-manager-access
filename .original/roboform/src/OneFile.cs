// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;

namespace RoboForm
{
    internal static class OneFile
    {
        public static void Parse(byte[] blob, string password)
        {
            if (blob.Length < 30) // magic(8) + flags(1) + checksum-type(1) + length(4) + md5(16)
                throw new InvalidOperationException("Onefile: File is too short");

            using (var stream = new MemoryStream(blob))
            using (var io = new BinaryReader(stream))
            {
                // 00-07 (8): magic ("onefile1")
                var magic = io.ReadBytes(8);
                if (!magic.SequenceEqual("onefile1".ToBytes()))
                    throw new InvalidOperationException(
                        string.Format("Onefile: Invalid signature: [{0}]", PrintBytes(magic)));

                // 08 (1): flags
                //     - bit 0: set if the checksum is written into the file
                //     - bit 1: set if encrypted (fails if not set in the original JavaScript code)
                //     - bit 2: set if zipped
                var flags = io.ReadByte();
                var hasChecksum = (flags & 0x01) != 0;
                var isEncrypted = (flags & 0x02) != 0;
                var isCompressed = (flags & 0x04) != 0;

                // Doesn't fail in the original code, but they always check MD5 of the content
                if (!hasChecksum)
                    throw new InvalidOperationException(
                        "Onefile: Unchecked content is not supported");

                // Fails in the original JavaScript code when not encrypted
                if (!isEncrypted)
                    throw new InvalidOperationException(
                        "Onefile: Unencrypted content is not supported");

                // 09 (1): integrity check algorithm
                //     - 0: CRC32
                //     - 1: MD5 (hardcoded to use MD5, though there's code to handle other types)
                //     - 2: SHA-1
                //     - 3: SHA-256
                var checksumType = io.ReadByte();
                if (checksumType != 1)
                    throw new InvalidOperationException(
                            string.Format("Onefile: Invalid checksum type: {0}", checksumType));

                // 10-13 (4): encrypted content length (LE)
                var contentLength = (int)io.ReadUInt32LittleEndian();
                if (contentLength < 0)
                    throw new InvalidOperationException("Onefile: Content length is negative");

                // 14-29: (16) MD5 checksum
                var storedChecksum = io.ReadBytes(16);

                // 30-end: (contentLength): encrypted content
                var content = io.ReadBytes(contentLength);
                if (content.Length != contentLength)
                    throw new InvalidOperationException("Onefile: Content is too short");

                var actualChecksum = Crypto.Md5(content);
                if (!actualChecksum.SequenceEqual(storedChecksum))
                    throw new InvalidOperationException("Onefile: Checksum doesn't match");

                var compressed = DecryptContent(content, password);
                var raw = isCompressed ? DecompressContent(compressed) : compressed;

                // TODO: Parse raw into JSON
            }
        }

        //
        // Internal
        //

        internal static byte[] DecryptContent(byte[] content, string password)
        {
            return content;
        }

        internal static byte[] DecompressContent(byte[] content)
        {
            return content;
        }

        internal static string PrintBytes(byte[] bytes)
        {
            return string.Join(", ", bytes.Select(i => i.ToString("x2")));
        }
    }
}
