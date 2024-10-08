// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.IO;

namespace PasswordManagerAccess.Common
{
    // Very-very basic ASN.1 parser. Just enough to extract the RSA key
    // parameters stored in a vault. Supports only sequences, octet strings
    // and numbers. Error handling is minimal too.
    internal static class Asn1
    {
        public enum Kind
        {
            Integer,
            Bytes,
            Null,
            Sequence,
        }

        public static KeyValuePair<Kind, byte[]> ParseItem(byte[] bytes)
        {
            return bytes.Open(ExtractItem);
        }

        public static void SkipItem(BinaryReader reader)
        {
            _ = ExtractItem(reader);
        }

        public static KeyValuePair<Kind, byte[]> ExtractItem(BinaryReader reader)
        {
            var id = reader.ReadByte();
            var tag = id & 0x1F;

            var kind = tag switch
            {
                2 => Kind.Integer,
                4 => Kind.Bytes,
                5 => Kind.Null,
                16 => Kind.Sequence,
                _ => throw new InternalErrorException($"Unknown ASN.1 tag {tag}"),
            };

            var size = (int)reader.ReadByte();
            if ((size & 0x80) != 0)
            {
                var sizeLength = size & 0x7F;
                size = 0;
                for (var i = 0; i < sizeLength; ++i)
                {
                    var oneByte = reader.ReadByte();
                    size = size * 256 + oneByte;
                }
            }

            var payload = reader.ReadBytes(size);

            return new KeyValuePair<Kind, byte[]>(kind, payload);
        }
    }
}
