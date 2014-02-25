// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;

namespace LastPass
{
    // Very-very basic ASN.1 parser. Just enough to extract the RSA key
    // parameters stored in a vault. Supports only sequences, octet strings
    // and numbers. Error handling is minimal too.
    static class Asn1
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
            return ParserHelper.WithBytes(bytes, reader => ExtractItem(reader));
        }

        public static KeyValuePair<Kind, byte[]> ExtractItem(BinaryReader reader)
        {
            var id = reader.ReadByte();
            var tag = id & 0x1F;

            Kind kind;
            switch (tag)
            {
            case 2:
                kind = Kind.Integer;
                break;
            case 4:
                kind = Kind.Bytes;
                break;
            case 5:
                kind = Kind.Null;
                break;
            case 16:
                kind = Kind.Sequence;
                break;
            default:
                throw new ArgumentException(string.Format("Unknown ASN.1 tag {0}", tag));
            }

            int size = reader.ReadByte();
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
