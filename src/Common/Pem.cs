// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace PasswordManagerAccess.Common
{
    internal static class Pem
    {
        public static RSAParameters ParsePrivateKeyPkcs8(byte[] asn1)
        {
            // See: https://tools.ietf.org/html/rfc5208
            var privateKeyInfo = ExtractAsn1Item(asn1, Asn1.Kind.Sequence);
            var privateKey = privateKeyInfo.Open(reader => {
                ExtractAsn1Item(reader, Asn1.Kind.Integer); // Discard the version
                ExtractAsn1Item(reader, Asn1.Kind.Sequence); // Discard the algorithm

                return ExtractAsn1Item(reader, Asn1.Kind.Bytes);
            });
            var berEncodedPrivateKey = ExtractAsn1Item(privateKey, Asn1.Kind.Sequence);

            // See: https://tools.ietf.org/html/rfc3447#appendix-C
            return berEncodedPrivateKey.Open(reader => {
                ExtractAsn1Item(reader, Asn1.Kind.Integer); // Discard the version

                // There are occasional leading zeros that must be stripped
                byte[] ReadInteger() => ExtractAsn1Item(reader, Asn1.Kind.Integer).SkipWhile(i => i == 0).ToArray();

                return new RSAParameters
                {
                    Modulus = ReadInteger(),
                    Exponent = ReadInteger(),
                    D = ReadInteger(),
                    P = ReadInteger(),
                    Q = ReadInteger(),
                    DP = ReadInteger(),
                    DQ = ReadInteger(),
                    InverseQ = ReadInteger()
                };
            });
        }

        //
        // Internal
        //

        internal static byte[] ExtractAsn1Item(byte[] bytes, Asn1.Kind expectedKind)
        {
            return bytes.Open(reader => ExtractAsn1Item(reader, expectedKind));
        }

        internal static byte[] ExtractAsn1Item(BinaryReader reader, Asn1.Kind expectedKind)
        {
            var item = Asn1.ExtractItem(reader);
            if (item.Key != expectedKind)
                throw new InternalErrorException($"ASN1 decoding failed, expected {expectedKind}, got {item.Key}");

            return item.Value;
        }
    }
}
