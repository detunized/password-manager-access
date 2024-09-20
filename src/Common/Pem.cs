// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace PasswordManagerAccess.Common
{
    internal static class Pem
    {
        public static RSAParameters ParsePrivateKeyPkcs8(string text)
        {
            return ParsePrivateKeyPkcs8(ExtractPrivateKey(text, BeginPrivateKey, EndPrivateKey));
        }

        public static RSAParameters ParseRsaPrivateKeyPkcs1(string text)
        {
            return ParseRsaPrivateKeyPkcs1(ExtractPrivateKey(text, BeginRsaPrivateKey, EndRsaPrivateKey));
        }

        public static RSAParameters ParsePrivateKeyPkcs8(byte[] asn1)
        {
            // See: https://tools.ietf.org/html/rfc5208
            var privateKeyInfo = ExtractAsn1Item(asn1, Asn1.Kind.Sequence);
            var privateKey = privateKeyInfo.Open(reader =>
            {
                ExtractAsn1Item(reader, Asn1.Kind.Integer); // Discard the version
                ExtractAsn1Item(reader, Asn1.Kind.Sequence); // Discard the algorithm

                return ExtractAsn1Item(reader, Asn1.Kind.Bytes);
            });

            return ParseRsaPrivateKeyPkcs1(privateKey);
        }

        public static RSAParameters ParseRsaPrivateKeyPkcs1(byte[] asn1)
        {
            var berEncodedPrivateKey = ExtractAsn1Item(asn1, Asn1.Kind.Sequence);

            // See: https://tools.ietf.org/html/rfc3447#appendix-C
            return berEncodedPrivateKey.Open(reader =>
            {
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
                    InverseQ = ReadInteger(),
                };
            });
        }

        //
        // Internal
        //

        internal static byte[] ExtractPrivateKey(string text, string keyHeader, string keyFooter)
        {
            var header = text.IndexOf(keyHeader, StringComparison.Ordinal);
            if (header == -1)
                throw new InternalErrorException("Invalid private key format: header is not found");
            header += keyHeader.Length;

            var footer = text.IndexOf(keyFooter, header, StringComparison.Ordinal);
            if (footer == -1)
                throw new InternalErrorException("Invalid private key format: footer is not found");
            footer--;

            while (char.IsWhiteSpace(text[header]))
                header++;

            while (char.IsWhiteSpace(text[footer]))
                footer--;

            return text.Substring(header, footer - header + 1).Decode64();
        }

        internal static byte[] ExtractAsn1Item(byte[] bytes, Asn1.Kind expectedKind)
        {
            return bytes.Open(reader => ExtractAsn1Item(reader, expectedKind));
        }

        internal static byte[] ExtractAsn1Item(BinaryReader reader, Asn1.Kind expectedKind)
        {
            var item = Asn1.ExtractItem(reader);
            if (item.Key == expectedKind)
                return item.Value;

            throw new InternalErrorException($"ASN.1 decoding failed, expected {expectedKind}, got {item.Key}");
        }

        //
        // Data
        //

        private const string BeginPrivateKey = "-----BEGIN PRIVATE KEY-----";
        private const string EndPrivateKey = "-----END PRIVATE KEY-----";
        private const string BeginRsaPrivateKey = "-----BEGIN RSA PRIVATE KEY-----";
        private const string EndRsaPrivateKey = "-----END RSA PRIVATE KEY-----";
    }
}
