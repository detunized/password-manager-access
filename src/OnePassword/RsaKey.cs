// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
{
    internal class RsaKey: IDecryptor
    {
        public const string ContainerType = "b5+jwk+json";
        public const string EncryptionScheme = "RSA-OAEP";

        public readonly string Id;
        public readonly RSAParameters Parameters;

        public static RsaKey Parse(Response.RsaKey json)
        {
            RSAParameters parameters = new RSAParameters
            {
                Exponent = json.Exponent.Decode64Loose(),
                Modulus = json.Modulus.Decode64Loose(),
                P = json.P.Decode64Loose(),
                Q = json.Q.Decode64Loose(),
                DP = json.DP.Decode64Loose(),
                DQ = json.DQ.Decode64Loose(),
                InverseQ = json.InverseQ.Decode64Loose(),
                D = json.D.Decode64Loose(),
            };

            return new RsaKey(json.Id, RestoreLeadingZeros(parameters));
        }

        public RsaKey(string id, RSAParameters parameters)
        {
            Id = id;
            Parameters = parameters;
        }

        public byte[] Decrypt(Encrypted e)
        {
            if (e.KeyId != Id)
                throw new InternalErrorException("Mismatching key id");

            if (e.Scheme != EncryptionScheme)
                throw new InternalErrorException(
                    $"Invalid encryption scheme '{e.Scheme}', expected '{EncryptionScheme}'");

            return Crypto.DecryptRsaSha1(e.Ciphertext, Parameters);
        }

        //
        // Internal
        //

        // Sometimes we see the numbers with too few bits, which is normal BTW. The .NET is very
        // picky about that and it requires us to add the leading zeros to have the exact length.
        // The exact length is not really known so we're trying to guess it from the numbers
        // themselves.
        internal static RSAParameters RestoreLeadingZeros(RSAParameters parameters)
        {
            var bytes = GuessKeyBitLength(parameters) / 8;
            return new RSAParameters()
            {
                Exponent = parameters.Exponent,
                Modulus = PrepadWithZeros(parameters.Modulus, bytes),
                P = PrepadWithZeros(parameters.P, bytes / 2),
                Q = PrepadWithZeros(parameters.Q, bytes / 2),
                DP = PrepadWithZeros(parameters.DP, bytes / 2),
                DQ = PrepadWithZeros(parameters.DQ, bytes / 2),
                InverseQ = PrepadWithZeros(parameters.InverseQ, bytes / 2),
                D = PrepadWithZeros(parameters.D, bytes),
            };
        }

        internal static int GuessKeyBitLength(RSAParameters parameters)
        {
            var bits = parameters.Modulus.Length * 8;

            foreach (var i in SupportedRsaBits)
                if (bits <= i && bits > i * 3 / 4)
                    return i;

            throw new UnsupportedFeatureException($"{bits}-bit RSA encryption mode is not supported");
        }

        internal static byte[] PrepadWithZeros(byte[] bytes, int desiredLength)
        {
            var length = bytes.Length;

            if (length == desiredLength)
                return bytes;

            if (length < desiredLength)
                return new byte[desiredLength - length].Concat(bytes).ToArray();

            throw new InternalErrorException("The input array is too long to be padded");
        }

        private static readonly int[] SupportedRsaBits = new[] {1024, 2048, 4096};
    }
}
