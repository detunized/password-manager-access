// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;

namespace OnePassword
{
    internal class RsaKey
    {
        public const string ContainerType = "b5+jwk+json";
        public const string EncryptionScheme = "RSA-OAEP";

        public readonly string Id;
        public readonly RSAParameters Parameters;

        public static RsaKey Parse(JToken json)
        {
            RSAParameters parameters = new RSAParameters
            {
                Exponent = json.StringAt("e").Decode64(),
                Modulus = json.StringAt("n").Decode64(),
                P = json.StringAt("p").Decode64(),
                Q = json.StringAt("q").Decode64(),
                DP = json.StringAt("dp").Decode64(),
                DQ = json.StringAt("dq").Decode64(),
                InverseQ = json.StringAt("qi").Decode64(),
                D = json.StringAt("d").Decode64(),
            };

            return new RsaKey(id: json.StringAt("kid"), parameters: RestoreLeadingZeros(parameters));
        }

        public RsaKey(string id, RSAParameters parameters)
        {
            Id = id;
            Parameters = parameters;
        }

        public byte[] Decrypt(Encrypted e)
        {
            if (e.KeyId != Id)
                throw ExceptionFactory.MakeInvalidOperation("RSA key: mismatching key id");

            if (e.Scheme != EncryptionScheme)
                throw ExceptionFactory.MakeInvalidOperation(
                    string.Format("RSA key: invalid encryption scheme '{0}', expected '{1}'",
                                  e.Scheme,
                                  EncryptionScheme));

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(Parameters);
                return rsa.Decrypt(e.Ciphertext, true);
            }
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

            throw ExceptionFactory.MakeUnsupported($"{bits}-bit RSA encryption mode is not supported");
        }

        internal static byte[] PrepadWithZeros(byte[] bytes, int desiredLength)
        {
            var length = bytes.Length;

            if (length == desiredLength)
                return bytes;

            if (length < desiredLength)
                return new byte[desiredLength - length].Concat(bytes).ToArray();

            throw ExceptionFactory.MakeInvalidOperation("The array is too long to be padded");
        }

        private static readonly int[] SupportedRsaBits = new[] {1024, 2048, 4096};
    }
}
