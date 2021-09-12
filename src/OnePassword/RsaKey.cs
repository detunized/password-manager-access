// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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

            return new RsaKey(json.Id, parameters);
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
    }
}
