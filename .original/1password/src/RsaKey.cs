// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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
            return new RsaKey(id: json.StringAt("kid"),
                              parameters: new RSAParameters
                              {
                                  Exponent = json.StringAt("e").Decode64(),
                                  Modulus = json.StringAt("n").Decode64(),
                                  P = json.StringAt("p").Decode64(),
                                  Q = json.StringAt("q").Decode64(),
                                  DP = json.StringAt("dp").Decode64(),
                                  DQ = json.StringAt("dq").Decode64(),
                                  InverseQ = json.StringAt("qi").Decode64(),
                                  D = json.StringAt("d").Decode64(),
                              });
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
    }
}
