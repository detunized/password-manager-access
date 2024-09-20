// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.ZohoVault;

namespace PasswordManagerAccess.Test.ZohoVault
{
    internal static class TestData
    {
        // Calculated with the original Js code
        public static readonly byte[] Key = "d7643007973dba7243d724f66fd806bf".ToBytes();
        public static readonly byte[] Key2 = "c16c3e48073b8932c77c1aaa2170fbf3".ToBytes();
        public const string Passphrase = "passphrase123";

        // Based on "auth-info-response.json"
        public static readonly Client.AuthInfo AuthInfo =
            new(
                iterationCount: 1000,
                salt: "f78e6ffce8e57501a02c9be303db2c68".ToBytes(),
                encryptionCheck: "awNZM8agxVecKpRoC821Oq6NlvVwm6KpPGW+cLdzRoc2Mg5vqPQzoONwww==".Decode64()
            );
    }
}
