// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Test.ZohoVault
{
    static class TestData
    {
        // Calculated with the original Js code
        public static readonly byte[] Key = "d7643007973dba7243d724f66fd806bf".ToBytes();
        public static readonly byte[] Key2 = "c16c3e48073b8932c77c1aaa2170fbf3".ToBytes();
        public const string Passphrase = "passphrase123";
    }
}
