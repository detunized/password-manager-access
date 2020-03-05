// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.StickyPassword;
using Xunit;

namespace PasswordManagerAccess.Test.StickyPassword
{
    public class ParserTest
    {
        [Fact]
        public void IsKeyCorrect_returns_true()
        {
            var key = Crypto.DeriveDbKey(Password, KeySalt);

            Assert.True(Parser.IsKeyCorrect(key, KeyVerification));
        }

        [Fact]
        public void IsKeyCorrect_return_false()
        {
            var key = Crypto.DeriveDbKey("Incorrect password", KeySalt);

            Assert.False(Parser.IsKeyCorrect(key, KeyVerification));
        }

        //
        // Data
        //

        private const string Password = "Password123";

        // The actual bytes from the user database
        private static readonly byte[] KeySalt =
        {
            0x63, 0x51, 0xee, 0x97, 0x8c, 0x6e, 0xe0, 0xd8,
            0x1e, 0x66, 0xdf, 0x61, 0x90, 0x3a, 0x5a, 0x88
        };

        // The actual bytes from the user database
        private static readonly byte[] KeyVerification =
        {
            0x08, 0xbc, 0x5a, 0x27, 0x4d, 0x4b, 0xd6, 0x42,
            0x9e, 0xf5, 0x9b, 0x95, 0x4d, 0xd1, 0x2b, 0xfd
        };
    }
}
