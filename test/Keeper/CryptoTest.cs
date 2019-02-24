// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Keeper.Test
{
    public class CryptoTest
    {
        [Fact]
        public void HashPassword_returns_hashed_password()
        {
            var hash = Crypto.HashPassword("password", "saltsaltsaltsalt".ToBytes(), 100);
            Assert.Equal("bWbRG1iqy6UG9WIFz8igJa5ItR65ujAFWexQt2ka3Y4=".Decode64(), hash);
        }
    }
}
