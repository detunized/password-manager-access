// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class UtilTest
    {
        [Theory]
        [InlineData(1, "C/Bh2SGWxI8JDu54DbbpV8J9wa6pKbesIb9MAXkeF3Y=")]
        [InlineData(5, "pE9goazSCRqnWwcixWM4NHJjWMvB5T15dMhe6ug1pZg=")]
        [InlineData(10, "n9S0SyJdrMegeBHtkxUx8Lzc7wI6aGl+y3/udGmVey8=")]
        [InlineData(50, "GwI8/kNy1NjIfe3Z0VAZfF78938UVuCi6xAL3MJBux0=")]
        [InlineData(100, "piGdSULeHMWiBS3QJNM46M5PIYwQXA6cNS10pLB3Xf8=")]
        [InlineData(500, "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=")]
        [InlineData(1000, "z7CdwlIkbu0XvcB7oQIpnlqwNGemdrGTBmDKnL9taPg=")]
        public void DeriveKey_returns_derived_key(int iterations, string expected)
        {
            var key = Util.DeriveKey(Username, Password, iterations);
            Assert.Equal(expected.Decode64(), key);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(-1337)]
        public void MakeKey_throws_on_invalid_iteration_count(int iterations)
        {
            Exceptions.AssertThrowsInternalError(
                () => Util.DeriveKey(Username, Password, iterations),
                "Iteration count should be positive");
        }

        [Theory]
        [InlineData(1, "a1943cfbb75e37b129bbf78b9baeab4ae6dd08225776397f66b8e0c7a913a055")]
        [InlineData(5, "a95849e029a7791cfc4503eed9ec96ab8675c4a7c4e82b00553ddd179b3d8445")]
        [InlineData(10, "0da0b44f5e6b7306f14e92de6d629446370d05afeb1dc07cfcbe25f169170c16")]
        [InlineData(50, "1d5bc0d636da4ad469cefe56c42c2ff71589facb9c83f08fcf7711a7891cc159")]
        [InlineData(100, "82fc12024acb618878ba231a9948c49c6f46e30b5a09c11d87f6d3338babacb5")]
        [InlineData(500, "3139861ae962801b59fc41ff7eeb11f84ca56d810ab490f0d8c89d9d9ab07aa6")]
        [InlineData(1000, "03161354566c396fcd624a424164160e890e96b4b5fa6d942fc6377ab613513b")]
        public void DeriveKeyHash_returns_derived_key_hash(int iterations, string expected)
        {
            var hash = Util.DeriveKeyHash(Username, Password, iterations);
            Assert.Equal(expected.DecodeHex(), hash);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(-1337)]
        public void MakeHash_throws_on_invalid_iteration_count(int iterations)
        {
            Exceptions.AssertThrowsInternalError(
                () => Util.DeriveKeyHash(Username, Password, iterations),
                "Iteration count should be positive");
        }

        //
        // Data
        //

        private const string Username = "postlass@gmail.com";
        private const string Password = "pl1234567890";
    }
}
