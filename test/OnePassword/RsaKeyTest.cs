// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class RsaKeyTest: TestBase
    {
        [Fact]
        public void Parse_returns_key()
        {
            var key = RsaKey.Parse(RsaKeyData);
            Assert.Equal("szerdhg2ww2ahjo4ilz57x7cce", key.Id);
        }

        [Fact]
        public void RestoreLeadingZeros_pads_to_correct_length()
        {
            var rsa = new RSAParameters
            {
                Exponent = new byte[3],
                Modulus = new byte[2048 / 8 - 1],
                P = new byte[13],
                Q = new byte[17],
                DP = new byte[23],
                DQ = new byte[37],
                InverseQ = new byte[53],
                D = new byte[133],
            };

            var padded = RsaKey.RestoreLeadingZeros(rsa);

            Assert.Equal(3, padded.Exponent.Length);
            Assert.Equal(2048 / 8, padded.Modulus.Length);
            Assert.Equal(1024 / 8, padded.P.Length);
            Assert.Equal(1024 / 8, padded.Q.Length);
            Assert.Equal(1024 / 8, padded.DP.Length);
            Assert.Equal(1024 / 8, padded.DQ.Length);
            Assert.Equal(1024 / 8, padded.InverseQ.Length);
            Assert.Equal(2048 / 8, padded.D.Length);
        }

        [Fact]
        public void RestoreLeadingZeros_doesnt_change_valid_parameters()
        {
            var rsa = new RSAParameters
            {
                Exponent = RsaKeyData.Exponent.Decode64Loose(),
                Modulus = RsaKeyData.Modulus.Decode64Loose(),
                P = RsaKeyData.P.Decode64Loose(),
                Q = RsaKeyData.Q.Decode64Loose(),
                DP = RsaKeyData.DP.Decode64Loose(),
                DQ = RsaKeyData.DQ.Decode64Loose(),
                InverseQ = RsaKeyData.InverseQ.Decode64Loose(),
                D = RsaKeyData.D.Decode64Loose(),
            };

            var padded = RsaKey.RestoreLeadingZeros(rsa);

            Assert.Equal(rsa.Exponent, padded.Exponent);
            Assert.Equal(rsa.Modulus, padded.Modulus);
            Assert.Equal(rsa.P, padded.P);
            Assert.Equal(rsa.Q, padded.Q);
            Assert.Equal(rsa.DP, padded.DP);
            Assert.Equal(rsa.DQ, padded.DQ);
            Assert.Equal(rsa.InverseQ, padded.InverseQ);
            Assert.Equal(rsa.D, padded.D);
        }

        [Theory]
        [InlineData(1024)]
        [InlineData(2048)]
        [InlineData(4096)]
        public void GuessKeyBitLength_guesses_correctly(int bits)
        {
            foreach (var i in new[] { bits * 3 / 4 + 8, bits - 16, bits - 8, bits })
            {
                var guessed = RsaKey.GuessKeyBitLength(new RSAParameters() { Modulus = new byte[i / 8] });
                Assert.Equal(bits, guessed);
            }
        }

        [Theory]
        [InlineData(768)]
        [InlineData(4096 + 8)]
        public void GuessKeyBitLength_throws_on_invalid_values(int bits)
        {
            Exceptions.AssertThrowsUnsupportedFeature(
                () => RsaKey.GuessKeyBitLength(new RSAParameters() { Modulus = new byte[bits / 8] }),
                "not supported");
        }

        //
        // Data
        //

        private readonly R.RsaKey RsaKeyData; // Has to be initialized from the constructor

        public RsaKeyTest()
        {
            RsaKeyData = ParseFixture<R.RsaKey>("rsa-key");
        }
    }
}
