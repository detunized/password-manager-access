// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class CipherStringTest
    {
        [Fact]
        public void Parse_handles_default_cipher_mode()
        {
            var cs = CipherString.Parse("aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==");

            Assert.Equal(CipherMode.Aes256Cbc, cs.Mode);
            Assert.Equal(Iv, cs.Iv);
            Assert.Equal(Ciphertext, cs.Ciphertext);
        }

        [Fact]
        public void Parse_handles_cipher_mode_0()
        {
            var cs = CipherString.Parse("0.aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==");

            Assert.Equal(CipherMode.Aes256Cbc, cs.Mode);
            Assert.Equal(Iv, cs.Iv);
            Assert.Equal(Ciphertext, cs.Ciphertext);
        }

        [Fact]
        public void Parse_handles_cipher_mode_1()
        {
            var cs = CipherString.Parse("1.aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==|bWFjIG1hYyBtYWMgbWFjIG1hYyBtYWMgbWFjIG1hYyA=");

            Assert.Equal(CipherMode.Aes128CbcHmacSha256, cs.Mode);
            Assert.Equal(Iv, cs.Iv);
            Assert.Equal(Ciphertext, cs.Ciphertext);
            Assert.Equal(Mac, cs.Mac);
        }

        [Fact]
        public void Parse_handles_cipher_mode_2()
        {
            var cs = CipherString.Parse("2.aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==|bWFjIG1hYyBtYWMgbWFjIG1hYyBtYWMgbWFjIG1hYyA=");

            Assert.Equal(CipherMode.Aes256CbcHmacSha256, cs.Mode);
            Assert.Equal(Iv, cs.Iv);
            Assert.Equal(Ciphertext, cs.Ciphertext);
            Assert.Equal(Mac, cs.Mac);
        }

        [Fact]
        public void Parse_handles_cipher_mode_4()
        {
            var cs = CipherString.Parse("4.dcGElncBCW/5N+J9gcO0StC+TvUbRgAaV6PrWked/ejcmjqZxZTlFJ/K7mt1lcyEOz4aq/+2wrveHois5hvDv2Ft0M+MMk6iLiSc+TwHFjxX1jINVymRQMQwEsLF6HA2sTPyhi+HhebWXI0c+jBOW2m17DItEipUXODeCjGa6skWPb+U3+eFV0Un+GObaYP6/BmJw2jVePzudgwJ6b0ai1OtQMvIVlTaE/p3lJiEMhCPw5LGcLxe2Kmjer2Z1jABr+zmowveSnZ35sJcvpUHQLPi4j5Sj66PEPv6I0A+h7f0Jlm1S/MB+ViZN5k2KGNGIGfisGvCIl0GU+rmg8wFnw==");

            Assert.Equal(CipherMode.Rsa2048OaepSha1, cs.Mode);
            Assert.Empty(cs.Iv);
            Assert.Equal(256, cs.Ciphertext.Length);
            Assert.Empty(cs.Mac);
        }

        [Fact]
        public void Parse_throws_on_malformed_input()
        {
            var invalid = new[] {"0..", "0.|||"};
            foreach (var i in invalid)
                VerifyThrowsInvalidFormat(i, "Invalid/unsupported cipher string format");
        }

        [Fact]
        public void Parse_throws_on_invalid_cipher_mode()
        {
            var invalid = new[] {"7.", "A."};
            foreach (var i in invalid)
                VerifyThrowsInvalidFormat(i, "Invalid/unsupported cipher mode");
        }

        [Fact]
        public void Properties_are_set()
        {
            var mode = CipherMode.Aes256CbcHmacSha256;
            var cs = new CipherString(mode, Iv, Ciphertext, Mac);

            Assert.Equal(mode, cs.Mode);
            Assert.Equal(Iv, cs.Iv);
            Assert.Equal(Ciphertext, cs.Ciphertext);
            Assert.Equal(Mac, cs.Mac);
        }

        [Fact]
        public void Ctor_throws_on_nulls()
        {
            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256Cbc,
                                      iv: null,
                                      ciphertext: Ciphertext,
                                      mac: Mac,
                                      expectedMessage: "IV, ciphertext and MAC must not be null");

            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256Cbc,
                                      iv: Iv,
                                      ciphertext: null,
                                      mac: Mac,
                                      expectedMessage: "IV, ciphertext and MAC must not be null");

            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256Cbc,
                                      iv: Iv,
                                      ciphertext: Ciphertext,
                                      mac: null,
                                      expectedMessage: "IV, ciphertext and MAC must not be null");
        }

        [Fact]
        public void Ctor_throws_on_invalid_aes_256_cbc()
        {
            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256Cbc,
                                      iv: "invalid iv".ToBytes(),
                                      ciphertext: Ciphertext,
                                      mac: "".ToBytes(),
                                      expectedMessage: "IV must be 16 bytes long");

            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256Cbc,
                                      iv: Iv,
                                      ciphertext: Ciphertext,
                                      mac: Mac,
                                      expectedMessage: "MAC is not supported");
        }

        [Fact]
        public void Ctor_throws_on_invalid_aes_128_cbc_hmac_sha_256()
        {
            VerifyThrowsInvalidFormat(mode: CipherMode.Aes128CbcHmacSha256,
                                      iv: "invalid iv".ToBytes(),
                                      ciphertext: Ciphertext,
                                      mac: Mac,
                                      expectedMessage: "IV must be 16 bytes long");

            VerifyThrowsInvalidFormat(mode: CipherMode.Aes128CbcHmacSha256,
                                      iv: Iv,
                                      ciphertext: Ciphertext,
                                      mac: "invalid mac".ToBytes(),
                                      expectedMessage: "MAC must be 32 bytes long");
        }

        [Fact]
        public void Ctor_throws_on_invalid_aes_256_cbc_hmac_sha_256()
        {
            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256CbcHmacSha256,
                                      iv: "invalid iv".ToBytes(),
                                      ciphertext: Ciphertext,
                                      mac: Mac,
                                      expectedMessage: "IV must be 16 bytes long");

            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256CbcHmacSha256,
                                      iv: Iv,
                                      ciphertext: Ciphertext,
                                      mac: "invalid mac".ToBytes(),
                                      expectedMessage: "MAC must be 32 bytes long");
        }

        [Fact]
        public void Ctor_throws_on_invalid_rsa_2048_oaep_sha_1()
        {
            VerifyThrowsInvalidFormat(mode: CipherMode.Rsa2048OaepSha1,
                                    iv: "invalid iv".ToBytes(),
                                    ciphertext: RsaCiphertext,
                                    mac: "".ToBytes(),
                                    expectedMessage: "IV is not supported");

            VerifyThrowsInvalidFormat(mode: CipherMode.Rsa2048OaepSha1,
                                    iv: "".ToBytes(),
                                    ciphertext: "invalid ciphertext".ToBytes(),
                                    mac: "".ToBytes(),
                                    expectedMessage: "Ciphertext must be 256 bytes long");

            VerifyThrowsInvalidFormat(mode: CipherMode.Rsa2048OaepSha1,
                                    iv: "".ToBytes(),
                                    ciphertext: RsaCiphertext,
                                    mac: "invalid mac".ToBytes(),
                                    expectedMessage: "MAC is not supported");
        }

        [Fact]
        public void Decrypt_decrypts_ciphertext_without_mac()
        {
            var cs = new CipherString(mode: CipherMode.Aes256Cbc,
                                      iv: "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                                      ciphertext: "TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                                      mac: "".ToBytes());
            var plaintext = cs.Decrypt("OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64());

            Assert.Equal("All your base are belong to us".ToBytes(), plaintext);
        }

        [Fact]
        public void Decrypt_decrypts_ciphertext_with_expanded_key()
        {
            var key = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
            var iv = "XZ2vMa5oFCcp7BUAfPowvA==".Decode64();
            var ciphertext = "1/GDPwJWo+2Iacio0UkRfR0zXXUufGjMIxD+y/A/YfQPKKep69B0nfbueqZJ1nA1pv15qVounBVJLhetVMGW7mKSxdVtTYObe0Uiqm/C9/s=".Decode64();
            var mac = "ZLZcTYFq4o1tBSYkGUbQEIj64/rAE8sAVmfzpOhPTNM=".Decode64();
            var expected = "7Zo+OWHAKzu+Ovxisz38Na4en13SnoKHPxFngLUgLiHzSZCWbq42Mohdr6wInwcsWbbezoVaS2vwZlSlB6G7Mg==".Decode64();

            var cs = new CipherString(mode: CipherMode.Aes256CbcHmacSha256, iv: iv, ciphertext: ciphertext, mac: mac);
            var plaintext = cs.Decrypt(key);

            Assert.Equal(expected, plaintext);
        }

        [Fact]
        public void Decrypt_throws_on_mismatching_mac()
        {
            var key = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
            var iv = "XZ2vMa5oFCcp7BUAfPowvA==".Decode64();
            var ciphertext = "1/GDPwJWo+2Iacio0UkRfR0zXXUufGjMIxD+y/A/YfQPKKep69B0nfbueqZJ1nA1pv15qVounBVJLhetVMGW7mKSxdVtTYObe0Uiqm/C9/s=".Decode64();
            var mac = "mismatching MAC, mismatching MAC".ToBytes();
            var cs = new CipherString(mode: CipherMode.Aes256CbcHmacSha256, iv: iv, ciphertext: ciphertext, mac: mac);

            Exceptions.AssertThrowsCrypto(() => cs.Decrypt(key), "MAC doesn't match");
        }

        //
        // Helper
        //

        // TODO: Get rid of
        private static void VerifyThrowsInvalidFormat(string input, string expectedMessage)
        {
            Exceptions.AssertThrowsInternalError(() => CipherString.Parse(input), expectedMessage);
        }

        private static void VerifyThrowsInvalidFormat(CipherMode mode,
                                                      byte[] iv,
                                                      byte[] ciphertext,
                                                      byte[] mac,
                                                      string expectedMessage)
        {
            Exceptions.AssertThrowsInternalError(() => new CipherString(mode, iv, ciphertext, mac), expectedMessage);
        }

        //
        // Data
        //

        private static readonly byte[] Iv = "iviviviviviviviv".ToBytes();
        private static readonly byte[] Ciphertext = "ciphertext".ToBytes();
        private static readonly byte[] Mac = "mac mac mac mac mac mac mac mac ".ToBytes();

        private static readonly byte[] RsaCiphertext = new string('!', 256).ToBytes();
    }
}
