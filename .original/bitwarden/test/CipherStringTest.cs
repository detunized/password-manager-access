// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace Bitwarden.Test
{
    [TestFixture]
    public class CipherStringTest
    {
        [Test]
        public void Parse_handles_default_cipher_mode()
        {
            var cs = CipherString.Parse("aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==");

            Assert.That(cs.Mode, Is.EqualTo(CipherMode.Aes256Cbc));
            Assert.That(cs.Iv, Is.EqualTo(Iv));
            Assert.That(cs.Ciphertext, Is.EqualTo(Ciphertext));
        }

        [Test]
        public void Parse_handles_cipher_mode_0()
        {
            var cs = CipherString.Parse("0.aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==");

            Assert.That(cs.Mode, Is.EqualTo(CipherMode.Aes256Cbc));
            Assert.That(cs.Iv, Is.EqualTo(Iv));
            Assert.That(cs.Ciphertext, Is.EqualTo(Ciphertext));
        }

        [Test]
        public void Parse_handles_cipher_mode_1()
        {
            var cs = CipherString.Parse("1.aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==|bWFjIG1hYyBtYWMgbWFjIG1hYyBtYWMgbWFjIG1hYyA=");

            Assert.That(cs.Mode, Is.EqualTo(CipherMode.Aes128CbcHmacSha256));
            Assert.That(cs.Iv, Is.EqualTo(Iv));
            Assert.That(cs.Ciphertext, Is.EqualTo(Ciphertext));
            Assert.That(cs.Mac, Is.EqualTo(Mac));
        }

        [Test]
        public void Parse_handles_cipher_mode_2()
        {
            var cs = CipherString.Parse("2.aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==|bWFjIG1hYyBtYWMgbWFjIG1hYyBtYWMgbWFjIG1hYyA=");

            Assert.That(cs.Mode, Is.EqualTo(CipherMode.Aes256CbcHmacSha256));
            Assert.That(cs.Iv, Is.EqualTo(Iv));
            Assert.That(cs.Ciphertext, Is.EqualTo(Ciphertext));
            Assert.That(cs.Mac, Is.EqualTo(Mac));
        }

        [Test]
        public void Parse_handles_cipher_mode_4()
        {
            var cs = CipherString.Parse("4.dcGElncBCW/5N+J9gcO0StC+TvUbRgAaV6PrWked/ejcmjqZxZTlFJ/K7mt1lcyEOz4aq/+2wrveHois5hvDv2Ft0M+MMk6iLiSc+TwHFjxX1jINVymRQMQwEsLF6HA2sTPyhi+HhebWXI0c+jBOW2m17DItEipUXODeCjGa6skWPb+U3+eFV0Un+GObaYP6/BmJw2jVePzudgwJ6b0ai1OtQMvIVlTaE/p3lJiEMhCPw5LGcLxe2Kmjer2Z1jABr+zmowveSnZ35sJcvpUHQLPi4j5Sj66PEPv6I0A+h7f0Jlm1S/MB+ViZN5k2KGNGIGfisGvCIl0GU+rmg8wFnw==");

            Assert.That(cs.Mode, Is.EqualTo(CipherMode.Rsa2048OaepSha1));
            Assert.That(cs.Iv.Length, Is.EqualTo(0));
            Assert.That(cs.Ciphertext.Length, Is.EqualTo(256));
            Assert.That(cs.Mac.Length, Is.EqualTo(0));
        }

        [Test]
        public void Parse_throws_on_malformed_input()
        {
            var invalid = new[] {"", "0.", "0..", "0.|||"};
            foreach (var i in invalid)
                VerifyThrowsInvalidFormat(i, "Invalid/unsupported cipher string format");
        }

        [Test]
        public void Parse_throws_on_invalid_cipher_mode()
        {
            var invalid = new[] {"3.", "A."};
            foreach (var i in invalid)
                VerifyThrowsInvalidFormat(i, "Invalid/unsupported cipher mode");
        }

        [Test]
        public void Properties_are_set()
        {
            var mode = CipherMode.Aes256CbcHmacSha256;
            var cs = new CipherString(mode, Iv, Ciphertext, Mac);

            Assert.That(cs.Mode, Is.EqualTo(mode));
            Assert.That(cs.Iv, Is.EqualTo(Iv));
            Assert.That(cs.Ciphertext, Is.EqualTo(Ciphertext));
            Assert.That(cs.Mac, Is.EqualTo(Mac));
        }

        [Test]
        public void Ctor_throws_on_invalid_parameters()
        {
            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256Cbc,
                                      iv: null,
                                      ciphertext: Ciphertext,
                                      mac: null,
                                      expectedMessage: "IV must be 16 bytes long");

            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256Cbc,
                                      iv: "invalid iv".ToBytes(),
                                      ciphertext: Ciphertext,
                                      mac: null,
                                      expectedMessage: "IV must be 16 bytes long");

            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256Cbc,
                                      iv: Iv,
                                      ciphertext: null,
                                      mac: null,
                                      expectedMessage: "Ciphertext must not be null");

            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256Cbc,
                                      iv: Iv,
                                      ciphertext: Ciphertext,
                                      mac: Mac,
                                      expectedMessage: "MAC is not supported in AES-256-CBC mode");

            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256CbcHmacSha256,
                                      iv: Iv,
                                      ciphertext: Ciphertext,
                                      mac: null,
                                      expectedMessage : "MAC must be 32 bytes long");

            VerifyThrowsInvalidFormat(mode: CipherMode.Aes256CbcHmacSha256,
                                      iv: Iv,
                                      ciphertext: Ciphertext,
                                      mac: "invalid mac".ToBytes(),
                                      expectedMessage : "MAC must be 32 bytes long");
        }

        [Test]
        public void Decrypt_decrypts_ciphertext_without_mac()
        {
            var cs = new CipherString(mode: CipherMode.Aes256Cbc,
                                      iv: "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                                      ciphertext: "TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                                      mac: null);
            var plaintext = cs.Decrypt("OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64());

            Assert.That(plaintext, Is.EqualTo("All your base are belong to us".ToBytes()));
        }

        [Test]
        public void Decrypt_decrypts_ciphertext_with_expanded_key()
        {
            var key = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
            var iv = "XZ2vMa5oFCcp7BUAfPowvA==".Decode64();
            var ciphertext = "1/GDPwJWo+2Iacio0UkRfR0zXXUufGjMIxD+y/A/YfQPKKep69B0nfbueqZJ1nA1pv15qVounBVJLhetVMGW7mKSxdVtTYObe0Uiqm/C9/s=".Decode64();
            var mac = "ZLZcTYFq4o1tBSYkGUbQEIj64/rAE8sAVmfzpOhPTNM=".Decode64();
            var expected = "7Zo+OWHAKzu+Ovxisz38Na4en13SnoKHPxFngLUgLiHzSZCWbq42Mohdr6wInwcsWbbezoVaS2vwZlSlB6G7Mg==".Decode64();

            var cs = new CipherString(mode: CipherMode.Aes256CbcHmacSha256, iv: iv, ciphertext: ciphertext, mac: mac);
            var plaintext = cs.Decrypt(key);

            Assert.That(plaintext, Is.EqualTo(expected));
        }

        [Test]
        public void Decrypt_throws_on_mismatching_mac()
        {
            var key = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
            var iv = "XZ2vMa5oFCcp7BUAfPowvA==".Decode64();
            var ciphertext = "1/GDPwJWo+2Iacio0UkRfR0zXXUufGjMIxD+y/A/YfQPKKep69B0nfbueqZJ1nA1pv15qVounBVJLhetVMGW7mKSxdVtTYObe0Uiqm/C9/s=".Decode64();
            var mac = "mismatching MAC, mismatching MAC".ToBytes();
            var cs = new CipherString(mode: CipherMode.Aes256CbcHmacSha256, iv: iv, ciphertext: ciphertext, mac: mac);

            Assert.That(() => cs.Decrypt(key),
                        Throws.InstanceOf<ClientException>()
                            .And.Message.Contains("MAC doesn't match")
                            .And.Property("Reason").EqualTo(ClientException.FailureReason.CryptoError));
        }

        //
        // Helper
        //

        private static void VerifyThrowsInvalidFormat(string input, string expectedMessage)
        {
            Assert.That(() => CipherString.Parse(input),
                        Throws.InstanceOf<ClientException>()
                            .And.Message.Contains(expectedMessage)
                            .And.Property("Reason")
                            .EqualTo(ClientException.FailureReason.InvalidFormat));
        }

        private static void VerifyThrowsInvalidFormat(CipherMode mode,
                                                      byte[] iv,
                                                      byte[] ciphertext,
                                                      byte[] mac,
                                                      string expectedMessage)
        {
            Assert.That(() => new CipherString(mode, iv, ciphertext, mac),
                        Throws.InstanceOf<ClientException>()
                            .And.Message.Contains(expectedMessage)
                            .And.Property("Reason")
                            .EqualTo(ClientException.FailureReason.InvalidFormat));
        }

        //
        // Data
        //

        private static readonly byte[] Iv = "iviviviviviviviv".ToBytes();
        private static readonly byte[] Ciphertext = "ciphertext".ToBytes();
        private static readonly byte[] Mac = "mac mac mac mac mac mac mac mac ".ToBytes();
    }
}
