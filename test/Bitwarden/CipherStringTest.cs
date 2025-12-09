// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Common;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.Bitwarden
{
    public class CipherStringTest
    {
        //
        // Parse
        //

        [Fact]
        public void Parse_handles_default_two_piece_cipher_mode()
        {
            // Arrange/Act
            var cs = CipherString.Parse("aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Aes256Cbc);
            cs.Iv.ShouldBe(Iv);
            cs.Ciphertext.ShouldBe(Ciphertext);
        }

        [Fact]
        public void Parse_handles_default_three_piece_cipher_mode()
        {
            // Arrange/Act
            var cs = CipherString.Parse("aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==|bWFjIG1hYyBtYWMgbWFjIG1hYyBtYWMgbWFjIG1hYyA=");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Aes128CbcHmacSha256);
            cs.Iv.ShouldBe(Iv);
            cs.Ciphertext.ShouldBe(Ciphertext);
            cs.Mac.ShouldBe(Mac);
        }

        [Fact]
        public void Parse_handles_cipher_mode_0()
        {
            // Arrange/Act
            var cs = CipherString.Parse("0.aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Aes256Cbc);
            cs.Iv.ShouldBe(Iv);
            cs.Ciphertext.ShouldBe(Ciphertext);
        }

        [Fact]
        public void Parse_handles_cipher_mode_1()
        {
            // Arrange/Act
            var cs = CipherString.Parse("1.aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==|bWFjIG1hYyBtYWMgbWFjIG1hYyBtYWMgbWFjIG1hYyA=");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Aes128CbcHmacSha256);
            cs.Iv.ShouldBe(Iv);
            cs.Ciphertext.ShouldBe(Ciphertext);
            cs.Mac.ShouldBe(Mac);
        }

        [Fact]
        public void Parse_handles_cipher_mode_2()
        {
            // Arrange/Act
            var cs = CipherString.Parse("2.aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==|bWFjIG1hYyBtYWMgbWFjIG1hYyBtYWMgbWFjIG1hYyA=");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Aes256CbcHmacSha256);
            cs.Iv.ShouldBe(Iv);
            cs.Ciphertext.ShouldBe(Ciphertext);
            cs.Mac.ShouldBe(Mac);
        }

        [Fact]
        public void Parse_handles_cipher_mode_4()
        {
            // Arrange/Act
            var cs = CipherString.Parse($"4.{RsaCiphertextBase64}");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Rsa2048OaepSha1);
            cs.Iv.ShouldBeEmpty();
            cs.Ciphertext.ShouldBe(RsaCiphertext);
            cs.Mac.ShouldBeEmpty();
        }

        [Theory]
        [InlineData("0..")]
        [InlineData("0.|||")]
        public void Parse_throws_on_malformed_input(string invalid)
        {
            // Arrange
            var act = () => CipherString.Parse(invalid);

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("Invalid/unsupported cipher string format");
        }

        [Theory]
        [InlineData("7.")]
        [InlineData("A.")]
        public void Parse_throws_on_invalid_cipher_mode(string invalid)
        {
            // Arrange
            var act = () => CipherString.Parse(invalid);

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("Invalid/unsupported cipher mode");
        }

        //
        // ParseRsa
        //

        [Fact]
        public void ParseRsa_handles_default_mode()
        {
            // Arrange/Act
            var cs = CipherString.ParseRsa(RsaCiphertextBase64);

            // Assert
            cs.Mode.ShouldBe(CipherMode.Rsa2048OaepSha256);
            cs.Iv.ShouldBeEmpty();
            cs.Ciphertext.ShouldBe(RsaCiphertext);
            cs.Mac.ShouldBeEmpty();
        }

        [Fact]
        public void ParseRsa_handles_modes_3()
        {
            // Arrange/Act
            var cs = CipherString.ParseRsa($"3.{RsaCiphertextBase64}");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Rsa2048OaepSha256);
            cs.Iv.ShouldBeEmpty();
            cs.Ciphertext.ShouldBe(RsaCiphertext);
            cs.Mac.ShouldBeEmpty();
        }

        [Fact]
        public void ParseRsa_handles_modes_4()
        {
            // Arrange/Act
            var cs = CipherString.ParseRsa($"4.{RsaCiphertextBase64}");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Rsa2048OaepSha1);
            cs.Iv.ShouldBeEmpty();
            cs.Ciphertext.ShouldBe(RsaCiphertext);
            cs.Mac.ShouldBeEmpty();
        }

        [Fact]
        public void ParseRsa_handles_modes_5_and_ignores_mac()
        {
            // Arrange/Act
            var cs = CipherString.ParseRsa($"5.{RsaCiphertextBase64}|{MacBase64}");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Rsa2048OaepSha256HmacSha256);
            cs.Iv.ShouldBeEmpty();
            cs.Ciphertext.ShouldBe(RsaCiphertext);
            cs.Mac.ShouldAllBe(x => x == 0);
        }

        [Fact]
        public void ParseRsa_handles_modes_5_without_mac()
        {
            // Arrange/Act
            var cs = CipherString.ParseRsa($"5.{RsaCiphertextBase64}");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Rsa2048OaepSha256HmacSha256);
            cs.Iv.ShouldBeEmpty();
            cs.Ciphertext.ShouldBe(RsaCiphertext);
            cs.Mac.ShouldAllBe(x => x == 0);
        }

        [Fact]
        public void ParseRsa_handles_modes_6_and_ignores_mac()
        {
            // Arrange/Act
            var cs = CipherString.ParseRsa($"6.{RsaCiphertextBase64}|{MacBase64}");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Rsa2048OaepSha1HmacSha256);
            cs.Iv.ShouldBeEmpty();
            cs.Ciphertext.ShouldBe(RsaCiphertext);
            cs.Mac.ShouldAllBe(x => x == 0);
        }

        [Fact]
        public void ParseRsa_handles_modes_6_without_mac()
        {
            // Arrange/Act
            var cs = CipherString.ParseRsa($"6.{RsaCiphertextBase64}");

            // Assert
            cs.Mode.ShouldBe(CipherMode.Rsa2048OaepSha1HmacSha256);
            cs.Iv.ShouldBeEmpty();
            cs.Ciphertext.ShouldBe(RsaCiphertext);
            cs.Mac.ShouldAllBe(x => x == 0);
        }

        [Fact]
        public void ParseRsa_throws_on_malformed_input()
        {
            // Arrange
            var act = () => CipherString.ParseRsa("..");

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("Invalid/unsupported cipher string format");
        }

        [Fact]
        public void ParseRsa_throws_on_valid_non_rsa_input()
        {
            // Arrange
            var act = () => CipherString.ParseRsa("0.aXZpdml2aXZpdml2aXZpdg==|Y2lwaGVydGV4dA==");

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("Invalid RSA cipher string format");
        }

        [Fact]
        public void Properties_are_set()
        {
            // Arrange
            var mode = CipherMode.Aes256CbcHmacSha256;

            // Act
            var cs = new CipherString(mode, Iv, Ciphertext, Mac);

            // Assert
            cs.Mode.ShouldBe(mode);
            cs.Iv.ShouldBe(Iv);
            cs.Ciphertext.ShouldBe(Ciphertext);
            cs.Mac.ShouldBe(Mac);
        }

        [Fact]
        public void Ctor_throws_on_null_iv()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Aes256Cbc, null, Ciphertext, Mac);

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("IV, ciphertext and MAC must not be null");
        }

        [Fact]
        public void Ctor_throws_on_null_ciphertext()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Aes256Cbc, Iv, null, Mac);

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("IV, ciphertext and MAC must not be null");
        }

        [Fact]
        public void Ctor_throws_on_null_mac()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Aes256Cbc, Iv, Ciphertext, null);

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("IV, ciphertext and MAC must not be null");
        }

        [Fact]
        public void Ctor_throws_on_invalid_aes_256_cbc_iv_length()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Aes256Cbc, "invalid iv".ToBytes(), Ciphertext, "".ToBytes());

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("IV must be 16 bytes long");
        }

        [Fact]
        public void Ctor_throws_on_invalid_aes_256_cbc_mac_not_supported()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Aes256Cbc, Iv, Ciphertext, Mac);

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("MAC is not supported");
        }

        [Fact]
        public void Ctor_throws_on_invalid_aes_128_cbc_hmac_sha_256_iv_length()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Aes128CbcHmacSha256, "invalid iv".ToBytes(), Ciphertext, Mac);

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("IV must be 16 bytes long");
        }

        [Fact]
        public void Ctor_throws_on_invalid_aes_128_cbc_hmac_sha_256_mac_length()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Aes128CbcHmacSha256, Iv, Ciphertext, "invalid mac".ToBytes());

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("MAC must be 32 bytes long");
        }

        [Fact]
        public void Ctor_throws_on_invalid_aes_256_cbc_hmac_sha_256_iv_length()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Aes256CbcHmacSha256, "invalid iv".ToBytes(), Ciphertext, Mac);

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("IV must be 16 bytes long");
        }

        [Fact]
        public void Ctor_throws_on_invalid_aes_256_cbc_hmac_sha_256_mac_length()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Aes256CbcHmacSha256, Iv, Ciphertext, "invalid mac".ToBytes());

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("MAC must be 32 bytes long");
        }

        [Fact]
        public void Ctor_throws_on_invalid_rsa_2048_oaep_sha_1_iv_not_supported()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Rsa2048OaepSha1, "invalid iv".ToBytes(), RsaCiphertext, "".ToBytes());

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("IV is not supported");
        }

        [Fact]
        public void Ctor_throws_on_invalid_rsa_2048_oaep_sha_1_ciphertext_length()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Rsa2048OaepSha1, "".ToBytes(), "invalid ciphertext".ToBytes(), "".ToBytes());

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("Ciphertext must be 256 bytes long");
        }

        [Fact]
        public void Ctor_throws_on_invalid_rsa_2048_oaep_sha_1_mac_not_supported()
        {
            // Arrange
            var act = () => new CipherString(CipherMode.Rsa2048OaepSha1, "".ToBytes(), RsaCiphertext, "invalid mac".ToBytes());

            // Act
            var ex = Should.Throw<InternalErrorException>(act);

            // Assert
            ex.Message.ShouldContain("MAC is not supported");
        }

        [Fact]
        public void Decrypt_decrypts_ciphertext_without_mac()
        {
            // Arrange
            var cs = new CipherString(
                mode: CipherMode.Aes256Cbc,
                iv: "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                ciphertext: "TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                mac: "".ToBytes()
            );

            // Act
            var plaintext = cs.Decrypt("OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64());

            // Assert
            plaintext.ShouldBe("All your base are belong to us".ToBytes());
        }

        [Fact]
        public void Decrypt_decrypts_ciphertext_with_expanded_key()
        {
            // Arrange
            var key = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
            var iv = "XZ2vMa5oFCcp7BUAfPowvA==".Decode64();
            var ciphertext =
                "1/GDPwJWo+2Iacio0UkRfR0zXXUufGjMIxD+y/A/YfQPKKep69B0nfbueqZJ1nA1pv15qVounBVJLhetVMGW7mKSxdVtTYObe0Uiqm/C9/s=".Decode64();
            var mac = "ZLZcTYFq4o1tBSYkGUbQEIj64/rAE8sAVmfzpOhPTNM=".Decode64();
            var expected = "7Zo+OWHAKzu+Ovxisz38Na4en13SnoKHPxFngLUgLiHzSZCWbq42Mohdr6wInwcsWbbezoVaS2vwZlSlB6G7Mg==".Decode64();
            var cs = new CipherString(mode: CipherMode.Aes256CbcHmacSha256, iv: iv, ciphertext: ciphertext, mac: mac);

            // Act
            var plaintext = cs.Decrypt(key);

            // Assert
            plaintext.ShouldBe(expected);
        }

        [Fact]
        public void Decrypt_throws_on_mismatching_mac()
        {
            // Arrange
            var key = "SLBgfXoityZsz4ZWvpEPULPZMYGH6vSqh3PXTe5DmyM=".Decode64();
            var iv = "XZ2vMa5oFCcp7BUAfPowvA==".Decode64();
            var ciphertext =
                "1/GDPwJWo+2Iacio0UkRfR0zXXUufGjMIxD+y/A/YfQPKKep69B0nfbueqZJ1nA1pv15qVounBVJLhetVMGW7mKSxdVtTYObe0Uiqm/C9/s=".Decode64();
            var mac = "mismatching MAC, mismatching MAC".ToBytes();
            var cs = new CipherString(mode: CipherMode.Aes256CbcHmacSha256, iv: iv, ciphertext: ciphertext, mac: mac);

            // Act
            var act = () => cs.Decrypt(key);

            // Assert
            var ex = Should.Throw<CryptoException>(act);
            ex.Message.ShouldContain("MAC doesn't match");
        }

        //
        // Data
        //

        private static readonly byte[] Iv = "iviviviviviviviv".ToBytes();
        private static readonly byte[] Ciphertext = "ciphertext".ToBytes();

        private static readonly byte[] Mac = "mac mac mac mac mac mac mac mac ".ToBytes();
        private static readonly string MacBase64 = Mac.ToBase64();

        private static readonly byte[] RsaCiphertext = new string('!', 256).ToBytes();
        private static readonly string RsaCiphertextBase64 = RsaCiphertext.ToBase64();
    }
}
