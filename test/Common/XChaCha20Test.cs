// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class XChaCha20Test
    {
        [Fact]
        public void Ctor_throws_on_invalid_key_size()
        {
            Exceptions.AssertThrowsInternalError(() => new XChaCha20(new byte[1337], new byte[24]),
                                                 "Key must be 32 bytes");
        }

        [Fact]
        public void Ctor_throws_on_invalid_nonce_size()
        {
            Exceptions.AssertThrowsInternalError(() => new XChaCha20(new byte[32], new byte[1337]),
                                                 "Nonce must be 24 bytes");
        }

        // Test vectors from https://github.com/golang/crypto/blob/master/chacha20/vectors_test.go
        [Theory]
        [InlineData("9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232",
                    "c047548266b7c370d33566a2425cbf30d82d1eaf5294109e",
                    "",
                    "")]
        [InlineData("9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232",
                    "c047548266b7c370d33566a2425cbf30d82d1eaf5294109e",
                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae90fc31097cfc")]
        [InlineData("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                    "404142434445464748494a4b4c4d4e4f5051525354555658",
                    "5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e",
                    "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a66393b93111c1a55dd7421a10184974c7c5")]
        public void ProcessBytes_returns_encrypted_bytes(string keyHex, string nonceHex, string inputHex, string expectedHex)
        {
            var input = inputHex.DecodeHex();
            var size = input.Length;
            var output = new byte[size];
            new XChaCha20(keyHex.DecodeHex(), nonceHex.DecodeHex()).ProcessBytes(input, 0, size, output, 0);

            Assert.Equal(expectedHex.DecodeHex(), output);
        }

        [Fact]
        public void HChaCha20_computes_key()
        {
            // From https://trac.tools.ietf.org/html/draft-irtf-cfrg-xchacha-01#section-2.2.1
            var key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".DecodeHex();
            var nonce = "000000090000004a0000000031415927".DecodeHex();
            var expected = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc".DecodeHex();
            var result = new byte[32];
            XChaCha20.HChaCha20(key, nonce, result);

            Assert.Equal(expected, result);
        }
    }
}
