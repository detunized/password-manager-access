// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using FluentAssertions;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class CryptoTest
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(129)]
        [InlineData(1337)]
        public void RandomBytes_returns_correct_number_of_bytes(int numBytes)
        {
            // Arrange/Act
            var bytes = Crypto.RandomBytes(numBytes);

            // Assert
            bytes.Length.Should().Be(numBytes);
        }

        [Fact]
        public void RandomBytes_looks_random()
        {
            // Act/Arrange
            var bytes1 = Crypto.RandomBytes(32);
            var bytes2 = Crypto.RandomBytes(32);
            var bytes3 = Crypto.RandomBytes(32);

            // Assert
            bytes1.Should().NotEqual(bytes2);
            bytes1.Should().NotEqual(bytes3);
            bytes2.Should().NotEqual(bytes3);
        }

        //
        // CRC32
        //

        // Generated with Ruby: `Zlib::crc32(input).to_s(16)`
        [Theory]
        [InlineData("", 0)]
        [InlineData("123456789", 0xCBF43926)]
        [InlineData("All your base are belong to us", 0x536EC108)]
        public void Crc32_returns_checksum(string input, uint expected)
        {
            Assert.Equal(expected, Crypto.Crc32(input.ToBytes()));
        }

        //
        // MD5
        //

        [Fact]
        public void Md5_string_returns_hashed_message()
        {
            Assert.Equal(MessageMd5, Crypto.Md5(Message));
        }

        [Fact]
        public void Md5_bytes_returns_hashed_message()
        {
            Assert.Equal(MessageMd5, Crypto.Md5(MessageBytes));
        }

        [Fact]
        public void Md5_byte_range_returns_hashed_message()
        {
            Assert.Equal(MessageMd5, Crypto.Md5(MessageBlahBytes, MessageStart, MessageLength));
        }

        [Fact]
        public void Md5_span_returns_hashed_message()
        {
            Assert.Equal(MessageMd5, Crypto.Md5(MessageBytes.AsRoSpan()));
        }

        //
        // SHA-1
        //

        [Fact]
        public void Sha1_string_returns_hashed_message()
        {
            Assert.Equal(MessageSha1, Crypto.Sha1(Message));
        }

        [Fact]
        public void Sha1_bytes_returns_hashed_message()
        {
            Assert.Equal(MessageSha1, Crypto.Sha1(MessageBytes));
        }

        [Fact]
        public void Sha1_byte_range_returns_hashed_message()
        {
            Assert.Equal(MessageSha1, Crypto.Sha1(MessageBlahBytes, MessageStart, MessageLength));
        }

        [Fact]
        public void Sha1_span_returns_hashed_message()
        {
            Assert.Equal(MessageSha1, Crypto.Sha1(MessageBytes.AsRoSpan()));
        }

        //
        // SHA-256
        //

        [Fact]
        public void Sha256_string_returns_hashed_message()
        {
            Assert.Equal(MessageSha256, Crypto.Sha256(Message));
        }

        [Fact]
        public void Sha256_bytes_returns_hashed_message()
        {
            Assert.Equal(MessageSha256, Crypto.Sha256(MessageBytes));
        }

        [Fact]
        public void Sha256_byte_range_returns_hashed_message()
        {
            Assert.Equal(MessageSha256, Crypto.Sha256(MessageBlahBytes, MessageStart, MessageLength));
        }

        [Fact]
        public void Sha256_span_returns_hashed_message()
        {
            Assert.Equal(MessageSha256, Crypto.Sha256(MessageBytes.AsRoSpan()));
        }

        //
        // SHA-512
        //

        [Fact]
        public void Sha512_string_returns_hashed_message()
        {
            Assert.Equal(MessageSha512, Crypto.Sha512(Message));
        }

        [Fact]
        public void Sha512_bytes_returns_hashed_message()
        {
            Assert.Equal(MessageSha512, Crypto.Sha512(MessageBytes));
        }

        [Fact]
        public void Sha512_byte_range_returns_hashed_message()
        {
            Assert.Equal(MessageSha512, Crypto.Sha512(MessageBlahBytes, MessageStart, MessageLength));
        }

        [Fact]
        public void Sha512_span_returns_hashed_message()
        {
            Assert.Equal(MessageSha512, Crypto.Sha512(MessageBytes.AsRoSpan()));
        }

        //
        // HMAC-SHA-256
        //

        [Fact]
        public void HmacSha256_string_returns_mac()
        {
            Assert.Equal(MessageHmacSha256, Crypto.HmacSha256("key".ToBytes(), Message));
        }

        [Fact]
        public void HmacSha256_bytes_returns_mac()
        {
            Assert.Equal(MessageHmacSha256, Crypto.HmacSha256("key".ToBytes(), MessageBytes));
        }

        [Fact]
        public void HmacSha256_byte_range_returns_mac()
        {
            Assert.Equal(MessageHmacSha256,
                         Crypto.HmacSha256("key".ToBytes(), MessageBlahBytes, MessageStart, MessageLength));
        }

        [Fact]
        public void HmacSha256_span_returns_mac()
        {
            Assert.Equal(MessageHmacSha256, Crypto.HmacSha256("key".ToBytes(), MessageBytes.AsRoSpan()));
        }

        //
        // PBKDF2
        //
        // We're not implementing the algorithm in Crypto and it doesn't make sense to have
        // an exhaustive test suite here. PBKDF2 is tested elsewhere. We just need to check
        // that we're calling the functions correctly.

        [Fact]
        public void Pbkdf2Sha1_returns_correct_result()
        {
            var derived = Crypto.Pbkdf2Sha1("password", "saltsalt".ToBytes(), 13, 32);

            Assert.Equal("Uyh7Yhywug6MOvQr33lUKcwxFx/bFNLViotFCggREnc=".Decode64(), derived);
        }

        [Fact]
        public void Pbkdf2Sha256_returns_correct_result()
        {
            var derived = Crypto.Pbkdf2Sha256("password", "saltsalt".ToBytes(), 13, 32);

            Assert.Equal("vJEouk0ert2NexzPxbIn09X1I34luPYBn2IKmJQu66s=".Decode64(), derived);
        }

        [Fact]
        public void Pbkdf2Sha512_returns_correct_result()
        {
            var derived = Crypto.Pbkdf2Sha512("password", "saltsalt".ToBytes(), 13, 32);

            Assert.Equal("zpWyQNRZlkwRdVOkHlemEWCjT8P8js2m6sYqcakt+ns=".Decode64(), derived);
        }

        //
        // AES (ECB)
        //

        [Fact]
        public void DecryptAes256Ecb_decrypts_ciphertext()
        {
            var plaintext = Crypto.DecryptAes256Ecb(AesCiphertextEcb, AesIv, AesKey);

            Assert.Equal(AesPlaintext, plaintext);
        }

        [Fact]
        public void DecryptAes256EcbNoPadding_decrypts_ciphertext()
        {
            var plaintext = Crypto.DecryptAes256EcbNoPadding(AesCiphertextEcbAligned, AesIv, AesKey);

            Assert.Equal(AesPlaintextAligned, plaintext);
        }

        [Fact]
        public void EncryptAes256Ecb_encrypts_plaintext()
        {
            var ciphertext = Crypto.EncryptAes256Ecb(AesPlaintext, AesIv, AesKey);

            Assert.Equal(AesCiphertextEcb, ciphertext);
        }

        [Fact]
        public void EncryptAes256EcbNoPadding_encrypts_plaintext()
        {
            var ciphertext = Crypto.EncryptAes256EcbNoPadding(AesPlaintextAligned, AesIv, AesKey);

            Assert.Equal(AesCiphertextEcbAligned, ciphertext);
        }

        //
        // AES (CBC)
        //

        [Fact]
        public void DecryptAes256Cbc_decrypts_ciphertext()
        {
            var plaintext = Crypto.DecryptAes256Cbc(AesCiphertextCbc, AesIv, AesKey);

            Assert.Equal(AesPlaintext, plaintext);
        }

        [Fact]
        public void DecryptAes256CbcNoPadding_decrypts_ciphertext()
        {
            var plaintext = Crypto.DecryptAes256CbcNoPadding(AesCiphertextCbcAligned, AesIv, AesKey);

            Assert.Equal(AesPlaintextAligned, plaintext);
        }

        [Fact]
        public void EncryptAes256Cbc_encrypts_plaintext()
        {
            var ciphertext = Crypto.EncryptAes256Cbc(AesPlaintext, AesIv, AesKey);

            Assert.Equal(AesCiphertextCbc, ciphertext);
        }

        [Fact]
        public void EncryptAes256CbcNoPadding_encrypts_plaintext()
        {
            var ciphertext = Crypto.EncryptAes256CbcNoPadding(AesPlaintextAligned, AesIv, AesKey);

            Assert.Equal(AesCiphertextCbcAligned, ciphertext);
        }

        //
        // AES (general)
        //

        [Theory]
        [InlineData("invalid ciphertext", "invalid iv", "invalid key")]
        [InlineData("too short", "iviviviviviviviv", "key key key key key key key key!")]
        [InlineData("too long too long", "iviviviviviviviv", "key key key key key key key key!")]
        public void DecryptAes256_throws_on_invalid_input(string ciphertext, string iv, string key)
        {
            foreach (var cipherMode in new[] {CipherMode.ECB, CipherMode.CBC})
            foreach (var padding in new[] {PaddingMode.None, PaddingMode.PKCS7})
                Exceptions.AssertThrowsCrypto(() => Crypto.DecryptAes256(ciphertext.ToBytes(),
                                                                         iv.ToBytes(),
                                                                         key.ToBytes(),
                                                                         cipherMode,
                                                                         padding));
        }

        //
        // XChaCha20Poly1305
        //

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(15)]
        public void DecryptXChaCha20Poly1305_throws_on_too_short_ciphertext(int size)
        {
            Exceptions.AssertThrowsInternalError(
                () => Crypto.DecryptXChaCha20Poly1305(new byte[size], new byte[24], new byte[32]),
                "Ciphertext must be at least 16 bytes long");
        }

        [Theory]
        [MemberData(nameof(XChaCha20Poly1305TestCases))]
        public void DecryptXChaCha20Poly1305_decrypts_ciphertext(CryptoTestVectors.XChaCha20Poly1305TestVector v)
        {
            // TODO: Associated data is not supported yet
            if (v.AssociatedData.Length > 0)
                return;

            var plaintext = Crypto.DecryptXChaCha20Poly1305(v.Ciphertext, v.Nonce, v.Key);

            Assert.Equal(v.Plaintext, plaintext);
        }

        [Theory]
        [MemberData(nameof(XChaCha20Poly1305TestCases))]
        public void DecryptXChaCha20Poly1305_throws_on_corrupt_data(CryptoTestVectors.XChaCha20Poly1305TestVector v)
        {
            // TODO: Associated data is not supported yet
            if (v.AssociatedData.Length > 0)
                return;

            static void Check(byte[] ciphertext, byte[] nonce, byte[] key)
            {
                Exceptions.AssertThrowsCrypto(() => Crypto.DecryptXChaCha20Poly1305(ciphertext, nonce, key),
                                              "Tag doesn't match, the data is corrupted or the key is incorrect");
            }

            static byte[] Corrupt(byte[] original)
            {
                var corrupted = original.Sub(0, int.MaxValue);
                corrupted[corrupted.Length / 2]++;
                return corrupted;
            }

            Check(Corrupt(v.Ciphertext), v.Nonce, v.Key);
            Check(v.Ciphertext, Corrupt(v.Nonce), v.Key);
            Check(v.Ciphertext, v.Nonce, Corrupt(v.Key));
        }

        //
        // RSA
        //

        [Fact]
        public void DecryptRsaPkcs1_decrypts_ciphertext()
        {
            var plaintext = Crypto.DecryptRsaPkcs1(RsaPkcs1.Ciphertext, RsaKey);

            Assert.Equal(RsaPlaintext.ToBytes(), plaintext);
        }

        [Fact]
        public void DecryptRsaSha1_decrypts_ciphertext()
        {
            var plaintext = Crypto.DecryptRsaSha1(RsaSha1.Ciphertext, RsaKey);

            Assert.Equal(RsaPlaintext.ToBytes(), plaintext);
        }

        [Fact]
        public void DecryptRsaSha256_decrypts_ciphertext()
        {
            var plaintext = Crypto.DecryptRsaSha256(RsaSha256.Ciphertext, RsaKey);

            Assert.Equal(RsaPlaintext.ToBytes(), plaintext);
        }

        [Fact]
        public void RestoreLeadingZeros_pads_to_correct_length()
        {
            var rsa = new RSAParameters
            {
                Exponent = DummyBigInt(24),
                Modulus = DummyBigInt(2040),
                P = DummyBigInt(104),
                Q = DummyBigInt(136),
                DP = DummyBigInt(184),
                DQ = DummyBigInt(296),
                InverseQ = DummyBigInt(424),
                D = DummyBigInt(1064),
            };

            var padded = Crypto.RestoreLeadingZeros(rsa);

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
                Exponent = DummyBigInt(24),
                Modulus = DummyBigInt(2048),
                P = DummyBigInt(1024),
                Q = DummyBigInt(1024),
                DP = DummyBigInt(1024),
                DQ = DummyBigInt(1024),
                InverseQ = DummyBigInt(1024),
                D = DummyBigInt(2048),
            };

            var padded = Crypto.RestoreLeadingZeros(rsa);

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
                var guessed = Crypto.GuessKeyBitLength(new RSAParameters() { Modulus = new byte[i / 8] });
                Assert.Equal(bits, guessed);
            }
        }

        [Theory]
        [InlineData(768)]
        [InlineData(4096 + 8)]
        public void GuessKeyBitLength_throws_on_invalid_values(int bits)
        {
            Exceptions.AssertThrowsUnsupportedFeature(
                () => Crypto.GuessKeyBitLength(new RSAParameters() { Modulus = new byte[bits / 8] }),
                "not supported");
        }

        [Fact]
        public void PrepadWithZeros_pads_with_zeros()
        {
            var original = "deadbeef".DecodeHex();

            Assert.Equal("00deadbeef", Crypto.PrepadWithZeros(original, 5).ToHex());
            Assert.Equal("0000deadbeef", Crypto.PrepadWithZeros(original, 6).ToHex());
            Assert.Equal("000000deadbeef", Crypto.PrepadWithZeros(original, 7).ToHex());
        }

        [Fact]
        public void PrepadWithZeros_returns_original_array()
        {
            var original = "deadbeef".DecodeHex();
            var padded = Crypto.PrepadWithZeros(original, original.Length);

            Assert.Same(original, padded);
        }

        //
        // Misc
        //

        [Fact]
        public void AreEqual_returns_true_for_empty_arrays()
        {
            Assert.True(Crypto.AreEqual("".ToBytes(), "".ToBytes()));
        }

        [Fact]
        public void AreEqual_returns_true_for_equal_arrays()
        {
            Assert.True(Crypto.AreEqual("Blah-blah".ToBytes(), "Blah-blah".ToBytes()));
        }

        [Theory]
        [InlineData("", "Blah-blah")]
        [InlineData("Blah-blah", "")]
        [InlineData("Blah-blah", "Blah-blah-blah")]
        public void AreEqual_returns_false_for_different_arrays(string a, string b)
        {
            Assert.False(Crypto.AreEqual(a.ToBytes(), b.ToBytes()));
        }

        //
        // Helpers
        //

        private static byte[] DummyBigInt(int bits)
        {
            return Enumerable.Range(0, bits / 8).Select(x => (byte)(x % 127 + 1)).ToArray();
        }

        //
        // Data
        //

        //
        // Hashes
        //

        private const string Message = "message";
        private static readonly byte[] MessageBytes = Message.ToBytes();

        // $ echo -n message | openssl dgst -md5 -binary | openssl base64 -A
        private static readonly byte[] MessageMd5 = "eOcxAn2P1Q7WQjQLfJpjsw==".Decode64();

        // $ echo -n message | openssl dgst -sha1 -binary | openssl base64 -A
        private static readonly byte[] MessageSha1 = "b5ua881ui4pzws3O03/p9ZIm4n0=".Decode64();

        // $ echo -n message | openssl dgst -sha256 -binary | openssl base64 -A
        private static readonly byte[] MessageSha256 = "q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64();

        // $ echo -n message | openssl dgst -sha512 -binary | openssl base64 -A
        private static readonly byte[] MessageSha512 = "+Nr1ejNHzE1rnVdbMf5gd+LLSH9gqWIzwIy0edvzFTjMkV7G1IvbqpbdwaFttPT5bzcnbPyzUQuCRiQXcNWVLA==".Decode64();

        // $ echo -n message | openssl dgst -sha256 -hmac "key" -binary | openssl base64 -A
        private static readonly byte[] MessageHmacSha256 = "bp7ym3X//Ft6uuUn1Y/a2y/kLnIZARl2kXNDBl9Y7Uo=".Decode64();

        private static readonly byte[] MessageBlahBytes = $"blah-{Message}-blah".ToBytes();
        private const int MessageStart = 5;
        private static readonly int MessageLength = Message.Length;

        //
        // AES
        //

        private static readonly byte[] AesIv = "605ba2015660383d8afaceb2f3268c3b".DecodeHex();
        private static readonly byte[] AesKey = "39f394bd59d0cc1e2fe3db0d878f8f7702056fd16be7e8d57d64537fe1361a18".DecodeHex();

        private static readonly byte[] AesPlaintext = "All your base are belong to us".ToBytes();
        private static readonly byte[] AesPlaintextAligned = "All your base are belong to us!!".ToBytes();

        // $ echo -n 'All your base are belong to us' | openssl enc -aes-256-ecb -K 39f394bd59d0cc1e2fe3db0d878f8f7702056fd16be7e8d57d64537fe1361a18 -iv 605ba2015660383d8afaceb2f3268c3b | base64
        // BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM=
        private static readonly byte[] AesCiphertextEcb = "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM=".Decode64();

        // $ echo -n 'All your base are belong to us!!' | openssl enc -aes-256-ecb -K 39f394bd59d0cc1e2fe3db0d878f8f7702056fd16be7e8d57d64537fe1361a18 -iv 605ba2015660383d8afaceb2f3268c3b -nopad | base64
        // BNhd3Q3ZVODxk9c0C788NUNlKltXfjtuF6YrSq9K+lo=
        private static readonly byte[] AesCiphertextEcbAligned = "BNhd3Q3ZVODxk9c0C788NUNlKltXfjtuF6YrSq9K+lo=".Decode64();

        // $ echo -n 'All your base are belong to us' | openssl enc -aes-256-cbc -K 39f394bd59d0cc1e2fe3db0d878f8f7702056fd16be7e8d57d64537fe1361a18 -iv 605ba2015660383d8afaceb2f3268c3b | base64
        // TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=
        private static readonly byte[] AesCiphertextCbc = "TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64();

        // $ echo -n 'All your base are belong to us!!' | openssl enc -aes-256-cbc -K 39f394bd59d0cc1e2fe3db0d878f8f7702056fd16be7e8d57d64537fe1361a18 -iv 605ba2015660383d8afaceb2f3268c3b -nopad | base64
        // TZ1+if9ofqRKTatyUaOnfono97F1Jjr+jVBAKgu/dq8=
        private static readonly byte[] AesCiphertextCbcAligned = "TZ1+if9ofqRKTatyUaOnfono97F1Jjr+jVBAKgu/dq8=".Decode64();

        //
        // XChaCha20Poly1305
        //

        public static readonly IEnumerable<object[]> XChaCha20Poly1305TestCases =
            TestBase.ToMemberData(CryptoTestVectors.XChaCha20Poly1305TestVectors);

        //
        // RSA
        //

        private static readonly RSAParameters RsaKey = new RSAParameters()
        {
            Modulus = ("snUkaje/g2JTLP6J/3LrA7EL6Zd4tZ72zsFtT1OPLcyUCN9EEGbiYnFtIrUuPGv8AhpfZm6i" +
                       "rAXq12uChvW9QVWWKrHAiYz1WF/rXgL7TI1ta5EPCojImh/XJqe4U8ETMVZqa2+gbSeKV+zG" +
                       "vhP/Z941z3LFM/h5w4ib+H4utQPaeu6kQ39SIQ0tC/+SKYCQO66KrYy/FhQOgdk3YqqD1bOi" +
                       "v4il4+lUrheqk8i/q7RHshhHSCmd1FXymGiiJsBlAq7Ge91f/amsaRcRwBl7toYbz1eNbSqX" +
                       "dhdieLGM1hTVxEubBtEroCHecQGlojbwLqYuiT7EhLuti3M2S8Lk5Q==").Decode64(),

            Exponent = "AQAB".Decode64(),

            D = ("eDRPgvxqE6V3QSdy7I4Ln0DyNTXCKRQaSsofRv+Rwde7Hv7EagfjFUwxpt9DdY+HACOjfuumxxh1Rw" +
                 "UztpRwFkIAFGIGvqAj4pM5humbO8VHntzmtMHN3YL0+SSgFEpJE0KSDCv0c5HerbrfY8k0kFItDL7R" +
                 "9l+4JO0vogHclDATdtE96R7jLo4ws9XuLf0dFO2GadbQX1r3k8kRa/s0Gp6Scs3qf5eO4Ar7T/weAO" +
                 "ETA3+hA0/noRnCvsxsdE6bL9ca02yEzYdAcBUK/PbROKAIsx4gAvkeYQ+BwpbTtzO9Rvrx2om0bmHf" +
                 "3gqJfnEO7jpRdR50UbsMpOIAoYDTQQ==").Decode64(),

            P = ("xaqDLBwDTaas+Q6ZqdZ4UgM9uklrFDzrWOS39rY4buMXv9icCADR2OikOL1aWMoex8d7DYqAzXfrFo" +
                 "rAFFohdoj274S6ZI0h/1g1cP7Nm4TiZoa6AggBN4gPPLZWakDVP3KFpzSrR0ZAVmePIjmVdVJ1hqsj" +
                 "qPR6yBlfQ9WhZnM=").Decode64(),

            Q = ("5x9yfmdXM9B5cg2BLN8TUDWYdhECngIDLuTZxrjOT9V1Tcjzryjy12aodAA8NzS6CQeMZ6dK2YqGTW" +
                 "PFES6KPjBPZGelHW8pOvzme0Hjl+p24lwnaIAz2hJS6uuA9Kos0XSdEyaz9Iq+SErlD9YmvNYDMRpr" +
                 "CRkGiuK6vyE42Uc=").Decode64(),

            DP = ("B5qEizjUo7MKqlX2cUMPw8/eGwFh/hhN0VCTBwmBaDqSGk4hymkFqXthfdFC3XGA95xjzmSKidzYD" +
                  "TjvJJlG+kFQhmwro1yOdz0UaTFUBWx6LQl3tEZMja9NLr+w2Ut/KH6mR4VOJWK9bNV0+xMN/cJbRP" +
                  "/mUkR9SJ85O+nG2KM=").Decode64(),

            DQ = ("2fNz2vPE7h3IiN9nU1NCOT9xeNVtrGelbNFu9NFN7UcUibfY5PMuniY28L1QC5dzYBR4OT8vfJn/M" +
                  "HfHXP6QazjPhZWfxXQQY4oeJ1npMFdwqOHSX9+WBi2Fd/eB8jeQcC0R+v9icFduPWozPI3sleMTu3" +
                  "h4O2oYG1zYUmkX3P0=").Decode64(),

            InverseQ = ("DQuR3VAvBwjMjADJhmekTbU/BbofAxrIGcu+GpUU7Zz0GWnoJ+CGUc9l0ZaTslbhNOA5HOu" +
                        "ma437eKruLiKaop9eTG1M/6YqDQguBZ1fAg9wpYBNMuzCAJnPUVCa4YqxFV3QAf39VkM33v" +
                        "ifzU7j2+i8Mho6p67EQLOUZTVqE60=").Decode64(),
        };

        public class RsaTestCase
        {
            public readonly RSAEncryptionPadding Padding;
            public readonly byte[] Ciphertext;

            public RsaTestCase(RSAEncryptionPadding padding, string ciphertext)
            {
                Padding = padding;
                Ciphertext = ciphertext.Decode64();
            }
        }

        private const string RsaPlaintext = "All your base are belong to us";

        private static readonly RsaTestCase RsaPkcs1 = new RsaTestCase(
            RSAEncryptionPadding.Pkcs1,
            "BgHvJEsjMEFMMaEirQkWNrAn/eyfkyahZHUCVTuU0/w9xwkJuA1YKXsBI3lUptu2G8U+PtwyMqTTJAee2WX" +
            "aC37EJImUryPVFJxAed7z0HWMfwwaGIpDex3OiXCnzZZ8pIX1T0NE9qeUcO9aqF2EuN3fp+PDhXW/VhPnwi" +
            "INI7kkVw1PQiMgpEfNAvFj1SJA9yPYQeqSQ3HdT6/+Wxd/NamRonaQRAURElokh8xSBu3QCUzCps/8rUklX" +
            "NbIZf48mnTKZYHa1oCDZBH2rj0EVoRmPRXj0gX3y4TryqRtYdeOKUtKVZKJH6e55lxhSw+U2EBA/jn2crnZ" +
            "rWsOBjM9uQ==");

        private static readonly RsaTestCase RsaSha1 = new RsaTestCase(
            RSAEncryptionPadding.OaepSHA1,
            "o70rRrBsZZmmRgWGCqUPQj1LoxObFP6D9X9X8VsAxd9RolqHRjRzzIy7aQBgJyIiwfxCEBwZO3r+B8vUY61" +
            "rmOQpvhosi1nN8efgKm//YfL5GwWMZ7yEzk5KSPm+uP/renOwHITbpuzlFeJWI1j6PJomAXxLvJvEx0n7pY" +
            "wKFS0Ny79pa7aqwtxKftokLM/ckztZyKQG5svqUAyKQIteduOvi6xg88K5+93a6/hOHc/E/Kn8L6xSVOXBp" +
            "lRokZGYVqhiFk364eyT8X1ZualO4TfTxNeZPCfJADVB6lVWXAIXVhL2wdupX2KsThAYmjPKKGlcOdPnR8ZZ" +
            "WD1F7stgIw==");

        private static readonly RsaTestCase RsaSha256 = new RsaTestCase(
            RSAEncryptionPadding.OaepSHA256,
            "Ap0o4nz8O86QfK2USakYCIPbaQTpXVHo70bDYyNwdCzp61P7kUPMRXcdcmtZzSjUoRkDhuoRpXxxzojLdHt" +
            "XBsvo2/L6/h0sdo7kGHD1nIhBVyda/7akWyCgm5uVUhsZcl/xTsfTLREh/DRKrhyXOBBO5A4raUVmtP/dj1" +
            "GJmSsEdkltPMRpNl2KQptxDROsQ0/I63wEH4Qt1e7Lu1yf+yCP0pN+2i1OaL5RUUYmvzwSbZ5sTgRbtqLO3" +
            "8fJdUgkunM+0An6OpFKXJx1bQNenwe8Cd9qGytgh6FSwTQv77LO/ug3/QpR6GxfCY0hNZTe7J0uticAtthx" +
            "tpGYxyej5Q==");
    }
}
