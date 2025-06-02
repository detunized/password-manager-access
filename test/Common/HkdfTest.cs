// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Security.Cryptography;
using PasswordManagerAccess.Common;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class HkdfTest
    {
        // TODO: This method tests the internal function Hkdf.DeriveKey. It should test the public methods instead.
        [Theory]
        [MemberData(nameof(TestCases))]
        public void Generate_returns_expected_values(TestCase tc)
        {
            foreach (var (hmac, expected) in tc.Expected)
            {
                // Arrange
                var ikm = tc.Ikm.DecodeHex();
                var salt = tc.Salt.DecodeHex();
                var info = tc.Info.DecodeHex();

                // Act
                var result = Hkdf.DeriveKey(ikm: ikm, salt: salt, info: info, byteCount: tc.ByteCount, hash: hmac);

                // Assert
                result.ShouldBe(expected.DecodeHex());
            }
        }

        [Fact]
        public void Generate_throws_on_negative_byteCount()
        {
            // Arrange
            var act = () =>
                Hkdf.DeriveKey(ikm: "ikm".ToBytes(), salt: "salt".ToBytes(), info: "info".ToBytes(), byteCount: -1, hash: HashAlgorithmName.SHA256);

            // Act
            var ex = act.ShouldThrow<InternalErrorException>();

            // Assert
            ex.Message.ShouldContain("Byte count should be nonnegative");
        }

        //
        // Data
        //

        public readonly record struct TestCase(string Ikm, string Salt, string Info, int ByteCount, Dictionary<HashAlgorithmName, string> Expected);

        // Test vectors from https://github.com/brycx/Test-Vector-Generation/blob/master/HKDF/hkdf-hmac-sha2-test-vectors.md
        private static readonly TestCase[] TestCasesData =
        [
            // RFC 5869 Test Case 1
            new(
                Ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                Salt: "000102030405060708090a0b0c",
                Info: "f0f1f2f3f4f5f6f7f8f9",
                ByteCount: 42,
                Expected: new Dictionary<HashAlgorithmName, string>
                {
                    [HashAlgorithmName.SHA1] = "d6000ffb5b50bd3970b260017798fb9c8df9ce2e2c16b6cd709cca07dc3cf9cf26d6c6d750d0aaf5ac94",
                    [HashAlgorithmName.SHA256] = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                    [HashAlgorithmName.SHA384] = "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5",
                    [HashAlgorithmName.SHA512] = "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
                }
            ),
            // RFC 5869 Test Case 2
            new(
                Ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                Salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                Info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                ByteCount: 82,
                Expected: new Dictionary<HashAlgorithmName, string>
                {
                    [HashAlgorithmName.SHA1] =
                        "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
                    [HashAlgorithmName.SHA256] =
                        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
                    [HashAlgorithmName.SHA384] =
                        "484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649eebf69f8d5c832856bf4e4fbc17967d54975324a94987f7f41835817d8994fdbd6f4c09c5500dca24a56222fea53d8967a8b2e",
                    [HashAlgorithmName.SHA512] =
                        "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93",
                }
            ),
            // RFC 5869 Test Case 3
            new(
                Ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                Salt: "",
                Info: "",
                ByteCount: 42,
                Expected: new Dictionary<HashAlgorithmName, string>
                {
                    [HashAlgorithmName.SHA1] = "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
                    [HashAlgorithmName.SHA256] = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                    [HashAlgorithmName.SHA384] = "c8c96e710f89b0d7990bca68bcdec8cf854062e54c73a7abc743fade9b242daacc1cea5670415b52849c",
                    [HashAlgorithmName.SHA512] = "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac",
                }
            ),
            // RFC 5869 Test Case 4
            new(
                Ikm: "0b0b0b0b0b0b0b0b0b0b0b",
                Salt: "000102030405060708090a0b0c",
                Info: "f0f1f2f3f4f5f6f7f8f9",
                ByteCount: 42,
                Expected: new Dictionary<HashAlgorithmName, string>
                {
                    [HashAlgorithmName.SHA1] = "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
                    [HashAlgorithmName.SHA256] = "58dce10d5801cdfda831726bfebcb743d14a7ee83aa057a93d59b0a1317ff09d105ccecf535692b14dd5",
                    [HashAlgorithmName.SHA384] = "fb7e6743eb42cde96f1b70778952ab7548cafe53249f7ffe1497a1635b201ff185b93e951992d858f11a",
                    [HashAlgorithmName.SHA512] = "7413e8997e020610fbf6823f2ce14bff01875db1ca55f68cfcf3954dc8aff53559bd5e3028b080f7c068",
                }
            ),
        ];

        public static readonly IEnumerable<TheoryDataRow<TestCase>> TestCases = TestBase.ToTheoryData(TestCasesData);
    }
}
