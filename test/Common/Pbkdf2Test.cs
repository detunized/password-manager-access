// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Runtime.Intrinsics.Arm;
using FluentAssertions;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class Pbkdf2Test
    {
        [Fact]
        public void GenerateShaXXX_returns_correct_result()
        {
            for (var i = 0; i < Results.Length; i++)
                Generate_returns_correct_result(Generators[i], Results[i]);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        public void GenerateShaXXX_throws_on_zero_iterationCount(int iterationCount)
        {
            foreach (var generate in Generators)
            {
                var act = () => generate("password".ToBytes(), "salt".ToBytes(), iterationCount, 32);
                act.Should().Throw<InternalErrorException>().WithMessage("Iteration count should be positive");
            }
        }

        [Fact]
        public void GenerateShaXXX_throws_on_negative_byteCount()
        {
            foreach (var generate in Generators)
            {
                var act = () => generate("password".ToBytes(), "salt".ToBytes(), 1, -1);
                act.Should().Throw<InternalErrorException>().WithMessage("Byte count should be nonnegative");
            }
        }

        //
        // Helpers
        //

        private void Generate_returns_correct_result(Func<byte[], byte[], int, int, byte[]> generator, string[] expectedResults)
        {
            expectedResults.Should().HaveCount(TestCases.Length);

            for (var i = 0; i < TestCases.Length; i++)
            {
                // Arrange
                var testCase = TestCases[i];
                var expectedHex = expectedResults[i];
                var expectedBytes = expectedHex.DecodeHex();

                var password = testCase.Password.ToBytes();
                var salt = testCase.Salt.ToBytes();
                var iterationCount = testCase.IterationCount;
                var byteCount = expectedBytes.Length;

                // Act
                var actual = generator(password, salt, iterationCount, byteCount);

                // Assert
                actual.Should().Equal(expectedBytes);
            }
        }

        //
        // Data
        //

        private readonly record struct TestCase(string Password, string Salt, int IterationCount);

        private static readonly TestCase[] TestCases =
        [
            new(Password: "password", Salt: "salt", IterationCount: 1),
            new(Password: "password", Salt: "salt", IterationCount: 1),
            new(Password: "password", Salt: "salt", IterationCount: 2),
            new(Password: "password", Salt: "salt", IterationCount: 4096),
            new(Password: "passwordPASSWORDpassword", Salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt", IterationCount: 4096),
            new(Password: "pass\0word", Salt: "sa\0lt", IterationCount: 4096),
        ];

        private static readonly string[] Sha1Results =
        [
            "",
            "0c60c80f961f0e71f3a9b524af6012062fe037a6",
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
            "4b007901b765489abead49d926f721d065a429c1",
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
            "56fa6aa75548099dcc37d7f03425e0c3",
        ];

        private static readonly string[] Sha256Results =
        [
            "",
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
            "89b69d0516f829893c696226650a8687",
        ];

        private static readonly string[] Sha512Results =
        [
            "",
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252",
            "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c",
            "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5",
            "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd953",
            "9d9e9c4cd21fe4be24d5b8244c759665",
        ];

        private static readonly Func<byte[], byte[], int, int, byte[]>[] Generators =
        [
            Pbkdf2.GenerateSha1,
            Pbkdf2.GenerateSha256,
            Pbkdf2.GenerateSha512,
        ];

        private static readonly string[][] Results = [Sha1Results, Sha256Results, Sha512Results];
    }
}
