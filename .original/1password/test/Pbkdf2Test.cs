// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Security.Cryptography;
using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    class Pbkdf2Test
    {
        [Test]
        public void Generate_sha_1_returns_correct_result()
        {
            VerifyGenerator(Pbkdf2.GenerateSha1, Sha1TestCases);
            VerifyGenerator(Pbkdf2.Generate<HMACSHA1>, Sha1TestCases);
        }

        [Test]
        public void Generate_sha_256_returns_correct_result()
        {
            VerifyGenerator(Pbkdf2.GenerateSha256, Sha256TestCases);
            VerifyGenerator(Pbkdf2.Generate<HMACSHA256>, Sha256TestCases);
        }

        [Test]
        public void Generate_sha_512_returns_correct_result()
        {
            VerifyGenerator(Pbkdf2.GenerateSha512, Sha512TestCases);
            VerifyGenerator(Pbkdf2.Generate<HMACSHA512>, Sha512TestCases);
        }

        private void VerifyGenerator(Func<byte[], byte[], int, int, byte[]> generate,
                                     TestCase[] testCases)
        {
            foreach (var i in testCases)
            {
                var expected = i.Expected.DecodeHex();

                Assert.That(generate(i.Password.ToBytes(),
                                     i.Salt.ToBytes(),
                                     i.IterationCount,
                                     expected.Length),
                            Is.EqualTo(expected));
            }
        }

        [Test]
        public void Generate_throws_on_zero_iterationCount()
        {
            foreach (var generate in Generators)
                Assert.That(() => generate("password".ToBytes(), "salt".ToBytes(), 0, 32),
                            Throws.InstanceOf<ArgumentOutOfRangeException>()
                                .And.Message.StartsWith("Iteration count should be positive"));
        }

        [Test]
        public void Generate_throws_on_negative_iterationCount()
        {
            foreach (var generate in Generators)
                Assert.That(() => generate("password".ToBytes(), "salt".ToBytes(), -1, 32),
                            Throws.InstanceOf<ArgumentOutOfRangeException>()
                                .And.Message.StartsWith("Iteration count should be positive"));
        }

        [Test]
        public void Generate_throws_on_negative_byteCount()
        {
            foreach (var generate in Generators)
                Assert.That(() => generate("password".ToBytes(), "salt".ToBytes(), 1, -1),
                            Throws.InstanceOf<ArgumentOutOfRangeException>()
                                .And.Message.StartsWith("Byte count should be nonnegative"));
        }

        //
        // Data
        //

        private struct TestCase
        {
            public string Password;
            public string Salt;
            public int IterationCount;
            public string Expected;
        };

        //
        // SHA-1
        //

        private static readonly TestCase[] Sha1TestCases =
        {
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 1,
                Expected = ""
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 1,
                Expected = "0c60c80f961f0e71f3a9b524af6012062fe037a6"
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 2,
                Expected = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 4096,
                Expected = "4b007901b765489abead49d926f721d065a429c1"
            },
            new TestCase
            {
                Password = "passwordPASSWORDpassword",
                Salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                IterationCount = 4096,
                Expected = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
            },
            new TestCase
            {
                Password = "pass\0word",
                Salt = "sa\0lt",
                IterationCount = 4096,
                Expected = "56fa6aa75548099dcc37d7f03425e0c3"
            },
        };

        //
        // SHA-256
        //

        // Test vectors for PBKDF2 HMAC-SHA256 are from
        // http://stackoverflow.com/a/5136918/362938
        private static readonly TestCase[] Sha256TestCases =
        {
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 1,
                Expected = ""
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 1,
                Expected = "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 2,
                Expected = "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 4096,
                Expected = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
            },
            new TestCase
            {
                Password = "passwordPASSWORDpassword",
                Salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                IterationCount = 4096,
                Expected =
                    "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"
            },
            new TestCase
            {
                Password = "pass\0word",
                Salt = "sa\0lt",
                IterationCount = 4096,
                Expected = "89b69d0516f829893c696226650a8687"
            },
        };

        //
        // SHA-512
        //

        // There are no official PBKDF2 SHA512 test vectors. So these are generated
        // with the following Ruby program:
        //
        // [
        //     ["password", "salt", 1, 0],
        //     ["password", "salt", 1, 32],
        //     ["password", "salt", 2, 32],
        //     ["password", "salt", 4096, 32],
        //     ["passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40],
        //     ["pass\0word", "sa\0lt", 4096, 16],
        // ].each do |i|
        //     k = OpenSSL::PKCS5.pbkdf2_hmac *i[0, 4], "sha512"
        //     puts %Q{new TestCase(...),}
        // end
        private static readonly TestCase[] Sha512TestCases =
        {
            new TestCase
            {Password = "password", Salt = "salt", IterationCount = 1, Expected = ""},
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 1,
                Expected = "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 2,
                Expected = "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 4096,
                Expected = "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5"
            },
            new TestCase
            {
                Password = "passwordPASSWORDpassword",
                Salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                IterationCount = 4096,
                Expected =
                    "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd953"
            },
            new TestCase
            {
                Password = "pass\0word",
                Salt = "sa\0lt",
                IterationCount = 4096,
                Expected = "9d9e9c4cd21fe4be24d5b8244c759665"
            },
        };

        private static readonly Func<byte[], byte[], int, int, byte[]>[] Generators =
        {
            Pbkdf2.GenerateSha1,
            Pbkdf2.GenerateSha256,
            Pbkdf2.GenerateSha512,
            Pbkdf2.Generate<HMACSHA1>,
            Pbkdf2.Generate<HMACSHA256>,
            Pbkdf2.Generate<HMACSHA512>,
        };
    }
}
