// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Security.Cryptography;
using NUnit.Framework;

namespace RoboForm.Test
{
    [TestFixture]
    public class Pbkdf2Test
    {
        [Test]
        public void Generate_sha_1_returns_correct_result()
        {
            VerifyGenerator(Pbkdf2.GenerateSha1, Sha1);
            VerifyGenerator(Pbkdf2.Generate<HMACSHA1>, Sha1);
        }

        [Test]
        public void Generate_sha_256_returns_correct_result()
        {
            VerifyGenerator(Pbkdf2.GenerateSha256, Sha256);
            VerifyGenerator(Pbkdf2.Generate<HMACSHA256>, Sha256);
        }

        [Test]
        public void Generate_sha_512_returns_correct_result()
        {
            VerifyGenerator(Pbkdf2.GenerateSha512, Sha512);
            VerifyGenerator(Pbkdf2.Generate<HMACSHA512>, Sha512);
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
        };

        private static readonly TestCase[] TestCases =
        {
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 1,
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 1,
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 2,
            },
            new TestCase
            {
                Password = "password",
                Salt = "salt",
                IterationCount = 4096,
            },
            new TestCase
            {
                Password = "passwordPASSWORDpassword",
                Salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                IterationCount = 4096,
            },
            new TestCase
            {
                Password = "pass\0word",
                Salt = "sa\0lt",
                IterationCount = 4096,
            },
        };

        // From https://tools.ietf.org/html/rfc6070
        private static readonly string[] Sha1 =
        {
            "",
            "DGDID5YfDnHzqbUkr2ASBi/gN6Y=",
            "6mwBTcctb4zNHtkqzh1B8NjeiVc=",
            "SwB5AbdlSJq+rUnZJvch0GWkKcE=",
            "PS7sT+QchJuAyNg2YsDkSospGpZM8vBwOA==",
            "Vvpqp1VICZ3MN9fwNCXgww=="
        };

        // From https://stackoverflow.com/a/5136918/362938
        private static readonly string[] Sha256 =
        {
            "",
            "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs=",
            "rk0Mla9rRtMtCt/5KPBt0CowP47zwlHf1uLYWpVHTEM=",
            "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o=",
            "NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q==",
            "ibadBRb4KYk8aWImZQqGhw==",
        };

        // I could not find the official PBKDF2 SHA512 test vectors. So these are generated
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
        //     puts %Q{new TestCase(#{i[0].inspect}, #{i[1].inspect}, #{i[2]}, #{k.e64.inspect}),}
        // end
        private static readonly string[] Sha512 =
        {
            "",
            "hn9wzxreAs/zdSWZo6U9xK80x6ZpgVrl1RNVThyM8lI=",
            "4dnBaqaBcIpF9cfE4hXOtm4BGi6fAEBxPxiu/bhm1Tw=",
            "0Zexsz2wFD4BixLz0dFHnmzevcyXxcD4f2kC4HL0V7U=",
            "jAUR9Mbll8asYxXY8DYuIl88UBSVuiO4aMAFF03E7nERW1n55gzZUw==",
            "nZ6cTNIf5L4k1bgkTHWWZQ==",
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

        //
        // Helpers
        //

        private static void VerifyGenerator(Func<byte[], byte[], int, int, byte[]> generate,
                                            string[] expectedResults)
        {
            Assert.That(TestCases.Length, Is.EqualTo(expectedResults.Length));

            foreach (var i in TestCases.Zip(expectedResults, (t, e) => new { Test = t, Expected = e }))
            {
                var expected = i.Expected.Decode64();

                Assert.That(generate(i.Test.Password.ToBytes(),
                                     i.Test.Salt.ToBytes(),
                                     i.Test.IterationCount,
                                     expected.Length),
                            Is.EqualTo(expected));
            }
        }
    }
}
