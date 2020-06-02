// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace PasswordManagerAccess.Test.OpVault
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
                Assert.That(() => generate(Bytes("password"), Bytes("salt"), 0, 32),
                            Throws.InstanceOf<ArgumentOutOfRangeException>()
                                .And.Message.StartsWith("Iteration count should be positive"));
        }

        [Test]
        public void Generate_throws_on_negative_iterationCount()
        {
            foreach (var generate in Generators)
                Assert.That(() => generate(Bytes("password"), Bytes("salt"), -1, 32),
                            Throws.InstanceOf<ArgumentOutOfRangeException>()
                                .And.Message.StartsWith("Iteration count should be positive"));
        }

        [Test]
        public void Generate_throws_on_negative_byteCount()
        {
            foreach (var generate in Generators)
                Assert.That(() => generate(Bytes("password"), Bytes("salt"), 1, -1),
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

        private static readonly string[] Sha1 =
        {
            "",
            "DGDID5YfDnHzqbUkr2ASBi/gN6Y=",
            "6mwBTcctb4zNHtkqzh1B8NjeiVc=",
            "SwB5AbdlSJq+rUnZJvch0GWkKcE=",
            "PS7sT+QchJuAyNg2YsDkSospGpZM8vBwOA==",
            "Vvpqp1VICZ3MN9fwNCXgww==",
        };

        private static readonly string[] Sha256 =
        {
            "",
            "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs=",
            "rk0Mla9rRtMtCt/5KPBt0CowP47zwlHf1uLYWpVHTEM=",
            "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o=",
            "NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q==",
            "ibadBRb4KYk8aWImZQqGhw==",
        };

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
                var expected = Decode64(i.Expected);

                Assert.That(generate(Bytes(i.Test.Password),
                                     Bytes(i.Test.Salt),
                                     i.Test.IterationCount,
                                     expected.Length),
                            Is.EqualTo(expected));
            }
        }

        private static byte[] Bytes(string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        private static byte[] Decode64(string s)
        {
            return Convert.FromBase64String(s);
        }
    }
}
