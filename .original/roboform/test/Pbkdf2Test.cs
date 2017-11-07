// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace RoboForm.Test
{
    [TestFixture]
    class Pbkdf2Test
    {
        [Test]
        public void Generate_returns_correct_result()
        {
            foreach (var i in TestData)
            {
                var expected = i.Expected.Decode64();

                Assert.That(Pbkdf2.Generate(i.Password,
                                            i.Salt,
                                            i.IterationCount,
                                            expected.Length),
                            Is.EqualTo(expected));

                Assert.That(Pbkdf2.Generate(i.Password.ToBytes(),
                                            i.Salt,
                                            i.IterationCount,
                                            expected.Length),
                            Is.EqualTo(expected));

                Assert.That(Pbkdf2.Generate(i.Password,
                                            i.Salt.ToBytes(),
                                            i.IterationCount,
                                            expected.Length),
                            Is.EqualTo(expected));

                Assert.That(Pbkdf2.Generate(i.Password.ToBytes(),
                                            i.Salt.ToBytes(),
                                            i.IterationCount,
                                            expected.Length),
                            Is.EqualTo(expected));
            }
        }

        [Test]
        public void Generate_throws_on_zero_iterationCount()
        {
            Assert.That(() => Pbkdf2.Generate("password", "salt", 0, 32),
                        Throws.InstanceOf<ArgumentOutOfRangeException>()
                            .And.Message.StartsWith("Iteration count should be positive"));
        }

        [Test]
        public void Generate_throws_on_negative_iterationCount()
        {
            Assert.That(() => Pbkdf2.Generate("password", "salt", -1, 32),
                        Throws.InstanceOf<ArgumentOutOfRangeException>()
                            .And.Message.StartsWith("Iteration count should be positive"));
        }

        [Test]
        public void Generate_throws_on_negative_byteCount()
        {
            Assert.That(() => Pbkdf2.Generate("password", "salt", 1, -1),
                        Throws.InstanceOf<ArgumentOutOfRangeException>()
                            .And.Message.StartsWith("Byte count should be nonnegative"));
        }

        //
        // Data
        //

        private class TestCase
        {
            public readonly string Password;
            public readonly string Salt;
            public readonly int IterationCount;
            public readonly string Expected;

            public TestCase(string password, string salt, int iterationCount, string expected)
            {
                Password = password;
                Salt = salt;
                IterationCount = iterationCount;
                Expected = expected;
            }
        };

        // Test data for PBKDF2 HMAC-SHA256 is from http://stackoverflow.com/a/5136918/362938
        private static readonly TestCase[] TestData =
        {
            new TestCase("password", "salt", 1, ""),
            new TestCase("password", "salt", 1, "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs="),
            new TestCase("password", "salt", 2, "rk0Mla9rRtMtCt/5KPBt0CowP47zwlHf1uLYWpVHTEM="),
            new TestCase("password", "salt", 4096, "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o="),
            new TestCase("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "NIyJ28vTKy8y2BS4EW6EzysXNH68GAAYHE4qH7jdU+HGNVGMfaxH6Q=="),
            new TestCase("pass\0word", "sa\0lt", 4096, "ibadBRb4KYk8aWImZQqGhw==")
        };
    }
}
