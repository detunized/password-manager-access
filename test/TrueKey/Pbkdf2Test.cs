// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class Pbkdf2Test
    {
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

        // There's no official PBKDF2 SHA512 test vectors. So these are generated
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
        private static readonly TestCase[] TestData =
        {
            new TestCase("password", "salt", 1, ""),
            new TestCase("password", "salt", 1, "hn9wzxreAs/zdSWZo6U9xK80x6ZpgVrl1RNVThyM8lI="),
            new TestCase("password", "salt", 2, "4dnBaqaBcIpF9cfE4hXOtm4BGi6fAEBxPxiu/bhm1Tw="),
            new TestCase("password", "salt", 4096, "0Zexsz2wFD4BixLz0dFHnmzevcyXxcD4f2kC4HL0V7U="),
            new TestCase("passwordPASSWORDpassword",
                         "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                         4096,
                         "jAUR9Mbll8asYxXY8DYuIl88UBSVuiO4aMAFF03E7nERW1n55gzZUw=="),
            new TestCase("pass\0word", "sa\0lt", 4096, "nZ6cTNIf5L4k1bgkTHWWZQ=="),
        };

        [Fact]
        public void Generate_returns_correct_result()
        {
            foreach (var i in TestData)
            {
                var expected = i.Expected.Decode64();

                Assert.Equal(expected,
                             Pbkdf2.Generate(i.Password, i.Salt, i.IterationCount, expected.Length));
                Assert.Equal(expected,
                             Pbkdf2.Generate(i.Password.ToBytes(), i.Salt, i.IterationCount, expected.Length));
                Assert.Equal(expected,
                             Pbkdf2.Generate(i.Password, i.Salt.ToBytes(), i.IterationCount, expected.Length));
                Assert.Equal(expected,
                             Pbkdf2.Generate(i.Password.ToBytes(), i.Salt.ToBytes(), i.IterationCount, expected.Length));
            }
        }

        [Fact]
        public void Generate_throws_on_zero_iterationCount()
        {
            var e = Assert.Throws<ArgumentOutOfRangeException>(() => Pbkdf2.Generate("password", "salt", 0, 32));
            Assert.StartsWith("Iteration count should be positive", e.Message);
        }

        [Fact]
        public void Generate_throws_on_negative_iterationCount()
        {
            var e = Assert.Throws<ArgumentOutOfRangeException>(() => Pbkdf2.Generate("password", "salt", -1, 32));
            Assert.StartsWith("Iteration count should be positive", e.Message);
        }

        [Fact]
        public void Generate_throws_on_negative_byteCount()
        {
            var e = Assert.Throws<ArgumentOutOfRangeException>(() => Pbkdf2.Generate("password", "salt", 1, -1));
            Assert.StartsWith("Byte count should be nonnegative", e.Message);
        }
    }
}
