// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Text;
using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class ParserTest
    {
        private static readonly byte[] Salt = "saltsaltsaltsaltsaltsaltsaltsalt".ToBytes();

        [Test]
        public void ComputeEncryptionKey_returns_correct_result()
        {
            var key = Parser.ComputeEncryptionKey("password", Salt);
            Assert.AreEqual("OAIU9FREAugcAkNtoeoUithzi2qXJQc6Gfj5WgPD0mY=".Decode64(), key);
        }

        [Test]
        public void Sha1_computes_sha1_given_times()
        {
            var bytes = "All your base are belong to us".ToBytes();
            var check = new Action<int, string>((iterations, expected) =>
                Assert.That(Parser.Sha1(bytes, iterations), Is.EqualTo(expected.Decode64())));

            check(0, Convert.ToBase64String(bytes));
            check(1, "xgmXgTCENlJpbnSLucn3NwPXkIk=");
            check(5, "RqcjtwJ5KY1MON7n3WwvqGhrrpg=");
        }

        [Test]
        public void DeriveEncryptionKeyAndIv_computes_key_and_iv_for_given_number_of_iterations()
        {
            var key = "OAIU9FREAugcAkNtoeoUithzi2qXJQc6Gfj5WgPD0mY=".Decode64();
            var check = new Action<int, string, string>((iterations, expectedKey, expectedIv) =>
            {
                var keyIv = Parser.DeriveEncryptionKeyAndIv(key, Salt, iterations);
                Assert.That(keyIv.Key, Is.EqualTo(expectedKey.Decode64()));
                Assert.That(keyIv.Iv, Is.EqualTo(expectedIv.Decode64()));
            });

            check(1, "6HA2Rq9GTeKzAc1imNjvyaXBGW4zRA5wIr60Vbx/o8w=", "fCk2EkpIYGn05JHcVfR8eQ==");
            check(5, "fsuGfEOoYL4uOmp24ZuAExIuVePh6YIu7t0rfCDogpM=", "/vsHfrsRzyGCQOBP4UEQuw==");
        }
    }
}
