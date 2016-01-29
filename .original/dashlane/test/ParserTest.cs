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
        [Test]
        public void ComputeEncryptionKey_returns_correct_result()
        {
            var key = Parser.ComputeEncryptionKey(
                "password",
                "saltsaltsaltsaltsaltsaltsaltsalt".ToBytes());
            Assert.AreEqual("OAIU9FREAugcAkNtoeoUithzi2qXJQc6Gfj5WgPD0mY=".Decode64(), key);
        }

        [Test]
        public void Sha1_computes_sha1_given_times()
        {
            var bytes = "All your base are belong to us".ToBytes();
            Assert.AreEqual(bytes, Parser.Sha1(bytes, 0));
            Assert.AreEqual("xgmXgTCENlJpbnSLucn3NwPXkIk=".Decode64(), Parser.Sha1(bytes, 1));
            Assert.AreEqual("RqcjtwJ5KY1MON7n3WwvqGhrrpg=".Decode64(), Parser.Sha1(bytes, 5));
        }
    }
}
