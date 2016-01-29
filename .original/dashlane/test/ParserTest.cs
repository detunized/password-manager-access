// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Text;
using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    internal class ParserTest
    {
        [Test]
        public void ComputeEncryptionKey_returns_correct_result()
        {
            var key = Parser.ComputeEncryptionKey(
                "password",
                "saltsaltsaltsaltsaltsaltsaltsalt".ToBytes());
            Assert.AreEqual(
                Convert.FromBase64String("OAIU9FREAugcAkNtoeoUithzi2qXJQc6Gfj5WgPD0mY="),
                key);
        }

        [Test]
        public void Sha1_computes_sha1_given_times()
        {
            var bytes = "All your base are belong to us".ToBytes();
            Assert.AreEqual(bytes, Parser.Sha1(bytes, 0));
            Assert.AreEqual(
                Convert.FromBase64String("xgmXgTCENlJpbnSLucn3NwPXkIk="),
                Parser.Sha1(bytes, 1));
            Assert.AreEqual(
                Convert.FromBase64String("RqcjtwJ5KY1MON7n3WwvqGhrrpg="),
                Parser.Sha1(bytes, 5));
        }
    }
}
