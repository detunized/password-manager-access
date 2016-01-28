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
                Encoding.UTF8.GetBytes("saltsaltsaltsaltsaltsaltsaltsalt"));
            Assert.AreEqual(
                Convert.FromBase64String("OAIU9FREAugcAkNtoeoUithzi2qXJQc6Gfj5WgPD0mY="),
                key);
        }
    }
}
