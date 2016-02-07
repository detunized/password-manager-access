// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class UkiTest
    {
        [Test]
        public void Generate_returns_uki()
        {
            Assert.That(Uki.Generate(), Is.StringMatching(@"[0-9a-f]+-webaccess-[0-9]+"));
        }
    }
}
