using System;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class FetcherHelperTest
    {
        [Test]
        public void MakeKey()
        {
            var expected = Convert.FromBase64String("C/Bh2SGWxI8JDu54DbbpV8J9wa6pKbesIb9MAXkeF3Y=");
            var username = "postlass@gmail.com";
            var password = "pl1234567890";
            var iterationCount = 1;
            var result = FetcherHelper.MakeKey(username, password, iterationCount);

            Assert.AreEqual(expected, result);
        }
    }
}
