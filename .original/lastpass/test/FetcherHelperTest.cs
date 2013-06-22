using System;
using System.Collections.Generic;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class FetcherHelperTest
    {
        [Test]
        public void MakeKey()
        {
            var testCases = new Dictionary<int, string>
            {
                {1, "C/Bh2SGWxI8JDu54DbbpV8J9wa6pKbesIb9MAXkeF3Y="}
            };

            var username = "postlass@gmail.com";
            var password = "pl1234567890";

            foreach (var i in testCases)
            {
                var result = FetcherHelper.MakeKey(username, password, i.Key);
                Assert.AreEqual(Convert.FromBase64String(i.Value), result);
            }
        }
    }
}
