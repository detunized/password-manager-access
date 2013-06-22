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
                {1, "C/Bh2SGWxI8JDu54DbbpV8J9wa6pKbesIb9MAXkeF3Y="},
                {5, "pE9goazSCRqnWwcixWM4NHJjWMvB5T15dMhe6ug1pZg="},
                {10, "n9S0SyJdrMegeBHtkxUx8Lzc7wI6aGl+y3/udGmVey8="},
                {50, "GwI8/kNy1NjIfe3Z0VAZfF78938UVuCi6xAL3MJBux0="},
                {100, "piGdSULeHMWiBS3QJNM46M5PIYwQXA6cNS10pLB3Xf8="},
                {500, "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg="},
                {1000, "z7CdwlIkbu0XvcB7oQIpnlqwNGemdrGTBmDKnL9taPg="}
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
