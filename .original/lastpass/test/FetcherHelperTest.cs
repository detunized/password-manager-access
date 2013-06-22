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
                {1000, "z7CdwlIkbu0XvcB7oQIpnlqwNGemdrGTBmDKnL9taPg="},
            };

            var username = "postlass@gmail.com";
            var password = "pl1234567890";

            foreach (var i in testCases)
            {
                var result = FetcherHelper.MakeKey(username, password, i.Key);
                Assert.AreEqual(Convert.FromBase64String(i.Value), result);
            }
        }

        [Test]
        public void MakeHash()
        {
            var testCases = new Dictionary<int, string>
            {
                {1, "a1943cfbb75e37b129bbf78b9baeab4ae6dd08225776397f66b8e0c7a913a055"},
            };

            var username = "postlass@gmail.com";
            var password = "pl1234567890";

            foreach (var i in testCases)
            {
                var result = FetcherHelper.MakeHash(username, password, i.Key);
                Assert.AreEqual(i.Value, result);
            }
        }

        [Test]
        public void ToHexString()
        {
            var testCases = new Dictionary<string, byte[]>
            {
                {"", new byte[] {}},
                {"00", new byte[] {0}},
                {"00ff", new byte[] {0, 255}},
                {"00010203040506070809", new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
                {"000102030405060708090a0b0c0d0e0f", new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
                {"8af633933e96a3c3550c2734bd814195", new byte[] {0x8a f6 33 93 3e 96 a3 c3 55 0c 27 34 bd 81 41 95}},
            };

            foreach (var i in testCases)
            {
                Assert.AreEqual(i.Key, FetcherHelper.ToHexString(i.Value));
            }
        }
    }
}
