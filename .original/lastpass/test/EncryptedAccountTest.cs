using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class EncryptedAccountTest
    {
        [Test]
        public void EncryptedAccount_properties_are_set()
        {
            var name = "DEADBEEF".DecodeHex();
            var username = "FEEDBEEF".DecodeHex();
            var password = "BEEFDEAD".DecodeHex();
            var url = "url";

            var account = new EncryptedAccount(name, username, password, url);
            Assert.AreEqual(name, account.Name);
            Assert.AreEqual(username, account.Username);
            Assert.AreEqual(password, account.Password);
            Assert.AreEqual(url, account.Url);
        }
    }
}
