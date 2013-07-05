using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class EncryptedAccountTest
    {
        [Test]
        public void EncryptedAccount_properties_are_set()
        {
            var id = "1234567890";
            var name = "DEADBEEF".DecodeHex();
            var username = "FEEDBEEF".DecodeHex();
            var password = "BEEFDEAD".DecodeHex();
            var url = "url";
            var group = "FEEDDEAD".DecodeHex();

            var account = new EncryptedAccount(id, name, username, password, url, group);
            Assert.AreEqual(id, account.Id);
            Assert.AreEqual(name, account.Name);
            Assert.AreEqual(username, account.Username);
            Assert.AreEqual(password, account.Password);
            Assert.AreEqual(url, account.Url);
            Assert.AreEqual(group, account.Group);
        }
    }
}
