namespace LastPass
{
    public class EncryptedAccount
    {
        public EncryptedAccount(string id, byte[] name, byte[] username, byte[] password, string url)
        {
            Id = id;
            Name = name;
            Username = username;
            Password = password;
            Url = url;
        }

        public string Id { get; private set; }
        public byte[] Name { get; private set; }
        public byte[] Username { get; private set; }
        public byte[] Password { get; private set; }
        public string Url { get; private set; }
    }
}