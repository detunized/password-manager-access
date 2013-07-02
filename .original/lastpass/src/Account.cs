namespace LastPass
{
    public class Account
    {
        public Account(byte[] name, byte[] username, byte[] password, string url)
        {
            Name = name;
            Username = username;
            Password = password;
            Url = url;
        }

        public byte[] Name { get; private set; }
        public byte[] Username { get; private set; }
        public byte[] Password { get; private set; }
        public string Url { get; private set; }
    }
}