namespace LastPass
{
    public class Account
    {
        public Account(string id, string name, string username, string password, string url, string group)
        {
            Id = id;
            Name = name;
            Username = username;
            Password = password;
            Url = url;
            Group = group;
        }

        public string Id { get; private set; }
        public string Name { get; private set; }
        public string Username { get; private set; }
        public string Password { get; private set; }
        public string Url { get; private set; }
        public string Group { get; private set; }
    }
}