using LastPass;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            var session = Fetcher.Login("username", "password");
            var blob = Fetcher.Fetch(session);
            var vault = Vault.Create(blob);
        }
    }
}
