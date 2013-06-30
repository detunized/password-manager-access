using LastPass;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            var session = Fetcher.Login("username", "password");
            var blob = Fetcher.Fetch(session);
        }
    }
}
