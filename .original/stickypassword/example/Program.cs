using StickyPassword;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            Remote.GetEncryptedToken("lastpass.ruby@gmail.com", "stickypassword-sharp");
        }
    }
}
