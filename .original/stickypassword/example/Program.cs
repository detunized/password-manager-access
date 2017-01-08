using System;
using System.IO;
using StickyPassword;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            // Read StickyPassword credentials from a file
            // The file should contain 2 lines: username and password
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            Remote.GetEncryptedToken(username, "stickypassword-sharp", DateTime.Now);
        }
    }
}
