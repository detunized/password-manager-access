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

            // TODO: Move this to the config
            var deviceId = "12345678-1234-1234-1234-123456789abc";
            var deviceName = "stickypassword-sharp";

            var encryptedToken = Remote.GetEncryptedToken(username, deviceId, DateTime.Now);
            var token = Crypto.DecryptToken(username, password, encryptedToken);
            Remote.AuthorizeDevice(username, token, deviceId, deviceName, DateTime.Now);
            Remote.GetS3Token(username, token, deviceId, DateTime.Now);
        }
    }
}
