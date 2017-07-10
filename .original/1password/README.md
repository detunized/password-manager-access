1Password C# API
================

**This is unofficial 1Password API.**

This library provides access to the [1Password online vault][1password]. This
library does not decode any locally stored keychains, only what's available
online.

This library provides a very high level mode of operations. It simply
downloads all the available vaults, parses and decrypts them. Only web
accounts are supported. The API is pretty trivial and it's easy to use. Simply
call `OnePassword.Client.OpenVaults` with a few parameters and inspect the
output. Here's a quick example (for the complete example program please to
refer to `example/Program.cs`):

```csharp
using OnePassword;

var vaults = Client.OpenAllVaults(username, password, accountKey, uuid);
foreach (var vault in vaults)
{
    Console.WriteLine("{0} {1} {2}", vault.Id, vault.Name, vault.Description);
    for (int i = 0; i < vault.Accounts.Length; ++i)
    {
        var account = vault.Accounts[i];
        Console.WriteLine("  - {0}: {1} {2} {3} {4} {5} {6}",
                          i + 1,
                          account.Id,
                          account.Name,
                          account.Username,
                          account.Password,
                          account.Url,
                          account.Note);
    }
}
```

`username`, `password` and the `accountKey` are, obviously, your credentials
to the online vault. `uuid` is a device ID from which the access is made. This
ID should be unique for each new client. A new ID will be registered with the
server and it should be reused on subsequent calls. It's possible to use a new
ID every time but this will pollute the [list of trusted devices][profile] on
the server. To generate a new uuid please use provided
`Client.GenerateRandomUuid` funciton.


Notes
-----

The library alters some global parameters that might affect the application.
Please take a look at the static constructor of the `HttpClient` class.
`ServicePointManager.SecurityProtocol` is changed to support SSL3 and TLS 1.0
through 1.2. Otherwise 1password.com refuses to open a secure connection.


License
-------

The library is released under [the MIT
license](http://www.opensource.org/licenses/mit-license.php).


[1password]: https://my.1password.com/signin
[profile]: https://my.1password.com/profile
