Bitwarden C# API
================

**This is unofficial Bitwarden API.**

This library implements a read-only access to Bitwarden online password vault.
As with the other libraries from this family the interface is intentionally very
simple. It's just one call to `Vault.Open`. `Vault.Open` takes two arguments:
username and password.

A quick example of accessing your account information:

```csharp
using Bitwarden;

var vault = Vault.Open(username, password);
foreach (var i in vault.Accounts)
    Console.WriteLine("{0}: {1}, {2}", i.Name, i.Username, i.Password);
```

For more detail please refer to the provided complete [example program][example].

License
-------

The library is released under [the MIT
license](http://www.opensource.org/licenses/mit-license.php).

[example]: example/Program.cs
