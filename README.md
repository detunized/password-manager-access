# Password Manager Access for .NET in C#

Provides access API to various online password managers. This repo is an
attempt to join and unify all the libraries I've written in the past (see
detunized/lastpass-sharp, detunized/1password-sharp and many more).

**This is work in progress and will be for a while.**

## Keeper

Example:

```c#
var accounts = Keeper.Vault.Open(username, password);
foreach (var i in accounts)
    Console.WriteLine($"{i.Name} {i.Username} {i.Password} {i.Url} {i.Notes} {i.Folder}");
```

For more details please see example/Keeper project.

## License

The library is released under [the MIT license][mit]. See [LICENSE][license]
for details.

[mit]: http://www.opensource.org/licenses/mit-license.php
[license]: LICENSE
