# Password Manager Access for .NET in C#

[![Build status](https://ci.appveyor.com/api/projects/status/83qpps4fqdv0vn60?svg=true)](https://ci.appveyor.com/project/detunized/password-manager-access)
[![Build Status](https://detunized.visualstudio.com/password-manager-access/_apis/build/status/detunized.password-manager-access?branchName=master)](https://detunized.visualstudio.com/password-manager-access/_build/latest?definitionId=1&branchName=master)
[![NuGet Badge](https://buildstats.info/nuget/PasswordManagerAccess)](https://www.nuget.org/packages/PasswordManagerAccess/)

Provides access API to various online password managers. This repo is an
attempt to join and unify all the libraries I've written in the past (see
detunized/lastpass-sharp, detunized/1password-sharp and many more).

**This is work in progress and will be for a while.**

## Keeper

Example:

```c#
var accounts = Keeper.Vault.Open(username, password, ui, storage);
foreach (var i in accounts)
    Console.WriteLine($"{i.Name} {i.Username} {i.Password} {i.Url} {i.Notes} {i.Folder}");
```

To see what the `ui` and `storage` are for and for more details please see
example/Keeper project.

## License

The library is released under [the MIT license][mit]. See [LICENSE][license]
for details.

[mit]: http://www.opensource.org/licenses/mit-license.php
[license]: LICENSE
