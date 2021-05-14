# Password Manager Access for .NET in C#

[![Build status](https://ci.appveyor.com/api/projects/status/83qpps4fqdv0vn60?svg=true)](https://ci.appveyor.com/project/detunized/password-manager-access)
[![Build Status](https://detunized.visualstudio.com/password-manager-access/_apis/build/status/detunized.password-manager-access?branchName=master)](https://detunized.visualstudio.com/password-manager-access/_build/latest?definitionId=1&branchName=master)
[![NuGet Badge](https://buildstats.info/nuget/PasswordManagerAccess)](https://www.nuget.org/packages/PasswordManagerAccess/)

Password Manager Access provides read only access API to various online
password managers. This unified library is a successor to a bunch of
independent libraries written in the past, such as
[lastpass-sharp](https://github.com/detunized/lastpass-sharp),
[1password-sharp](https://github.com/detunized/1password-sharp) and
[dashlane-sharp](https://github.com/detunized/dashlane-sharp)

The following services are supported by this library:

  - [1Password](https://1password.com)
  - [Bitwarden](https://bitwarden.com)
  - [Dashlane](https://dashlane.com)
  - [Dropbox Passwords (work in progress)](https://www.dropbox.com/features/security/passwords)
  - [Kaspersky Password Manager](https://www.kaspersky.com/password-manager)
  - [LastPass](https://lastpass.com)
  - [RoboForm](https://roboform.com)
  - [Sticky Password](https://www.stickypassword.com)
  - [True Key](https://www.truekey.com)
  - [Zoho Vault](https://www.zoho.com/vault)

Additionally the library provides support for parsing and decryption of the
offline [OpVault vault format](https://support.1password.com/opvault-design/).

All services support basic log in, retrieve, decrypt, log out sequence. Though
the modules providing support for different services are quite similar, they
do not provide a unified interface. That is mainly due to the differences in
the API and the data provided by the services themselves.

A typical work flow with simple password authentication looks like this:

```c#
var vault = Vault.Open("username",
                       "password",
                       new ClientInfo(Platform.Desktop,
                                      "device-id",
                                      "client-description"),
                       null);

foreach (var a in vault.Accounts)
    Console.WriteLine($"{a.Name}: {a.Username} {a.Password} {a.Url}");
```

This code snippet downloads and decrypts a LastPass vault and prints all the
accounts to the standard output. For the fully working example please refer to
the [examples](examples) folder in this repo.

## License

The library is released under [the MIT license][mit]. See [LICENSE][license]
for details.

[mit]: http://www.opensource.org/licenses/mit-license.php
[license]: LICENSE
