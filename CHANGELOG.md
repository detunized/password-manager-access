# Changelog

## 10.3.0
  - LastPass: added support for the favorite flag for the parsed items (see `IsFavorite` in `Account`)
  - LastPass: set a flag when the item is shared (see `IsShared` in `Account`)
  - LastPass: added `ParserOptions.ParseSecureNotesToAccount` to control whether the secure notes
    should be parsed into accounts or left as is. This allows extraction of all secure notes, not
    only of the "server" type (thanks to Kyle Spearrin @kspearrin)

## 10.2.1
  - Bitwarden: fixed an "unusual traffic" error that was happening in some setups

## 10.2.0
  - 1Password: added support for WebAuthn MFA with USB keys on Windows 10+

## 10.1.0
  - Dashlane: added support for "Always on" OTP
  - Dashlane: fixed a login problem on Windows

## 10.0.0
  - Dashlane: new web protocol to replace the outdated and no longer supported desktop protocol

## 9.1.1
  - Newtonsoft.Json upgraded to 13.0.1 to fix a potential vulnerability

## 9.1.0
  - LastPass: added support to the regional server redirect

## 9.0.2
  - LastPass: fixed a bug where login might fail when the email contained upper case
    letters

## 9.0.1
  - ZohoVault: fixed a bug where logout might fail due to too many HTTP redirects

## 9.0.0
  - Bitwarden: collections and organizations added to the vault
  - Bitwarden: accounts changed to store collection IDs and not collection names
  - Bitwarden: errors collected during parsing and decryption are now stored in the vault
  - Bitwarden: occasional inverted "hide password" flag bug fixed

## 8.7.0
  - Bitwarden: private and organization collection support
  - Bitwarden: "hide password" collection flag support

## 8.6.4
  - 1Password: fixed a bug where login might fail when emails contain uppercase
    letters

## 8.6.3
  - 1Password: changed to client name/version to the latest CLI to minimize the
    "deprecated" errors in the future

## 8.6.2
  - 1Password: bumped the client version to get rid of the "deprecated" error

## 8.6.1
  - 1Password: bumped the client version to get rid of the "deprecated" error

## 8.6.0
  - Bitwarden: new CLI/API to bypass the captcha

## 8.5.3
  - Bitwarden: updated the login protocol to match the latest server software updates

## 8.5.2
  - ZohoVault: fixed a vault parsing problem for records with missing attributes

## 8.5.1
  - Bitwarden: fixed a problem with some private RSA keys causing crashes

## 8.5.0
  - Bitwarden: added support for Duo MFA option for organizations

## 8.4.9
  - Dashlane: fixed major performance issues when opening large vaults

## 8.4.8
  - 1Password: bumped the client version to get rid of the "deprecated" error

## 8.4.7
  - 1Password: fixed a rarely occurring issue with the decryption of the keysets

## 8.4.6
  - 1Password: the login protocol updated to match the current
  - 1Password: better error reporting on failures

## 8.4.5
  - RoboForm: fixed a crash when account parsing failed. Now the accounts that
    failed to parse are marked with "failed to parse".

## 8.4.4
  - Bitwarden: fixed a protocol change
  - Bitwarden: handle "too many requests" error in a better way

## 8.4.3
  - LastPass: fixed a problem during login where it would fail with an unknown error

## 8.4.2
  - Kaspersky: fixed a problem during login (obsolete cookie)

## 8.4.1
  - Kdbx: added public facing API that was forgotten in 8.4.0

## 8.4.0
  - Kdbx: added overloads to the API that take streams and byte arrays as input

## 8.3.0
  - Bitwarden: added support for TOTP and DeletedDate fields

## 8.2.7
  - Kaspersky: fixed a problem during login

## 8.2.6
  - TrueKey: fixed a problem that happened for some accounts during the login
    sequence

## 8.2.5
  - Kaspersky: fixed downloading of large vaults with lots of items or edits

## 8.2.4
  - ZohoVault: 200 vault item limit removed

## 8.2.3
  - 1Password: authentication protocol upgraded to the current version v3

## 8.2.2
  - Kaspersky: web socket connection timeout increased to 30 seconds to help
    with the slow networks

## 8.2.1
  - Kaspersky: fixed occasional crashes in logout

## 8.2.0
  - Kaspersky: added support for folders

## 8.1.1
  - Kaspersky: the now defunct HTTP BOSH protocol is replaced with a new web
    socket XMPP protocol implementation

## 8.1.0
  - Kdbx: added support for additional account fields (see Account.Fields
    property)
  - Kdbx: the account path is now built starting from the root folder

## 8.0.0
  - Kdbx: added support for KeePass KDBX 4 file format

## 7.0.0
  - ZohoVault: new log in protocol supported
  - ZohoVault: Zoho removed support for original YubiKey, removed support for
    it. FIDO U2F is not supported yet.
  - ZohoVault: `Ui` class refactored to `Ui.IUi` interface

## 6.0.0
  - 1Password: changed the API to allow selective vault retrieval and on
    demand decryption. All the Vault and Account properties are now lazily
    decrypted and cached.
  - 1Password: ILogger interface removed

## 5.0.1
  - 1Password: fixed a crash when the "require modern app" option is enabled

## 5.0.0
  - Kaspersky: Kaspersky Password Manager support added

## 4.1.0
  - RoboForm: added support for shared folders

## 4.0.1
  - RoboForm: fixed a crash on vaults with additional root folder siblings
    (this happens, for example, when the vault has had its master password
    changed)

## 4.0.0
  - OpVault: ported from the original repo and now could be used

## 3.0.0
  - Bitwarden: added support for the Duo multifactor authentication
  - Examples: many refactored to share code and make things simpler

## 2.0.0
  - LastPass: added support for the Duo SDK option in the settings to allow
    for the Duo device selection
  - LastPass: added support for passcodes for the out-of-band authentication
    modes
  - LastPass: Toopher support removed as it's no longer available
  - LastPass: `Ui` class refactored to `Ui.IUi` interface

## 1.0.0
  - Duo: moved out of Bitwarden and made part of the Common module so it could
    be used by other modules
  - Bitwarden: `Ui` class refactored to `Ui.IUi` interface

## 0.10.4
  - StickyPassword: support for second factor PIN code from the verification
    email for new devices

## 0.10.3
  - StickyPassword: fixed issues with incorrect exceptions thrown on Mono

## 0.10.2
  - StickyPassword: fixed Xamarin.Android problem with the Date header formatting

## 0.10.1
  - TrueKey: fixed a crash that sometimes happened during the login process

## 0.10.0
  - LastPass: ported from the original repo and now could be used
  - Better error handling in Crypto on Mono

## 0.9.0
  - TrueKey: ported from the original repo and now could be used
  - Dashlane: the last System exceptions replaced with project local ones
  - Examples: plain storage now stores all values in base64 (incompatible with
    `storage.yaml` from the previous versions)

## 0.8.0
  - StickyPassword: ported from the original repo and now could be used

## 0.7.1
  - Unfinished StickyPassword port removed from the release

## 0.7.0
  - The main library compiles with C# 8 instead of C# 7.3
  - 1Password: support for "server" secrets
  - ZohoVault: fixed a rare bug with MFA and region redirect

## 0.6.0
  - Default `ISecureStorage` implementation that does nothing (`NullStorage`)
    and could be used to disable "remember me" feature.

## 0.5.0
  - RoboForm: ported from the original repo and now could be used
  - ZohoVault: MFA "remember me" option
  - Bitwarden: Fixed Duo on Xamarin Android

## 0.4.0
  - ZohoVault: support for regions
  - ZohoVault: support for shared items
  - ZohoVault: fixed a crash with enabled MFA

## 0.3.0
  - The main library compiles with C# 7.3 instead of C# 6.0
  - 1Password: ported from the original repo and now could be used
  - Dashlane: fixed a crash with edited entries in the vault

## 0.2.5
  - The changelog has not been kept before 0.3.0. There has been a lot of
    changes related to the porting of Bitwarden, Dashlane and ZohoVault, as
    well as CI and common library improvements.
