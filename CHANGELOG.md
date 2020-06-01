# Changelog

## 3.0.0
  - Bitwarden: added support Duo multifactor authentication
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
  - ZohoVault: MFA "rememeber me" option
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
