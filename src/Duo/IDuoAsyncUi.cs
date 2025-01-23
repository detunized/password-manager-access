// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Duo;

// Adds Duo functionality to the module-specific Ui class
public interface IDuoAsyncUi
{
    // At this point it's possible to:
    //   1. Proceed with one of the Duo devices. To do that return IDuoAsyncUi.Choice(device, factor, rememberMe).
    //   2. Choose a different MFA method (if available). To do that return IDuoAsyncUi.SelectDifferentMethod(method).
    //   3. Cancel the login process altogether. To do that return IDuoAsyncUi.CancelChoice().
    Task<OneOf<DuoChoice, MfaMethod, DuoCancelled>> ChooseDuoFactor(
        DuoDevice[] devices,
        MfaMethod[] otherMethods,
        CancellationToken cancellationToken
    );

    // At this point it's no longer possible to choose a different MFA method. So either:
    //   1. Provide a passcode. To do that return IDuoAsyncUi.Passcode(code).
    //   2. To cancel return CancelPasscode()
    Task<OneOf<DuoPasscode, DuoCancelled>> ProvideDuoPasscode(DuoDevice device, CancellationToken cancellationToken);

    // This updates the UI with the messages from the server.
    Task UpdateDuoStatus(DuoStatus status, string text, CancellationToken cancellationToken);

    //
    // Result factory methods
    //

    public static OneOf<DuoChoice, MfaMethod, DuoCancelled> Choice(DuoDevice device, DuoFactor factor, bool rememberMe) =>
        OneOf<DuoChoice, MfaMethod, DuoCancelled>.FromA(new DuoChoice(device, factor, rememberMe));
    public static OneOf<DuoChoice, MfaMethod, DuoCancelled> SelectDifferentMethod(MfaMethod method) =>
        OneOf<DuoChoice, MfaMethod, DuoCancelled>.FromB(method);
    public static OneOf<DuoChoice, MfaMethod, DuoCancelled> CancelChoice() => OneOf<DuoChoice, MfaMethod, DuoCancelled>.FromC(new("User cancelled"));

    public static OneOf<DuoPasscode, DuoCancelled> Passcode(string passcode) => OneOf<DuoPasscode, DuoCancelled>.FromA(new(passcode));
    public static OneOf<DuoPasscode, DuoCancelled> CancelPasscode() => OneOf<DuoPasscode, DuoCancelled>.FromB(new("User cancelled"));
}

public enum DuoFactor
{
    Push,
    Call,
    Passcode,
    SendPasscodesBySms,
}

public enum DuoStatus
{
    Success,
    Error,
    Info,
}

public record DuoChoice(DuoDevice Device, DuoFactor Factor, bool RememberMe);

public record DuoDevice(string Id, string Name, DuoFactor[] Factors);

public record DuoPasscode(string Passcode);

public record DuoCancelled(string Reason);
