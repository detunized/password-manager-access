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
    Task<OneOf<Choice, MfaMethod, Cancelled>> ChooseFactor(Device[] devices, MfaMethod[] otherMethods, CancellationToken cancellationToken);

    // At this point it's no longer possible to choose a different MFA method. So either:
    //   1. Provide a passcode. To do that return IDuoAsyncUi.Passcode(code).
    //   2. To cancel return CancelPasscode()
    Task<OneOf<Passcode, Cancelled>> ProvidePasscode(Device device, CancellationToken cancellationToken);

    // This updates the UI with the messages from the server.
    Task UpdateStatus(Status status, string text, CancellationToken cancellationToken);

    //
    // Result factory methods
    //

    public static OneOf<Choice, MfaMethod, Cancelled> Choice(Device device, Factor factor, bool rememberMe) =>
        OneOf<Choice, MfaMethod, Cancelled>.FromA(new Choice(device, factor, rememberMe));
    public static OneOf<Choice, MfaMethod, Cancelled> SelectDifferentMethod(MfaMethod method) => OneOf<Choice, MfaMethod, Cancelled>.FromB(method);
    public static OneOf<Choice, MfaMethod, Cancelled> CancelChoice() => OneOf<Choice, MfaMethod, Cancelled>.FromC(new("User cancelled"));

    public static OneOf<Passcode, Cancelled> Passcode(string passcode) => OneOf<Passcode, Cancelled>.FromA(new(passcode));
    public static OneOf<Passcode, Cancelled> CancelPasscode() => OneOf<Passcode, Cancelled>.FromB(new("User cancelled"));
}

public enum Factor
{
    Push,
    Call,
    Passcode,
    SendPasscodesBySms,
}

public enum Status
{
    Success,
    Error,
    Info,
}

public record Choice(Device Device, Factor Factor, bool RememberMe);

public record Device(string Id, string Name, Factor[] Factors);

public record Passcode(string Code);

public record Cancelled(string Reason);
