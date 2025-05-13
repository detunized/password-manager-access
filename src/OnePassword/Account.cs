// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword;

public class Account : VaultItem
{
    public readonly record struct Url(string Name, string Value);

    public readonly record struct Otp(string Name, string Secret, string Section);

    // Decrypted on demand
    public string Username => _username ??= GetUsername();
    public string Password => _password ??= GetPassword();
    public string MainUrl => _url ??= GetUrl();
    public Url[] Urls => _urls ??= ParseUrls();
    public Otp[] Otps => _otps ??= ParseOtps();

    //
    // Internal
    //

    internal const string LoginTemplateId = "001";
    internal const string ServerTemplateId = "110";

    internal Account(R.VaultItem itemInfo, Keychain keychain)
        : base(itemInfo, keychain) { }

    internal string GetUsername() => FindField("username");

    internal string GetPassword() => FindField("password");

    internal string GetUrl() =>
        TemplateId switch
        {
            LoginTemplateId => Overview.Url ?? "",
            ServerTemplateId => FindField("URL"),
            var id => throw new InternalErrorException($"Unsupported vault item type {id}"),
        };

    internal Url[] ParseUrls() => Overview.Urls?.Select(x => new Url(x.Name, x.Url))?.ToArray() ?? [];

    internal Otp[] ParseOtps()
    {
        var otps = new List<Otp>();

        foreach (var section in Details.Sections ?? [])
        foreach (var field in section.Fields ?? [])
            if (field.Kind == "concealed" && field.Id?.StartsWith("TOTP_") == true)
                otps.Add(new Otp(field.Name, field.Value, section.Name));

        return otps.ToArray();
    }

    //
    // Private
    //

    // Cache
    private string? _username;
    private string? _password;
    private string? _url;
    private Url[]? _urls;
    private Otp[]? _otps;
}
