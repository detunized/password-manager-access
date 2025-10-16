// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword.Ui;
using Ristretto;

namespace PasswordManagerAccess.OnePassword;

public static partial class Client
{
    //
    // Login
    //

    public static async Task<bool> IsSsoAccount(string username, CancellationToken cancellationToken)
    {
        using var transport = new RestTransport();
        var loginInfo = await GetLoginInfo(username, MakeRestClient(transport, GetApiUrl(DefaultDomain)), cancellationToken).ConfigureAwait(false);
        return loginInfo.AuthMethods.Any(x => x.Type == "OIDC");
    }

    public static async Task<Session> SsoLogIn(
        Credentials credentials,
        AppInfo app,
        IAsyncUi ui,
        IAsyncSecureStorage storage,
        CancellationToken cancellationToken
    )
    {
        var transport = new RestTransport();
        try
        {
            return await SsoLogIn(credentials, app, ui, storage, transport, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // We only need to dispose in case of an error, otherwise it's returned with the session.
            transport.Dispose();
            throw;
        }
    }

    //
    // Internal
    //

    internal static async Task<Session> SsoLogIn(
        Credentials credentials,
        AppInfo app,
        IAsyncUi ui,
        IAsyncSecureStorage storage,
        IRestTransport transport,
        CancellationToken cancellationToken
    )
    {
        var rest = MakeRestClient(transport, GetApiUrl(DefaultDomain));

        // 1. Get the login info to check if SSO is available and get the sign-in address
        var loginInfo = await GetLoginInfo(credentials.Username, rest, cancellationToken).ConfigureAwait(false);

        // Make sure SSO is available for this account
        if (loginInfo.AuthMethods.All(x => x.Type != "OIDC"))
            throw new InternalErrorException($"No SSO login method found for account {credentials.Username}");

        // 2. Make a new REST client for the SSO API
        var ssoRest = MakeRestClient(transport, $"{loginInfo.SignInAddress}/api");

        // 3. Start the SSO login process by getting the SSO login URL
        var ssoLoginUrl = await StartSsoLogin(credentials, loginInfo, storage, ssoRest, cancellationToken).ConfigureAwait(false);

        // 4. Perform the SSO login
        var (code, state) = await PerformSsoLogin(ssoLoginUrl, ui, cancellationToken).ConfigureAwait(false);

        // 5. Verify the SSO login
        var ssoSession = await VerifySsoLogin(code, state, credentials.DeviceUuid, app, ssoRest, cancellationToken).ConfigureAwait(false);

        // 6. Update the REST client with the session ID
        ssoRest = MakeRestClient(ssoRest, sessionId: ssoSession.User.SessionUuid);

        // 7. Enroll the device if needed
        var isNewDevice = ssoSession.State switch
        {
            "device_not_enrolled" => true,
            "found" => false,
            _ => throw new InternalErrorException($"Unexpected SSO session state: {ssoSession.State}"),
        };

        // If the device is already enrolled, we need to get the credentials from the SSO response and the decryption key from the storage
        var (credentialBundle, enrollmentUuid) = isNewDevice
            ? await EnrollDevice(
                    credentials: credentials,
                    loginInfo: loginInfo,
                    ssoSession: ssoSession,
                    ui: ui,
                    rest: ssoRest,
                    cancellationToken: cancellationToken
                )
                .ConfigureAwait(false)
            : (await RestoreCredentials(ssoSession, storage, cancellationToken).ConfigureAwait(false), "");

        // 8. Log in with the received credential bundle
        var (sessionKey, sessionRest) = await Login(
                credentials: credentials,
                app: app,
                credentialBundle: credentialBundle,
                signInToken: ssoSession.SsoAuth.SignInTokenDetails.Token,
                deviceUuid: credentials.DeviceUuid,
                userUuid: loginInfo.UserUuid,
                ssoSessionId: ssoSession.User.SessionUuid,
                rest: ssoRest,
                cancellationToken: cancellationToken
            )
            .ConfigureAwait(false);

        // 9. In case it was a new device, the initial enrollment and the credential exchange is only a part of the process.
        //    The exchanged credentials only exist in memory at this point. They need to be encrypted and stored on the server.
        //    The credentials are encrypted with a locally generated and stored device key. So this should be secure.
        if (isNewDevice)
            await CommitDevice(ssoSession, enrollmentUuid, credentialBundle, storage, sessionKey, sessionRest, cancellationToken)
                .ConfigureAwait(false);

        // 10. Done
        var keychain = new Keychain(new AesKey(MasterKeyId, credentials.Key.Key));
        return new Session(credentials, keychain, sessionKey, sessionRest);
    }

    internal static async Task<Model.CredentialBundle> RestoreCredentials(
        Model.SsoSession ssoSession,
        IAsyncSecureStorage storage,
        CancellationToken cancellationToken
    )
    {
        var deviceKey = await LoadAndDeriveDeviceKey(storage, cancellationToken).ConfigureAwait(false);
        return DecryptCredentialBundle(ssoSession.Auth.EncryptedCredentials, deviceKey);
    }

    internal static Model.Encrypted EncryptCredentialBundle(Model.CredentialBundle credentialBundle, AesKey deviceKey)
    {
        return deviceKey
            .Encrypt(
                JsonSerializer.SerializeToUtf8Bytes(credentialBundle),
                Crypto.RandomBytes(AesKey.IvSize),
                "1P_SSO_CREDENTIAL_BUNDLE:LOCAL2"u8.ToArray()
            )
            .ToModel();
    }

    internal static Model.CredentialBundle DecryptCredentialBundle(Model.Encrypted encryptedCredentials, AesKey deviceKey) =>
        // TODO: Handle errors
        DeserializeJson<Model.CredentialBundle>(
            deviceKey.Decrypt(Encrypted.Parse(encryptedCredentials), "1P_SSO_CREDENTIAL_BUNDLE:LOCAL2"u8.ToArray())
        );

    internal static async Task<DeviceKeyDerivation> LoadDeviceKey(IAsyncSecureStorage storage, CancellationToken cancellationToken) =>
        LoadDeviceKey(await storage.LoadString(DeviceKeyName, cancellationToken).ConfigureAwait(false));

    internal static DeviceKeyDerivation LoadDeviceKey(string json)
    {
        // TODO: Handle errors
        var encryptedDeviceKey = DeserializeJson<Model.Encrypted>(json);
        var deviceKey = DecryptFromStorage(Encrypted.Parse(encryptedDeviceKey));
        return deviceKey;
    }

    internal static async Task<AesKey> LoadAndDeriveDeviceKey(IAsyncSecureStorage storage, CancellationToken cancellationToken) =>
        LoadAndDeriveDeviceKey(await storage.LoadString(DeviceKeyName, cancellationToken).ConfigureAwait(false));

    internal static AesKey LoadAndDeriveDeviceKey(string json)
    {
        var deviceKey = LoadDeviceKey(json);
        return DeriveDeviceKey(deviceKey);
    }

    internal static async Task<Model.LoginInfo> GetLoginInfo(string username, RestClient rest, CancellationToken cancellationToken)
    {
        var response = await rest.PostJsonAsync<Model.LoginInfo>(
                "v2/auth/methods",
                new Dictionary<string, object> { ["email"] = username },
                cancellationToken
            )
            .ConfigureAwait(false);
        if (!response.IsSuccessful)
            throw MakeError(response);

        return response.Data;
    }

    internal static async Task<string> StartSsoLogin(
        Credentials credentials,
        Model.LoginInfo loginInfo,
        IAsyncSecureStorage storage,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var parameters = new Dictionary<string, object> { ["userUuid"] = loginInfo.UserUuid };

        // TODO: Make sure these are not stale
        var accountUuid = await storage.LoadString(AccountIdName, cancellationToken).ConfigureAwait(false);
        if (!accountUuid.IsNullOrEmpty())
            parameters["accountUuid"] = accountUuid;

        // TODO: Make sure these are not stale
        var keyId = await storage.LoadString(CredentialsEncryptionKeyIdName, cancellationToken).ConfigureAwait(false);
        if (!keyId.IsNullOrEmpty())
            parameters["keyId"] = keyId;

        var response = await rest.PostJsonAsync<Model.SsoLoginUrl>("v3/auth/sso/oidc/start", parameters, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessful)
            throw MakeError(response);

        return response.Data.OidcUrl;
    }

    internal static async Task<(string Code, string State)> PerformSsoLogin(string ssoLoginUrl, IAsyncUi ui, CancellationToken cancellationToken)
    {
        var redirectTo = Uri.UnescapeDataString(Url.ExtractQueryParameter(ssoLoginUrl, "redirect_uri"));

        // Ask the user to login to the SSO provider like Microsoft or Google. This potentially take a long while.
        var redirectedToUrl = await ui.PerformSsoLogin(ssoLoginUrl, redirectTo, cancellationToken).ConfigureAwait(false);

        if (redirectedToUrl.IsNullOrEmpty())
            throw new CanceledSsoLoginException("The SSO login was canceled by the user");

        // An example of the returned URL:
        //   https://acme.1password.com/sso/oidc/redirect/#code=1.ASgAwV5aTMWaEkabTGvtF4u2Wpb4VTvGf8dGlwsZADrH0JkoAAAoAA.AgABBAIAAABVrSpeuWamRam2jAF1XRQEAwDs_wUA9P-k9NH9m4zDf3ZQpZopbFWrPs95L25K4RDHx4pOfNnyO5wfWKwtSUEeVYosJQYKmkarnxfGO5F0Wp8sjg1aE2MheBSCu3c7sSfwZpj9nfhztoMQSPZLhYbFGMkW1gkjX7I5_AVKkpbzmUkHpeGNGC9pTOF4bTp_M6ZnKMrtXVB0LjqeqrHnwe9tkCThg2qgrjH_glcbxA0VQfbk7DMR0cjoYsATNQHk7MylJj30SnL3_ur1rWo1IYtKwZia2PlRkjsXXLqU3refbf9gE6fneiaPwgV2YCsbJ7RoMfJkyZoC_SvwV98BB__sgJahjsW4CJ-d6tsUoueWUA3NI6ufyL8MnIxMBVR1tGEEtoIyxH-OItX3JgbZfKuEodaLN0BZj1ikOcMCTcBG0O5RP39lbqTDOcTpojW7UlZJRt7IRcEHmYB5Jec9RVBMBg2IAx11dnIDMFYabP4NmFeuXLqv2s1B0Rd95jjFm3X7FTGESn3zT07-ViLi5GvTLJJbllO6M8NSNA9Tqk1OhKreZQy5KdNx_CsmayO7ywk5ISE5aqZk2my5Ayby9SzATSdTyUtsxFKPULmvO1QJR-xXDa1IZ2WWVHKmVSEU0vhipZdeubyJwP51QnecUADeXFA5DBqXxCQDBfC929oeImouQY-ZfN2Tx83XdHjhzIZtfVuFSBlYoGs4ESZIRZWoiK-SsXzOiiYDqTD5HlGF4TH07wmxlfa44WnI1OlP-zcZR_IywftwGZofA9YUt41b-ho9X8bLap6SBwvoqLggV3hfmkiBCRNMD9iFczW6qYHNqeSTidp5UWCNic8JrE3zIY5L5Mt1S0HzH3SVve5YPA2_7iVMynfhETLOzrvpqumbbjsXCEFpxZZMnbWvVnpOTKVHhr5f&state=AheikL9HpINJRhPsoa9KWw&session_state=002f7c59-8098-a5c0-a0d5-dd5ed564dd9a

        var code = Url.ExtractQueryParameter(redirectedToUrl, "code");
        if (code.IsNullOrEmpty())
            throw new InternalErrorException("No code returned from the SSO provider");

        var state = Url.ExtractQueryParameter(redirectedToUrl, "state");
        if (state.IsNullOrEmpty())
            throw new InternalErrorException("No state returned from the SSO provider");

        return (code, state);
    }

    internal static async Task<Model.SsoSession> VerifySsoLogin(
        string code,
        string state,
        string deviceUuid,
        AppInfo app,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var response = await rest.PostJsonAsync<Model.SsoSession>(
                "v3/auth/sso/oidc/verify",
                new Dictionary<string, object>
                {
                    ["code"] = code,
                    ["state"] = state,
                    ["device"] = new Dictionary<string, string>
                    {
                        ["uuid"] = deviceUuid,
                        ["clientName"] = ClientName,
                        ["clientVersion"] = ClientVersion,
                        ["osName"] = GetOsName(),
                        ["osVersion"] = "", // TODO: It's not so trivial to detect the proper OS version in .NET. Look into that.
                        ["name"] = app.Name,
                        ["model"] = app.Version,
                    },
                },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        return response.Data;
    }

    internal static async Task<(Model.CredentialBundle, string EnrollmentUuid)> EnrollDevice(
        Credentials credentials,
        Model.LoginInfo loginInfo,
        Model.SsoSession ssoSession,
        IAsyncUi ui,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var signInToken = ssoSession.SsoAuth.SignInTokenDetails.Token;

        // 1. Kick off the enrollment process. This should send a signal to the already enrolled devices to
        //    prepare to transfer the key to the new device.
        var ssoEnroll = await StartEnrollment(signInToken, rest, cancellationToken).ConfigureAwait(false);

        // 2. Wait for the user to click on one of the existing devices the "Transfer key" button to initiate the enrollment.
        // Note: when the user clicks the "Deny" button the status update fails with 404.
        if (
            !await PollStatusUntilDone(EnrollmentStatus.WaitingForCode, signInToken, ssoEnroll.EnrollmentUuid, rest, cancellationToken)
                .ConfigureAwait(false)
        )
            throw new InternalErrorException("Enrollment failed");

        // 3. Exchange credentials
        var credentialBundle = await ExchangeCredentials(
                username: credentials.Username,
                signInAddress: loginInfo.SignInAddress,
                signInToken: signInToken,
                enrollmentUuid: ssoEnroll.EnrollmentUuid,
                ui: ui,
                rest: rest,
                cancellationToken: cancellationToken
            )
            .ConfigureAwait(false);

        return (credentialBundle, ssoEnroll.EnrollmentUuid);
    }

    internal static async Task CommitDevice(
        Model.SsoSession ssoSession,
        string enrollmentUuid,
        Model.CredentialBundle credentialBundle,
        IAsyncSecureStorage storage,
        AesKey sessionKey,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        // 1. Generate a local key for the device and encrypt the credential bundle with it
        var deviceKeyDerivation = GenerateDeviceKeyDerivation();
        var deviceKey = DeriveDeviceKey(deviceKeyDerivation);
        var encryptCredentialBundle = EncryptCredentialBundle(credentialBundle, deviceKey);

        // 2. Store the device credentials on the server. Only after this the server will consider the device fully
        //    enrolled and won't be requesting the device enrollment again.
        var result = await PostEncryptedJsonNoDecrypt<Model.SuccessResult>(
                "v3/user/devicecredentials",
                new Dictionary<string, object>
                {
                    ["deviceCredentials"] = new Dictionary<string, object> { ["encCredentials"] = encryptCredentialBundle, ["v"] = 2 },
                    ["keyId"] = deviceKey.Id,
                    ["enrollmentUuid"] = enrollmentUuid,
                },
                sessionKey,
                rest,
                cancellationToken
            )
            .ConfigureAwait(false);

        if (result.Success != 1)
            throw new InternalErrorException("Failed to store device credentials");

        // 3. When it's all good, store the device key for the next time
        // TODO: Unify this all into one model/JSON
        await storage.StoreString(UserIdName, ssoSession.User.UserUuid, cancellationToken).ConfigureAwait(false);
        await storage.StoreString(AccountIdName, ssoSession.User.AccountUuid, cancellationToken).ConfigureAwait(false);
        await storage.StoreString(CredentialsEncryptionKeyIdName, deviceKey.Id, cancellationToken).ConfigureAwait(false);
        await storage
            .StoreString(DeviceKeyName, JsonSerializer.Serialize(EncryptForStorage(deviceKeyDerivation).ToModel()), cancellationToken)
            .ConfigureAwait(false);
    }

    internal record DeviceKeyDerivation(string Id, byte[] Key, byte[] Salt);

    internal static DeviceKeyDerivation GenerateDeviceKeyDerivation() => new(GenerateRandomUuid(), Crypto.RandomBytes(32), Crypto.RandomBytes(48));

    internal static AesKey DeriveDeviceKey(DeviceKeyDerivation deviceKeyDerivation)
    {
        var key = Hkdf.Sha384(deviceKeyDerivation.Key, deviceKeyDerivation.Id.ToBytes(), "1P_SSO_CREDENTIAL_BUNDLE_KEY:LOCAL"u8.ToArray(), 32);
        return new AesKey(deviceKeyDerivation.Id, key);
    }

    internal static async Task<Model.SsoEnrollInfo> StartEnrollment(string signInToken, RestClient rest, CancellationToken cancellationToken)
    {
        var response = await rest.PostJsonAsync<Model.SsoEnrollInfo>(
                "v3/device/enrollments",
                new Dictionary<string, object> { ["signInToken"] = signInToken },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        return response.Data;
    }

    internal static Encrypted EncryptForStorage(DeviceKeyDerivation deviceKeyDerivation) =>
        EncryptForStorage(deviceKeyDerivation, Crypto.RandomBytes(AesKey.IvSize));

    // Encrypts for storage similar to the browser local storage. The key is encrypted with a hardcoded key, which is more an obfuscation.
    // It's up to the application to store the key in a secure way.
    internal static Encrypted EncryptForStorage(DeviceKeyDerivation deviceKeyDerivation, byte[] iv)
    {
        var model = new Model.DeviceKeyDerivation
        {
            Id = deviceKeyDerivation.Id,
            Key = deviceKeyDerivation.Key.ToUrlSafeBase64NoPadding(),
            Salt = deviceKeyDerivation.Salt.ToUrlSafeBase64NoPadding(),
        };
        var json = JsonSerializer.SerializeToUtf8Bytes(model);
        var key = new AesKey("3tnqywhecddkhvl375l6yu7qri", "01be638ec19d0b5bf7a310239d817aa1"u8.ToArray());
        return key.Encrypt(json, iv);
    }

    internal static DeviceKeyDerivation DecryptFromStorage(Encrypted encrypted)
    {
        var key = new AesKey(encrypted.KeyId, "01be638ec19d0b5bf7a310239d817aa1"u8.ToArray());
        // TODO: Handle errors
        var json = key.Decrypt(encrypted);
        // TODO: Handle errors
        var model = DeserializeJson<Model.DeviceKeyDerivation>(json);
        return new DeviceKeyDerivation(model.Id, model.Key.Decode64Loose(), model.Salt.Decode64Loose());
    }

    internal enum EnrollmentStatus
    {
        SelectingVerifier,
        WaitingForCode,
        Unknown,
    }

    internal static async Task<bool> PollStatusUntilDone(
        EnrollmentStatus waitFor,
        string signInToken,
        string enrollmentUuid,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        // TODO: Fix this! 20 is too little and shouldn't be done like this!
        for (var i = 0; i < 20; i++)
        {
            var status = await GetEnrollmentStatus(signInToken, enrollmentUuid, rest, cancellationToken).ConfigureAwait(false);
            if (status == waitFor)
                return true;

            await Task.Delay(500, cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    internal static async Task<EnrollmentStatus> GetEnrollmentStatus(
        string signInToken,
        string enrollmentUuid,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        // TODO: Handle the case where the user clicks the "Deny" button. The response will be a 404.
        var response = await rest.PostJsonAsync<Model.SsoEnrollStatus>(
                "v3/device/enrollments/status",
                new Dictionary<string, object> { ["signInToken"] = signInToken, ["enrollmentUuid"] = enrollmentUuid },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        return response.Data.Status switch
        {
            "SELECTING_VERIFIER" => EnrollmentStatus.SelectingVerifier,
            "WAITING_FOR_CODE" => EnrollmentStatus.WaitingForCode,
            _ => EnrollmentStatus.Unknown,
        };
    }

    internal static async Task<Model.CredentialBundle> ExchangeCredentials(
        string username,
        string signInAddress,
        string signInToken,
        string enrollmentUuid,
        IAsyncUi ui,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        // 1. Ask the user to enter the verification code displayed on the existing device.
        // TODO: Implement UI method for device enrollment verification code
        throw new NotImplementedException("SSO device enrollment UI not yet implemented");

#pragma warning disable CS0162 // Unreachable code detected
        // var passcode = await ui.ProvideDeviceEnrollmentVerificationCode(cancellationToken).ConfigureAwait(false);
        // if (passcode == Passcode.Cancel)
        //     throw new CanceledSsoLoginException("Device enrollment canceled by the user");
        //
        // // 2. Perform the secure credentials exchange. This is a complicated multi-step process that involves
        // //    a bunch of back-and-forth between the client and the server.
        // var credentials = PerformCpace(
        //     username: username,
        //     signInAddress: signInAddress,
        //     signInToken: signInToken,
        //     enrollmentUuid: enrollmentUuid,
        //     verificationCode: passcode.Code,
        //     rest: rest
        // );
        //
        // return credentials;
#pragma warning restore CS0162 // Unreachable code detected
    }

    internal static async Task<(AesKey, RestClient)> Login(
        Credentials credentials,
        AppInfo app,
        Model.CredentialBundle credentialBundle,
        string signInToken,
        string deviceUuid,
        string userUuid,
        string ssoSessionId,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        // 1. Start with a new session. Weirdly, the session ID we are supposed to keep from the previous SSO flow.
        var session = await StartAuth(signInToken, deviceUuid, userUuid, rest, cancellationToken).ConfigureAwait(false);

        // TODO: Update credentials outside of this function
        credentials.SrpX = credentialBundle.SrpX.Decode64Loose().ToHex();
        credentials.Key = new AesKey(credentialBundle.Auk.KeyId, credentialBundle.Auk.Key.Decode64Loose());

        // 2. Do a regular SRP like in a normal login flow. Only here it's version 2.
        var srpInfo = new SrpInfo(
            srpMethod: session.Auth.Method,
            keyMethod: session.Auth.Algorithm,
            iterations: session.Auth.Iterations,
            salt: session.Auth.Salt.Decode64Loose()
        );
        // TODO: Implement SrpV2.PerformAndVerify
        throw new NotImplementedException("SRP v2 not yet implemented");

#pragma warning disable CS0162 // Unreachable code detected
        // var sessionKey = SrpV2.PerformAndVerify(credentials, srpInfo, session.KeyUuid, ssoSessionId, rest);
        //
        // // 3. All the following requests need to be signed with the session key.
        // var macRest = MakeRestClient(rest, new MacRequestSigner(sessionKey, 1), ssoSessionId);
        //
        // // 4. Complete the login process by sending the device info.
        // CompleteAuth(credentials, app, signInToken, sessionKey, macRest);
        //
        // return (sessionKey, macRest);
#pragma warning restore CS0162 // Unreachable code detected
    }

    private static async Task<Model.NewSession> StartAuth(
        string signInToken,
        string deviceUuid,
        string userUuid,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var newSessionResponse = await rest.PostJsonAsync<Model.NewSession>(
                "v3/auth/start",
                new Dictionary<string, object>
                {
                    ["signInToken"] = signInToken,
                    ["deviceUuid"] = deviceUuid,
                    ["userUuid"] = userUuid,
                },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!newSessionResponse.IsSuccessful)
            throw MakeError(newSessionResponse);

        var newSession = newSessionResponse.Data;
        return newSession;
    }

    private static async Task CompleteAuth(
        Credentials credentials,
        AppInfo app,
        string signInToken,
        AesKey sessionKey,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        await PostEncryptedJson<Model.AuthComplete>(
                "v2/auth/complete",
                new Dictionary<string, object>
                {
                    ["client"] = ClientId,
                    ["signInToken"] = signInToken,
                    ["device"] = new Dictionary<string, string>
                    {
                        ["uuid"] = credentials.DeviceUuid,
                        ["clientName"] = ClientName,
                        ["clientVersion"] = ClientVersion,
                        ["name"] = app.Name,
                        ["model"] = app.Version,
                        ["osName"] = GetOsName(),
                        ["osVersion"] = "", // TODO: OS version detection
                        ["userAgent"] = "", // TODO: User agent string
                    },
                },
                sessionKey,
                rest,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    //
    // Data
    //

    private const string UserIdName = "user-id";
    private const string AccountIdName = "account-id";
    private const string CredentialsEncryptionKeyIdName = "key-id";
    private const string DeviceKeyName = "device-key";
}

// Cpace bits
// TODO: Move out to a separate class
public static partial class Client
{
    internal static Task<Model.CredentialBundle> PerformCpace(
        string username,
        string signInAddress,
        string signInToken,
        string enrollmentUuid,
        string verificationCode,
        RestClient rest,
        CancellationToken cancellationToken
    ) =>
        PerformCpace(
            username: username,
            signInAddress: signInAddress,
            signInToken: signInToken,
            enrollmentUuid: enrollmentUuid,
            verificationCode: verificationCode,
            clientSecret: Crypto.RandomBytes(64),
            rest: rest,
            cancellationToken: cancellationToken
        );

    //
    // CPACE networking
    //

    internal static async Task<Model.CredentialBundle> PerformCpace(
        string username,
        string signInAddress,
        string signInToken,
        string enrollmentUuid,
        string verificationCode,
        byte[] clientSecret,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        // 1. Get "msga"
        var msgA = await RequestMsgA(signInToken, enrollmentUuid, rest, cancellationToken).ConfigureAwait(false);

        // 2. Calculate "msgb"
        var msgB = CalculateMsgB(
            username: username,
            signInAddress: signInAddress,
            enrollmentUuid: enrollmentUuid,
            verificationCode: verificationCode,
            msgA: msgA,
            clientSecret: clientSecret
        );

        // 3. Respond with "msgb"
        await SendMsgB(msgB, signInToken, enrollmentUuid, rest, cancellationToken).ConfigureAwait(false);

        // 4. Get "taga"
        var tagA = await GetTagA(signInToken, enrollmentUuid, rest, cancellationToken).ConfigureAwait(false);

        // 5. Verify "taga" to make sure it's authentic. Currently, we don't do this, we just trust the server.
        VerifyTagA(tagA);

        // 6. Calculate "tagb"
        var (authB, tagB) = CalculateAuthBTagB(clientSecret, msgA, msgB);

        // 7. Respond with "tagb"
        await SendTagB(tagB, signInToken, enrollmentUuid, rest, cancellationToken).ConfigureAwait(false);

        // 8. Receive credentials from the enrolled device via the central server.
        //    The credentials are encrypted with the exchange key and are unknown to the central server.
        var encryptedCredentials = await RequestEncryptedCredentials(signInToken, enrollmentUuid, rest, cancellationToken).ConfigureAwait(false);

        // 9. Derive the exchange key locally. The other device could do the same thanks to the CPACE protocol.
        var exchangeKey = DeriveExchangeKey(authB);

        // 10. Decrypt and parse the credentials
        var credentials = DecryptCredentials(encryptedCredentials, exchangeKey);

        // 11. Phew, done!
        return credentials;
    }

    internal static async Task<MsgA> RequestMsgA(string signInToken, string enrollmentUuid, RestClient rest, CancellationToken cancellationToken)
    {
        var msgAResponse = await rest.PostJsonAsync<Model.CpaceMsgA>(
                GetCpaceEndpoint(enrollmentUuid, "msga"),
                new Dictionary<string, object> { ["signInToken"] = signInToken },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!msgAResponse.IsSuccessful)
            throw MakeError(msgAResponse);

        return ParseMsgA(msgAResponse.Data.MsgA.Decode64Loose());
    }

    internal record MsgA(byte[] Ya, Ad Ad, byte[] OriginalMessage);

    internal record Ad(int Version, byte[] Salt, byte[] SessionId);

    internal static MsgA ParseMsgA(byte[] json)
    {
        var model = DeserializeJson<Model.MsgA>(json);
        return new MsgA(
            Ya: model.Ya.Decode64Loose(),
            Ad: new Ad(Version: model.Ad.Version, Salt: model.Ad.Salt.Decode64Loose(), SessionId: [.. model.Ad.SessionId.Select(x => (byte)x)]),
            OriginalMessage: json
        );
    }

    internal static async Task SendMsgB(byte[] msgB, string signInToken, string enrollmentUuid, RestClient rest, CancellationToken cancellationToken)
    {
        var response = await rest.PutJsonAsync<Model.SuccessResult>(
                GetCpaceEndpoint(enrollmentUuid, "msgb"),
                new Dictionary<string, object> { ["signInToken"] = signInToken, ["msgb"] = msgB.ToUrlSafeBase64NoPadding() },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        if (response.Data.Success != 1)
            throw new InternalErrorException("Failed to exchange credentials");
    }

    internal static async Task<byte[]> GetTagA(string signInToken, string enrollmentUuid, RestClient rest, CancellationToken cancellationToken)
    {
        var result = await PostJsonUntilResult<Model.CpaceTagA>(
                GetCpaceEndpoint(enrollmentUuid, "taga"),
                new Dictionary<string, object> { ["signInToken"] = signInToken },
                rest,
                cancellationToken
            )
            .ConfigureAwait(false);

        return result.TagA.Decode64Loose();
    }

    private static async Task SendTagB(byte[] tagB, string signInToken, string enrollmentUuid, RestClient rest, CancellationToken cancellationToken)
    {
        var response = await rest.PutJsonAsync<Model.SuccessResult>(
                GetCpaceEndpoint(enrollmentUuid, "tagb"),
                new Dictionary<string, object> { ["signInToken"] = signInToken, ["tagb"] = tagB.ToUrlSafeBase64NoPadding() },
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.IsSuccessful)
            throw MakeError(response);

        if (response.Data.Success != 1)
            throw new InternalErrorException("Failed to submit tagb");
    }

    internal static async Task<Model.Encrypted> RequestEncryptedCredentials(
        string signInToken,
        string enrollmentUuid,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        var result = await PostJsonUntilResult<Model.SsoCredentials>(
                GetEnrollmentEndpoint(enrollmentUuid, "share/credentials"),
                new Dictionary<string, object> { ["signInToken"] = signInToken },
                rest,
                cancellationToken
            )
            .ConfigureAwait(false);

        return result.EncryptedCredentials;
    }

    // Sometimes the server returns 200 OK with an empty body. Need to go again. The web frontend does the same.
    internal static async Task<T> PostJsonUntilResult<T>(
        string endpoint,
        Dictionary<string, object> parameters,
        RestClient rest,
        CancellationToken cancellationToken
    )
    {
        // TODO: Fix this! 20 is too little and shouldn't be done like this!
        for (var i = 0; i < 20; i++)
        {
            var response = await rest.PostJsonAsync<T>(endpoint, parameters, cancellationToken).ConfigureAwait(false);

            // Done
            if (response.IsSuccessful)
                return response.Data;

            if (response.IsHttpOk && response.Content.IsNullOrEmpty())
            {
                // Retry
                await Task.Delay(500, cancellationToken).ConfigureAwait(false);
                continue;
            }

            // Some other kind of error
            throw MakeError(response);
        }

        throw new InternalErrorException($"Failed to get a response from the server (endpoint: {endpoint})");
    }

    internal static string GetEnrollmentEndpoint(string enrollmentUuid, string method) => $"v3/device/enrollments/{enrollmentUuid}/{method}";

    internal static string GetCpaceEndpoint(string enrollmentUuid, string method) => GetEnrollmentEndpoint(enrollmentUuid, $"cpace/{method}");

    //
    // CPACE crypto
    //

    internal static byte[] CalculateMsgB(
        string username,
        string signInAddress,
        string enrollmentUuid,
        string verificationCode,
        MsgA msgA,
        byte[] clientSecret
    )
    {
        // Some arbitrary crypto stuff reverse engineered from the 1Password WASM module
        var passcodeHash = CalculatePasscodeHash(verificationCode, msgA.Ad.Salt);
        var firstHash = CalculateFirstHash(username, signInAddress, enrollmentUuid, msgA);
        var secondHash = CalculateSecondHash(firstHash, passcodeHash, msgA);
        var clientScalar = Scalar.FromBytesModOrderWide(clientSecret);
        var hashRistretto = RistrettoElement.FromUniformBytes(secondHash);
        var finalRistretto = hashRistretto.Multiply(clientScalar);
        return finalRistretto.Compress().ToByteArray();
    }

    internal static byte[] CalculatePasscodeHash(string passcode, byte[] salt)
    {
        return Crypto.Pbkdf2Sha256(passcode, salt, 100_000, 32);
    }

    internal static byte[] CalculateFirstHash(string email, string signInAddress, string enrollmentUuid, MsgA msgA)
    {
        using var memory = new MemoryStream();
        using var writer = new BinaryWriter(memory);

        WriteLeb128Prefixed(writer, "1P-SSO-TRUSTED-DEVICE");
        WriteLeb128Prefixed(writer, "1P-SSO-NEW-DEVICE");
        WriteLeb128Prefixed(writer, email);
        WriteLeb128Prefixed(writer, signInAddress);
        WriteLeb128Prefixed(writer, enrollmentUuid);
        WriteLeb128Prefixed(writer, msgA.Ad.Salt);
        WriteLeb128Prefixed(writer, [1]);

        return Crypto.Sha512(memory.ToArray());
    }

    internal static byte[] CalculateSecondHash(byte[] firstHash, byte[] passcodeHash, MsgA msgA)
    {
        using var memory = new MemoryStream();
        using var writer = new BinaryWriter(memory);

        WriteLeb128Prefixed(writer, "CPaceRistretto255");
        WriteLeb128Prefixed(writer, passcodeHash);
        WriteLeb128Prefixed(writer, Enumerable.Repeat((byte)0, 76).ToArray()); // pad to 128 bytes, the length is fixed
        WriteLeb128Prefixed(writer, firstHash);
        WriteLeb128Prefixed(writer, msgA.Ad.SessionId);

        return Crypto.Sha512(memory.ToArray());
    }

    internal static void WriteLeb128Prefixed(BinaryWriter writer, string text)
    {
        WriteLeb128Prefixed(writer, text.ToBytes());
    }

    internal static void WriteLeb128Prefixed(BinaryWriter writer, byte[] data)
    {
        // Write LEB128 encoded length
        var length = data.Length;
        do
        {
            byte b = (byte)(length & 0x7F);
            length >>= 7;
            if (length != 0)
                b |= 0x80;
            writer.Write(b);
        } while (length != 0);

        // Write the actual data
        writer.Write(data);
    }

    internal static void VerifyTagA(byte[] tagA)
    {
        // TODO: Implement
    }

    private static (byte[] AuthB, byte[] TagB) CalculateAuthBTagB(byte[] clientSecret, MsgA msgA, byte[] msgB)
    {
        var authA = CalculateAuthAHash(msgA, clientSecret);
        var authB = CalculateAuthBHash(authA, msgA, msgB);
        var tagB = CalculateTagB(authB, msgB);
        return (authB, tagB);
    }

    internal static byte[] CalculateAuthAHash(MsgA msgA, byte[] clientSecret)
    {
        var clientScalar = Scalar.FromBytesModOrderWide(clientSecret);
        return new CompressedRistretto(msgA.Ya).Decompress().Multiply(clientScalar).Compress().ToByteArray();
    }

    internal static byte[] CalculateAuthBHash(byte[] yaHash, MsgA msgA, byte[] msgB)
    {
        using var memory = new MemoryStream();
        using var writer = new BinaryWriter(memory);

        WriteLeb128Prefixed(writer, "CPaceRistretto255_ISK");
        WriteLeb128Prefixed(writer, msgA.Ad.SessionId);
        WriteLeb128Prefixed(writer, yaHash);
        writer.Write(msgA.OriginalMessage);
        writer.Write(msgB);

        return Crypto.Sha512(memory.ToArray());
    }

    internal static byte[] CalculateTagB(byte[] authBHash, byte[] msgB)
    {
        using var memory = new MemoryStream();
        using var writer = new BinaryWriter(memory);

        writer.Write("CPaceMac"u8.ToArray());
        writer.Write(authBHash);

        var hashA = Crypto.Sha512(memory.ToArray());

        return Crypto.HmacSha512(hashA, msgB);
    }

    internal static byte[] DeriveExchangeKey(byte[] authB)
    {
        var hmac1 = Crypto.HmacSha384("1P_SSO_ENROLLMENT_TRANSPORT_KEY"u8.ToArray(), authB);
        var hmac2 = Crypto.HmacSha384(hmac1, "1P_SSO_CREDENTIAL_BUNDLE_KEY:ENROLL\x01"u8.ToArray());
        return hmac2[0..32];
    }

    internal static Model.CredentialBundle DecryptCredentials(Model.Encrypted encryptedCredentials, byte[] exchangeKey)
    {
        var aesKey = new AesKey("1P_SSO_ENROLLMENT_TRANSPORT_KEY", exchangeKey);
        var credentialsBytes = aesKey.Decrypt(Encrypted.Parse(encryptedCredentials), adata: "1P_SSO_CREDENTIAL_BUNDLE:ENROLL"u8.ToArray());

        return DeserializeJson<Model.CredentialBundle>(credentialsBytes);
    }

    internal static T DeserializeJson<T>(string jsonString) => DeserializeJson<T>(jsonString.ToBytes());

    internal static T DeserializeJson<T>(byte[] jsonBytes)
    {
        const string errorMessage = "Failed to deserialize JSON";
        try
        {
            var o = JsonSerializer.Deserialize<T>(jsonBytes);
            return o == null ? throw MakeError() : o;
        }
        catch (JsonException e)
        {
            throw MakeError(e);
        }

        static InternalErrorException MakeError(Exception? e = null) => new(errorMessage, e);
    }
}
