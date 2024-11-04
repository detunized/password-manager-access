// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using HtmlAgilityPack;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo.Response;
using R = PasswordManagerAccess.Duo.ResponseV1;

namespace PasswordManagerAccess.Duo
{
    internal static class DuoV1
    {
        public static Result Authenticate(string host, string signature, IDuoUi ui, IRestTransport transport, ISimpleLogger logger = null)
        {
            return AuthenticateAsync(host, signature, ui, transport, logger, CancellationToken.None).GetAwaiter().GetResult();
        }

        // Returns the second factor token from Duo or null when canceled by the user.
        public static async Task<Result> AuthenticateAsync(
            string host,
            string signature,
            IDuoUi ui,
            IRestTransport transport,
            ISimpleLogger logger,
            CancellationToken cancellationToken
        )
        {
            var rest = new RestClient(transport, $"https://{host}", logger: logger);

            var (tx, app) = ParseSignature(signature);
            var html = await DownloadFrame(tx, rest, cancellationToken).ConfigureAwait(false);
            var (sid, devices) = ParseFrame(html);

            while (true)
            {
                // Ask the user to choose what to do
                var choice = ui.ChooseDuoFactor(devices);
                if (choice == null)
                    return null; // Canceled by user

                // SMS is a special case: it doesn't submit any codes, it rather tells the server to send
                // a new batch of passcodes to the phone via SMS.
                if (choice.Factor == DuoFactor.SendPasscodesBySms)
                {
                    await SubmitFactor(sid, choice, "", rest, cancellationToken).ConfigureAwait(false);
                    choice = new DuoChoice(choice.Device, DuoFactor.Passcode, choice.RememberMe);
                }

                // Ask for the passcode
                var passcode = "";
                if (choice.Factor == DuoFactor.Passcode)
                {
                    passcode = ui.ProvideDuoPasscode(choice.Device);
                    if (passcode.IsNullOrEmpty())
                        return null; // Canceled by user
                }

                var token = await SubmitFactorAndWaitForToken(sid, choice, passcode, ui, rest, cancellationToken).ConfigureAwait(false);

                // Flow error like an incorrect passcode. The UI has been updated with the error. Keep going.
                if (token.IsNullOrEmpty())
                    continue;

                // All good
                return new Result($"{token}:{app}", "", choice.RememberMe);
            }
        }

        //
        // Internal
        //

        // Duo signature looks like this: TX|ZGV...Dgx|5a8...cd4:APP|ZGV...zgx|f8d...24f
        internal static (string Tx, string App) ParseSignature(string signature)
        {
            var parts = signature.Split(':');
            if (parts.Length != 2)
                throw Util.MakeInvalidResponseError("the signature is invalid or has an unsupported format");

            return (parts[0], parts[1]);
        }

        internal static async Task<HtmlDocument> DownloadFrame(string tx, RestClient rest, CancellationToken cancellationToken)
        {
            const string parent = "https%3A%2F%2Fvault.bitwarden.com%2F%23%2F2fa";
            const string version = "2.6";

            string html = await Post($"frame/web/v1/auth?tx={tx}&parent={parent}&v={version}", rest, cancellationToken).ConfigureAwait(false);
            return Util.Parse(html);
        }

        internal static async Task<string> Post(string url, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await rest.PostFormAsync(url, [], cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessful)
                return response.Content;

            throw Util.MakeSpecializedError(response);
        }

        internal static (string Sid, DuoDevice[] Devices) ParseFrame(HtmlDocument html)
        {
            // Find the main form
            var form = html.DocumentNode.SelectSingleNode("//form[@id='login-form']");
            if (form == null)
                throw Util.MakeInvalidResponseError("main form is not found");

            // Find all the devices and the signature
            var sid = GetInputValue(form, "sid");
            var devices = GetDevices(form);

            if (sid == null || devices == null)
                throw Util.MakeInvalidResponseError("signature or devices are not found");

            return (sid, devices);
        }

        // All the info is the frame is stored in input fields <input name="name" value="value">
        internal static string GetInputValue(HtmlNode form, string name)
        {
            return form.SelectSingleNode($"./input[@name='{name}']")?.Attributes["value"]?.DeEntitizeValue;
        }

        // Returns the transaction id. In some cases it's blank, like with SMS, for example.
        internal static async Task<string> SubmitFactor(
            string sid,
            DuoChoice choice,
            string passcode,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var parameters = new Dictionary<string, object>
            {
                { "sid", sid },
                { "device", choice.Device.Id },
                { "factor", Util.GetFactorParameterValue(choice.Factor) },
            };

            if (!passcode.IsNullOrEmpty())
                parameters["passcode"] = passcode;

            var response = await Util.PostForm<SubmitFactor>("frame/prompt", parameters, rest, cancellationToken).ConfigureAwait(false);
            return response.TransactionId ?? "";
        }

        // Returns null when a recoverable flow error (like incorrect code or time out) happened
        // TODO: Don't return null, use something more obvious
        internal static async Task<string> SubmitFactorAndWaitForToken(
            string sid,
            DuoChoice choice,
            string passcode,
            IDuoUi ui,
            RestClient rest,
            CancellationToken cancellationToken
        )
        {
            var txid = await SubmitFactor(sid, choice, passcode, rest, cancellationToken).ConfigureAwait(false);
            if (txid.IsNullOrEmpty())
                throw Util.MakeInvalidResponseError("transaction ID (txid) is expected but wasn't found");

            var url = await PollForResultUrl(sid, txid, ui, rest, cancellationToken).ConfigureAwait(false);
            if (url.IsNullOrEmpty())
                return null;

            return await FetchToken(sid, url, ui, rest, cancellationToken).ConfigureAwait(false);
        }

        // Returns null when a recoverable flow error (like incorrect code or time out) happened
        // TODO: Don't return null, use something more obvious
        internal static async Task<string> PollForResultUrl(string sid, string txid, IDuoUi ui, RestClient rest, CancellationToken cancellationToken)
        {
            const int maxPollAttempts = 100;

            // Normally it wouldn't poll nearly as many times. Just a few at most. It either bails on error or
            // returns the result. This number here just to prevent an infinite loop, which is never a good idea.
            for (var i = 0; i < maxPollAttempts; i += 1)
            {
                var response = await Util.PostForm<R.Poll>(
                        "frame/status",
                        new Dictionary<string, object> { ["sid"] = sid, ["txid"] = txid },
                        rest,
                        cancellationToken
                    )
                    .ConfigureAwait(false);

                var (status, text) = GetResponseStatus(response);
                Util.UpdateUi(status, text, ui);

                switch (status)
                {
                    case DuoStatus.Success:
                        var url = response.Url;
                        if (url.IsNullOrEmpty())
                            throw Util.MakeInvalidResponseError("result URL (result_url) was expected but wasn't found");

                        // Done
                        return url;
                    case DuoStatus.Error:
                        return null; // TODO: Use something better than null
                }
            }

            throw Util.MakeInvalidResponseError("expected to receive a valid result or error, got none of it");
        }

        internal static async Task<string> FetchToken(string sid, string url, IDuoUi ui, RestClient rest, CancellationToken cancellationToken)
        {
            var response = await Util.PostForm<R.FetchToken>(url, new Dictionary<string, object> { ["sid"] = sid }, rest, cancellationToken)
                .ConfigureAwait(false);

            UpdateUi(response, ui);

            var token = response.Cookie;
            if (token.IsNullOrEmpty())
                throw Util.MakeInvalidResponseError("authentication token is expected in response but wasn't found");

            return token;
        }

        internal static void UpdateUi(R.Status response, IDuoUi ui)
        {
            var (status, text) = GetResponseStatus(response);
            Util.UpdateUi(status, text, ui);
        }

        internal static (DuoStatus Status, string Text) GetResponseStatus(R.Status response)
        {
            var status = response.Result switch
            {
                "SUCCESS" => DuoStatus.Success,
                "FAILURE" => DuoStatus.Error,
                _ => DuoStatus.Info,
            };

            return (status, response.Message ?? "");
        }

        // Extracts all devices listed in the login form.
        // Devices with no supported methods are ignored.
        internal static DuoDevice[] GetDevices(HtmlNode form)
        {
            var devices = form.SelectNodes("//select[@name='device']/option")
                ?.Select(x => (Id: x.Attributes["value"]?.DeEntitizeValue, Name: HtmlEntity.DeEntitize(x.InnerText ?? "")))
                .ToArray();

            if (devices == null || devices.Any(x => x.Id == null || x.Name == null))
                return null;

            return devices.Select(x => new DuoDevice(x.Id, x.Name, GetDeviceFactors(form, x.Id))).Where(x => x.Factors.Length > 0).ToArray();
        }

        // Extracts all the second factor methods supported by the device.
        // Unsupported methods are ignored.
        internal static DuoFactor[] GetDeviceFactors(HtmlNode form, string deviceId)
        {
            var sms = CanSendSmsToDevice(form, deviceId) ? [DuoFactor.SendPasscodesBySms] : Array.Empty<DuoFactor>();

            return form.SelectSingleNode($".//fieldset[@data-device-index='{deviceId}']")
                    ?.SelectNodes(".//input[@name='factor']")
                    ?.Select(x => x.Attributes["value"]?.DeEntitizeValue)
                    ?.Select(ParseFactor)
                    ?.Where(x => x != null)
                    ?.Select(x => x.Value)
                    ?.Concat(sms)
                    ?.ToArray() ?? [];
        }

        internal static bool CanSendSmsToDevice(HtmlNode form, string deviceId)
        {
            return form.SelectSingleNode($".//fieldset[@data-device-index='{deviceId}']")
                    ?.SelectSingleNode(".//input[@name='phone-smsable' and (@value='true' or @value='True')]") != null;
        }

        internal static DuoFactor? ParseFactor(string factor)
        {
            return factor switch
            {
                "Duo Push" => DuoFactor.Push,
                "Phone Call" => DuoFactor.Call,
                "Passcode" => DuoFactor.Passcode,
                _ => null,
            };
        }
    }
}
