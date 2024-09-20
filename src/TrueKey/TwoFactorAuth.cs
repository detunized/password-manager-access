// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.TrueKey
{
    internal class TwoFactorAuth
    {
        public enum Step
        {
            Done,
            WaitForOob,
            ChooseOob,
            WaitForEmail,
            Face,
            Fingerprint,
        }

        public class Settings
        {
            public readonly Step InitialStep;
            public readonly string TransactionId;
            public readonly string Email;
            public readonly OobDevice[] Devices;
            public readonly string OAuthToken;

            public Settings(Step initialStep, string transactionId, string email, OobDevice[] devices, string oAuthToken)
            {
                InitialStep = initialStep;
                TransactionId = transactionId;
                Email = email;
                Devices = devices;
                OAuthToken = oAuthToken;
            }

            public bool IsAuthenticated => InitialStep == Step.Done && !OAuthToken.IsNullOrEmpty();
        }

        public struct OobDevice
        {
            public readonly string Name;
            public readonly string Id;

            public OobDevice(string name, string id)
            {
                Name = name;
                Id = id;
            }
        }

        public static string Start(Client.ClientInfo clientInfo, Settings settings, Ui ui, RestClient rest)
        {
            return new TwoFactorAuth(clientInfo, settings, ui, rest).Run(settings.InitialStep);
        }

        //
        // private
        //

        private abstract class State
        {
            public virtual bool IsDone => false;
            public virtual bool IsSuccess => false;
            public virtual string Result => throw new NotImplementedException();

            public abstract State Advance(TwoFactorAuth owner);

            // TODO: Shared code for most states. It's not really good that it's in the base class.
            protected State Check(TwoFactorAuth owner)
            {
                var result = Client.AuthCheck(owner._clientInfo, owner._settings.TransactionId, owner._rest);
                return new Done(result);
            }
        }

        private class Done : State
        {
            public Done(string oAuthToken)
            {
                _oAuthToken = oAuthToken;
            }

            public override bool IsDone => true;
            public override bool IsSuccess => true;
            public override string Result => _oAuthToken;

            public override State Advance(TwoFactorAuth owner) => throw new NotImplementedException();

            private readonly string _oAuthToken;
        }

        private class SendEmail : State
        {
            public override State Advance(TwoFactorAuth owner)
            {
                Client.AuthSendEmail(owner._clientInfo, owner._settings.Email, owner._settings.TransactionId, owner._rest);
                return new WaitForEmail();
            }
        }

        private class SendPush : State
        {
            public SendPush(int deviceIndex)
            {
                _deviceIndex = deviceIndex;
            }

            public override State Advance(TwoFactorAuth owner)
            {
                Client.AuthSendPush(owner._clientInfo, owner._settings.Devices[_deviceIndex].Id, owner._settings.TransactionId, owner._rest);
                return new WaitForOob(_deviceIndex);
            }

            private readonly int _deviceIndex;
        }

        private class WaitForEmail : State
        {
            public override State Advance(TwoFactorAuth owner)
            {
                var validAnswers = new[] { Ui.Answer.Check, Ui.Answer.Resend };
                var answer = owner._ui.AskToWaitForEmail(owner._settings.Email, validAnswers);
                switch (answer)
                {
                    case Ui.Answer.Check:
                        return Check(owner);
                    case Ui.Answer.Resend:
                        Client.AuthSendEmail(owner._clientInfo, owner._settings.Email, owner._settings.TransactionId, owner._rest);
                        return this;
                }

                throw new InternalErrorException($"Invalid answer '{answer}'");
            }
        }

        private class WaitForOob : State
        {
            public WaitForOob(int deviceIndex)
            {
                _deviceIndex = deviceIndex;
            }

            public override State Advance(TwoFactorAuth owner)
            {
                var validAnswers = new[] { Ui.Answer.Check, Ui.Answer.Resend, Ui.Answer.Email };
                var answer = owner._ui.AskToWaitForOob(owner._settings.Devices[_deviceIndex].Name, owner._settings.Email, validAnswers);
                switch (answer)
                {
                    case Ui.Answer.Check:
                        return Check(owner);
                    case Ui.Answer.Resend:
                        Client.AuthSendPush(owner._clientInfo, owner._settings.Devices[_deviceIndex].Id, owner._settings.TransactionId, owner._rest);
                        return this;
                    case Ui.Answer.Email:
                        Client.AuthSendEmail(owner._clientInfo, owner._settings.Email, owner._settings.TransactionId, owner._rest);
                        return new WaitForEmail();
                }

                throw new InternalErrorException($"Invalid answer '{answer}'");
            }

            private readonly int _deviceIndex;
        }

        private class ChooseOob : State
        {
            public override State Advance(TwoFactorAuth owner)
            {
                var names = owner._settings.Devices.Select(i => i.Name).ToArray();
                var validAnswers = Enumerable
                    .Range(0, owner._settings.Devices.Length)
                    .Select(i => Ui.Answer.Device0 + i)
                    .Concat(new[] { Ui.Answer.Email })
                    .ToArray();
                var answer = owner._ui.AskToChooseOob(names, owner._settings.Email, validAnswers);

                if (answer == Ui.Answer.Email)
                {
                    Client.AuthSendEmail(owner._clientInfo, owner._settings.Email, owner._settings.TransactionId, owner._rest);
                    return new WaitForEmail();
                }

                var deviceIndex = answer - Ui.Answer.Device0;
                if (deviceIndex >= 0 && deviceIndex < owner._settings.Devices.Length)
                {
                    Client.AuthSendPush(owner._clientInfo, owner._settings.Devices[deviceIndex].Id, owner._settings.TransactionId, owner._rest);
                    return new WaitForOob(deviceIndex);
                }

                throw new InternalErrorException($"Invalid answer '{answer}'");
            }
        }

        private TwoFactorAuth(Client.ClientInfo clientInfo, Settings settings, Ui ui, RestClient rest)
        {
            _clientInfo = clientInfo;
            _settings = settings;
            _ui = ui;
            _rest = rest;
        }

        private string Run(Step nextStep)
        {
            var state = CreateInitialState(nextStep);
            while (!state.IsDone)
                state = state.Advance(this);

            if (state.IsSuccess)
                return state.Result;

            throw new InternalErrorException($"Two step verification failed: {state.Result}");
        }

        private State CreateInitialState(Step step)
        {
            switch (step)
            {
                case Step.Done:
                    return new Done(_settings.OAuthToken);
                case Step.WaitForEmail:
                    return new WaitForEmail();
                case Step.WaitForOob:
                    if (_settings.Devices.Length > 1)
                        return new ChooseOob();
                    return new WaitForOob(0);
                case Step.ChooseOob:
                    return new ChooseOob();
                case Step.Face:
                case Step.Fingerprint:
                    // Face and fingerprint are not really supported but the server sometimes
                    // sends those as a valid next step. The Chrome extension silently ignores
                    // at least some of them. So we here fall back to push or email.
                    switch (_settings.Devices.Length)
                    {
                        case 0:
                            return new SendEmail();
                        case 1:
                            return new SendPush(0);
                        default:
                            return new ChooseOob();
                    }
            }

            throw new InternalErrorException($"Two factor auth step {step} is not supported");
        }

        private readonly Client.ClientInfo _clientInfo;
        private readonly Settings _settings;
        private readonly Ui _ui;
        private readonly RestClient _rest;
    }
}
