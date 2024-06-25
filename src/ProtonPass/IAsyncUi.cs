// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable
using System.Threading;
using System.Threading.Tasks;

namespace PasswordManagerAccess.ProtonPass
{
    public interface IAsyncUi
    {
        public class Result
        {
            public bool Solved { get; set; }
            public string Token { get; set; } = "";
        }

        Task<Result> SolveCaptcha(string url, string humanVerificationToken, CancellationToken cancellationToken);
    }
}
