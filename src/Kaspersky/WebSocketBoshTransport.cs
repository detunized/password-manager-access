// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.IO;
using System.Net.WebSockets;
using System.Threading;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    internal class WebSocketBoshTransport: IBoshTransport
    {
        private readonly ClientWebSocket _webSocket = new ClientWebSocket();
        private readonly MemoryStream _message = new MemoryStream(1024);
        private readonly ArraySegment<byte> _buffer = new ArraySegment<byte>(new byte[1024]);
        private bool _disposed;

        public WebSocketBoshTransport()
        {
            _webSocket.Options.AddSubProtocol("xmpp");
        }

        //
        // IBoshTransport
        //

        public Exception? Connect(string url)
        {
            try
            {
                _webSocket.ConnectAsync(new Uri(url), CancellationToken.None).GetAwaiter().GetResult();
                return null;
            }
            catch (Exception e) // TODO: Not a good practice, but it's not clear what ConnectAsync might throw
            {
                return e;
            }
        }

        public Try<string> Request(string body)
        {
            try
            {
                _webSocket.SendAsync(new ArraySegment<byte>(body.ToBytes()),
                                     WebSocketMessageType.Text,
                                     true,
                                     CancellationToken.None);

                for (var i = 0; i < 3; i++)
                {
                    _message.Position = 0;
                    while (true)
                    {
                        var part = _webSocket.ReceiveAsync(_buffer, CancellationToken.None).GetAwaiter().GetResult();
                        _message.Write(_buffer.Array!, 0, part.Count);
                        if (part.EndOfMessage)
                            break;

                        if (_message.Position > 1024 * 1024)
                            return Try<string>.FromError("Message is too long");
                    }
                }

                return Try.FromValue(_message.ToArray().ToUtf8());
            }
            catch (Exception e)
            {
                return Try.FromError<string>(e);
            }
        }

        //
        // IDisposable
        //

        public void Dispose()
        {
            if (_disposed)
                return;

            _webSocket.Dispose();
            _message.Dispose();
            _disposed = true;
        }
    }
}
