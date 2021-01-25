// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    internal class Bosh
    {
        public Bosh(string url, Jid jid, string password, IBoshTransport transport)
        {
            _url = url;
            _jid = jid;
            _password = password;
            _transport = transport;
        }

        public void Connect()
        {
            //
            // 1. Connect
            //

            if (_transport.Connect(_url) is { } error)
                throw MakeError($"Failed to connect to '{_url}'", error);

            //
            // 2. Initialize
            //

            var response = Request($"<stream:stream to='{_jid.Host}' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>", 2);
            if (!response.Contains("<mechanism>PLAIN</mechanism>"))
                throw MakeError("PLAIN auth method is not supported by the server");

            //
            // 3. Authenticate
            //

            var auth = GetPlainAuthString(_jid, _password);
            response = Request($"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{auth}</auth>", 1);
            if (!response.StartsWith("<success xmlns='"))
                throw MakeError("Authentication failed");

            //
            // 4. Restart
            //

            response = Request($"<stream:stream to='{_jid.Host}' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>", 2);
            if (!response.Contains("<bind xmlns='") || !response.Contains("<session xmlns='"))
                throw MakeError("Restart failed");

            //
            // 5. Bind resource
            //

            var xml = RequestXml($"<iq type='set' id='_bind_auth_2' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>{_jid.Resource}</resource></bind></iq>");
            var xJid = GetChild(xml, "iq/bind/jid");
            if (xJid == null || xJid.Value != _jid.Full)
                throw MakeError("Resource bind failed");

            //
            // 6. Set session
            //

            xml = RequestXml("<iq type='set' id='_session_auth_2' xmlns='jabber:client'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>");
            if (GetChild(xml, "iq/session") == null)
                throw MakeError("Session auth failed");
        }

        public enum Operation
        {
            Changed,
            Removed,
            Inactive,
            Deprecated,
        }

        public readonly struct Change
        {
            public readonly string Id;
            public readonly Operation Operation;
            public readonly string Type;
            public readonly string Data;

            public Change(string id, Operation operation, string type, string data)
            {
                Id = id;
                Operation = operation;
                Type = type;
                Data = data;
            }
        }

        public IEnumerable<Change> GetChanges(string command, string commandId, string authKey = "")
        {
            Exception InvalidResponse(string reason) =>
                MakeError($"Invalid response for XMPP command '{command}': {reason}");

            IEnumerable<Change> allChanges = Array.Empty<Change>();
            var serverBlob = "";

            while (true)
            {
                var xml = SendCommand(command: command,
                                      commandId: commandId,
                                      serverBlob: serverBlob,
                                      authKey: authKey);

                var root = GetChild(xml, "message/root");
                if (root == null)
                    throw InvalidResponse("root not found");

                var changes = GetChild(xml, "message/root/changes");
                if (changes == null)
                    throw InvalidResponse("changes not found");

                var batch = from e in changes.Elements()
                    let id = e.Attribute("id")?.Value
                    where id != null
                    let operation = ParseOperation(e.Attribute("unique_id")?.Value)
                    where operation != null
                    select new Change(id,
                                      operation.Value,
                                      e.Attribute("type")?.Value ?? "",
                                      e.Attribute("dataInBase64")?.Value ?? "");

                allChanges = allChanges.Concat(batch);

                if (root.Attribute("moreChangesAvailable")?.Value != "1")
                    break;

                serverBlob = root.Attribute("serverBlob")?.Value;
                if (serverBlob.IsNullOrEmpty())
                    throw InvalidResponse("expected non-empty serverBlob attribute");
            }

            return allChanges;
        }

        //
        // Internal
        //

        internal XDocument SendCommand(string command, string commandId, string serverBlob, string authKey = "")
        {
            var timestamp = Os.UnixMilliseconds();
            var id = $"{command}-{Client.DeviceKind}-{Client.ServiceId}-{timestamp}";
            var auth = authKey.IsNullOrEmpty() ? "" : $"MPAuthKeyValueInBase64='{authKey}' ";

            return RequestXml($"<message xmlns='jabber:client' id='{id}' to='kpm-sync@{_jid.Host}' from='{_jid.Bare}'><body/><root unique_id='{commandId}' productVersion='' protocolVersion='' projectVersion='9.2.0.1' deviceType='0' osType='0' serverBlob='{serverBlob}' {auth}/></message>");
        }

        internal static string GetPlainAuthString(Jid jid, string password)
        {
            return $"{jid.Bare}\0{jid.Node}\0{password}".ToBase64();
        }

        internal string Request(string body, int expectedMessageCount)
        {
            var response = _transport.Request(body, expectedMessageCount);
            if (response.IsError)
                throw new InternalErrorException($"Request to {_url} failed", response.Error);

            return response.Value;
        }

        internal XDocument RequestXml(string body)
        {
            var xml = Request(body, 1);
            return XDocument.Parse(xml);
        }

        internal static XElement GetChild(XContainer root, string path, XElement defaultValue = null)
        {
            var current = root;
            foreach (var name in path.Split('/'))
            {
                current = current.Elements().FirstOrDefault(x => x.Name.LocalName == name);
                if (current == null)
                    return defaultValue;
            }

            return (XElement)current;
        }

        internal static Operation? ParseOperation(string operation) => operation switch
        {
            "1203265602" => Operation.Changed,
            "3122616881" => Operation.Removed,
            "1570712235" => Operation.Inactive,
            "33200760" => Operation.Deprecated,
            _ => null
        };

        internal static BaseException MakeError(string message, Exception inner = null)
        {
            throw new InternalErrorException(message, inner);
        }

        private readonly string _url;
        private readonly Jid _jid;
        private readonly string _password;
        private readonly IBoshTransport _transport;
    }
}
