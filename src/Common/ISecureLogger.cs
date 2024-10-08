// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;

namespace PasswordManagerAccess.Common;

public readonly record struct LogEntry(DateTime Timestamp, string Tag, string Message);

public interface ISecureLogger
{
    void Log(LogEntry entry);
}

//
// Internal
//

internal interface ISimpleLogger : ISecureLogger
{
    void Log(string message);
}

internal interface ICensoredLogger : ISimpleLogger
{
    void AddFilter(string filter);
}

internal class NullLogger : ISecureLogger
{
    public void Log(LogEntry entry) { }
}

internal class TaggedLogger(string tag, ISecureLogger logger) : ICensoredLogger
{
    public string Tag { get; } = tag;

    public List<string> Filters { get; } = [];

    public List<LogEntry> Entries { get; } = [];

    public void Clear() => Entries.Clear();

    //
    // ISecureLogger implementation
    //

    public void Log(LogEntry entry)
    {
        var censored = entry with { Message = Censor(entry.Message) };
        Entries.Add(censored);
        logger.Log(censored);
    }

    //
    // ISimpleLogger implementation
    //

    public void Log(string message) => Log(new LogEntry(DateTime.UtcNow, Tag, message));

    //
    // ICensoredLogger implementation
    //

    public void AddFilter(string filter) => Filters.Add(filter);

    //
    // Internal
    //

    internal string Censor(string message)
    {
        foreach (var filter in Filters)
            message = message.Replace(filter, new string('*', filter.Length));

        return message;
    }
}
