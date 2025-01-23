// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordManagerAccess.Common;

// TODO: Quick hack for now. Maybe rather use https://github.com/mcintyre321/OneOf
public readonly struct OneOf<TA, TB>
{
    public bool IsA => _state == State.A;
    public bool IsB => _state == State.B;

    public TA A => IsA ? _a : throw new InvalidOperationException("OneOf is not in the A state");
    public TB B => IsB ? _b : throw new InvalidOperationException("OneOf is not in the B state");

    public object Case =>
        _state switch
        {
            State.A => _a,
            State.B => _b,
            _ => throw new InvalidOperationException("Invalid state"),
        };

    public static OneOf<TA, TB> FromA(TA a) => new(a, default!, State.A);

    public static OneOf<TA, TB> FromB(TB b) => new(default!, b, State.B);

    public OneOf()
    {
        throw new InvalidOperationException("OneOf cannot be instantiated without arguments");
    }

    //
    // Private
    //

    private enum State
    {
        A,
        B,
    }

    private readonly TA _a;
    private readonly TB _b;
    private readonly State _state;

    private OneOf(TA a, TB b, State state)
    {
        _a = a;
        _b = b;
        _state = state;
    }
}

public readonly struct OneOf<TA, TB, TC>
{
    public bool IsA => _state == State.A;
    public bool IsB => _state == State.B;
    public bool IsC => _state == State.C;

    public TA A => IsA ? _a : throw new InvalidOperationException("OneOf is not in a Left state");
    public TB B => IsB ? _b : throw new InvalidOperationException("OneOf is not in a Right state");
    public TC C => IsC ? _c : throw new InvalidOperationException("OneOf is not in a Right state");

    public object Case =>
        _state switch
        {
            State.A => _a,
            State.B => _b,
            State.C => _c,
            _ => throw new InvalidOperationException("Invalid state"),
        };

    public static OneOf<TA, TB, TC> FromA(TA a) => new(a, default!, default!, State.A);

    public static OneOf<TA, TB, TC> FromB(TB b) => new(default!, b, default!, State.B);

    public static OneOf<TA, TB, TC> FromC(TC c) => new(default!, default!, c, State.C);

    public OneOf()
    {
        throw new InvalidOperationException("OneOf cannot be instantiated without arguments");
    }

    //
    // Private
    //

    private enum State
    {
        A,
        B,
        C,
    }

    private readonly TA _a;
    private readonly TB _b;
    private readonly TC _c;
    private readonly State _state;

    private OneOf(TA a, TB b, TC c, State state)
    {
        _a = a;
        _b = b;
        _c = c;
        _state = state;
    }
}
