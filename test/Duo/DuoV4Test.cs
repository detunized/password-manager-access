// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Duo;
using Shouldly;
using Xunit;
using R = PasswordManagerAccess.Duo.ResponseV4;

namespace PasswordManagerAccess.Test.Duo;

public class DuoV4Test
{
    [Fact]
    public void ParseDeviceData_returns_empty_when_methods_is_null()
    {
        // Arrange
        var data = new R.Data { Phones = [new R.Phone { Id = "0", Name = "phone", Key = "key" }], Methods = null };

        // Act
        var devices = DuoV4.ParseDeviceData(data);

        // Assert
        devices.ShouldBeEmpty();
    }

    [Fact]
    public void ParseDeviceData_returns_empty_when_phones_is_null()
    {
        // Arrange
        var data = new R.Data { Phones = null, Methods = [new R.Method { DeviceKey = "key", Factor = "Duo Push" }] };

        // Act
        var devices = DuoV4.ParseDeviceData(data);

        // Assert
        devices.ShouldBeEmpty();
    }

    [Fact]
    public void ParseDeviceData_returns_empty_when_both_are_null()
    {
        // Arrange
        var data = new R.Data { Phones = null, Methods = null };

        // Act
        var devices = DuoV4.ParseDeviceData(data);

        // Assert
        devices.ShouldBeEmpty();
    }

    [Fact]
    public void ParseDeviceData_returns_devices_with_matching_factors()
    {
        // Arrange
        var data = new R.Data
        {
            Phones =
            [
                new R.Phone { Id = "0", Name = "iPhone", Key = "phone-key" },
            ],
            Methods =
            [
                new R.Method { DeviceKey = "phone-key", Factor = "Duo Push" },
                new R.Method { DeviceKey = "phone-key", Factor = "Phone Call" },
            ],
        };

        // Act
        var devices = DuoV4.ParseDeviceData(data);

        // Assert
        devices.Length.ShouldBe(1);
        devices[0].Id.ShouldBe("0");
        devices[0].Name.ShouldBe("iPhone");
        devices[0].Factors.ShouldBe([DuoFactor.Push, DuoFactor.Call]);
    }

    [Fact]
    public void ParseDeviceData_skips_null_phones()
    {
        // Arrange
        var data = new R.Data
        {
            Phones = [null, new R.Phone { Id = "0", Name = "iPhone", Key = "phone-key" }, null],
            Methods = [new R.Method { DeviceKey = "phone-key", Factor = "Duo Push" }],
        };

        // Act
        var devices = DuoV4.ParseDeviceData(data);

        // Assert
        devices.Length.ShouldBe(1);
        devices[0].Id.ShouldBe("0");
    }

    [Fact]
    public void ParseDeviceData_skips_null_methods()
    {
        // Arrange
        var data = new R.Data
        {
            Phones = [new R.Phone { Id = "0", Name = "iPhone", Key = "phone-key" }],
            Methods = [null, new R.Method { DeviceKey = "phone-key", Factor = "Duo Push" }, null],
        };

        // Act
        var devices = DuoV4.ParseDeviceData(data);

        // Assert
        devices.Length.ShouldBe(1);
        devices[0].Factors.ShouldBe([DuoFactor.Push]);
    }
}
