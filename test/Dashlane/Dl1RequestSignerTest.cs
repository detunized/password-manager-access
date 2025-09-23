// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net.Http;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane;

// All DL1 request signers tests
public class Dl1RequestSignerTest
{
    //
    // Dl1AppRequestSigner tests
    //

    [Fact]
    public void Dl1AppRequestSigner_Sign_returns_headers()
    {
        // Arrange
        var originalHeaders = new Dictionary<string, string>
        {
            ["name1"] = "value1",
            ["name2"] = "value2",
            ["name3"] = "value3",
            ["User-Agent"] = "Browser",
            ["Content-Length"] = "1337",
        };

        // Act
        var signedHeaders = new Dl1AppRequestSigner().Sign(
            new Uri("https://blah.blah"),
            HttpMethod.Post,
            originalHeaders,
            MakeHttpContent(),
            1234567890
        );

        // Assert
        // Only one header is added
        Assert.Equal(originalHeaders.Count + 1, signedHeaders.Count);

        // All headers are the same
        foreach (var k in originalHeaders.Keys)
        {
            var v = Assert.Contains(k, signedHeaders);
            Assert.Equal(originalHeaders[k], v);
        }

        // Authorization header is added
        var auth = Assert.Contains("Authorization", signedHeaders);
        Assert.StartsWith(
            "DL1-HMAC-SHA256 AppAccessKey=HB9JQATDY6Y62JYKT7KXBN4C7FH8HKC5,Timestamp=1234567890,SignedHeaders=content-type;user-agent,Signature=",
            auth
        );
    }

    [Fact]
    public void Dl1AppRequestSigner_BuildAuthHeader_returns_header()
    {
        // Arrange/Act
        var header = new Dl1AppRequestSigner().BuildAuthHeader(1234567890, ["h1", "h2", "h3"], "deadbeef");

        // Assert
        Assert.Equal(
            "DL1-HMAC-SHA256 AppAccessKey=HB9JQATDY6Y62JYKT7KXBN4C7FH8HKC5,Timestamp=1234567890,SignedHeaders=h1;h2;h3,Signature=deadbeef",
            header
        );
    }

    //
    // Dl1DeviceRequestSigner tests
    //

    [Fact]
    public void Dl1DeviceRequestSigner_Sign_returns_headers()
    {
        // Arrange
        var originalHeaders = new Dictionary<string, string>
        {
            ["name1"] = "value1",
            ["name2"] = "value2",
            ["name3"] = "value3",
            ["User-Agent"] = "Browser",
            ["Content-Length"] = "1337",
        };

        // Act
        var signedHeaders = new Dl1DeviceRequestSigner
        {
            Username = "username@example.com",
            DeviceAccessKey = "device-access-key",
            DeviceSecretKey = "device-secret-key",
        }.Sign(new Uri("https://blah.blah"), HttpMethod.Post, originalHeaders, MakeHttpContent(), 1234567890);

        // Assert
        // Only one header is added
        Assert.Equal(originalHeaders.Count + 1, signedHeaders.Count);

        // All headers are the same
        foreach (var k in originalHeaders.Keys)
        {
            var v = Assert.Contains(k, signedHeaders);
            Assert.Equal(originalHeaders[k], v);
        }

        // Authorization header is added
        var auth = Assert.Contains("Authorization", signedHeaders);
        Assert.StartsWith(
            "DL1-HMAC-SHA256 Login=username@example.com,AppAccessKey=HB9JQATDY6Y62JYKT7KXBN4C7FH8HKC5,DeviceAccessKey=device-access-key,"
                + "Timestamp=1234567890,SignedHeaders=content-type;user-agent,Signature=",
            auth
        );
    }

    [Fact]
    public void Dl1DeviceRequestSigner_BuildAuthHeader_returns_header()
    {
        // Arrange/Act
        var header = new Dl1DeviceRequestSigner
        {
            Username = "username@example.com",
            DeviceAccessKey = "device-access-key",
            DeviceSecretKey = "device-secret-key",
        }.BuildAuthHeader(1234567890, ["h1", "h2", "h3"], "deadbeef");

        // Assert
        Assert.Equal(
            "DL1-HMAC-SHA256 Login=username@example.com,AppAccessKey=HB9JQATDY6Y62JYKT7KXBN4C7FH8HKC5,DeviceAccessKey=device-access-key,"
                + "Timestamp=1234567890,SignedHeaders=h1;h2;h3,Signature=deadbeef",
            header
        );
    }

    //
    // Dl1BaseRequestSigner tests
    //

    [Fact]
    public void HashBody_return_body_hash()
    {
        // Arrange/Act
        var hash = Dl1BaseRequestSigner.HashBody(MakeHttpContent());

        // Assert
        Assert.Equal(ContentSha256, hash);
    }

    [Fact]
    public void FormatHeaderForSigning_returns_headers()
    {
        // Arrange
        var content = new ByteArrayContent("".ToBytes());
        content.Headers.Add("Content-Length", "1337");
        content.Headers.Add("Content-Header", "content-header-value1");
        content.Headers.Add("Content-Header", "content-header-value2");
        content.Headers.Add("Content-Type", "application/octet-stream");

        // Act
        var headers = Dl1BaseRequestSigner.FormatHeaderForSigning(
            new Dictionary<string, string>
            {
                ["name1"] = "value1",
                ["name2"] = "value2",
                ["name3"] = "value3",
                ["User-Agent"] = "Browser",
                ["Content-Length"] = "1337",
            },
            content
        );

        // Assert
        var expected = new Dictionary<string, string> { ["user-agent"] = "Browser", ["content-type"] = "application/octet-stream" };
        Assert.Equal(expected, headers);
    }

    [Fact]
    public void BuildRequest_returns_request_string()
    {
        // Arrange/Act
        var request = Dl1BaseRequestSigner.BuildRequest(
            new Uri("https://blah.blah"),
            HttpMethod.Post,
            new Dictionary<string, string>
            {
                ["name3"] = "value3",
                ["ignored2"] = "ignored2",
                ["name2"] = "value2",
                ["ignored1"] = "ignored1",
                ["name1"] = "value1",
            },
            ["name1", "name2", "name3"],
            MakeHttpContent()
        );

        // Assert
        var expected = new[] { "POST", "/", "", "name1:value1", "name2:value2", "name3:value3", "", "name1;name2;name3", ContentSha256 }.JoinToString(
            "\n"
        );

        Assert.Equal(expected, request);
    }

    [Fact]
    public void BuildAuthSiefagningMaterial_returns_signing_material()
    {
        // Arrange/Act
        var material = Dl1BaseRequestSigner.BuildAuthSigningMaterial(1234567890, "deadbeef");

        // Assert
        Assert.Equal("DL1-HMAC-SHA256\n1234567890\ndeadbeef", material);
    }

    //
    // Helpers
    //

    internal static HttpContent MakeHttpContent()
    {
        var content = new StringContent("string-content-line1\nstring-content-line2");
        content.Headers.Add("content-header-name", "content-header-value");
        content.Headers.Add("ignored-content-header-name", "ignored-content-header-value");
        return content;
    }

    //
    // Data
    //

    private const uint Timestamp = 1234567890;
    private const string ContentSha256 = "121daa986d8b8ef61459c322035929d9b14724cff672b88a9b8fc4ccf5787965";
    private const string RequestHash = "deadbeef";
}
