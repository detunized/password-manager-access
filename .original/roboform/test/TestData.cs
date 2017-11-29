// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace RoboForm.Test
{
    internal static class TestData
    {
        public const string Username = "lastpass.ruby@gmail.com";
        public const string Password = "h74@aB$SCt9dTBQ3%rmAVN3oOmtGLt58Nix7!3z%vUO4Ni07rfjutHRbhJ9!SkOk";
        public const string Nonce = "-DeHRrZjC8DZ_0e8RGsisg";

        public static readonly AuthInfo AuthInfo = new AuthInfo(
            sid: "6Ag93Y02vihucO9IQl1fbg",
            data: "cj0tRGVIUnJaakM4RFpfMGU4UkdzaXNnTTItdGpnZi02MG0tLUZCaExRMjZ0ZyxzPUErRnQ4VU0" +
                  "2NzRPWk9PalVqWENkYnc9PSxpPTQwOTY=",
            nonce: "-DeHRrZjC8DZ_0e8RGsisgM2-tjgf-60m--FBhLQ26tg",
            salt: "A+Ft8UM674OZOOjUjXCdbw==".Decode64(),
            iterationCount: 4096,
            isMd5: false);

        public static readonly byte[] Blob = (
            "b25lZmlsZTEHAY8GAACVds6Fe4wEu/T0DayGA/TwZ3NlbmNzdDEAAgAQAAAQmalFVuiCSwJ0PCCBxMZejz" +
            "SjUl0mYQLyH6komWcc/2M2CS35wBIhatR7uI1a3+NMCvLWbFcwWY0c/1+DuUs/b8zfndMot12m9MgNijzS" +
            "QfRYbL9XjHtIBOB66xMd4ep0bmnMlRx6rt7IPuvVIOVDB25x8vVzXJI7NaCVH/mcK5L/6+4Qokfo9DscH8" +
            "NJv6FgxfUP7OS4U7D8HkshX7fqwWAmbMtCH42RbqS3nu4MM0PhIVybifOIr/wiBQaQg08lhZ5Q0mu1D0th" +
            "dOL6FchljR3nWRgWmEdec39YBTYdaJeq6489WY2hewq/6WiALwP8w9ANDs4qSOd+pCPPx2GnRVLoCtA6e9" +
            "Q1/iqOH+lA7u77sKLY3zkNQ1+apxhWKPvTy2hIr3Y+ZzLmr2gSMeHvNZJ87s9ePCtouesV/obvBfApxP8Y" +
            "Xf28Dmegswd0GFQmC94M9EDLXUu6fGHNDCKEo49ht+6+6hEIV+ntE5pb4yaS4SKOKzUsLMl8UVUXCEPl1Y" +
            "OyaBxIiP/niGn5t0V49naJ/oClB/eLoiVa3ywSCTh8VgrxhEqFoIERr+yGr2hpNMzUebFdHZo/RW4cqi70" +
            "QxmoJ1udAfn3trFVeH9ZtqV3QTCb6UOAoEJQLSIAElcuwblpEz3pVaQ5eBdBQNSviEj2BphHbW4POklw1e" +
            "PoxqQwNqE7VpIwJ9v3sU20QvTlxlQ6IRdZa4WkBMZ9hfAPNFU1OwhZfylR+cDIKxH5wSuS8oEiNZS7wK9i" +
            "6xElA0syueih1H/Lu8dFA4Kov1rzzEq4fnIVl84BtAiJZnOg/9KzDXiwm2gvYvvFrA00DEdnW/uhC84ELD" +
            "5UY+p19VXdWjyVWdaaml0ISWTdQGK4TAPZdghFGnfxZGJWmE3UEHrhW/VePMWQb1+BJqWqLwsapBThVdX+" +
            "rxOl8E3jo7bLbCPh3NtvNpgudy1s30ggQCEDFn1ra5PI3IfLVxgWVVNu1z5Bof36yUC9TeXCIi5wm7a9y+" +
            "g0ZXUYMDUN9UX8NxUG1bSq+4jSi+0LcVgF8hcmY918LeY/0miPV9JUmifItq1rUY3gi3naL99yOf534lKA" +
            "3FibutuFxJ9+dUBPYq6Atxi/irTPfkzAr2IyFQy9JzoXXn0qflpTWIZpa6fM8R39UVzSltFVcfKSsbEfFk" +
            "INgBUJ3nRNoc+LDBi4/t5i0SY/QLUUE0VyS9ffHwlK/A10ceXELIg6phnU7HnDv86dlsm2Ey19A49QWSjt" +
            "xP4vMHZhGnGhyvOpuHmt8VogcgDf/JY+9SK8dQRjIijlvMqT28HUehJiOgnBENGeDmoV4g+noj3ibajpzM" +
            "eVxfpkd9BOYer0vPMmPjBqZFFXYeGlL8k91fGaX6MEWTbFUKjupJ7JhBDX1lTfc6wTK5f9l8biAMZSUvqr" +
            "DQ/EYpsoy4nAmCgwT7NxMbslAqY8eEWl3S9BIOIrOBRI2HPcWMEBVBZ25nub2mNrIjdheksdr7xm1/Zk7o" +
            "a35CnDnv0EKC0/LV3OWSi48P2AQ96dsF+yx5wEJ9Kb5WuOvMwl31mQIwOhl35bA1umI6+PRf9Y6J4cfNc3" +
            "4olCc+8SUZMNckPWsPSM/ULpGQ1tpCicKkJBaFBWjxRDUuKxvANgxXgWUohyrx7X5YeXY3Y5HEY+edQCju" +
            "dk6qE/gV8SCTlMwj0I8OXz/1okRHvZPL+86mVj5YS5rzGLTnnPn4eSEnMSQ11HRlfh5Pmp5uz/tslsm+aF" +
            "5B1zOJx/ryP0Uy8a5D7Dqb5juThCpDrJDxOO4SNTMSVO7jOBueitUvmOHaBBRHYVhItRm2BkQojDq5o+h+" +
            "RVeopvcbm+cUWrwN4paja04hUe/AAkQ3l+71RnUy7rgozMNPQEsdZRabAQafMwKTaKS9mjP7msKTd/HHju" +
            "zd8LW6Mf3HuECAGIjW9GVy3MkTrSRF4O5dq3e9tTQ2Yuuv3M5TAJkjKtdhoztl91cJ4WjxDDYrq6sp07do" +
            "R7yRi4dRymOZcFNtLEJNPESe3hiHXx7197FNtSW9DLyBq0Wnsmz01fS4Z+7/uGuLG8TMRfzpcwlim+R0sb" +
            "qyrWGQNfIAwd11ngfqvYNBx6Jh7VtcZjmLdNCiM2nEAWsuvRv0RwjnZkA29iaJs/2x81cUkemPJk94oh+P" +
            "KK5BQ1XhfzDbqhMk8FiO7NU6SRZqE48MCPNRkEhZjssSGGS4zpb4tKkJG+ZgJwXnEAAAAA").Decode64();
    }
}
