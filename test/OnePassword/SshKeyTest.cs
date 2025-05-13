// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.OnePassword;

namespace PasswordManagerAccess.Test.OnePassword;

public class SshKeyTest
{
    [Theory]
    [InlineData(Rsa2048Pkcs8)]
    [InlineData(Rsa3072Pkcs8)]
    [InlineData(Rsa4096Pkcs8)]
    [InlineData(Ed25519Pkcs8)]
    public void ConvertToOpenSsh_returns_openssh_key(string pkcs8Key)
    {
        // Arrange/Act
        var key = SshKey.ConvertToOpenSsh(pkcs8Key);

        // Assert
        key.ShouldStartWith("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG");
    }

    [Theory]
    [InlineData(Rsa2048Pkcs8)]
    [InlineData(Rsa3072Pkcs8)]
    [InlineData(Rsa4096Pkcs8)]
    public void ConvertToPkcs1_returns_pkcs1_key(string pkcs8Key)
    {
        // Arrange/Act
        var key = SshKey.ConvertToPkcs1(pkcs8Key);

        // Assert
        key.ShouldStartWith("-----BEGIN RSA PRIVATE KEY-----\nMII");
    }

    //
    // Data
    //

    private const string Rsa2048Pkcs8 = """
        -----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBfhilM/4iOgUf
        V9fIHdwyzc4g7S3heuP5W2RLLjZpy/N2WiFgTOXv/DzQq9mgxDGtSYlvodpfqpuE
        nOZa5v4AvbeitTLpKqRbWthrPhscSOeNtDbanSCjUXElg3KvxXrSVDdZrr4ANADP
        7DJLLGUNdO/JAXnWnBS6gxduixuWmBGm+6J5VxxLNjQJWBccPJ8g5o8jH4Zq7/2N
        XDN/U+T401zk/YQQR5Gaj0nfJFKbTOEbPxMHc2uBm62XMPNpwdgmTGlaTJVPD1+L
        NceFInj1/SxU7v9/SEiw5HNF4GF+H/UR5+lq5W7TuK7/Gh3NaIv/igXiz9qvi5WK
        p4mzz35PAgMBAAECggEAZ6LAVIvajD6DS9xi6P6FWHi+9QfUUTbfMEnxGAtyfYwN
        pNB1m/zUE4wIjsPc1qz+5o/CmxYXvrHEhmz7PKkIVyFGYFGpKRX73ip0TEyBfM7X
        pyBlWQZb2t3eOneDT/334PvWgaSEg9tWrAcYkQcAQQrm+8Rcm8QRnixkuoKrjiaI
        wTfl/ksvpcNgkJqOR+Ggr+TZ8Fmljq6GnY2xRL9myb0HCQQbssegBf9h9AcClRex
        qzzlvxk+9dkA03h9xVRk3w7Dm66LO71UXRVhLAPysLdTsnELSw38G+2RQwoH1wWO
        ggpjLvD4reMuxEQF/g8y4OVqp5Gwiwp02WpTRGSfoQKBgQD84TG+caLxaogYUjxD
        VIL9WGhTDL1wAQqe2PWD2fZMHhNVxDuPFQuidrMV4geNO6MGYeJNDbhxzQHt+6CU
        PXobeV41ZvBxOhvTmZzCDrkNb4bjOAb+DyXFtG3QejtVqPKAumeJOwvlDe4i692R
        N26W/8tZqTiHr/bvT5miyzSsyQKBgQDD4U7KRQtOGJh5iHCQ2ytEkS+lbw4LF6x5
        jps71FPuDtaZ9y3UjNKSubx+S1/KHQhHbV1ob2OPikWnp2XyShBStjW6ZtYwwUvS
        HUF1lwwX3owS/FhDC6CkuXFclp1tBs3CO/xRtTWBje12IIw+2yn7aoq0tPUgWagq
        kisVbtOWVwKBgH7fuWZ0ey0mpuuU7tlVIHddkNICNVVpoFt8PQoPJEyiVk8UqlEq
        XPEBHu7eva01e6CrIbBJLv4hvlMZiUJ26bm5FfQzFnWokueCTazrWBsOlp2Psaps
        DSZ5VRNhED31Ct5dJ68padldONpaforqRdkKs4rjpRImzfzZchrEW0RJAoGBAJB0
        ORHMB0FJvDBsYW9CYk9HrtaW5slhZQ2kEHD37glyoeqbsg286JHSLeMJnRPFg1SB
        n9AjzU2PED1Ko1EiM5V70HWt3ynHcy3560tX4FA+DBj4RfLzwT2ZkLNSU7iSuu0S
        JcrwEwx+6W8jI6o7IGPMN4x6owd/dxgmAWXl/F4zAoGBAMpERCFxDNA8N03TvtwW
        JmhO42U3FIfxnwk/n4E18qvokXKOwjy30gcSlKzuzeniBshM6RAPiBBnYNpS0wfX
        49333VNUmvie3+w4TVMl+i5sNwtj1bXHdNwXDsraIjdlKcJp/48Z4m37IHQA5qVR
        LzJ7wxscW32g+t5TTzuHo8z5
        -----END PRIVATE KEY-----
        """;

    private const string Rsa3072Pkcs8 = """
        -----BEGIN PRIVATE KEY-----
        MIIG/gIBADANBgkqhkiG9w0BAQEFAASCBugwggbkAgEAAoIBgQC6FJiiNltm336g
        8S+tEOUoJ3z6kBAmAAMcTFpMxv9d0VcpIedZJFS9o8SUYl4ry5F43RoPtErKJrLb
        kVqUdnM6zKt866flnpRVez3ivVeVFo0Klrd1h30Pu95Vmr+CCNlnfo78mi/PI+JY
        j/Y6lVDhZiLtzbC7kZcy7JziIQHWx7jr3NvgnK1Yf9pEZ0vbW/yDpULdDQaDhWGQ
        ETN3+a/MH4l7cUALgYKZ5gYStnug2yyfnioeh/evdZOa2tN7NvnseIMXpUkX59Ja
        0ZMYTcBn72lwMzzlObdmvWSIo4gBL+lj+AMW4WbJDgKC+Zfl/3ojwMsKRqGdArtd
        tYPXMFUR4Qx1skGso+2uCo8M1XycCXCu5VAIWuZM3LqeNrrBLVxil9Oz62KpwnAn
        LMkg0svuii48JuStwh5cl6G17tjIJLBwrRsXu0n3vexoTCEzoQiP/AUnMHHq+kHy
        7INM6DATVlTS6FRI+Qx2kjH0u9pR6E5NLFKc4u/twHYN+2kKxmECAwEAAQKCAYAK
        w4w8veY1ojIB/1Ghsjt/QiGBoPm+KPwFFAmZLV2yQJzJHVPznR1lxuZlKveFkwX8
        NtX+GJDG9swb1WGm+t8ZhKNa24rfxneQJkvjJM6/KgnIlgVQwCCk21o2G3h+fiKN
        UQ3WYNjpI4tBUjqNEvwVvcHBfcd+YiKb6IH+tqgTk4QH6MOzT3zbhLHMiSkjLEQE
        HXgrr0g0LXACVGxkwUXBCgX65QcuYzR50IuDY5jtKiB/rzeCgpz6QlPifkwDcZ+T
        /4S8xNZrhF0jtOVGq2Ve7DY0TxvLLQRs4oWrrr85uPNw0tdpXUuadLm4mY2tSfjx
        XDYvUVburJZ4ujPJfFYWB6zqj59tKGSeFzNiSwBMQT/POVHpbtlSg0LD6aqZGLK8
        Gu03T5k6LgksEhTpe2kAENriC5av7NcEvmJq3t19ix1dpO3/5aDgqP2QkMFXnZgl
        C3Z1hUYysoaPb9PpBHHZ4T5sLT+ksb9cSpQeEIi1oF2fws+ui/I2v3I38OFZ1q0C
        gcEA8xJqULdHXlgOIF+hMHmvCmZLtVi75F0Y7xN3EXfze3P8TQS3I/U3mSTcDbnh
        IKgaYJ9FSg2WVlp6r3xR5tkG19gQQI4OxKZM0sF+sCz2U4NopC99IBo4utN9XPBB
        sk3Id8nrOrLUJ5+MTEm1BlsjP7G9siqFKfvkGc8bJUxapJ9XyASuAv96Kvcng+58
        Ql6Mf716R/yZlSmkEHc8hVrV638Lxm6hJLVFyxrWTr3qdyXyNHhQtb076EczN1RK
        RUIDAoHBAMP6NE8pwa8b+oQvBof11ExYFPvLcCtq3FR8LGNbMaESN2LVTFcWQbTr
        XeB3ItOuVb7dwTUlgu9xaOf7cH28sc5pN3tEV9vqVJWbwQzhnRcw37IJai/74hVF
        l0IxCCqsztCxl476QlnwbDAF7KD2Tz5JFJJ2ajeRFilMQzjUK1JG9Mz33Q4BhCYO
        zoLVT4/Ax2HHDQAKEGK7QqgFFqRp11TO9XzdYj8dWUVvXK94LbMdcEdnQ+vmPiM1
        iEyM9456ywKBwQCZOSKLfv0eG6PMBHw3cn1EsPdIeYb3jTgKfNqxyEtTpumEI1TO
        9eT2RKXygRnI3C7EeaHT7Hy4MpDjzhpSyrvlk+2qw+HLVIlY0WBq7ezY+B0eYlEd
        y2m3W1nLHChNnXqhCEef2Nqjn49xB4V1XD38CK7rgKIwtPg0zLjv6hG5dDiBfXGz
        shfwvZvLLqplq/QlEevjNPgbbwRc3MzpwzjWGl/x1gr+eMZmIaS2PkFumhzztmQq
        K/93jGpclmW7AsECgcAvlcwnwKLXyvpcKDL0xlsDIowNy4rz7+GJ3hDFGzqEurCa
        HeKIbs4LiO7ldugM8BK/4oZsSixtyWLImUPqM+wUi3W+R4zxyAc7wHLylsGXBPX7
        +8890XJG6fvdRZyPCCC7ibOcMuXzgq4yRu3683OwUvxcx8XosiDobC0SWmoecz4z
        mqehI/sbZpL8L6E+7Xc8JaHhdZAe+QspUvr5dv2jCRGQfQzC+HRZqL2fmZW3HRnL
        LKbQW7qQwAnVVJEzllsCgcEAp3vrf1ASAMeWUtKeYF47aqbCUgGTmx6UZ+awqGe7
        Iy4WZFqYZVpSHeMYeO+m38PTkAeyaS3DZbMVAl4rCkOZ7qVNMG/XZnXlMsvuwlbp
        vxWfm3QFKfWIYMqJgVDZxzbZk0yCSHxL//ahXBg2ZVEScpqlbtTpaFZUy56sfCib
        MwOVHcXcMTjwG/xDubBLWkMHEod79Z67x6FdSPqFb2TmNnDXTu3SrFs7Q1FIpNb5
        oyqacECCbtZ4fnybEhxpD/OK
        -----END PRIVATE KEY-----
        """;

    private const string Rsa4096Pkcs8 = """
        -----BEGIN PRIVATE KEY-----
        MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDog74oWdgcilVY
        tuqTnrDwBXgBgMiISdb27dGrbS1x1S8f79NvtJhEH9N/+xnXOfNxGcj14OFQHv/g
        /12Hea2QV8Rp5lB6wDRBTCDs/EqSLgYt00XC+YRbe9wBekjwk6GjycB15Q7YnApT
        gbkRj2H6agiZ5fkbyc9V6hqHq+aKHWTJ9UGEywq8tl5kc+9TcFA1JifExW/UGU0S
        IvT9MMON67E5ZpLl63PMxPkcvGYqH8pm3jpN7jMdvfSPaHVhEC8ou5L1fsZEiMI1
        LZeul8mSL5OnxR2SS2kmU3aoM4dE4TOwflsvj+3qqgBKEeNa2CEtZ3sWTAxl0Jno
        8EyRGcmVei/s3vyH9+2UAdVwGYFeGBj8h6w/ia4I9BGJQKiqWWHwZDEgoCM7p4Se
        YJ30zakgiNyt+xLzKGVsrmjNH553XN9eImhSdCR5Oz12PRey6NXxsOKykvzGLPnb
        +xCyDD9hw3yekxF9zI/mTzwQbl3F0KVnups4XLVW78z23NGVGPODVV2OuboO5ZsW
        HNonhaW7+Evqmxzk6NZ7D1xn5j0ugJqdD2K5WFAOpYEKxcRvjXjQLC+6E9pIx/pC
        WGV5UJY24DsJ+/M93wuEFA+RBtDBLGrmzrn9nNWceGz8f+cN1gXRLhP9ZgUWk/n1
        Iem7QQ63c9w/Yj6czRjI+wEiUz3K0wIDAQABAoICAQDTH+zmzs3A/IsKhuzxJcMb
        7ptNIhb0Sbf7d25O7k+5cQ3dPfMLFzy7fvqY1vRbza8TH4quWIe+LKfDMZ1HimDj
        FA6w6gRhsWzBbdLn3R4JJelOauyJYe+g8hKO9O6OJD89bdBoPJkCbo2hzcSyATPC
        Ic21kHBlnxW4uV1lm901xALkruHTJlqViDKlm+/QH8d0uzSZI32rZV3p/fveewzW
        LRE7QbxZMTZw1NouEZPi5ALw7RCb+pJHi1gpb3xFqmBn6ApFB9wYFuXhS4jTa9gH
        +VNln0J+uCK+PkMb783/6Uz6EYHS6inqTnr8xslej6lwhOnrERqgyI04Shn8FyJF
        8R9QvOygifkPi9dlS1N+lDartgX15gt7noDorqT7xx1XU8/78Q4JU1P5+dOSEuGR
        D4d4YdtJ/DIMPS+lyqpgx69uUuf4CKR2P/ZgHmGf7st+Cvl9NWsNcY9tdWnpEPla
        /SsbYMzYGdTPjDwI4BGhJ7qL76gSdKO8npE4tguPWq6+Z2B51fyZWF39Zm59Ogqb
        wsG525AD8gF9QrL4VeQSS29JZO8fSQyM/o+BbQ6k3/90NTMV8Zb142qktDdN3mFx
        k9Lcpb9iVA30i7NUz4XnlJclIUmhv5+LV5ohR1YzwKNxrMiEArVE4lmPpcywXZsE
        hN7oiUMYLKBrNpzxrS6lgQKCAQEA9En2pyv4FNOnH/2SMIhal8c2ahLv4naaP9ex
        yHeloMJI+Der6BWvkH+t/Gv1rMUm2LweB3kqiCOrprmrjSobHR+/6vxb+UL+9vLb
        EWvtzt5QSK1rqZ1iz7RqsXyvTCQLVO3RUaVtZPIXMuqGiPCviHRXwFJ7jC4XWL5m
        NcgyreNnZ8uGMtbFCTv2ZlowNVxXH4q0dBA7WGbwouOYxfQxC+uhjWE/InhGa6nA
        ai/bN2U+qMrlf1ckXRH8kn1sD1IyFUQ0i7QME3mHjqNpwrGV+pzuAz2/CmLGgU9S
        b/1rdul3q5jagBmKgkQLKJsn+Y89SqnDXvgyyveJrJJ8H9P0cQKCAQEA86lHeNqs
        huDBK6tLOCRrsg/MtAWiZ8P6dPwwksDL0I4KOUzukA21hTZWQO4PjSVqr8xHbqwP
        HHrHWTtynFkoQWZIqqb9ck8lwfCb8RIuPTYXUkDFYE/EtMB3EMuUx8VijW/O6Gwu
        P6xcYcVXmPGq6rhnKPOaBHOx6Ji6tiBv1KQKJKyu1FRdGE8hWIdZhB4BYUHwsklk
        BNcQ2ZpD4Iu4k0FDG8FGNSwpBgJPWHcpvWzFyaOXP6yQSGuwEgQx2T9oP4/pe579
        ZmMpVx3stoZIE16Yg/mkP1RZHADEx45ip/jOPwjJiqCb608+akZFl/JqfDFXuIsV
        iVz55PcSONmFgwKCAQAFif/LvpV7c2kgspE0BIN5WY0ETrWdvu60b+GaGAxrXrxk
        1G5TbtpyPlLlnFUPu9CrrWhI5xhtydFEkIUxSDkhKe0iGOLE/h3l34/UD0xvGl9b
        poMAb48kAoVAzQD0iwSuwk2yujuGxG5+Ow8d38c7ItgyhixC+3CQFJEguw9bHgLk
        OZsrX+9LzE5D99uL+jIHhw+cahnOYVcnel2mb2kFSix5ljDmSS/flRPF1Jv135fS
        H/egMYujiJrff3SJzGVSUh+W41g6wNCwDUiCn6A09IX5ENdaFu9FU1UdMPPU2Gpc
        O7UInoujdIOEQjBf2j2bicniR2Jvc7ltbkzeM+IhAoIBAQCHSpXRx/GFzqPTgH/6
        g1Z8/wLVbk93uDyH2kOKKJzChyusF0hbGhGRDtOjp8tgvsbXJ+D91XFqic3IgRap
        M2QDtCxi/Oe7IbFAVz3vA/5CpJccZ7RwPrpk9nzmCXPp3HJVQCCtsuuXFTgSXYW+
        +WjCfXNiLKh3ElpVYQBDAg22DwNGy88jPFiYl89XHYgZsKNpgjiIdfGgMl47xMkt
        k8b/lHwTnCREf+mjWYL/BuNZN103Eat4gnN2kryntEaNbwSOTnUA3A2tXR/mLEp0
        Kmk4wAyFMwb81vPHdbHNcATdaWvzWgi1/Wm1pUFttukLbmGr5aXkZO2nYMWsWXd3
        s2fLAoIBAFr0o6sI5oxv3x0/WRJ+UGEfMctOQeBaAxbUf3AKmrU/ZV+EBXXBSEQs
        dyrxJtlNNopjgbx/SjayuFAawrYOj61nAP59VKOKhz5iwEOerQtxES+lmn32Rh7C
        kL7q/lfVnpLXEkgsdDsy9bfOatZtaNwFtjCxP7655IgfcwB/7iJfhuJf+0JudzzF
        RfKSMUfQWgY1uM9GtLUKYzqnO7o9U82EK0AaAoTkDgkx1uROBRn5xPJDDkd6hP/s
        VBYv39uSrMF2l0fDFNzXtryqDo1V2gQg9/4NnJdec4Tx0/NZ3WHxZLZWdcI8jOQZ
        dhdsLDDv6avPHs2XxNs9FJmJZSzFqOU=
        -----END PRIVATE KEY-----
        """;

    private const string Ed25519Pkcs8 = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIOf6hh3KzsGvOh+iaZlHPw3vyvw+a5298mC6jJxReuTw
        -----END PRIVATE KEY-----
        """;
}
