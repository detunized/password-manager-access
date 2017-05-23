True Key C# API
===============

**This is unofficial True Key API.**

Notes
-----

The library implements a read-only access to the True Key online password vault.
As with the other libraries from this family the interface is intentionally very
simple. It's just one call to `Vault.Open`. Because of the way things are
implemented in TK the login process cannot be made fully non-interactive. In the
initial login the second factor authentication step seems to be mandatory. This
obviously requires some user interaction. `Vault.Open` takes 4 arguments:
username, password, UI and secure storage.

**UI**

UI interface describes the process of interaction with the user. Depending on
the response from the server and the state the authentication finite state
machine is in there could be up to 3 different requests to the user.

`AskToWaitForEmail`: a verification email has been sent and the user must be
instructed to check his/her inbox and click the confirm link sent by the server.
Once it's done the `Check` answer must be returned by the method. Another valid
answer is `Resend` to tell the server to resend the email.

`AskToWaitForOob`: a second factor push message has been sent to the OOB (out of
bound) device, usually a mobile phone. The user must be instructed to to check
the device with the given name and confirm. Once it's done the `Check` answer is
expected to continue. Other possible answers are `Resend` to resend the push
message and `Email` to send an email instead.

`AskToChooseOob`: the user must be presented with a list of OOB devices to
choose from. The function should return `Device0` + index of the device chosen.
A push message will be send to this device. Alternatively the function could
return `Email` to send an email instead.

`Example.Program.TextUi` provides a simple implementation example.

**Secure storage**

An implementation of `ISecureStorage` interface is used to store a couple of
values between sessions. It's important to reuse these client identification
values issued by the server in order to avoid a new device registration every
time the login is performed. This also bypasses second factor steps on
subsequent logins. Be careful to reuse the stored values or there's a risk that
the list of trusted devices on the server will overflow.

See sample implementation is in `Example.Program.PlainStorage` for reference.


Possible improvements
---------------------

Currently the name of the client is hardcoded in the library It's "truekey-
sharp". It's possible to make it configurable as it shows up in the list of
trusted devices on the user account page. Perhaps it's better to name it after
the product application.

In the current implementation after the login is performed the device is added
to the trusted list on the server. This could be made configurable, in case the
user doesn't want that to happen.

Currently there's no way to break out of the authentication FSM unless an error
happens. It's possible to add another valid answer `Cancel` to stop the process.

License
-------

The library is released under [the MIT
license](http://www.opensource.org/licenses/mit-license.php).
