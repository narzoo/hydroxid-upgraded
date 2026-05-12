# hydroxide

A third-party, open-source ProtonMail bridge. For power users only, designed to
run on a server.

hydroxide supports CardDAV, IMAP and SMTP.

Rationale:

* No GUI, only a CLI (so it runs in headless environments)
* Standard-compliant (we don't care about Microsoft Outlook)
* Fully open-source

Feel free to join the IRC channel: #emersion on Libera Chat.

## How does it work?

hydroxide is a server that translates standard protocols (SMTP, IMAP, CardDAV)
into ProtonMail API requests. It allows you to use your preferred e-mail clients
and `git-send-email` with ProtonMail.

    +-----------------+             +-------------+  ProtonMail  +--------------+
    |                 | IMAP, SMTP  |             |     API      |              |
    |  E-mail client  <------------->  hydroxide  <-------------->  ProtonMail  |
    |                 |             |             |              |              |
    +-----------------+             +-------------+              +--------------+

## Setup

### Go

hydroxide is implemented in Go. Head to [Go website](https://golang.org) for
setup information.

### Installing

Start by installing hydroxide:

```shell
git clone https://github.com/emersion/hydroxide.git
go build ./cmd/hydroxide
```

Then you'll need to login to ProtonMail via hydroxide, so that hydroxide can
retrieve e-mails from ProtonMail. You can do so with this command:

```shell
hydroxide auth <username>
```

If Proton asks for human verification (error code `9001`), the local auth flow
now switches into a manual browser-assisted mode:

1. Hydroxide prints a `https://verify.proton.me/...` URL.
2. Open your browser developer tools and paste the listener snippet that
   Hydroxide prints.
3. Solve the challenge in your browser.
4. Paste the solved token back into the CLI prompt.

This keeps the login flow headless-friendly while still letting you complete
Proton's verification challenge in your own browser session.

Once you're logged in, a "bridge password" will be printed. Don't close your
terminal yet, as this password is not stored anywhere by hydroxide and will be
needed when configuring your e-mail client.

Your ProtonMail credentials are stored on disk encrypted with this bridge
password (a 32-byte random password generated when logging in).

### Moving a valid auth session between machines

If you can authenticate on one machine but want the server to avoid automatic
full password re-authentication later, you can move the cached auth state:

```shell
hydroxide auth-export <username> exported-auth.json
hydroxide auth-import <username> exported-auth.json
```

By default, `auth-export` strips the cached login password but keeps the
mailbox password required to unlock Proton keys. The imported state is saved in
`refresh-only` mode, which means Hydroxide will continue to use refresh tokens
but will not automatically attempt a fresh password login when the refresh
token becomes invalid.

If you explicitly want an imported state to retain automatic password re-auth,
use:

```shell
hydroxide auth-import -allow-password-reauth <username> exported-auth.json
```

To verify a cached auth state without starting IMAP/SMTP:

```shell
hydroxide auth-verify <username>
```

## Usage

hydroxide can be used in multiple modes.

> Don't start hydroxide multiple times, instead you can use `hydroxide serve`.
> This requires ports 1025 (smtp), 1143 (imap), and 8080 (carddav).

### SMTP

To run hydroxide as an SMTP server:

```shell
hydroxide smtp
```

Once the bridge is started, you can configure your e-mail client with the
following settings:

* Hostname: `localhost`
* Port: 1025
* Security: none
* Username: your ProtonMail username
* Password: the bridge password (not your ProtonMail password)

### CardDAV

You must setup an HTTPS reverse proxy to forward requests to `hydroxide`.

```shell
hydroxide carddav
```

Tested on GNOME (Evolution) and Android (DAVDroid).

### IMAP

⚠️  **Warning**: IMAP support is work-in-progress. Here be dragons.

For now, it only supports unencrypted local connections.

```shell
hydroxide imap
```

## License

MIT
