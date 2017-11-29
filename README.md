# smimesign (S/MIME Sign)

Smimesign is an S/MIME signing utility that is compatible with Git. This allows developers to sign their Git commits and tags using X.509 certificates issued by pubic certificate authorities or their organization's internal certificate authority. Smimesign uses keys and certificates already stored in the *macOS Keychain* or the *Windows Certificate Store*.

## Git Signing, GnuPG, PKI, and S/MIME

Git allows developers to sign their work using GnuPG. This is a form of public key cryptography whereby the notion of trust is distributed. The party verifying a signature may directly know of the signer's identity and public key, or the signer's identity may be vouched for by a third party known to the verifier. Through layers of "vouching", a web-of-trust is established.

Such a model is well suited to an unstructured environment. In hierarchical environments though, such as a corporation or other large organizations, a simpler approach is for digital identities to be issued and vouched for by a centralized authority. With this approach — known as Public Key Infrastructure, or PKI — an organization's certificate authority (CA) issues signed certificates that identify subjects such as people or computers. Embedded in these certificates is the identity's public key, allowing others who trust the CA to verify that identity's signatures.

PKI is used in a variety of applications for encrypting or authenticating communications. Secure Mime (S/MIME) standardized a protocol for encrypting and signing emails using PKI. While protecting email was the original intent, S/MIME can protect any type of data, including Git commits and tags. Signing Git data with S/MIME  provides the same protections as GnuPG while allowing for the more hierarchical trust model of PKI.

## Installation

...

## Configuring Git

Git needs to be told to sign commits and tags using smimesign instead of GnuPG. This can be configured on a global or per-repository level.

**Configure Git to use smimesign for a single repository:**

```bash
$ cd /path/to/my/repository
$ git config --local gpg.program smimesign
```

**Configure Git to use smimesign for all repositories:**

```bash
$ git config --global gpg.program smimesign
```

## Configuring smimesign

No configuration is needed to use smimesign. However, you must already have a certificate and private key in order to make signatures. Furthermore, to sign Git commits or tags, it is best to have a certificate that includes your Git email address.

**Find your Git email address:**

```bash
$ git config --get user.email
```

**List available signing identities**

```bash
$ smimesign --list-keys
```
