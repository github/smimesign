# smimesign (S/MIME Sign) [![Windows Build Status](https://ci.appveyor.com/api/projects/status/hs3o1m9ornnp9d52/branch/master?svg=true)](https://ci.appveyor.com/project/github/smimesign-0bhgj/branch/main) [![macOS Build Status](https://travis-ci.org/github/smimesign.svg?branch=main)](https://travis-ci.org/github/smimesign)

Smimesign is an S/MIME signing utility for macOS and Windows that is compatible with Git. This allows developers to sign their Git commits and tags using X.509 certificates issued by public certificate authorities or their organization's internal certificate authority. Smimesign uses keys and certificates already stored in the _macOS Keychain_ or the _Windows Certificate Store_.

This project is pre-1.0, meaning that APIs and functionality may change without warning.

## Contributing

Different organizations do PKI differently and we weren't able to test everyone's setup. Contributions making this tool work better for your organization are welcome. See the [contributing docs](CONTRIBUTING.md) for more information on how to get involved.

## Git Signing, GnuPG, PKI, and S/MIME

Git allows developers to sign their work using GnuPG. This is a form of public key cryptography whereby the notion of trust is distributed. The party verifying a signature may directly know of the signer's identity and public key, or the signer's identity may be vouched for by a third party known to the verifier. Through layers of "vouching", a web-of-trust is established.

Such a model is well suited to an unstructured environment. In hierarchical environments though, such as a corporation or other large organizations, a simpler approach is for digital identities to be issued and vouched for by a centralized authority. With this approach — known as Public Key Infrastructure, or PKI — an organization's certificate authority (CA) issues signed certificates that identify subjects such as people or computers. Embedded in these certificates is the identity's public key, allowing others who trust the CA to verify that identity's signatures.

PKI is used in a variety of applications for encrypting or authenticating communications. Secure Mime (S/MIME) standardized a protocol for encrypting and signing emails using PKI. While protecting email was the original intent, S/MIME can protect any type of data, including Git commits and tags. Signing Git data with S/MIME provides the same protections as GnuPG while allowing for the more hierarchical trust model of PKI.

## Installation

### macOS

You can install `smimesign` using [Homebrew](https://brew.sh/):

```bash
brew install smimesign
```

You can also download a prebuilt macOS binary [here](https://github.com/github/smimesign/releases/latest). Put the binary on your `$PATH`, so Git will be able to find it.

### Windows

You can install `smimesign` using [`scoop`](https://github.com/lukesampson/scoop):

```batch
scoop install smimesign
```

You can download prebuilt Windows binaries [here](https://github.com/github/smimesign/releases/latest). Put the appropriate binary on your `%PATH%`, so Git will be able to find it.

### Building from source

- Make sure you have the [Go compiler](https://golang.org/dl/) installed.
- You'll probably want to put `$GOPATH/bin` on your `$PATH`.
- Run `go get github.com/github/smimesign`

## Configuring Git

Git needs to be told to sign commits and tags using smimesign instead of GnuPG. This can be configured on a global or per-repository level. The Git configuration directives for changing signing tools was changed in version 2.19.

### Git versions 2.19 and newer

**Configure Git to use smimesign for a single repository:**

```bash
$ cd /path/to/my/repository
$ git config --local gpg.x509.program smimesign
$ git config --local gpg.format x509
```

**Configure Git to use smimesign for all repositories:**

```bash
$ git config --global gpg.x509.program smimesign
$ git config --global gpg.format x509
```

### Git versions 2.18 and older

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

## Smart cards (PIV/CAC/Yubikey)

Many large organizations and government agencies distribute certificates and keys to end users via smart cards. These cards allow applications on the user's computer to use private keys for signing or encryption without giving them the ability to export those keys. The native certificate stores on both Windows and macOS can talk to smart cards, though special drivers or middleware may be required.

If you can find your certificate in the Keychain Access app on macOS or in the Certificate Manager (`certmgr`) on Windows, it will probably work with smimesign. If you can't find it, you may need to install some drivers or middlware.

### Yubikey

Many Yubikey models support the PIV smart card interface. To get your operating system to discover certificates and keys on your Yubikey, you may have to install the [OpenSC middleware](https://github.com/OpenSC/OpenSC/releases/latest). On macOS avoid installing OpenSC using homebrew, as it [omits an important component](https://discourse.brew.sh/t/opensc-formula-is-missing-the-opensc-tokend-component/1683/2). Instead use the installer provided by OpenSC or use the homebrew-cask formula.

Additionally, to manage the manage certificates and keys on the Yubikey on macOS, you'll need the [Yubikey PIV Manager](https://www.yubico.com/support/knowledge-base/categories/articles/smart-card-tools/) (GUI) or the [Yubikey PIV Tool](https://www.yubico.com/support/knowledge-base/categories/articles/smart-card-tools/) (command line).

![Yubikey PIV Keychain in macOS Keychain Access app](https://user-images.githubusercontent.com/248078/45328493-13705300-b511-11e8-97f4-1a04cf35cc6c.png)
