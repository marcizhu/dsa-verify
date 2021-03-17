# Security Policy

## Table of Contents

1. [Supported Versions](#versions)
2. [Reporting a Vulnerability](#reporting)
3. [Disclosure Policy](#disclosure-policy)
4. [Security Measures](#security-measures)
5. [Comments on this policy](#comments)


<a name="versions"></a>
## Supported Versions

This library might be used in critical scenarios where reliability and security might be the first priority. Thus, even
though this library is considered feature-complete, periodic updates with bug and/or security fixes will be published.
Consequently, some versions might get deprecated and thus be considered as "not supported". Please refer to the following
table before reporting a vulnerability.

| Version | Supported          |
| ------- | :----------------: |
| master  | :white_check_mark: |

<a name="reporting"></a>
## Reporting a Vulnerability

This project takes all security reports seriously and is committed to providing prompt attention to security issues.
We appreciate your efforts and responsible disclosure and will make every effort to acknowledge your contributions.
Security issues should be privately reported to marcizhu@gmail.com and **NEVER** discussed openly. **DO
NOT CREATE AN ISSUE TO REPORT A VULNERABILITY**.


<a name="disclosure-policy"></a>
## Disclosure Policy

When we receive a security bug report, we will assign it to a primary handler. This person will coordinate the fix and
release process, involving the following steps:

- Confirm the problem and determine the affected versions.
- Audit code to find any potential similar problems.
- Prepare fixes for all releases still under maintenance. These fixes will be released as fast as possible to GitHub Releases.


<a name="security-measures"></a>
## Security measures

Several security measures are taken in order to prevent new vulnerabilities from being added to existent code. The
following sections will briefly discuss said measures.


### Secure accounts with access

The my personal account requires 2FA authorization. All of my commits MUST be signed with
a GPG key (GPG Key ID: `2D8FA5B173E88095`). All contributors will be required to sign their
commits with a GPG key.


### Critical Updates And Security Notices

Critical and Security updates will be posted on a file on this repo and kept up-to-date with
information about the issue, remediation and fixes. The GitHub Release Notes for each version
will also contain details about bugfixes, security fixes and similar information.


### Close scrutiny of proposed changes

Pull Requests will be subject to close scrutiny by all members of the project, requiring explicit
aproval of changes from all members. This measure is designed to prevent the accidental (or
intentional) injection of vulnerabilities to the existing codebase.


<a name="comments"></a>
## Comments on this policy

If you have suggestions on how this policy could be improved please submit a pull request.
