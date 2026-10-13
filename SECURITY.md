# Security Policy

## Supported version

Security fixes are intended for the current maintained release line. The source snapshot in this repository is **1.16.0**; verify the latest release before reporting an issue.

## Report a vulnerability privately

Please **do not publish exploit steps, live invitation links, credentials, personal data, or attack details in a public GitHub issue**.

If the repository owner has enabled GitHub's **Private vulnerability reporting**, open the repository's **Security** tab and select **Report a vulnerability**. Otherwise, contact the repository maintainer privately through a verified contact method shown on their official WordPress.org or GitHub profile.

Share a clear description, affected versions, reproduction steps using a disposable site, and impact. Give the maintainer reasonable time to investigate before public disclosure.

## Administrator privilege caveat

A native WordPress Administrator is fully privileged; invitation-specific plugin safeguards cannot sandbox a malicious Administrator. Treat Administrator invitations as granting full site control. For less trusted individuals, choose the least privileged suitable WordPress role.

The CI checks in this repository are syntax and package-structure checks, **not** a security assessment.
