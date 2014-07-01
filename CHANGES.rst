httpsig Changes
---------------

1.0b2 (2014-Jul-01)
~~~~~~~~~~~~~~~~~~~
* Written against http://tools.ietf.org/html/draft-cavage-http-signatures-02
* Added "setup.py test" and tox support.
* Added sign/verify unit tests for all currently-supported algorithms.
* HeaderSigner and HeaderVerifier now share the same message-building logic.
* The HTTP method in the message is now properly lower-case.
* Resolved unit test failures.
* Updated Verifier and HeaderVerifier to handle verifying both RSA and HMAC sigs.
* Updated versioneer.
* Updated contact/author info.
* Removed stray keypair in test dir.
* Removed SSH agent support.
* Removed suport for reading keyfiles from disk as this is a huge security hole if this is used in a server framework like drf-httpsig.

1.0b1 (2014-Jun-23)
~~~~~~~~~~~~~~~~~~~~~~
* Removed HTTP version from request-line, per spec (breaks backwards compatability).
* Removed auto-generation of missing Date header (ensures client compatability).


http-signature (previous)
-------------------------

0.2.0 (unreleased)
~~~~~~~~~~~~~~~~~~

* Update to newer spec (incompatible with prior version).
* Handle `request-line` meta-header.
* Allow secret to be a PEM encoded string.
* Add test cases from spec.

0.1.4 (2012-10-03)
~~~~~~~~~~~~~~~~~~

* Account for ssh now being re-merged into paramiko: either package is acceptable (but paramiko should ideally be >= 1.8.0)

0.1.3 (2012-10-02)
~~~~~~~~~~~~~~~~~~

* Stop enabling `allow_agent` by default
* Stop requiring `ssh` package by default -- it is imported only when `allow_agent=True`
* Changed logic around ssh-agent: if one key is available, don't bother with any other authentication method
* Changed logic around key file usage: if decryption fails, prompt for password
* Bug fix: ssh-agent resulted in a nonsensical error if it found no correct keys (thanks, petervolpe)
* Introduce versioneer.py
