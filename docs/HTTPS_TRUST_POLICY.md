# HTTPS trust for TargetTransport

TargetTransport's anonymous and authenticated session clients now verify HTTPS
certificate chains and hostnames using a run-owned TLS policy. Both clients use
the same verified SSL context. System/default trust roots remain enabled. Every
redirect hop selects its destination's trust profile after scope and gate checks;
changing trust does not grant scope or enable a request capability.

For a supported local interception proxy, export its public CA certificate as a
PEM bundle and set an absolute path in ignored `harness/config.local.yaml`:

```yaml
transport:
  tls:
    ca_bundle: 'C:\certificates\local-proxy-ca.pem'
```

The additional CA is loaded alongside system roots; hostname validation remains
required. A missing, relative, unreadable or malformed bundle fails configuration
without a verification bypass. The run records the exact loaded PEM content's
SHA256 instead of its contents or filesystem path. Restart only an owned run after
changing its trust configuration; existing client pools retain their run's policy.

Disposable isolated TLS fixtures can explicitly declare a literal loopback HTTPS
origin and a reason in local configuration:

```yaml
transport:
  tls:
    fixture_insecure_origins: ['https://127.0.0.1:9443']
    fixture_insecure_reason: 'Disposable synthetic TLS fixture'
```

The shipped list is empty. Only literal loopback IP origins are supported; remote
hosts, localhost names, userinfo, path/query suffixes and non-HTTPS URLs are denied.
An exception applies to precisely that normalized scheme/host/port. Every other
origin keeps certificate and hostname validation. There is no global verify:false
setting. Fixture clients and cookie jars use separate pools, so creating an
insecure fixture client cannot disable verification on the ordinary client.
Synthetic session header credentials still follow existing origin authorization.

First fixture-client creation emits a warning containing only the validated
loopback origin. `RunContext.config.transport_tls_provenance` records the declared
policy, additional CA content hash and explicit fixture origins; evidence events
add the selected destination profile and whether a client profile was applied.
Neither supplied reason text, certificate bytes, filesystem paths nor session
credentials appear in this TLS metadata. Run close releases both ordinary and
fixture client pools.

This change covers client construction through RunContext/TargetTransport and
ManagedSession. Other independent HTTP clients, provider TLS policy and operator
OS certificate-store behavior are separate boundaries. No live target/proxy or
Burp integration validation is claimed here. The tests use client-factory spies,
actual TargetTransport calls with an in-memory TLS adapter, synthetic certificate
chain/hostname controls via SSL MemoryBIO and no-socket guards. The fixture private
key in the test module is public synthetic test data with no production authority.
Smoke/full still require the reconciled loop's permitted execution context.
