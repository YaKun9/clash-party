# IP purity Beta 4

Four optional/available sources; user-supplied keys enable AbuseIPDB and ipapi.is.
AbuseIPDB uses GET /api/v2/check with a Key header and maxAgeInDays=90; no report/write endpoints.
ipapi.is uses POST JSON {q, key}; credentials are not in URLs.
Providers fail independently; missing sources are not zero-risk sources. Status enums only are cached.

## Experimental scoring v2

Weights: AbuseIPDB 40, Scamalytics 25, proxycheck.io 20, ipapi.is 15.
Normalize by the sum of weights of sources with valid score evidence. Show coverage separately;
it is neither confidence nor accuracy. Only proxy attributes are labelled limited evidence.
Score = round(100 - max(weighted risk, severe-signal risk floor)).

proxycheck.io raw scores are always visible. Proxy-only risk is capped at 25;
VPN at its documented 50 baseline maps to 15; hosting at its 33 baseline maps to 10.
Above those VPN/hosting baselines risk increases continuously up to 100. Tor is at least 60;
compromised is at least 90. Proxy risk 100 alone cannot separate proxy use from abuse;
bounding it is an explicit heuristic, not removal of proven abuse.

ipapi.is has no per-IP fraud score: the client maps is_abuser to 80, Tor 60,
Proxy 25, VPN 15, datacenter 10, taking the highest in that order. An explicit
is_abuser=false can yield zero if no positive attribute exists; unknown data cannot.
Company and ASN abuser_score are NOT included in the formula.

Floors prevent averaging away serious evidence: AbuseIPDB >=75 sets that risk as the
minimum; proxycheck Compromised sets 90; ipapi.is is_abuser sets 60;
Scamalytics >=90 sets 75. These are client policy choices, not vendor guarantees.

## Examples

VPN-only proxycheck raw 50 => score 85 (limited evidence).
Proxy-only raw 100 => score 75 (limited evidence), not zero.
AbuseIPDB 0 plus Proxy-only raw 100 => weighted risk 8.333 => score 92.
AbuseIPDB 95 plus three low sources => score at most 5 due to the evidence floor.

## Cache and credentials

Three-worker concurrency, IP deduplication, explicit refresh and disk persistence remain.
The source fingerprint includes the scoring version and added keys so old scores cannot
be reused under a new policy. Refresh once after upgrading. API keys are in config.yaml
and included in WebDAV backup, not in the cache. The cache is local-only as before.

## Provider documentation

https://docs.abuseipdb.com/#check-endpoint
https://ipapi.is/developers.html
https://proxycheck.io/api/
