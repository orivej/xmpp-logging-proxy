xmpp-logging-proxy is an XMPP intermediary (aka XMPP MITM) that acts like a server to clients, proxies communication to another XMPP server, and logs everything in plain text, even after STARTTLS negotiation.

Install: `go get github.com/orivej/xmpp-logging-proxy`

Given a client with JID `login@server`, XMPP server at `server.host` and proxy at `proxy.host`, you may either:

1. Make client connect to `proxy.host` instead of `server.host` (via client options, `/etc/hosts`, or DNS).  Run proxy as `xmpp-logging-proxy -server target.server:5222`.
2. Make client use JID `login@proxy.host`, and let `xmpp-logging-proxy` replace `proxy.host` with `server` in outgoing traffic and replace `server` with `proxy.host` in incoming traffic.  Run proxy as `xmpp-logging-proxy -server target.server:5222 -replace-local proxy.host -replace-remote server`.  The proxy will log the traffic from the perspective of the server (`proxy.host` will not occur in the log).
