xmpp-logging-proxy is an XMPP intermediary (aka XMPP MITM) that acts like a server to clients, proxies communication to another XMPP server, and logs everything in plain text, even after STARTTLS negotiation.

Install: `go get github.com/orivej/xmpp-logging-proxy`

Prepare: `openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -subj /`

Run: `xmpp-logging-proxy -key key.pem -cert cert.pem -server target.server:5222`

Configure your client to connect to your server and port instead of the target server.
