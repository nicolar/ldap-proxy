# ldap-proxy
This application act as a TCP proxy between an application and
a LDAP server, rectifying packets on the fly  (eg. to emulate different
LDAP servers).

## Usage

```
Usage of ./ldap-proxy:
  -local string
        local address (default ":3000")
  -remote string
        remote address (default ":4000")
  -verbose
        Print additional information
  -version
        Print software version and exit
```

## Working logic
ldap-proxy listen to a local address/port for incoming LDAP requests.
For each request it checks through many 'rectifiers' if data should be
'rectified' and sent to destination or send back to client.

Rectification *may* happen also from LDAP server to Client, if desired (see func handleRequest(conn net.Conn, rconn net.Conn, desc string, useRectifier bool))

## No data rectified
> Client ---> ldap-proxy (no modification) ---> LDAP Server

This is the standard behaviour, data is proxied 1:1 to the LDAP server

## Data rectified but NOT sendback
> Client ---> ldap-proxy (data modified) ---> LDAP Server

Data is modified on-the-fly by rectifier functions and sent to the LDAP Server

## Data rectified WITH sendback
> Client ----> ldap-proxy (data modified) ----> Client

Data is modified on-the-fly by rectifier functions and sent back to the Client, actually emulating and answer from the LDAP server

## Customization
Rectifier functions are (currently) hardcoded in initRectifiers() function

```go
	// Rectifier prova
	r = append(r, rectifier{
		req: []byte{
			0x63, 0x33, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x03, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, /* c3.............. */
			0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, /* .....objectClass */
			0x30, 0x13, 0x04, 0x11, 0x73, 0x75, 0x62, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x53, 0x75, 0x62, /* 0...subschemaSub */
			0x65, 0x6e, 0x74, 0x72, 0x79,
		},
		res: []byte{
			0x64, 0x26, 0x04, 0x00, 0x30, 0x22, 0x30, 0x20, 0x04, 0x11, 0x73, 0x75, 0x62, 0x73, 0x63, 0x68, /* d&..0"0 ..subsch */
			0x65, 0x6d, 0x61, 0x53, 0x75, 0x62, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x31, 0x0b, 0x04, 0x09, 0x63, /* emaSubentry1...c */
			0x6e, 0x3d, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, /* n=schema */
		},
		sendback: true, desc: "prova"})
```
you can append as many rectifiers as you want to the slice.

## Roadmap
* Change rectifier logic so that you can specify a totally custom function instead of the existing 'bytes.Contains(b, singleRectifier.req)'
* Transform rectifiers functions to be real plugins for ldap-proxy
