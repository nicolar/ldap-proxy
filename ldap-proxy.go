// ldap-proxy: lighweght proxy for LDAP
// This application act as a TCP proxy between an application and
// a LDAP server, rectifying packets on the fly  (eg. to emulate different
// LDAP servers).
//
// Copyright 2020 Nicola Ruggero
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Globals
const swVer = "1.0"

var verbose bool = false

// rectifier plugins structure
type rectifier struct {
	req, res []byte
	sendback bool
	desc     string
}

func logVerboseln(v ...interface{}) {
	if verbose {
		fmt.Println(v...)
	}
}

func logVerbosef(format string, v ...interface{}) {
	if verbose {
		fmt.Printf(format, v...)
	}
}

func main() {

	// Command line options
	localAddr := flag.String("local", ":3000", "local address")
	remoteAddr := flag.String("remote", ":4000", "remote address")
	verboseFlag := flag.Bool("verbose", false, "Print additional information")
	showSwVer := flag.Bool("version", false, "Print software version and exit")
	flag.Parse()

	// Show Software version
	if *showSwVer {
		fmt.Printf("ldap-proxy: lighweght proxy for LDAP\n")
		fmt.Printf("Version: %s\n", swVer)
		os.Exit(1)
	}

	// Assign globally
	verbose = *verboseFlag

	log.Printf("Starting ldap-proxy: lighweght proxy for LDAP\n")
	log.Printf("Version: %s\n", swVer)

	// Listen for connections
	ln, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatal("Unable to create listener:", err)
	}
	defer ln.Close()
	log.Println("Listening from: ", *localAddr)
	log.Println("Sending to: ", *remoteAddr)

	// Accept new incoming connections
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		// Start a new thread to handle the new incoming connection
		go handleConn(conn, *remoteAddr)
	}
}

// Handle new incoming connections, proxy data to remote server and send
// artificially crafted responses back to the clients when necessary
func handleConn(conn net.Conn, remoteAddr string) {

	log.Println("New connection from: ", conn.RemoteAddr())

	// Connect to remote server to proxy data to
	rconn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Println("Error dialing", err)
		rconn.Close()
		return
	}
	log.Println("Server connection to: ", rconn.RemoteAddr())

	// Start 2 new threads to handle the requests/responses inside the connection
	// we need 2 async threads otherwise an incomplete request/response
	// may block the communication flow from the OSI L7 perspective
	// because of infinite waiting for data from one of the counterparts
	go handleRequest(conn, rconn, "client to proxy", true)  // client to proxy
	go handleRequest(rconn, conn, "server to proxy", false) // server to proxy
}

func handleRequest(conn net.Conn, rconn net.Conn, desc string, useRectifier bool) {
	defer func() {
		if r := recover(); r != nil {
			logVerboseln("Recovering from panic:", r)
			logVerboseln("Stack Trace:")
			if verbose {
				debug.PrintStack()
			}
		}
		log.Println("handleRequest: deferred connection closure: ", desc)
		conn.Close()
		rconn.Close()
	}()

	// From source to proxy
	buf := bufio.NewReader(conn)

	// Loop while communication channel is alive
	for {
		// Read ASN.1 data from source
		start := time.Now()
		log.Println("   ber.PacketRead -> ", desc)
		packet, err := ber.ReadPacket(buf)
		if err != nil {
			log.Println("Error read:", err)
			return
		}
		t := time.Now()
		elapsed := t.Sub(start)
		logVerboseln("   Duration ber.PacketRead -> ", desc, elapsed)

		// Calculate total lenght
		packetLen := len(packet.Bytes())
		log.Printf("Received %d bytes: %s\n", packetLen, desc)
		logVerbosef("%s", hex.Dump(packet.Bytes()[:packetLen]))

		// Calculate lenght of the ASN.1 packet data without headers
		dataLen := packet.Data.Len()
		packetDataOffset := packetLen - dataLen
		logVerbosef("LEN-Data: %d\n", dataLen)
		logVerbosef("%s", hex.Dump(packet.Bytes()[packetDataOffset:packetLen]))

		// Sanity checks on the packet's children
		childrenLen := len(packet.Children)
		logVerbosef("LEN-Children: %d\n", childrenLen)
		if childrenLen == 0 {
			log.Println("Invalid packet: no children found")
			continue
		}
		if packet.Children[0].Tag != ber.TagInteger {
			log.Println("Unrecognized messageID", packet.Children[0].Value)
			continue
		}

		// Calculate lenght of the remaining ASN.1 packet without headers and LDAP messageID
		dataMessageIDLen := len(packet.Children[0].Bytes())
		packetDataNoMsgIDOffset := packetDataOffset + dataMessageIDLen
		messageID := packet.Children[0].Value.(int64)
		logVerbosef("messageID: %d\n", messageID)
		logVerbosef("LEN-messageID: %d\n", dataMessageIDLen)
		logVerbosef("%s", hex.Dump(packet.Bytes()[packetDataNoMsgIDOffset:packetLen]))

		// Prepare outgoing data
		out := make([]byte, 0)
		rectified := false
		sendback := false
		if useRectifier {
			// use rectifier function to rectify data
			log.Println("Rectifier enabled: processing")

			// Create ASN.1 LDAP header (SEQUENCE + messageID)
			// This is necessary to envelope the date after processing
			rectifiedPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
			rectifiedPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "messageID"))

			// Rectify data for *all* children
			for i, child := range packet.Children[1:] {
				d, r, s := rectifyData(child.Bytes())
				// Check if data has been actually rectified
				rectified = rectified || r
				// Check if data need to be sentback and NOT forwarded to destination
				sendback = sendback || s
				log.Printf("Rectifier [%d]: rectified: %t sendback: %t", i, rectified, sendback)
				rectifiedPacket.AppendChild(ber.DecodePacket(d))
			}

			out = append(out, rectifiedPacket.Bytes()[:]...)
		} else {
			// Copy data
			log.Println("Rectifier disabled: copying")
			out = append(out, packet.Bytes()[:]...)
		}

		// Write data to destination
		start = time.Now()
		if rectified && sendback {
			log.Println("   rconn.Write (sendback) -> ", desc)
			_, err = conn.Write(out)
		} else {
			log.Println("   rconn.Write -> ", desc)
			_, err = rconn.Write(out)
		}

		if err != nil {
			log.Println("Error write:", err)
			return
		}
		t = time.Now()
		elapsed = t.Sub(start)
		logVerboseln("   Duration rconn.Write -> ", desc, elapsed)
	}
}

func rectifyData(b []byte) ([]byte, bool, bool) {
	logVerboseln("rectifyData: entering")

	rectified := false
	sendback := false
	rectifiers := initRectifiers()
	for _, singleRectifier := range rectifiers[:] {
		if bytes.Contains(b, singleRectifier.req) {
			b = singleRectifier.res
			rectified = rectified || true
			sendback = sendback || singleRectifier.sendback
			logVerbosef("rectifyData [%s]: rectified\n", singleRectifier.desc)
		} else {
			rectified = rectified || false
			sendback = sendback || false
			logVerbosef("rectifyData [%s]: NOT rectified\n", singleRectifier.desc)
		}
	}
	return b, rectified, sendback
}

// Initialize all rectifiers
func initRectifiers() []rectifier {
	r := make([]rectifier, 0)

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
	return r
}
