package main

import (
	"net"
	"os"
	"time"
)

// stdioConn adapts stdin/stdout to net.Conn for the ssh transport.
type stdioConn struct{}

func (stdioConn) Read(p []byte) (int, error)       { return os.Stdin.Read(p) }
func (stdioConn) Write(p []byte) (int, error)      { return os.Stdout.Write(p) }
func (stdioConn) Close() error                     { return nil }
func (stdioConn) LocalAddr() net.Addr              { return nil }
func (stdioConn) RemoteAddr() net.Addr             { return nil }
func (stdioConn) SetDeadline(time.Time) error      { return nil }
func (stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (stdioConn) SetWriteDeadline(time.Time) error { return nil }
