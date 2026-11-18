package rpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"rsbx/internal/proto"
)

type ReverseRunner interface {
	RunLocal(context.Context, *proto.ExecReq, net.Conn) error
}

type ReverseChannel struct {
	conn       net.Conn
	StubSocket string
	ctx        context.Context
	cancel     context.CancelFunc
	writeMu    sync.Mutex
	mu         sync.Mutex
	calls      map[uint32]*reverseStream
	wg         sync.WaitGroup
	once       sync.Once
}

type reverseStream struct {
	conn  net.Conn
	input chan proto.Frame
}

func OpenReverse(ctx context.Context, target Target, runner ReverseRunner) (*ReverseChannel, error) {
	ctx, cancel := context.WithCancel(ctx)
	conn, err := target.DialContext(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err = proto.WriteFrame(conn, proto.THello, nil); err != nil {
		conn.Close()
		cancel()
		return nil, err
	}
	frame, err := proto.ReadFrame(conn)
	if err != nil || frame.Type != proto.TReady || len(frame.Payload) == 0 {
		conn.Close()
		cancel()
		return nil, fmt.Errorf("reverse registration failed: %s (%v)", frame.Payload, err)
	}
	conn.SetDeadline(time.Time{})
	channel := &ReverseChannel{conn: conn, StubSocket: string(frame.Payload), ctx: ctx, cancel: cancel, calls: map[uint32]*reverseStream{}}
	channel.wg.Add(1)
	go channel.serve(runner)
	return channel, nil
}

func (channel *ReverseChannel) send(id uint32, frame proto.Frame) error {
	payload := make([]byte, 5+len(frame.Payload))
	binary.BigEndian.PutUint32(payload, id)
	payload[4] = frame.Type
	copy(payload[5:], frame.Payload)
	channel.writeMu.Lock()
	defer channel.writeMu.Unlock()
	channel.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return proto.WriteFrame(channel.conn, proto.TLocalData, payload)
}

func (channel *ReverseChannel) serve(runner ReverseRunner) {
	defer channel.wg.Done()
	defer channel.cancel()
	defer func() {
		channel.mu.Lock()
		for _, call := range channel.calls {
			call.conn.Close()
		}
		channel.mu.Unlock()
	}()
	for {
		frame, err := proto.ReadFrame(channel.conn)
		if err != nil {
			return
		}
		if len(frame.Payload) < 4 {
			return
		}
		id := binary.BigEndian.Uint32(frame.Payload)
		if id == 0 {
			return
		}
		switch frame.Type {
		case proto.TExecLocal:
			req, err := proto.DecodeExecReq(frame.Payload[4:])
			if err != nil {
				channel.send(id, proto.Frame{Type: proto.TErr, Payload: []byte(err.Error())})
				channel.send(id, proto.Frame{Type: proto.TExit, Payload: proto.ExitPayload(126)})
				continue
			}
			channel.mu.Lock()
			if channel.calls[id] != nil || len(channel.calls) >= 32 {
				channel.mu.Unlock()
				return
			}
			local, peer := net.Pipe()
			call := &reverseStream{conn: peer, input: make(chan proto.Frame, 64)}
			channel.calls[id] = call
			channel.wg.Add(1)
			channel.mu.Unlock()
			go channel.run(id, req, call, local, runner)
		case proto.TLocalData:
			if len(frame.Payload) < 5 {
				return
			}
			channel.mu.Lock()
			call := channel.calls[id]
			channel.mu.Unlock()
			if call == nil {
				continue
			}
			incoming := proto.Frame{Type: frame.Payload[4], Payload: frame.Payload[5:]}
			if len(incoming.Payload) > 64<<10 {
				call.conn.Close()
				continue
			}
			select {
			case call.input <- incoming:
			default:
				call.conn.Close()
			}
		case proto.TLocalCancel:
			channel.mu.Lock()
			call := channel.calls[id]
			channel.mu.Unlock()
			if call != nil {
				call.conn.Close()
			}
		default:
			return
		}
	}
}

func (channel *ReverseChannel) run(id uint32, req *proto.ExecReq, call *reverseStream, local net.Conn, runner ReverseRunner) {
	defer channel.wg.Done()
	defer local.Close()
	defer call.conn.Close()
	defer func() { channel.mu.Lock(); delete(channel.calls, id); channel.mu.Unlock() }()
	done := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			select {
			case <-done:
				return
			case frame := <-call.input:
				if proto.WriteFrame(call.conn, frame.Type, frame.Payload) != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			frame, err := proto.ReadFrame(call.conn)
			if err != nil {
				return
			}
			if channel.send(id, frame) != nil {
				local.Close()
				return
			}
			if frame.Type == proto.TExit {
				return
			}
		}
	}()
	err := runner.RunLocal(channel.ctx, req, local)
	if err != nil {
		proto.WriteFrame(local, proto.TErr, []byte(err.Error()))
		proto.WriteFrame(local, proto.TExit, proto.ExitPayload(126))
	}
	close(done)
	local.Close()
	call.conn.Close()
	workers.Wait()
}

func (channel *ReverseChannel) Close() error {
	channel.once.Do(func() { channel.cancel(); channel.conn.Close(); channel.wg.Wait() })
	return nil
}

func RelayFrames(ctx context.Context, first, second net.Conn) error {
	stop := context.AfterFunc(ctx, func() { first.Close(); second.Close() })
	defer stop()
	results := make(chan error, 2)
	go func() { _, err := io.Copy(first, second); results <- err }()
	go func() { _, err := io.Copy(second, first); results <- err }()
	err := <-results
	first.Close()
	second.Close()
	<-results
	return err
}
