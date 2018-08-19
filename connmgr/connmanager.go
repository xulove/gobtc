// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package connmgr

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// maxFailedAttempts is the maximum number of successive failed connection
// attempts after which network failure is assumed and new connections will
// be delayed by the configured retry duration.
const maxFailedAttempts = 25

var (
	//ErrDialNil is used to indicate that Dial cannot be nil in the configuration.
	ErrDialNil = errors.New("Config: Dial cannot be nil")

	// maxRetryDuration is the max duration of time retrying of a persistent
	// connection is allowed to grow to.  This is necessary since the retry
	// logic uses a backoff mechanism which increases the interval base times
	// the number of retries that have been done.
	maxRetryDuration = time.Minute * 5

	// defaultRetryDuration is the default duration of time for retrying
	// persistent connections.
	defaultRetryDuration = time.Second * 5

	// defaultTargetOutbound is the default number of outbound connections to
	// maintain.
	defaultTargetOutbound = uint32(8)
)

// ConnState represents the state of the requested connection.
type ConnState uint8

// ConnState can be either pending, established, disconnected or failed.  When
// a new connection is requested, it is attempted and categorized as
// established or failed depending on the connection result.  An established
// connection which was disconnected is categorized as disconnected.
const (
	ConnPending ConnState = iota
	ConnFailing
	ConnCanceled
	ConnEstablished
	ConnDisconnected
)

// ConnReq is the connection request to a network address. If permanent, the
// connection will be retried on disconnection.
//ConnReq描述了一个连接，它的定义如下:

type ConnReq struct {
	// The following variables must only be used atomically.
	//连接的序号，用于索引
	id uint64
	//连接的目的地址
	Addr      net.Addr
	//标识是否与Peer保持永久连接，如果为true，则连接失败后，
	// 继续尝试与该Peer连接，而不是选择新的Peer地址重新连接;
	Permanent bool
	//连接成功后，真实的net.Conn对象;
	conn       net.Conn
	//连接的状态，有ConnPending、ConnEstablished、ConnDisconnected及ConnFailed等;
	state      ConnState
	//保护state状态的读写锁;
	stateMtx   sync.RWMutex
	//如果Permanent为true，retryCount记录该连接重复重连的次数;
	retryCount uint32
}

// updateState updates the state of the connection request.
func (c *ConnReq) updateState(state ConnState) {
	c.stateMtx.Lock()
	c.state = state
	c.stateMtx.Unlock()
}

// ID returns a unique identifier for the connection request.
func (c *ConnReq) ID() uint64 {
	return atomic.LoadUint64(&c.id)
}

// State is the connection state of the requested connection.
func (c *ConnReq) State() ConnState {
	c.stateMtx.RLock()
	state := c.state
	c.stateMtx.RUnlock()
	return state
}

// String returns a human-readable string for the connection request.
func (c *ConnReq) String() string {
	if c.Addr.String() == "" {
		return fmt.Sprintf("reqid %d", atomic.LoadUint64(&c.id))
	}
	return fmt.Sprintf("%s (reqid %d)", c.Addr, atomic.LoadUint64(&c.id))
}

// Config holds the configuration options related to the connection manager.
type Config struct {
	// Listeners defines a slice of listeners for which the connection
	// manager will take ownership of and accept connections.  When a
	// connection is accepted, the OnAccept handler will be invoked with the
	// connection.  Since the connection manager takes ownership of these
	// listeners, they will be closed when the connection manager is
	// stopped.
	//
	// This field will not have any effect if the OnAccept field is not
	// also specified.  It may be nil if the caller does not wish to listen
	// for incoming connections.
	// 节点上左右等待外部连接的接听点
	Listeners []net.Listener

	// OnAccept is a callback that is fired when an inbound connection is
	// accepted.  It is the caller's responsibility to close the connection.
	// Failure to close the connection will result in the connection manager
	// believing the connection is still active and thus have undesirable
	// side effects such as still counting toward maximum connection limits.
	//
	// This field will not have any effect if the Listeners field is not
	// also specified since there couldn't possibly be any accepted
	// connections in that case.
	// 节点应答并接受外部连接后的回调函数
	OnAccept func(net.Conn)

	// TargetOutbound is the number of outbound network connections to
	// maintain. Defaults to 8.
	// 节点主动向外连接peer的最大个数
	TargetOutbound uint32

	// RetryDuration is the duration to wait before retrying connection
	// requests. Defaults to 5s.
	// 连接失败后发起重连的等待时间，默认为5s，默认的最大重连等待时间为5min;
	RetryDuration time.Duration

	// OnConnection is a callback that is fired when a new outbound
	// connection is established.
	//连接建立成功后的回调函数;
	OnConnection func(*ConnReq, net.Conn)

	// OnDisconnection is a callback that is fired when an outbound
	// connection is disconnected.
	//连接关闭后的回调函数;
	OnDisconnection func(*ConnReq)

	// GetNewAddress is a way to get an address to make a network connection
	// to.  If nil, no new connections will be made automatically.
	//连接失败后，ConnMgr可能会选择新的Peer进行连接
	// GetNewAddress函数提供获取新Peer地址的方法，
	// 它最终会调用addrManager的GetAddress()来分配新地址，我们将在介绍addrmgr时详细介绍;
	GetNewAddress func() (net.Addr, error)

	// Dial connects to the address on the named network. It cannot be nil.
	//定义建立TCP连接的方式，是直连还是通过代理连接;
	Dial func(net.Addr) (net.Conn, error)
}

// registerPending is used to register a pending connection attempt. By
// registering pending connection attempts we allow callers to cancel pending
// connection attempts before their successful or in the case they're not
// longer wanted.
type registerPending struct {
	c    *ConnReq
	done chan struct{}
}

// handleConnected is used to queue a successful connection.
type handleConnected struct {
	c    *ConnReq
	conn net.Conn
}

// handleDisconnected is used to remove a connection.
type handleDisconnected struct {
	id    uint64
	retry bool
}

// handleFailed is used to remove a pending connection.
type handleFailed struct {
	c   *ConnReq
	err error
}

// ConnManager provides a manager to handle network connections.
type ConnManager struct {
	// The following variables must only be used atomically.
	// 记录主动连接其他节点的数量
	connReqCount uint64
	// 标识connMgr已经启动
	start        int32
	// 标识connMgr已经结束
	stop         int32
	// config相关属性可以从config结构体中看
	cfg            Config
	// 用户同步connMgr的退出状态，调用方可以阻塞等待connMgr的工作协成退出。
	wg             sync.WaitGroup
	// 某个连接失败后，ConnMgr尝试选择新的Peer地址连接的总次数
	failedAttempts uint64
	//用于与connmgr工作协程通信的管道;
	requests       chan interface{}
	//用于通知工作协程退出;
	quit           chan struct{}
}

// handleFailedConn handles a connection failed due to a disconnect or any
// other failure. If permanent, it retries the connection after the configured
// retry duration. Otherwise, if required, it makes a new connection request.
// After maxFailedConnectionAttempts new connections will be retried after the
// configured retry duration.
func (cm *ConnManager) handleFailedConn(c *ConnReq) {
	if atomic.LoadInt32(&cm.stop) != 0 {
		return
	}
	if c.Permanent {
		c.retryCount++
		d := time.Duration(c.retryCount) * cm.cfg.RetryDuration
		if d > maxRetryDuration {
			d = maxRetryDuration
		}
		log.Debugf("Retrying connection to %v in %v", c, d)
		time.AfterFunc(d, func() {
			cm.Connect(c)
		})
	} else if cm.cfg.GetNewAddress != nil {
		cm.failedAttempts++
		if cm.failedAttempts >= maxFailedAttempts {
			log.Debugf("Max failed connection attempts reached: [%d] "+
				"-- retrying connection in: %v", maxFailedAttempts,
				cm.cfg.RetryDuration)
			time.AfterFunc(cm.cfg.RetryDuration, func() {
				cm.NewConnReq()
			})
		} else {
			go cm.NewConnReq()
		}
	}
}

// connHandler handles all connection related requests.  It must be run as a
// goroutine.
//
// The connection handler makes sure that we maintain a pool of active outbound
// connections so that we remain connected to the network.  Connection requests
// are processed and mapped by their assigned ids.
func (cm *ConnManager) connHandler() {

	var (
		// pending holds all registered conn requests that have yet to
		// succeed.
		pending = make(map[uint64]*ConnReq)

		// conns represents the set of all actively connected peers.
		conns = make(map[uint64]*ConnReq, cm.cfg.TargetOutbound)
	)

out:
	for {
		select {
		case req := <-cm.requests:
			switch msg := req.(type) {

			case registerPending:
				connReq := msg.c
				connReq.updateState(ConnPending)
				pending[msg.c.id] = connReq
				close(msg.done)

			case handleConnected:
				connReq := msg.c

				if _, ok := pending[connReq.id]; !ok {
					if msg.conn != nil {
						msg.conn.Close()
					}
					log.Debugf("Ignoring connection for "+
						"canceled connreq=%v", connReq)
					continue
				}

				connReq.updateState(ConnEstablished)
				connReq.conn = msg.conn
				conns[connReq.id] = connReq
				log.Debugf("Connected to %v", connReq)
				connReq.retryCount = 0
				cm.failedAttempts = 0

				delete(pending, connReq.id)

				if cm.cfg.OnConnection != nil {
					go cm.cfg.OnConnection(connReq, msg.conn)
				}

			case handleDisconnected:
				connReq, ok := conns[msg.id]
				if !ok {
					connReq, ok = pending[msg.id]
					if !ok {
						log.Errorf("Unknown connid=%d",
							msg.id)
						continue
					}

					// Pending connection was found, remove
					// it from pending map if we should
					// ignore a later, successful
					// connection.
					connReq.updateState(ConnCanceled)
					log.Debugf("Canceling: %v", connReq)
					delete(pending, msg.id)
					continue

				}

				// An existing connection was located, mark as
				// disconnected and execute disconnection
				// callback.
				log.Debugf("Disconnected from %v", connReq)
				delete(conns, msg.id)

				if connReq.conn != nil {
					connReq.conn.Close()
				}

				if cm.cfg.OnDisconnection != nil {
					go cm.cfg.OnDisconnection(connReq)
				}

				// All internal state has been cleaned up, if
				// this connection is being removed, we will
				// make no further attempts with this request.
				if !msg.retry {
					connReq.updateState(ConnDisconnected)
					continue
				}

				// Otherwise, we will attempt a reconnection if
				// we do not have enough peers, or if this is a
				// persistent peer. The connection request is
				// re added to the pending map, so that
				// subsequent processing of connections and
				// failures do not ignore the request.
				if uint32(len(conns)) < cm.cfg.TargetOutbound ||
					connReq.Permanent {

					connReq.updateState(ConnPending)
					log.Debugf("Reconnecting to %v",
						connReq)
					pending[msg.id] = connReq
					cm.handleFailedConn(connReq)
				}

			case handleFailed:
				connReq := msg.c

				if _, ok := pending[connReq.id]; !ok {
					log.Debugf("Ignoring connection for "+
						"canceled conn req: %v", connReq)
					continue
				}

				connReq.updateState(ConnFailing)
				log.Debugf("Failed to connect to %v: %v",
					connReq, msg.err)
				cm.handleFailedConn(connReq)
			}

		case <-cm.quit:
			break out
		}
	}

	cm.wg.Done()
	log.Trace("Connection handler done")
}

// NewConnReq creates a new connection request and connects to the
// corresponding address.
func (cm *ConnManager) NewConnReq() {
	if atomic.LoadInt32(&cm.stop) != 0 {
		return
	}
	if cm.cfg.GetNewAddress == nil {
		return
	}

	c := &ConnReq{}
	atomic.StoreUint64(&c.id, atomic.AddUint64(&cm.connReqCount, 1))

	// Submit a request of a pending connection attempt to the connection
	// manager. By registering the id before the connection is even
	// established, we'll be able to later cancel the connection via the
	// Remove method.
	done := make(chan struct{})
	select {
	case cm.requests <- registerPending{c, done}:
	case <-cm.quit:
		return
	}

	// Wait for the registration to successfully add the pending conn req to
	// the conn manager's internal state.
	select {
	case <-done:
	case <-cm.quit:
		return
	}

	addr, err := cm.cfg.GetNewAddress()
	if err != nil {
		select {
		case cm.requests <- handleFailed{c, err}:
		case <-cm.quit:
		}
		return
	}

	c.Addr = addr

	cm.Connect(c)
}

// Connect assigns an id and dials a connection to the address of the
// connection request.
func (cm *ConnManager) Connect(c *ConnReq) {
	if atomic.LoadInt32(&cm.stop) != 0 {
		return
	}
	if atomic.LoadUint64(&c.id) == 0 {
		atomic.StoreUint64(&c.id, atomic.AddUint64(&cm.connReqCount, 1))

		// Submit a request of a pending connection attempt to the
		// connection manager. By registering the id before the
		// connection is even established, we'll be able to later
		// cancel the connection via the Remove method.
		done := make(chan struct{})
		select {
		case cm.requests <- registerPending{c, done}:
		case <-cm.quit:
			return
		}

		// Wait for the registration to successfully add the pending
		// conn req to the conn manager's internal state.
		select {
		case <-done:
		case <-cm.quit:
			return
		}
	}

	log.Debugf("Attempting to connect to %v", c)

	conn, err := cm.cfg.Dial(c.Addr)
	if err != nil {
		select {
		case cm.requests <- handleFailed{c, err}:
		case <-cm.quit:
		}
		return
	}

	select {
	case cm.requests <- handleConnected{c, conn}:
	case <-cm.quit:
	}
}

// Disconnect disconnects the connection corresponding to the given connection
// id. If permanent, the connection will be retried with an increasing backoff
// duration.
func (cm *ConnManager) Disconnect(id uint64) {
	if atomic.LoadInt32(&cm.stop) != 0 {
		return
	}

	select {
	case cm.requests <- handleDisconnected{id, true}:
	case <-cm.quit:
	}
}

// Remove removes the connection corresponding to the given connection id from
// known connections.
//
// NOTE: This method can also be used to cancel a lingering connection attempt
// that hasn't yet succeeded.
func (cm *ConnManager) Remove(id uint64) {
	if atomic.LoadInt32(&cm.stop) != 0 {
		return
	}

	select {
	case cm.requests <- handleDisconnected{id, false}:
	case <-cm.quit:
	}
}

// listenHandler accepts incoming connections on a given listener.  It must be
// run as a goroutine.
func (cm *ConnManager) listenHandler(listener net.Listener) {
	log.Infof("Server listening on %s", listener.Addr())
	for atomic.LoadInt32(&cm.stop) == 0 {
		conn, err := listener.Accept()
		if err != nil {
			// Only log the error if not forcibly shutting down.
			if atomic.LoadInt32(&cm.stop) == 0 {
				log.Errorf("Can't accept connection: %v", err)
			}
			continue
		}
		go cm.cfg.OnAccept(conn)
	}

	cm.wg.Done()
	log.Tracef("Listener handler done for %s", listener.Addr())
}

// Start launches the connection manager and begins connecting to the network.
func (cm *ConnManager) Start() {
	// Already started?
	// 源自操作是防止并发读写，+1 != 1,说明起初不是0
	if atomic.AddInt32(&cm.start, 1) != 1 {
		return
	}

	log.Trace("Connection manager started")
	cm.wg.Add(1)
	go cm.connHandler()

	// Start all the listeners so long as the caller requested them and
	// provided a callback to be invoked when connections are accepted.
	if cm.cfg.OnAccept != nil {
		for _, listner := range cm.cfg.Listeners {
			cm.wg.Add(1)
			go cm.listenHandler(listner)
		}
	}

	for i := atomic.LoadUint64(&cm.connReqCount); i < uint64(cm.cfg.TargetOutbound); i++ {
		go cm.NewConnReq()
	}
}

// Wait blocks until the connection manager halts gracefully.
func (cm *ConnManager) Wait() {
	cm.wg.Wait()
}

// Stop gracefully shuts down the connection manager.
func (cm *ConnManager) Stop() {
	if atomic.AddInt32(&cm.stop, 1) != 1 {
		log.Warnf("Connection manager already stopped")
		return
	}

	// Stop all the listeners.  There will not be any listeners if
	// listening is disabled.
	for _, listener := range cm.cfg.Listeners {
		// Ignore the error since this is shutdown and there is no way
		// to recover anyways.
		_ = listener.Close()
	}

	close(cm.quit)
	log.Trace("Connection manager stopped")
}

// New returns a new connection manager.
// Use Start to start connecting to the network.
func New(cfg *Config) (*ConnManager, error) {
	if cfg.Dial == nil {
		return nil, ErrDialNil
	}
	// Default to sane values
	if cfg.RetryDuration <= 0 {
		cfg.RetryDuration = defaultRetryDuration
	}
	if cfg.TargetOutbound == 0 {
		cfg.TargetOutbound = defaultTargetOutbound
	}
	cm := ConnManager{
		cfg:      *cfg, // Copy so caller can't mutate
		requests: make(chan interface{}),
		quit:     make(chan struct{}),
	}
	return &cm, nil
}
