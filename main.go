package main

import (
    "os"
    "log"
    "fmt"
    "bytes"
    "flag"
    "net"
    "io"
    "errors"
    "runtime"
)
var (
    users = make(map[string]bool)
    nconns int
)

const (
    socksVersion = uint8(5)
    authVersion = uint8(1)

	NoAuth          = uint8(0)
	noAcceptable    = uint8(255)
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

type Request struct {
    Cmd uint8
    DSTAddr string
    DSTPort int
}

func reply(r io.Writer, data ...byte) {
    _,err := r.Write(data)
    if err != nil {
        panic(err)
    }
}

func read(r io.Reader, n uint8) []byte {
    buf := make([]byte, n)
    _,err := io.ReadFull(r, buf)
    if err != nil {
        panic(err)
    }
    return buf
}

func readRequest(r io.Reader)(*Request) {
    req := Request{}
    header := read(r, 4)
    req.Cmd = header[1]
    atype := header[3]

    switch atype {
    case ipv4Address:
        ip := read(r, 4)
        req.DSTAddr = fmt.Sprintf("%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3])
    case fqdnAddress:
        n := read(r,1)[0]
        name := read(r, n)
        req.DSTAddr = string(name)
    default:
        log.Println("Unsupport address type:", atype)
        return nil
    }
    port := read(r,2)
    req.DSTPort = (int(port[0]) << 8) | int(port[1])
    return &req
}

func Auth(conn io.ReadWriter) bool {
    version := read(conn, 1)[0]
    if version != authVersion {
        log.Println("Unsupport auth version",version)
        reply(conn, version, authFailure)
        return false
    }

    ulen := read(conn, 1)[0]
    uname := read(conn, ulen)

    plen := read(conn, 1)[0]
    passwd := read(conn, plen)

    token := fmt.Sprintf("%s:%s",uname,passwd)
    succ := users[token]
    if succ {
        reply(conn, version, authSuccess)
    } else {
        reply(conn, version, authFailure)
    }
    return succ
}

func proxy(dst io.Writer, src io.Reader, c chan int) {
    io.Copy(dst,src)
    c<-1
}

func Serve(conn net.Conn) {
    defer func () {
        nconns--
        log.Printf("Disconnect from %s, number of conns:%d\n",conn.RemoteAddr(), nconns)
        conn.Close()
    }()
    defer func () {
        if err := recover(); err != nil {
            if _,ok := err.(runtime.Error);ok {
                panic(err)
            }
            log.Println(err)
        }
    }()

    data := read(conn,2)
    version := data[0]
    if version != 5 {
        log.Println("Unsupported SOCKS version: ", version)
        return
    }

    nmethods := data[1]
    methods := read(conn, nmethods)

    authType := NoAuth
    if len(users) != 0 {
        authType = UserPassAuth
    }
    if bytes.IndexByte(methods, authType) == -1 {
        reply(conn,socksVersion, noAcceptable)
        return
    }

    reply(conn, socksVersion, authType)

    if authType == UserPassAuth {
        succ := Auth(conn)
        if !succ {
            return
        }
    }

    req := readRequest(conn)
    if req == nil {
        reply(conn,socksVersion, addrTypeNotSupported)
        return
    }

    switch req.Cmd {
    case ConnectCommand:
        dst_conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", req.DSTAddr, req.DSTPort))
        if err != nil {
            reply(conn, socksVersion, hostUnreachable)
            log.Println("connect to dst failed: ", err)
            return
        }
        defer dst_conn.Close()
        reply(conn, socksVersion, successReply,0, ipv4Address, 0,0,0,0, 0,0)

        c := make(chan int, 2)
        go proxy(dst_conn, conn, c)
        go proxy(conn, dst_conn, c)

        for i := 0; i < 2; i++ {
            <-c
        }
    default:
        log.Println("Unsupport command:", req.Cmd)
        reply(conn,socksVersion, commandNotSupported)
    }

}

type arrayFlags struct{}

func (_ *arrayFlags) String() string {
    return "dummy array flag"
}

func (_ *arrayFlags) Set(v string) error {
    if users[v] {
        return errors.New("Duplicate <username:passwd>")
    }
    users[v] = true
    return nil
}

func main() {
    flag.Usage = func () {
        fmt.Printf("Usage:\n\t-l <host:port> [ -a <username:passwd> ]...\nFlags:\n")
        flag.PrintDefaults()
    }
    flag.Var(&arrayFlags{}, "a", "add auth <username:passwd>")
    addr := flag.String("l", "", "listen: <host:port>")
    flag.Parse()

    if *addr == "" {
        flag.Usage()
        return
    }

    l, err := net.Listen("tcp", *addr)
    if err != nil {
        fmt.Fprintln(os.Stderr, err);
        return
    }

    log.Println("Listen on:", *addr);

    for {
        conn, err := l.Accept()
        if err != nil {
            log.Fatal(err)
        }
        nconns++
        log.Printf("Accept conn from %s, number of conns: %d\n", conn.RemoteAddr(),nconns)
        go Serve(conn)
    }
}
