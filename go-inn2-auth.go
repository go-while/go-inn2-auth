package main

/*
 * https://www.eyrie.org/~eagle/software/inn/docs-2.7/external-auth.html
 *
 * nnrpd External Authentication Support
 * A fundamental part of the readers.conf(5)-based authorization mechanism is the interface
 * to external authenticator and resolver programs. This interface is documented below.
 * INN ships with a number of such programs (all written in C, although any language can be used).
 * Code for them can be found in authprogs/ of the source tree;
 * the authenticators are installed to pathbin/auth/passwd,
 * and the resolvers are installed to pathbin/auth/resolv.
 *
 *
 * 		usage: ./go-inn2-auth -daemon=true
 * 		TEST: echo -en "ClientAuthname: testuser1\r\nClientPassword: testpass1\r\nClientHost: localhost\r\nClientIP: 127.0.0.1\r\nClientPort: 5678\r\nLocalIP: 1.2.3.4\r\nLocalPort: 1234\r\n.\r\n" | ./go-inn2-auth | hexdump -c
 * 	inn2.conf: ????
 *
 */

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/textproto"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

const (
	LIMIT_REQUESTS int   = 16 // parallel requests
	RELOAD_USER    int64 = 60 // reloads user.json
	STDIN_SCAN_MAX int   = 7  // do not change! refers to 'external-auth' lines
)

type CFG struct {
	Settings   SETTINGS
	Json_Auth  JSON_AUTH
	Mysql_Auth MYSQL_AUTH
	Pgsql_Auth PGSQL_AUTH
	Redis_Auth REDIS_AUTH
} // end CFG

type SETTINGS struct {
	Max_Workers   int    `json:"Max_Workers"`
	STDIN_TIMEOUT int64  `json:"STDIN_TIMEOUT"`
	Debug         bool   `json:"Debug"`
	Debug_Daemon  bool   `json:"Debug_Daemon"`
	Debug_CLI     bool   `json:"Debug_CLI"`
	Daemon_Host   string `json:"Daemon_Host"`
	Daemon_TCP    string `json:"Daemon_TCP"`
	Daemon_Socket string `json:"Daemon_Socket"`
	Daemon_Chmod  int    `json:"Daemon_Chmod"`
	Auth_Mode     string `json:"Auth_Mode"`
	Pass_Mode     string `json:"Pass_Mode"`
	USER_Len_Min  int    `json:"USER_Len_Min"`
	PASS_Len_Min  int    `json:"PASS_Len_Min"`
	Logs_File     string `json:"Logs_File"`
} // end SETTINGS

type JSON_AUTH struct {
	User_File string `json:"User_File"`
}

type JSON_USERS struct {
	Users []JSON_USER
}

type JSON_USER struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
	Expire   int64  `json:"Expire"`
	Hostname string `json:"Hostname"`
	ClientIP string `json:"ClientIP"`
}

type MYSQL_AUTH struct {
	Mysql_User string `json:"Mysql_User"`
	Mysql_Pass string `json:"Mysql_Pass"`
	Mysql_Host string `json:"Mysql_Host"`
	Mysql_DB   string `json:"Mysql_DB"`
}

type PGSQL_AUTH struct {
	Pgsql_User string `json:"Pgsql_User"`
	Pgsql_Pass string `json:"Pgsql_Pass"`
	Pgsql_Host string `json:"Pgsql_Host"`
	Pgsql_DB   string `json:"Pgsql_DB"`
}

type REDIS_AUTH struct {
	Redis_User string `json:"Redis_User"`
	Redis_Pass string `json:"Redis_Pass"`
	Redis_Host string `json:"Redis_Host"`
	Redis_DB   string `json:"Redis_DB"`
}

type USER_DATA struct {
	Username string
	Password string
	Expire   int64
	Hostname string
	ClientIP string
}

type AUTH_CACHE struct {
	mux  sync.RWMutex
	data map[string]USER_DATA
	last int64
	hash string // hash of user.json: reloads only on change
}

var (
	auth                AUTH_CACHE
	done_daemons        chan struct{}
	REQUEST_CHAN        chan INN2_STDIN
	STDIN_TIMEOUT       int = 5 // default of inn2
	LIMIT_REQUESTS_CHAN     = make(chan struct{}, LIMIT_REQUESTS)
)

/*
  - LINES:
    ClientAuthname: user\r\n
    ClientPassword: pass\r\n
    ClientHost: hostname\r\n
    ClientIP: IP-address\r\n
    ClientPort: port\r\n
    LocalIP: IP-address\r\n
    LocalPort: port\r\n
    .\r\n
*/
type INN2_STDIN struct {
	ClientAuthname string
	ClientPassword string
	ClientHost     string
	ClientIP       string
	ClientPort     uint16
	LocalIP        string
	LocalPort      uint16
	Retchan        chan string
} // end INN2_STDIN struct

func main() {

	var DEBUG bool
	var DEBUG_DAEMON bool
	var DEBUG_CLI bool
	var boot_daemon bool
	var conf_file string
	var maxworkers int = 1

	/*
		var user_add	string
		var user_del	string
		var user_expi	int64
		var passwd		string
	*/

	flag.StringVar(&conf_file, "config", "config.json", "/path/config.json")
	flag.BoolVar(&boot_daemon, "daemon", false, "[true|false]")

	/*
		flag.StringVar(&passwd, "passwd", "", "username:newpasswd")
		flag.StringVar(&user_add, "useradd", "", "username:password")
		flag.StringVar(&user_del, "userdel", "", "username")
		flag.Int64Var(&user_expi, "expire", 0, "(date +%%s)")
	*/
	flag.Parse()

	cfg := ReadConfig(DEBUG, conf_file)
	if cfg.Settings.Max_Workers > 1 {
		maxworkers = cfg.Settings.Max_Workers
	}
	DEBUG = cfg.Settings.Debug
	DEBUG_CLI = cfg.Settings.Debug_CLI
	DEBUG_DAEMON = cfg.Settings.Debug_Daemon

	var timeout <-chan time.Time
	if !boot_daemon {
		go ReadStdin(DEBUG_CLI, cfg)
		timeout = time.After(time.Duration(cfg.Settings.STDIN_TIMEOUT) * time.Second)
	} else {
		auth.Make_AUTH_CACHE()
		switch cfg.Settings.Auth_Mode {
		case "json":
			auth.Update_Cache(auth.ReadUserJson(DEBUG, cfg))
		case "mongo":
			// TODO: check conn mongo
		case "mysql":
			// TODO: check conn mysql
		case "pgsql":
			// TODO: check conn pgsql
		case "redis":
			// TODO: check conn redis
		default:
			log.Fatal("ERROR main: unknown Auth_Mode")
		} // end switch
		REQUEST_CHAN = make(chan INN2_STDIN, maxworkers)
		done_daemons = make(chan struct{}, maxworkers)
		for wid := 1; wid <= maxworkers; wid++ {
			go Daemon(DEBUG_DAEMON, wid, cfg)
			time.Sleep(time.Second / 1000)
		}
		go TCP(DEBUG_DAEMON, cfg)
	} // end if boot_daemon

	// Setting up signal capturing
	// kill -2 $pid ==> SIGINT
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
forever:
	for {
		select {
		case <-stop:
			log.Printf("OS_SIGINT")
			break forever
		case <-timeout:
			log.Printf("CLI_TIMEOUT")
		}
	}
	os.Exit(1)
} // end func main

func ReadStdin(DEBUG bool, cfg CFG) {
	logf(DEBUG, "ReadStdin")
	rdr := bufio.NewReader(os.Stdin)
	var lines []string
scanner:
	for i := 1; i <= STDIN_SCAN_MAX; i++ {
		switch line, err := rdr.ReadString('\n'); err {
		case io.EOF:
			log.Printf("WARN Stdin io.EOF: read %d lines", i)
			break scanner
		case nil:
			// no error from stdin: clear CRLF
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			if line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			logf(DEBUG, "ReadStdin: line='%s'", line)
			if line == "." {
				logf(DEBUG, "ReadStdin: DOT @ line: %d", i)
				break scanner
			}
			lines = append(lines, line)
		} // end switch
	} // end for scanner

	if len(lines) < STDIN_SCAN_MAX {
		log.Printf("ERROR ReadStdin lines=%d", len(lines))
		os.Exit(1)
	}

	if username := CLI(DEBUG, cfg, lines); username != "" {
		line := fmt.Sprintf("User:%s\r\n", username)
		fmt.Print(line)
		os.Exit(0)
	}
	os.Exit(1)
} // end func ReadStdin

func ReadConfig(DEBUG bool, filename string) CFG {
	logf(DEBUG, "ReadConfig: file='%s'", filename)
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("%v", err)
	}
	var cfg CFG
	err = json.Unmarshal(file, &cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}
	return cfg
} // end func ReadConfig

func (ac *AUTH_CACHE) ReadUserJson(DEBUG bool, cfg CFG) (bool, map[string]USER_DATA, error) {
	ac.mux.RLock()
	if ac.last > UnixTimeSec()-RELOAD_USER {
		ac.mux.RUnlock()
		return DEBUG, nil, nil
	}

	filehash := FILEHASH(cfg.Json_Auth.User_File)
	if ac.hash == filehash {
		//logf(DEBUG, "IGNORE ReadUserJson hash == filehash")
		ac.mux.RUnlock()
		return DEBUG, nil, nil
	}
	ac.mux.RUnlock()

	logf(DEBUG, "ReadUserJson: file='%s'", cfg.Json_Auth.User_File)

	file, err := ioutil.ReadFile(cfg.Json_Auth.User_File)
	if err != nil {
		log.Printf("ERROR ReadUserJson err='%v'", err)
		return DEBUG, nil, err
	}
	var json_users JSON_USERS
	if err := json.Unmarshal(file, &json_users); err != nil {
		log.Printf("ERROR ReadUserJson Unmarshal err='%v'", err)
		return DEBUG, nil, err
	}
	now := UnixTimeSec()
	user_map := make(map[string]USER_DATA)
load_users2map:
	for i, usr := range json_users.Users {
		if usr.Username == "" || usr.Password == "" {
			log.Printf("ERROR JSON empty field i=%d: username|password", i)
			continue load_users2map
		}
		if usr.Expire >= 0 && usr.Expire < now { // set to -1 to never expire user
			since := now - usr.Expire
			log.Printf("EXPIRED user='%s' expi=%d diff=%d", usr.Username, usr.Expire, since)
			continue load_users2map
		}

		logf(DEBUG, "LOAD user='%s' pass='%s' expi=%d hostname='%s' clientip='%s'", usr.Username, usr.Password, usr.Expire, usr.Hostname, usr.ClientIP)

		user_map[usr.Username] = USER_DATA{usr.Username, usr.Password, usr.Expire, usr.Hostname, usr.ClientIP}
	}
	ac.mux.Lock()
	ac.hash = filehash
	ac.mux.Unlock()
	return DEBUG, user_map, nil
} // end func ReadUserJson

func Daemon(DEBUG bool, wid int, cfg CFG) {
	logf(DEBUG, "BOOT: DAEMON %d", wid)
	var reload <-chan time.Time
	timeout := time.Duration(RELOAD_USER)
	if wid == 1 { // only first worker may reload user data
		reload = time.After(timeout * time.Second)
	}
daemon:
	for {
		select {
		case auth_request, ok := <-REQUEST_CHAN:
			if !ok {
				break daemon
			}
			logf(DEBUG, "DAEMON: got auth_request='%v'", auth_request)

			if auth_request.ClientAuthname == "" || len(auth_request.ClientAuthname) < cfg.Settings.USER_Len_Min {
				logf(DEBUG, "ERROR ClientAuthname len=%d", len(auth_request.ClientAuthname))
				auth_request.Retchan <- "" // AUTH: DENIED short username
				continue daemon
			}
			if auth_request.ClientPassword == "" || len(auth_request.ClientPassword) < cfg.Settings.PASS_Len_Min {
				logf(DEBUG, "ERROR ClientPassword len=%d", len(auth_request.ClientPassword))
				auth_request.Retchan <- "" // AUTH: DENIED short password
				continue daemon
			}
			if AUTH(DEBUG, cfg, auth_request) {
				auth_request.Retchan <- auth_request.ClientAuthname // AUTH: OK
				continue daemon
			} // end AUTH
			auth_request.Retchan <- "" // AUTH: DENIED
			continue daemon

		case <-reload:
			switch cfg.Settings.Auth_Mode {
			case "json":
				auth.Update_Cache(auth.ReadUserJson(DEBUG, cfg))
			}
			reload = time.After(timeout * time.Second)
		} // end select
	} // end for daemon

	logf(DEBUG, "Daemon %d done", wid)
	done_daemons <- struct{}{}
} // end func Daemon

func AUTH(DEBUG bool, cfg CFG, auth_request INN2_STDIN) bool {
	/*  auth_request.
	ClientAuthname: testuser\r\n
	ClientPassword: testpass\r\n
	ClientHost: hostname\r\n
	ClientIP: IP-address\r\n
	ClientPort: port\r\n
	LocalIP: IP-address\r\n
	LocalPort: port\r\n
	+++ Retchan bool
	*/
	user_data := auth.Get_Cached_Userdata(auth_request.ClientAuthname)
	if user_data.Username == "" {
		// is not cached
		switch cfg.Settings.Auth_Mode {
		case "json":
			logf(DEBUG, "DENIED json: unknown user='%s' clientip='%s' hostname='%s'", auth_request.ClientAuthname, auth_request.ClientIP, auth_request.ClientHost)
			// user does not exist in user.json, maybe with next reload
			return false
		case "mongo":
			// TODO: get user_data from mongo && auth.Update_Userdata || return false
		case "mysql":
			// TODO: get user_data from myqsl && auth.Update_Userdata || return false
		case "pgsql":
			// TODO: get user_data from pgsql && auth.Update_Userdata || return false
		case "redis":
			// TODO: get user_data from redis && auth.Update_Userdata || return false
		default:
			logf(DEBUG, "ERROR AUTH: unknown Auth_Mode")
			return false
		} // end switch cfg.Settings.Auth_Mode
	}

	now := UnixTimeSec()
	if user_data.Expire >= 0 && user_data.Expire < now {
		// user expired
		logf(DEBUG, "AUTH: EXPIRED user=%s since=%d", user_data.Username, now-user_data.Expire)
		return false
	}

	if user_data.ClientIP != "" && user_data.ClientIP != auth_request.ClientIP {
		// check clientip failed
		logf(DEBUG, "DENIED user='%s' clientip='%s'", user_data.Username, auth_request.ClientIP)
		return false
	}

	if user_data.Hostname != "" && user_data.Hostname != auth_request.ClientHost {
		// check hostname failed
		logf(DEBUG, "DENIED user='%s' hostname='%s'", user_data.Username, auth_request.ClientHost)
		return false
	}

	switch cfg.Settings.Pass_Mode {
	case "plain":
		if user_data.Password == auth_request.ClientPassword {
			return true
		}
	case "bcrypt":
		passwd := BCRYPT(user_data.Password)
		if passwd != "" && passwd == auth_request.ClientPassword {
			return true
		}
	case "sha256":
		passwd := SHA256(user_data.Password)
		if passwd != "" && passwd == auth_request.ClientPassword {
			return true
		}
	} // end switch Auth_Mode

	return false
} // end func AUTH

func TCP(DEBUG bool, cfg CFG) {
	var conn net.Conn
	var err error
	listener_tcp, err := net.Listen(cfg.Settings.Daemon_TCP, cfg.Settings.Daemon_Host)
	if err != nil {
		log.Printf("ERROR TCP err='%v'", err)
		os.Exit(1)
	}
	defer listener_tcp.Close()
	logf(DEBUG, "Listen TCP: %s", cfg.Settings.Daemon_Host)
	var id uint64
listener:
	for {
		if conn, err = listener_tcp.Accept(); err != nil {
			log.Printf("ERROR TCP err='%v'", err)
			break listener
		}
		id++
		go handleRequest(DEBUG, id, conn)
	} // end for listener_tcp.Accept()

	logf(DEBUG, "TCP: closed addr=%s", cfg.Settings.Daemon_Host)
} // end func TCP

func lock_LIMIT_REQUESTS() {
	// will block when channel is full
	LIMIT_REQUESTS_CHAN <- struct{}{}
}

func return_LIMIT_REQUESTS() {
	<-LIMIT_REQUESTS_CHAN
}

func handleRequest(DEBUG bool, id uint64, conn net.Conn) {
	lock_LIMIT_REQUESTS()
	defer return_LIMIT_REQUESTS()
	defer conn.Close()

	logf(DEBUG, "handleRequest id=%d", id)

	tp := textproto.NewConn(conn)
	if lines, err := tp.ReadDotLines(); err != nil {
		logf(DEBUG, "ERROR handleRequest ReadDotLines err='%v'", err)
		return
	} else {
		if username := parse_request(DEBUG, lines); username != "" {
			logf(DEBUG, "handleRequest: 200 %s", username)
			tp.Cmd("200 %s", username)
			return
		}
		logf(DEBUG, "handleRequest: 400 DENIED")
		tp.Cmd("400 DENIED")
	}
} // end func handleRequest

func parse_request(DEBUG bool, lines []string) string {
	logf(DEBUG, "parse_request lines=%d", len(lines))
	var auth_request INN2_STDIN
	e := 0
	for _, line := range lines {
		l := strings.Split(line, " ")
		if len(l) != 2 {
			e++
			if e > 3 {
				break
			}
			continue
		}
		k, v := l[0], l[1]

		switch k {
		case "ClientAuthname:":
			auth_request.ClientAuthname = v
		case "ClientPassword:":
			auth_request.ClientPassword = v
		case "ClientHost:":
			auth_request.ClientHost = v
		case "ClientIP:":
			auth_request.ClientIP = v
		}
	} // end for lines
	auth_request.Retchan = make(chan string, 1)
	// send the received auth_request from TCP to REQUEST_CHAN
	REQUEST_CHAN <- auth_request
	username := <-auth_request.Retchan
	logf(DEBUG, "parse_request: Retchan got username='%s'", username)
	return username
} // end func parse_request

func CLI(DEBUG bool, cfg CFG, lines []string) string {
	var conn net.Conn
	var err error
	if conn, err = net.Dial(cfg.Settings.Daemon_TCP, cfg.Settings.Daemon_Host); err != nil {
		log.Printf("ERROR CLI Dial err='%v'", err)
		return ""
	}
	logf(DEBUG, "CLI lines=%d", len(lines))
	srvtp := textproto.NewConn(conn)
	dw := srvtp.DotWriter()
	buf := bufio.NewWriter(dw)
	for _, line := range lines {
		buf.WriteString(line + "\r\n")
	}
	buf.Flush()
	err = dw.Close()
	if err != nil {
		return ""
	}
	if code, username, err := srvtp.ReadCodeLine(200); err == nil {
		logf(DEBUG, "CLI code=%d msg=%s", code, username) // AUTH OK
		return username
	} else {
		logf(DEBUG, "ERROR CLI code=%d err='%v'", code, err) // AUTH FAIL
	}
	return ""
} // end func CLI

func (ac *AUTH_CACHE) Make_AUTH_CACHE() {
	ac.mux.Lock()
	if ac.data == nil {
		ac.data = make(map[string]USER_DATA)
	}
	ac.mux.Unlock()
} // auth.Make_AUTH_CACHE

func (ac *AUTH_CACHE) Update_Cache(DEBUG bool, newmap map[string]USER_DATA, err error) bool {
	if err != nil {
		log.Printf("ERROR Update_Cache caller err='%v'", err)
		return false
	}
	if newmap == nil {
		//logf(DEBUG, "IGNORE Update_Cache newmap=nil")
		return false
	}
	now := UnixTimeSec()
	ac.mux.Lock()
	if ac.last > now-RELOAD_USER {
		logf(DEBUG, "IGNORE Update_Cache not allowed")
		ac.mux.Unlock()
		return false
	}
	log.Printf("Update_Cache OK")
	ac.last, ac.data = now, newmap
	ac.mux.Unlock()
	return true
} // end func auth.Update_Cache

func (ac *AUTH_CACHE) Update_Userdata(username string, user_data USER_DATA) {
	ac.mux.Lock()
	ac.data[username] = user_data
	ac.mux.Unlock()
} // end func auth.Update_Cache

func (ac *AUTH_CACHE) Get_Cached_Userdata(user string) USER_DATA {
	var retval USER_DATA
	ac.mux.RLock()
	if ac.data != nil {
		retval = ac.data[user]
	}
	ac.mux.RUnlock()
	return retval
} // end func auth.Get_Cached_Userdata

func SHA256(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
} // end func SHA256

func BCRYPT(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		log.Printf("ERROR BCRYPT err='%v'", err)
		return ""
	}
	return string(bytes)
} // end func BCRYPT

func FILEHASH(file_path string) string {
	file, err := os.Open(file_path)
	if err != nil {
		return ""
	}
	defer file.Close()   // Be sure to close your file!
	hash := sha256.New() // Use the Hash in crypto/sha256
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	sum := fmt.Sprintf("%x", hash.Sum(nil)) // Get encoded hash sum
	return sum
} // end func FILEHASH

func UnixTimeSec() int64 {
	return time.Now().UnixNano() / 1e9
} // end func UnixTimeSec

func logf(DEBUG bool, format string, a ...any) {
	if DEBUG {
		log.Printf(format, a...)
	}
} // end logf
