
```
mv go-inn2-auth /usr/lib/news/bin/auth/passwd/go-inn2-auth
ln -sfv /usr/lib/news/bin/auth/passwd/go-inn2-auth /usr/bin/go-inn2-auth
chmod +x /usr/lib/news/bin/auth/passwd/go-inn2-auth
mv config.json user.json /etc/news
```

edit config.json
```
  set userfile: "/etc/news/user.json"
```

run daemon:
```
sudo -u nobody go-inn2-auth -daemon=true -config /etc/news/config.json
```

if you test from localhost: remove auth/access for localhost

and maybe set user.json ClientIP: "::1",

you can enable Debugs in config.json.

authentication works with debugs too.

```
tail -f /var/log/messages|grep nnrpd
```

```
### /etc/news/readers.conf ###

auth "foreignokay" {
    auth: "go-inn2-auth -config /etc/news/config.json"
    default: "<unauthenticated>"
}

access "authenticatedpeople" {
    users: "*"
    newsgroups: "*,!junk,!control,!control.*"
}

access "restrictive" {
    users: "<unauthenticated>"
    newsgroups: "!*"
}
access "readonly" {
    users: "<unauthenticated>"
    read: "local.*"
    post: "!*"
}

### EOF readers.conf
```

```
telnet localhost 119
Trying ::1...
Connected to localhost.
Escape character is '^]'.
200 localhost server INN 2.6.4 ready (transit mode)
> mode reader
200 localhost NNRP server INN 2.6.4 ready (posting ok)
> authinfo user testuser1
381 Enter password
> authinfo pass wrongpass
481 Authentication failed
> quit
205 Bye!
Connection closed by foreign host.

: localhost (::1) connect - port 119
: localhost auth: program error:  ReadStdin
: localhost auth: program error:  ReadStdin: line='ClientHost: localhost'
: localhost auth: program error:  ReadStdin: line='ClientIP: ::1'
: localhost auth: program error:  ReadStdin: line='ClientPort: 35582'
: localhost auth: program error:  ReadStdin: line='LocalIP: ::1'
: localhost auth: program error:  ReadStdin: line='LocalPort: 119'
: localhost auth: program error:  ReadStdin: line='ClientAuthname: testuser1'
: localhost auth: program error:  ReadStdin: line='ClientPassword: wrongpass'
: localhost auth: program error:  CLI lines=7
: localhost auth: program error:  ERROR CLI code=400 err='400 DENIED'
: localhost bad_auth
```


```
> telnet localhost 119
Trying ::1...
Connected to localhost.
Escape character is '^]'.
200 localhost InterNetNews server INN 2.6.4 ready (transit mode)
> authinfo user testuser1
502 Authentication will fail
> mode reader
200 localhost InterNetNews NNRP server INN 2.6.4 ready (posting ok)
> authinfo user testuser1
381 Enter password
> authinfo pass testpass1
281 Authentication succeeded
> quit
205 Bye!

: localhost auth: program error:  ReadStdin
: localhost auth: program error:  ReadStdin: line='ClientHost: localhost'
: localhost auth: program error:  ReadStdin: line='ClientIP: ::1'
: localhost auth: program error:  ReadStdin: line='ClientPort: 34674'
: localhost auth: program error:  ReadStdin: line='LocalIP: ::1'
: localhost auth: program error:  ReadStdin: line='LocalPort: 119'
: localhost auth: program error:  ReadStdin: line='ClientAuthname: testuser1'
: localhost auth: program error:  ReadStdin: line='ClientPassword: testpass1'
: localhost auth: program error:  CLI lines=7
: localhost auth: program error:  CLI code=200 msg=testuser1
: localhost user testuser1
```
