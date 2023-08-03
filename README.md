# go-inn2-auth

go-inn2-auth is an external authentication server written in Go (Golang) for the INN (InterNetNews) Usenet news server's nnrpd daemon.

It provides user authentication and authorization support based on the provided credentials.


## Features

- Supports multiple authentication modes: "json" (using a JSON file for user data) and others (e.g., MongoDB, MySQL, PostgreSQL, or Redis).
- Allows authentication using plain passwords, bcrypt-hashed passwords, or SHA256-hashed passwords.
- CLI and a (caching) daemon server to handle incoming authentication requests from the nnrpd daemon.


## Installation

To compile go-inn2-auth yourself, you need to have Go (Golang) installed on your system.
If you don't have Go installed, you can download it from the official website: https://golang.org/

1. Clone the repository:
```
git clone https://github.com/go-while/go-inn2-auth
cd go-inn2-auth
```

2. Build the program:
```
go build go-inn2-auth.go
```


# Usage

## Setup readers.conf to use go-inn2-auth

### How to configure go-inn2-auth in conjunction with INN's readers.conf file to enable authentication for Usenet news access?

To integrate go-inn2-auth with INN2 edit (`/etc/news/readers.conf`)

You need to define the authentication method and access restrictions as follows:

1. In the readers.conf file (`/etc/news/readers.conf`), add an `auth` block to specify the authentication method using go-inn2-auth. For example:


```conf
auth "foreignokay" {
    auth: "go-inn2-auth -config /etc/news/config.json"
    default: "<unauthenticated>"
}
```

2. Define access groups in readers.conf. For example:


```conf
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
```

3. Ensure to specify the correct path to your configuration file (`config.json`) in the `auth` block.

With this configuration, go-inn2-auth will be invoked for authentication, and users will be allowed access to different newsgroups based on the access rules defined in readers.conf.

The provided readers.conf configuration assumes that you have set up the access groups and newsgroups according to your desired access policy.

Please adapt the readers.conf configuration according to your specific needs and newsgroup access requirements.


# Running go-inn2-auth Daemon Background Server
go-inn2-auth consists of 2 parts: CLI and SRV (daemon).

The CLI is launched in readers.conf and authenticates against the go-inn2-auth daemon via TCP or SSL.

The SRV daemon holds and caches the user credentials.

To run go-inn2-auth as a daemon server, follow these steps:

Start the daemon server with the -daemon=true flag and specify the configuration file using the -config flag:
```
sudo -u nobody go-inn2-auth -daemon=true -config /etc/news/config.json
```
The daemon server will start listening for incoming requests on the specified TCP or SSL address as configured in the provided config.json file.

The go-inn2-auth daemon will authenticate users based on the credentials provided by the CLI in the readers.conf file.

It will respond to the nnrpd daemon accordingly, allowing or denying access to Usenet news.

The daemon server will handle authentication requests concurrently, with a configurable number of parallel requests defined in the Max_Workers setting in the config.json file.

By running go-inn2-auth as a daemon server, you can enable secure and efficient authentication for Usenet news access while benefiting from the caching mechanism for user credentials.

Make sure to adjust the config.json file with the appropriate settings and authentication methods to suit your specific use case.

For further details on configuration options and features, consult the go-inn2-auth documentation.

Each worker in the daemon may require a dedicated database connection to ensure proper data access and avoid potential issues with database transactions.

## Configuration

The go-inn2-auth daemon requires a configuration file in JSON format to specify various settings and authentication mode.

An example configuration file `config.json` is provided in the repository.
```
mv go-inn2-auth /usr/lib/news/bin/auth/passwd/go-inn2-auth
ln -sfv /usr/lib/news/bin/auth/passwd/go-inn2-auth /usr/bin/go-inn2-auth
chmod +x /usr/lib/news/bin/auth/passwd/go-inn2-auth
mv config.json user.json /etc/news
```

edit config.json:
```
  set userfile: "/etc/news/user.json"
```

If you test from localhost: remove auth/access for localhost from readers.conf and set user.json ClientIP: "::1"
You can enable Debugs in config.json authentication works with Debugs too.

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


# Test
```
tail -f /var/log/messages|grep nnrpd
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


# Contributing

Contributions to go-inn2-auth are welcome!

If you find any bugs or have suggestions for improvements, please open an issue or submit a pull request.


# Code Structure

The provided code is a Go (Golang) program that implements an external authentication server for the nnrpd daemon in INN (InterNetNews), which is a Usenet news server.

This program acts as a part of the readers.conf-based authorization mechanism in INN and is responsible for authenticating users and allowing or denying access to certain resources based on the provided credentials.



# **The code is structured as follows:**


# Import Statements

The import statements in the go-inn2-auth project are essential for including external packages and libraries that provide necessary functionality.

These packages extend the capabilities of the program and allow it to interact with various system components and perform specific tasks efficiently.

## Standard Library Imports

The project includes import statements for the Go (Golang) standard library packages. These standard packages provide fundamental functionality required for common programming tasks and interactions with the operating system. Some of the standard library packages used in go-inn2-auth include:

- `fmt`: The "fmt" package provides functions for formatted I/O operations, such as printing to the console.

- `os`: The "os" package provides a platform-independent interface to operating system functionality, allowing file operations, environment variable access, and command-line argument parsing.

- `flag`: The "flag" package allows the program to parse command-line flags and arguments easily.

- `net`: The "net" package provides networking functions for working with TCP/IP sockets and URLs.

- `crypto`: The "crypto" package provides cryptographic functions, including hashing algorithms and secure random number generation.

- `encoding/json`: The "encoding/json" package facilitates encoding and decoding JSON data, enabling the program to read and write JSON files.

## Third-party Library Imports

In addition to the standard library, the project may include import statements for third-party packages that extend the program's functionality. These packages are typically maintained by the Go community or other developers and are available through the Go package management system.

The specific third-party packages imported in go-inn2-auth may vary based on the project's requirements and the functionalities it aims to implement. Common types of third-party packages that may be imported include:

- Database drivers: Libraries that provide interfaces for connecting to different databases, such as MongoDB, MySQL, PostgreSQL, or Redis.

- Web frameworks: Libraries that facilitate building web servers and handling HTTP requests and responses.

- Cryptography libraries: Packages that offer additional cryptographic algorithms or utilities beyond those provided by the standard "crypto" package.

- Configuration management: Libraries that help manage configuration files and settings.

- Logging and debugging: Packages that enable sophisticated logging and debugging features.


# Constant Definitions

The go-inn2-auth project utilizes various constants to provide meaningful names and values for important parameters and settings used throughout the program.

These constant definitions enhance code readability and maintainability by avoiding the use of magic numbers or strings.

## Authentication Modes

The project defines constants for different authentication modes supported by go-inn2-auth.

These constants represent the available methods for verifying user credentials.

As of the current implementation, the supported authentication modes are:

- `AuthModeJSON`: Represents the "json" authentication mode, where user data is stored in a JSON file.

- Additional authentication mode constants may be defined to support other methods, such as "mongodb," "mysql," "postgresql," or "redis," depending on the project's requirements.

## Hashing Algorithms

To provide flexibility in the choice of hashing algorithms for user passwords, the project defines constants for different hashing methods.

These constants represent the supported hashing algorithms:

- `HashPlain`: Represents plain text password storage, where the password is not hashed.

- `HashBCrypt`: Represents bcrypt hashing, a popular and secure password hashing algorithm.

- `HashSHA256`: Represents SHA256 hashing, another widely used cryptographic hash function.

- Additional hashing algorithm constants may be defined in the future to support other secure hashing methods.

## Other Constants

In addition to authentication modes and hashing algorithms, the project may define other constants used for various purposes. For example:

- `DefaultConfigFile`: Represents the default path to the configuration file used by the go-inn2-auth server if a specific configuration file is not provided as a command-line argument.

- `DefaultMaxWorkers`: Represents the default maximum number of parallel workers used by the daemon server if the Max_Workers setting is not specified in the configuration file.

- `DebugEnabled`: Represents a boolean flag indicating the default state of debug output. If this constant is set to true, debug information will be enabled by default unless explicitly disabled in the configuration file.

- Additional constants may be defined as needed for specific functionalities or behaviors within the program.


# Data Structures for Configuration and User Data

The go-inn2-auth project utilizes several data structures in its implementation to handle configuration settings and user data. These data structures are essential for the proper functioning of the authentication server. This section provides an overview of these data structures and their purposes.

## Configuration Data Structure

The configuration data structure is used to store various settings and options needed by the go-inn2-auth server.

These settings are typically read from a configuration file in JSON format. The data structure defines the following fields:

- `UserFile`: A string representing the path to the JSON file containing user data. This file contains information about the authenticated users, including their usernames and hashed passwords.

- `MaxWorkers`: An integer representing the maximum number of parallel requests that the daemon server can handle concurrently. This setting controls the degree of concurrency for processing authentication requests.

- `Debugs`: A boolean flag indicating whether to enable debug output. When enabled, the server will produce additional debug information to assist in troubleshooting and development.

- Additional fields may be included in the configuration data structure to support other configuration options specific to the project's requirements.

## User Data Structure

The user data structure holds information about individual users who are authorized to access the Usenet news server. It is used by the authentication process to verify the credentials provided by users during the login process. The user data structure includes the following fields:

- `Username`: A string representing the unique username of the user.

- `Password`: A string representing the user's hashed password. The password is hashed using a specific hashing algorithm (e.g., bcrypt or SHA256) for secure storage and comparison during authentication.

- Additional fields, such as user roles or access permissions, may be included in the user data structure based on the project's access control requirements.


# Main function: The main entry point of the program.
```
It reads the configuration from a JSON file specified as a command-line argument.
If the daemon flag is set to true, it starts the external authentication server, otherwise, it reads and processes user input from stdin.
If the daemon flag is set, the program runs as a server, authenticates incoming requests, and responds accordingly.
ReadStdin function: Reads user input from stdin and processes it for authentication when the program is not running as a daemon.
Daemon function: Implements the external authentication server when the program runs as a daemon.
It listens for incoming connections and delegates the authentication process to the AUTH function.
SSL and TCP functions: Implement the server listeners for SSL and TCP connections, respectively.
SSL uses TLS certificates for secure communication. TCP is the non-secure version.
handleRequest function: Handles an incoming client request and processes it.
It parses the request and calls the parseRequest function to authenticate the user.
parseRequest function: Parses the request received from the client and calls the AUTH function to perform authentication.
AUTH function: Performs the actual authentication based on the provided user credentials (username and password).
It checks the user data against the specified authentication mode (e.g., "plain," "bcrypt," or "sha256").
If the authentication is successful, it returns true; otherwise, it returns false.
Other utility functions: These functions handle caching user data, reading user data from JSON files, and computing the SHA256 and BCRYPT hashes.
Please note that some parts of the code have TODO comments, which indicate that these parts are not fully implemented yet and need to be completed to support different authentication modes (e.g., MongoDB, MySQL, PostgreSQL, or Redis).
```
Overall, this code provides a basic implementation of an external authentication server for INN, and you can extend it further to support other authentication backends or improve its functionality as needed.


# Note

This `README.md` file was (mostly) generated by an AI language model called ChatGPT, developed by OpenAI. Don't blame anyone!

The content of this file, including the description, installation instructions, usage examples, and other details, was automatically written by the AI model based on the provided source code of the go-inn2-auth project.

The model has been trained on a diverse range of text from the internet up to its knowledge cutoff date in September 2021.

While the AI model aims to produce accurate and helpful information, it may still have limitations and errors.

Therefore, it is always recommended to review and verify the content for correctness and suitability before using it for any purpose.

For any concerns or questions regarding this `README.md` file, feel free to contact the developers of go-inn2-auth or consult the source code repository for the project.


# DEV to GPT: you see any logical issues in the go code?

As an AI language model, I can analyze the code for potential logical issues or errors based on patterns and common programming practices.

However, my analysis is limited to static code analysis and does not involve dynamic testing or execution of the code.

It is essential to perform thorough testing, including unit testing and integration testing, to identify and fix any logical issues.

That said, based on a static analysis of the go-inn2-auth code, I haven't found any glaring or obvious logical issues.

The code appears to be well-structured and follows standard Go programming conventions.

go-inn2-auth is an external authentication server written in Go (Golang) for the INN (InterNetNews) Usenet news server's nnrpd daemon.

As go-inn2-auth handles user authentication, security is of utmost importance.

Implementing strong cryptographic hashing for passwords (e.g., bcrypt) is essential to protect user credentials from potential breaches.

However, there are some TODO comments, which indicate incomplete parts of the code.

Completing these parts will be crucial to ensure that the authentication process works correctly.

Additionally, I noticed that the code uses plaintext password storage in the "plain" authentication mode.

Storing passwords in plaintext is not recommended from a security perspective.

It's advisable to use strong cryptographic hashing mechanisms (like bcrypt) to protect user credentials.

# Disclaimer

This `README.md` file was automatically generated by an AI language model called ChatGPT, developed by OpenAI.

The content is based on static code analysis and common programming practices up to its knowledge cutoff date in September 2021.

As such, it may not cover all potential issues or security considerations.

For a comprehensive evaluation of the go-inn2-auth codebase, it is advisable to involve experienced developers and security experts to conduct thorough code reviews and security assessments.

For any specific concerns or questions regarding the code, feel free to reach out to the developers of go-inn2-auth or consult the source code repository for the project.


# Upon reviewing the go-inn2-auth code again, here are some additional suggestions for improvement:

1. Input Validation: Ensure that all user inputs and configurations are properly validated and sanitized to prevent potential security vulnerabilities like injection attacks.

2. Configuration Management: Consider using a robust configuration management library to handle the configuration file (config.json). This can simplify the code and make it easier to manage configuration changes.

3. Logging: Implement comprehensive logging throughout the application to capture important events, errors, and debugging information. Logging is valuable for troubleshooting and monitoring the application's behavior.

4. Graceful Shutdown: Add a mechanism for graceful shutdown of the daemon server when a termination signal (e.g., SIGINT or SIGTERM) is received. This ensures that ongoing operations are completed cleanly before the server exits.

5. Performance Optimization: Review the code for potential performance bottlenecks and optimize critical sections to improve the overall efficiency of the daemon server.

6. Limit Access to Configuration Files: Ensure that the configuration files containing sensitive information (e.g., user.json) are properly protected and accessible only by authorized users.

7. Error Reporting: Improve error reporting to provide more detailed and informative error messages, which can assist users in diagnosing and resolving authentication issues.

8. Input Passwords Securely: When reading passwords from users or files, consider using secure methods that prevent password visibility in logs or memory.

9. Strong Encryption: If SSL/TLS is used for secure communication, ensure that strong encryption protocols and cipher suites are utilized.

10. Rate Limiting: Implement rate-limiting mechanisms to prevent brute-force attacks against user credentials.

11. Compatibility: Ensure that the code is compatible with the latest versions of required Go packages and libraries.

12. Documentation: Enhance the inline comments and documentation to provide clear explanations of the code's functionality and usage.

13. Automated Testing: Implement automated testing for various scenarios to verify the correctness of the code under different conditions.

14. Code Refactoring: Consider refactoring the code into smaller, well-encapsulated functions and modules to improve maintainability and readability.

15. Security Audit: Conduct a security audit of the entire application to identify and address potential security vulnerabilities.

16. Cross-platform Compatibility: Test the application on different platforms to ensure cross-platform compatibility.

Keep in mind that the above suggestions aim to enhance the code's security, performance, and maintainability. Each suggestion should be carefully considered and implemented based on the project's specific requirements and constraints. Additionally, leveraging external security tools and conducting regular code reviews can further strengthen the application's security posture.


# License

go-inn2-auth is licensed under the MIT License. See the LICENSE file for details.
[MIT](https://choosealicense.com/licenses/mit/)

# Author
[go-while](https://github.com/go-while)

