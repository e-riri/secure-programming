# Secure File Manager: Design and Threat Model

## 1. Project Overview

This project is a small command-line file manager developed for the TalTech Secure Programming course.

The application will provide basic file management operations for files and directories inside a configured managed directory. Planned operations include listing files, reading files, creating files and directories, copying files, moving files, and deleting files.

Security is a primary design requirement. The application must prevent users from accessing files outside the managed directory, bypassing authentication, or causing unintended file operations through malicious input or filesystem behavior.

The application will be implemented in C17 for Linux/POSIX systems. It will use standard POSIX filesystem APIs and OpenSSL where cryptographic functionality is required.

The application will run as a normal unprivileged user and will not require root or setuid privileges.

## 2. System Architecture

The application will consist of four main components:

1. **CLI and Input Validation**: receives commands and user input, checks input format and length, and passes valid requests to the appropriate component.

2. **Authentication and Password Handling**: handles the login process and password verification. Protected file operations will only be available after successful authentication.

3. **File Manager**: performs file operations such as listing, reading, creating, copying, moving, and deleting files. It will validate and canonicalize file paths before performing operations.

4. **POSIX Filesystem**: provides the underlying file and directory operations through Linux/POSIX APIs.

The application will use a configured managed directory as the boundary for normal file operations. The application must not allow user-supplied paths to access files outside this directory.

## 3. Architecture Diagram

```

                         USER
                           |
                           | commands / password
                           v
                +----------------------+
                | CLI & Input          |
                | Validation            |
                +----------+-----------+
                           |
                           v
                +----------------------+
                | Authentication       |
                | & Password Handling  |
                +----------+-----------+
                           |
                    authenticated
                           |
                           v
                +----------------------+
                | File Manager         |
                |                      |
                | Path validation      |
                | Path canonicalization|
                | File operations      |
                +----------+-----------+
                           |
                           | POSIX APIs
                           v
              ===========================
                 TRUST BOUNDARY
              ===========================
                           |
                           v
                +----------------------+
                | Linux Filesystem     |
                |                      |
                | Managed directory    |
                | Files & directories  |
                +----------------------+

                Password / credential
                         data
                          |
                          v
                +----------------------+
                | Protected credential |
                | storage              |
                +----------------------+ 
                ```
The main trust boundary is between the application and the underlying filesystem. User-controlled paths and filesystem objects must not be trusted automatically, even when they appear to be inside the managed directory.

Password or credential data is treated as a separate protected asset and must not be exposed through normal application output or logs.

## 4. Assets

The main assets are:

- User files and directories inside the managed directory
- Authentication credentials and cryptographic secrets
- File contents and filesystem metadata
- Application integrity

## 5. Threat Model

The following threats were identified during the design phase. Each threat includes its intended mitigation.

### File Handling

1. **Directory traversal:** A user may provide a path such as `../file` to access files outside the managed directory.
   **Mitigation:** Canonicalize paths and verify that the resolved path remains inside the configured managed directory.

2. **Symlink attack**: A symbolic link inside the managed directory may point to a file outside it.
   **Mitigation:** Restrict or reject symbolic links where appropriate and validate the resolved path before sensitive operations.

3. **TOCTOU race condition:** A filesystem object may be changed between a security check and the actual operation.
   **Mitigation:** Minimize the check-to-use gap and use atomic filesystem operations where possible.

4. **Unintended file replacement or truncation:** An operation may overwrite or truncate an existing file unintentionally.
   **Mitigation:** Avoid truncating existing files unless explicitly requested and use `O_CREAT | O_EXCL` when appropriate for new files.

### Authentication

5. **Authentication bypass:**  A user may attempt to perform protected file operations without logging in successfully.
   **Mitigation:** Require successful authentication before protected operations and deny access by default.

### Password and Key Handling

6. **Insecure password storage:** A plaintext password could be stored or exposed through logs.
   **Mitigation:** Never store or log plaintext passwords. Use protected password-verification data.

7. **Key or secret exposure:**  Cryptographic keys or other secrets could be exposed through source code, the repository, or unnecessary storage.
   **Mitigation:** Keep secrets out of source code and Git commits, protect their storage, and minimize their lifetime in memory.

### Other Security Concerns

8. **Malicious input**: Unexpectedly long or malformed input could cause memory corruption or unexpected behavior.
    **Mitigation:** Validate input format and length and use bounded memory operations.

## 6. Implementation Language and Libraries

The application will be implemented in C17 for Linux/POSIX systems. C is appropriate because the project focuses on secure memory handling, input validation, filesystem operations, permissions, and race conditions.

The project will use:

- GCC: C compiler
- GDB: debugger
- Make: build automation
- POSIX APIs: filesystem operations
- OpenSSL: cryptographic functionality where required

Unnecessary third-party dependencies will be avoided.

## 7. Project Scope and Planned CLI

The project will implement a small command-line file manager focused on secure file operations within a configured managed directory.

Planned commands are:

```text
login
list
read <file>
copy <source> <destination>
move <source> <destination>
delete <file>
create <file>
mkdir <directory>
logout
help
```

The application will not provide system-wide file management or require administrative privileges. File operations will be restricted to the configured managed directory.

Not all planned commands need to be fully implemented during the first checkpoint. The initial checkpoint focuses on the architecture, threat model, security requirements, and project design.
