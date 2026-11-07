#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define AUTH_FILE ".file-manager.auth"
#define MANAGED_DIR "managed"
#define MAX_LINE 4096
#define MAX_ARGS 4
#define PASSWORD_SIZE 256
#define SALT_SIZE 16
#define KEY_SIZE 32
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define HEADER_SIZE (4 + SALT_SIZE + NONCE_SIZE + TAG_SIZE)
#define PBKDF2_ITERATIONS 310000
#define IO_SIZE 32768

static int managed_fd = -1;
static bool authenticated;
static char session_password[PASSWORD_SIZE];

static int read_all(int fd, unsigned char *buffer, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = read(fd, buffer + offset, size - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            errno = count == 0 ? EINVAL : errno;
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int write_all(int fd, const unsigned char *buffer, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = write(fd, buffer + offset, size - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int derive_key(const char *password, const unsigned char *salt,
                      unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, SALT_SIZE,
                             PBKDF2_ITERATIONS, EVP_sha256(), KEY_SIZE, key);
}

static int read_secret(const char *prompt, char *secret, size_t capacity) {
    struct termios original;
    struct termios hidden;
    size_t used = 0;
    int result = -1;

    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &original) != 0) {
        fprintf(stderr, "A terminal is required to enter a password.\n");
        return -1;
    }
    hidden = original;
    hidden.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
        return -1;
    }

    fprintf(stderr, "%s", prompt);
    while (used + 1 < capacity) {
        unsigned char character;
        ssize_t count = read(STDIN_FILENO, &character, 1);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count != 1) {
            goto done;
        }
        if (character == '\n' || character == '\r') {
            result = 0;
            break;
        }
        if (character == 127 || character == 8) {
            if (used > 0) {
                --used;
            }
            continue;
        }
        if (character < 32 || character == 127) {
            continue;
        }
        secret[used++] = (char)character;
    }

done:
    secret[used] = '\0';
    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
    fputc('\n', stderr);
    if (result != 0) {
        OPENSSL_cleanse(secret, capacity);
    }
    return result;
}

static int auth_file_exists(void) {
    struct stat status;
    if (lstat(AUTH_FILE, &status) == 0) {
        return 1;
    }
    return errno == ENOENT ? 0 : -1;
}

static int save_credentials(const char *password) {
    unsigned char record[4 + SALT_SIZE + KEY_SIZE];
    int fd;
    memcpy(record, "SFA1", 4);
    if (RAND_bytes(record + 4, SALT_SIZE) != 1 ||
        derive_key(password, record + 4, record + 4 + SALT_SIZE) != 1) {
        OPENSSL_cleanse(record, sizeof(record));
        return -1;
    }
    fd = open(AUTH_FILE, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
              S_IRUSR | S_IWUSR);
    if (fd < 0) {
        OPENSSL_cleanse(record, sizeof(record));
        return -1;
    }
    if (write_all(fd, record, sizeof(record)) != 0 || fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        int saved_errno = errno;
        close(fd);
        (void)unlink(AUTH_FILE);
        OPENSSL_cleanse(record, sizeof(record));
        errno = saved_errno;
        return -1;
    }
    OPENSSL_cleanse(record, sizeof(record));
    if (close(fd) != 0) {
        (void)unlink(AUTH_FILE);
        return -1;
    }
    return 0;
}

static int verify_credentials(const char *password) {
    unsigned char record[4 + SALT_SIZE + KEY_SIZE];
    unsigned char candidate[KEY_SIZE];
    struct stat status;
    int fd = open(AUTH_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int valid = 0;
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != geteuid() || (status.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
        read_all(fd, record, sizeof(record)) != 0) {
        goto done;
    }
    unsigned char extra;
    ssize_t extra_count = read(fd, &extra, 1);
    if (extra_count != 0 || memcmp(record, "SFA1", 4) != 0 ||
        derive_key(password, record + 4, candidate) != 1) {
        goto done;
    }
    valid = CRYPTO_memcmp(candidate, record + 4 + SALT_SIZE, KEY_SIZE) == 0;

done:
    OPENSSL_cleanse(record, sizeof(record));
    OPENSSL_cleanse(candidate, sizeof(candidate));
    close(fd);
    return valid;
}

static int setup_account(void) {
    char first[PASSWORD_SIZE] = {0};
    char second[PASSWORD_SIZE] = {0};
    int exists = auth_file_exists();
    int result = -1;

    if (exists != 0) {
        fprintf(stderr, exists > 0 ? "An account is already configured.\n"
                                   : "Cannot inspect the account file.\n");
        return -1;
    }
    if (read_secret("New password (at least 8 characters): ", first, sizeof(first)) != 0 ||
        read_secret("Confirm password: ", second, sizeof(second)) != 0) {
        goto done;
    }
    if (strlen(first) < 8) {
        fprintf(stderr, "Password must be at least 8 characters.\n");
        goto done;
    }
    if (strcmp(first, second) != 0) {
        fprintf(stderr, "Passwords do not match.\n");
        goto done;
    }
    if (save_credentials(first) != 0) {
        perror("Creating account");
        goto done;
    }
    puts("Account created. Run 'login' to continue.");
    result = 0;

done:
    OPENSSL_cleanse(first, sizeof(first));
    OPENSSL_cleanse(second, sizeof(second));
    return result;
}

static int login(void) {
    char password[PASSWORD_SIZE] = {0};
    int result;
    if (authenticated) {
        puts("Already logged in.");
        return 0;
    }
    if (auth_file_exists() != 1) {
        fprintf(stderr, "No account found. Run 'setup' first.\n");
        return -1;
    }
    if (read_secret("Password: ", password, sizeof(password)) != 0) {
        OPENSSL_cleanse(password, sizeof(password));
        return -1;
    }
    result = verify_credentials(password);
    if (result == 1) {
        memcpy(session_password, password, sizeof(session_password));
        authenticated = true;
        puts("Login successful.");
    } else if (result == 0) {
        fprintf(stderr, "Incorrect password.\n");
    } else {
        perror("Checking credentials");
    }
    OPENSSL_cleanse(password, sizeof(password));
    return result == 1 ? 0 : -1;
}

static bool valid_component(const char *start, size_t length) {
    if (length == 0 || length > NAME_MAX ||
        (length == 1 && start[0] == '.') ||
        (length == 2 && start[0] == '.' && start[1] == '.')) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        unsigned char value = (unsigned char)start[index];
        if (value < 32 || value == 127 || value == '\\') {
            return false;
        }
    }
    return true;
}

static int open_parent(const char *path, char leaf[NAME_MAX + 1]) {
    char copy[PATH_MAX];
    size_t length = strlen(path);
    int current;
    char *component;
    char *slash;

    if (length == 0 || length >= sizeof(copy) || path[0] == '/' ||
        path[length - 1] == '/') {
        errno = EINVAL;
        return -1;
    }
    memcpy(copy, path, length + 1);
    current = dup(managed_fd);
    if (current < 0) {
        return -1;
    }
    component = copy;
    while ((slash = strchr(component, '/')) != NULL) {
        size_t component_length = (size_t)(slash - component);
        if (!valid_component(component, component_length)) {
            close(current);
            errno = EINVAL;
            return -1;
        }
        *slash = '\0';
        int next = openat(current, component,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            close(current);
            return -1;
        }
        close(current);
        current = next;
        component = slash + 1;
    }
    size_t leaf_length = strlen(component);
    if (!valid_component(component, leaf_length)) {
        close(current);
        errno = EINVAL;
        return -1;
    }
    memcpy(leaf, component, leaf_length + 1);
    return current;
}

static int open_directory(const char *path) {
    char copy[PATH_MAX];
    size_t length;
    int current;
    char *component;
    char *slash;

    if (path == NULL || path[0] == '\0') {
        return dup(managed_fd);
    }
    length = strlen(path);
    if (length >= sizeof(copy) || path[0] == '/' || path[length - 1] == '/') {
        errno = EINVAL;
        return -1;
    }
    memcpy(copy, path, length + 1);
    current = dup(managed_fd);
    if (current < 0) {
        return -1;
    }
    component = copy;
    for (;;) {
        slash = strchr(component, '/');
        size_t component_length = slash == NULL ? strlen(component)
                                                 : (size_t)(slash - component);
        if (!valid_component(component, component_length)) {
            close(current);
            errno = EINVAL;
            return -1;
        }
        if (slash != NULL) {
            *slash = '\0';
        }
        int next = openat(current, component,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            close(current);
            return -1;
        }
        close(current);
        current = next;
        if (slash == NULL) {
            return current;
        }
        component = slash + 1;
    }
}

static int open_regular(const char *path) {
    char leaf[NAME_MAX + 1];
    struct stat status;
    int parent = open_parent(path, leaf);
    int fd;
    if (parent < 0) {
        return -1;
    }
    fd = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    close(parent);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)) {
        int saved_errno = errno == 0 ? EINVAL : errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int create_temp(int parent, char name[32]) {
    static const char digits[] = "0123456789abcdef";
    unsigned char random[8];
    for (int attempt = 0; attempt < 8; ++attempt) {
        if (RAND_bytes(random, sizeof(random)) != 1) {
            errno = EIO;
            return -1;
        }
        memcpy(name, ".sfm-", 5);
        for (size_t index = 0; index < sizeof(random); ++index) {
            name[5 + index * 2] = digits[random[index] >> 4];
            name[6 + index * 2] = digits[random[index] & 15];
        }
        name[21] = '\0';
        int fd = openat(parent, name,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        S_IRUSR | S_IWUSR);
        if (fd >= 0 || errno != EEXIST) {
            OPENSSL_cleanse(random, sizeof(random));
            return fd;
        }
    }
    OPENSSL_cleanse(random, sizeof(random));
    errno = EEXIST;
    return -1;
}

static int publish_temp(int parent, const char *temporary, const char *destination) {
    if (linkat(parent, temporary, parent, destination, 0) != 0) {
        return -1;
    }
    if (unlinkat(parent, temporary, 0) != 0) {
        return -1;
    }
    return 0;
}

static int transform_file(const char *source, const char *destination, bool encrypt) {
    unsigned char header[HEADER_SIZE] = {0};
    unsigned char key[KEY_SIZE] = {0};
    unsigned char input[IO_SIZE];
    unsigned char output[IO_SIZE + EVP_MAX_BLOCK_LENGTH];
    char leaf[NAME_MAX + 1];
    char temporary[32] = {0};
    EVP_CIPHER_CTX *context = NULL;
    int source_fd = -1;
    int parent_fd = -1;
    int output_fd = -1;
    int output_length;
    int result = -1;
    bool temporary_exists = false;

    source_fd = open_regular(source);
    if (source_fd < 0) {
        perror("Opening source");
        goto done;
    }
    parent_fd = open_parent(destination, leaf);
    if (parent_fd < 0) {
        perror("Validating destination");
        goto done;
    }
    output_fd = create_temp(parent_fd, temporary);
    if (output_fd < 0) {
        perror("Creating temporary output");
        goto done;
    }
    temporary_exists = true;
    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        fprintf(stderr, "Unable to allocate cipher context.\n");
        goto done;
    }

    if (encrypt) {
        memcpy(header, "SFM1", 4);
        if (RAND_bytes(header + 4, SALT_SIZE + NONCE_SIZE) != 1 ||
            derive_key(session_password, header + 4, key) != 1 ||
            EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) != 1 ||
            EVP_EncryptInit_ex(context, NULL, NULL, key, header + 4 + SALT_SIZE) != 1 ||
            write_all(output_fd, header, 4 + SALT_SIZE + NONCE_SIZE) != 0) {
            fprintf(stderr, "Unable to initialize encryption.\n");
            goto done;
        }
        for (;;) {
            ssize_t count = read(source_fd, input, sizeof(input));
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count < 0) {
                perror("Reading source");
                goto done;
            }
            if (count == 0) {
                break;
            }
            if (EVP_EncryptUpdate(context, output, &output_length, input, (int)count) != 1 ||
                write_all(output_fd, output, (size_t)output_length) != 0) {
                fprintf(stderr, "Unable to encrypt file.\n");
                goto done;
            }
        }
        if (EVP_EncryptFinal_ex(context, output, &output_length) != 1 ||
            write_all(output_fd, output, (size_t)output_length) != 0 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                                header + 4 + SALT_SIZE + NONCE_SIZE) != 1 ||
            pwrite(output_fd, header + 4 + SALT_SIZE + NONCE_SIZE, TAG_SIZE,
                   4 + SALT_SIZE + NONCE_SIZE) != TAG_SIZE) {
            fprintf(stderr, "Unable to finish encryption.\n");
            goto done;
        }
    } else {
        if (read_all(source_fd, header, sizeof(header)) != 0 ||
            memcmp(header, "SFM1", 4) != 0 ||
            derive_key(session_password, header + 4, key) != 1 ||
            EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) != 1 ||
            EVP_DecryptInit_ex(context, NULL, NULL, key, header + 4 + SALT_SIZE) != 1) {
            fprintf(stderr, "Invalid encrypted file or cipher initialization failed.\n");
            goto done;
        }
        for (;;) {
            ssize_t count = read(source_fd, input, sizeof(input));
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count < 0) {
                perror("Reading encrypted source");
                goto done;
            }
            if (count == 0) {
                break;
            }
            if (EVP_DecryptUpdate(context, output, &output_length, input, (int)count) != 1 ||
                write_all(output_fd, output, (size_t)output_length) != 0) {
                fprintf(stderr, "Unable to decrypt file.\n");
                goto done;
            }
        }
        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                                header + 4 + SALT_SIZE + NONCE_SIZE) != 1 ||
            EVP_DecryptFinal_ex(context, output, &output_length) != 1 ||
            write_all(output_fd, output, (size_t)output_length) != 0) {
            fprintf(stderr, "Authentication failed; no plaintext was published.\n");
            goto done;
        }
    }

    if (fsync(output_fd) != 0 || close(output_fd) != 0) {
        output_fd = -1;
        perror("Flushing output");
        goto done;
    }
    output_fd = -1;
    if (publish_temp(parent_fd, temporary, leaf) != 0) {
        perror("Publishing output (destination must not already exist)");
        goto done;
    }
    temporary_exists = false;
    printf("%s complete: %s\n", encrypt ? "Encryption" : "Decryption", destination);
    result = 0;

done:
    if (output_fd >= 0) {
        close(output_fd);
    }
    if (temporary_exists && parent_fd >= 0) {
        (void)unlinkat(parent_fd, temporary, 0);
    }
    if (source_fd >= 0) {
        close(source_fd);
    }
    if (parent_fd >= 0) {
        close(parent_fd);
    }
    EVP_CIPHER_CTX_free(context);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(input, sizeof(input));
    OPENSSL_cleanse(output, sizeof(output));
    OPENSSL_cleanse(header, sizeof(header));
    return result;
}

static int list_directory(const char *path) {
    int fd = open_directory(path);
    DIR *directory;
    struct dirent *entry;
    if (fd < 0) {
        perror("Opening directory");
        return -1;
    }
    directory = fdopendir(fd);
    if (directory == NULL) {
        perror("Reading directory");
        close(fd);
        return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        struct stat status;
        char type = '?';
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (fstatat(dirfd(directory), entry->d_name, &status, AT_SYMLINK_NOFOLLOW) == 0) {
            type = S_ISDIR(status.st_mode) ? 'd' : S_ISREG(status.st_mode) ? '-' : '?';
        }
        printf("%c %s\n", type, entry->d_name);
        errno = 0;
    }
    int result = errno == 0 ? 0 : -1;
    if (result != 0) {
        perror("Reading directory");
    }
    closedir(directory);
    return result;
}

static int read_file(const char *path) {
    unsigned char buffer[IO_SIZE];
    int fd = open_regular(path);
    if (fd < 0) {
        perror("Opening file");
        return -1;
    }
    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0 || (count > 0 && write_all(STDOUT_FILENO, buffer, (size_t)count) != 0)) {
            perror("Reading file");
            close(fd);
            return -1;
        }
        if (count == 0) {
            break;
        }
    }
    close(fd);
    return 0;
}

static int create_file(const char *path) {
    char leaf[NAME_MAX + 1];
    int parent = open_parent(path, leaf);
    if (parent < 0) {
        perror("Validating path");
        return -1;
    }
    int fd = openat(parent, leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("Creating file (existing files are not overwritten)");
        close(parent);
        return -1;
    }
    close(fd);
    close(parent);
    printf("Created: %s\n", path);
    return 0;
}

static int make_directory(const char *path) {
    char leaf[NAME_MAX + 1];
    int parent = open_parent(path, leaf);
    if (parent < 0) {
        perror("Validating path");
        return -1;
    }
    int result = mkdirat(parent, leaf, S_IRWXU);
    if (result != 0) {
        perror("Creating directory");
    } else {
        printf("Created directory: %s\n", path);
    }
    close(parent);
    return result;
}

static int delete_file(const char *path) {
    char leaf[NAME_MAX + 1];
    struct stat status;
    int parent = open_parent(path, leaf);
    if (parent < 0) {
        perror("Validating path");
        return -1;
    }
    if (fstatat(parent, leaf, &status, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(status.st_mode)) {
        if (errno == 0) {
            errno = EINVAL;
        }
        perror("Deleting file (only regular files are supported)");
        close(parent);
        return -1;
    }
    int result = unlinkat(parent, leaf, 0);
    if (result != 0) {
        perror("Deleting file");
    } else {
        printf("Deleted: %s\n", path);
    }
    close(parent);
    return result;
}

static int parse_line(char *line, char *arguments[MAX_ARGS]) {
    char *read_position = line;
    char *write_position = line;
    int count = 0;
    while (*read_position != '\0') {
        bool quoted = false;
        while (*read_position == ' ' || *read_position == '\t') {
            ++read_position;
        }
        if (*read_position == '\0' || *read_position == '\n') {
            break;
        }
        if (count == MAX_ARGS) {
            return -1;
        }
        arguments[count++] = write_position;
        while (*read_position != '\0' && *read_position != '\n') {
            if (*read_position == '"') {
                quoted = !quoted;
                ++read_position;
            } else if (!quoted && (*read_position == ' ' || *read_position == '\t')) {
                break;
            } else {
                *write_position++ = *read_position++;
            }
        }
        if (quoted) {
            return -1;
        }
        if (*read_position == ' ' || *read_position == '\t') {
            ++read_position;
        }
        *write_position++ = '\0';
    }
    return count;
}

static void print_help(void) {
    puts("Commands:");
    puts("  setup                         create the local account");
    puts("  login                         authenticate");
    puts("  logout                        clear the current session");
    puts("  list [directory]              list managed files");
    puts("  read <file>                   print a file");
    puts("  create <file>                 create an empty file");
    puts("  mkdir <directory>             create a directory");
    puts("  delete <file>                 delete a regular file");
    puts("  encrypt <source> <destination> encrypt to a new file");
    puts("  decrypt <source> <destination> authenticate and decrypt to a new file");
    puts("  help                          show this help");
    puts("  exit                          quit");
    puts("Paths are relative to ./managed; quote paths containing spaces.");
}

static int command_loop(void) {
    char line[MAX_LINE];
    char *arguments[MAX_ARGS];
    puts("Secure File Manager. Type 'help' for commands.");
    for (;;) {
        fputs(authenticated ? "file-manager> " : "locked> ", stdout);
        fflush(stdout);
        if (fgets(line, sizeof(line), stdin) == NULL) {
            break;
        }
        size_t length = strlen(line);
        if (length > 0 && line[length - 1] != '\n' && !feof(stdin)) {
            int character;
            while ((character = getchar()) != '\n' && character != EOF) {
            }
            fprintf(stderr, "Input line is too long.\n");
            continue;
        }
        int count = parse_line(line, arguments);
        if (count < 0) {
            fprintf(stderr, "Invalid command line (too many arguments or unmatched quote).\n");
            continue;
        }
        if (count == 0) {
            continue;
        }
        if (strcmp(arguments[0], "help") == 0 && count == 1) {
            print_help();
        } else if (strcmp(arguments[0], "exit") == 0 && count == 1) {
            break;
        } else if (strcmp(arguments[0], "setup") == 0 && count == 1) {
            (void)setup_account();
        } else if (strcmp(arguments[0], "login") == 0 && count == 1) {
            (void)login();
        } else if (strcmp(arguments[0], "logout") == 0 && count == 1) {
            OPENSSL_cleanse(session_password, sizeof(session_password));
            authenticated = false;
            puts("Logged out.");
        } else if (!authenticated) {
            fprintf(stderr, "Log in before using file commands.\n");
        } else if (strcmp(arguments[0], "list") == 0 && count <= 2) {
            (void)list_directory(count == 2 ? arguments[1] : NULL);
        } else if (strcmp(arguments[0], "read") == 0 && count == 2) {
            (void)read_file(arguments[1]);
        } else if (strcmp(arguments[0], "create") == 0 && count == 2) {
            (void)create_file(arguments[1]);
        } else if (strcmp(arguments[0], "mkdir") == 0 && count == 2) {
            (void)make_directory(arguments[1]);
        } else if (strcmp(arguments[0], "delete") == 0 && count == 2) {
            (void)delete_file(arguments[1]);
        } else if (strcmp(arguments[0], "encrypt") == 0 && count == 3) {
            (void)transform_file(arguments[1], arguments[2], true);
        } else if (strcmp(arguments[0], "decrypt") == 0 && count == 3) {
            (void)transform_file(arguments[1], arguments[2], false);
        } else {
            fprintf(stderr, "Unknown command or invalid arguments. Type 'help'.\n");
        }
    }
    OPENSSL_cleanse(session_password, sizeof(session_password));
    authenticated = false;
    return 0;
}

int main(void) {
    if (mkdir(MANAGED_DIR, S_IRWXU) != 0 && errno != EEXIST) {
        perror("Creating managed directory");
        return EXIT_FAILURE;
    }
    managed_fd = open(MANAGED_DIR,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (managed_fd < 0) {
        perror("Opening managed directory");
        return EXIT_FAILURE;
    }
    if (fchmod(managed_fd, S_IRWXU) != 0) {
        perror("Protecting managed directory");
        close(managed_fd);
        return EXIT_FAILURE;
    }
    int result = command_loop();
    close(managed_fd);
    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}