/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Intentionally partial starter:
 *   - command-line shape is defined
 *   - key runtime data structures are defined
 *   - bounded-buffer skeleton is defined
 *   - supervisor / client split is outlined
 *
 * Students are expected to design:
 *   - the control-plane IPC implementation
 *   - container lifecycle and metadata synchronization
 *   - clone + namespace setup for each container
 *   - producer/consumer behavior for log buffering
 *   - signal handling and graceful shutdown
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    char log_path[PATH_MAX];
    int stop_requested;
    int client_fd_for_run;
    void *child_stack;
    void *child_config;
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);
    }
    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }
    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;
    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == 0 && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
    }
    if (buffer->count == 0 && buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }
    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;
    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    
    mkdir(LOG_DIR, 0755);

    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        if (item.length == 0) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);
        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            write(fd, item.data, item.length);
            close(fd);
        }
    }
    return NULL;
}

int child_fn(void *arg)
{
    child_config_t *config = (child_config_t *)arg;

    sethostname(config->id, strlen(config->id));

    if (config->log_write_fd > 0) {
        dup2(config->log_write_fd, STDOUT_FILENO);
        dup2(config->log_write_fd, STDERR_FILENO);
        close(config->log_write_fd);
    }

    if (config->nice_value != 0) {
        nice(config->nice_value);
    }

    if (chroot(config->rootfs) != 0) {
        return 1;
    }
    if (chdir("/") != 0) {
        return 1;
    }
    if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
        return 1;
    }

    char *args[] = { "sh", "-c", config->command, NULL };
    execvp(args[0], args);
    return 1;
}

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

static volatile int g_should_stop = 0;
static void sig_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_should_stop = 1;
    }
}
static void sigchld_handler(int sig) {
    (void)sig; // Interruption for blocking IO
}

typedef struct {
    int fd;
    char id[CONTAINER_ID_LEN];
    bounded_buffer_t *buf;
} producer_arg_t;

static void *producer_thread(void *arg) {
    producer_arg_t *parg = arg;
    char buf[1024];
    ssize_t n;
    while ((n = read(parg->fd, buf, sizeof(buf))) > 0) {
        log_item_t item;
        memset(&item, 0, sizeof(item));
        strncpy(item.container_id, parg->id, CONTAINER_ID_LEN);
        item.length = n;
        memcpy(item.data, buf, n);
        bounded_buffer_push(parg->buf, &item);
    }
    close(parg->fd);
    free(parg);
    return NULL;
}

static int run_supervisor(const char *rootfs)
{
    (void)rootfs;
    supervisor_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);

    pthread_mutex_init(&ctx.metadata_lock, NULL);
    bounded_buffer_init(&ctx.log_buffer);

    unlink(CONTROL_PATH);
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);
    bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(ctx.server_fd, 5);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = sigchld_handler;
    sigaction(SIGCHLD, &sa, NULL);

    pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);

    while (!g_should_stop) {
        struct sockaddr_un cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept(ctx.server_fd, (struct sockaddr *)&cli_addr, &cli_len);

        int status;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            pthread_mutex_lock(&ctx.metadata_lock);
            container_record_t *curr = ctx.containers;
            while (curr) {
                if (curr->host_pid == pid && (curr->state == CONTAINER_RUNNING || curr->state == CONTAINER_STARTING)) {
                    curr->state = (WIFEXITED(status)) ? CONTAINER_EXITED : CONTAINER_KILLED;
                    if (curr->stop_requested) {
                        curr->state = CONTAINER_STOPPED;
                    }
                    curr->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
                    curr->exit_signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
                    
                    if (curr->client_fd_for_run != -1) {
                        control_response_t resp;
                        memset(&resp, 0, sizeof(resp));
                        resp.status = curr->exit_code;
                        snprintf(resp.message, sizeof(resp.message), "Container exited with code %d", curr->exit_code);
                        write(curr->client_fd_for_run, &resp, sizeof(resp));
                        close(curr->client_fd_for_run);
                        curr->client_fd_for_run = -1;
                    }
                    
                    if (ctx.monitor_fd >= 0) {
                        unregister_from_monitor(ctx.monitor_fd, curr->id, pid);
                    }
                    
                    if (curr->child_stack) free(curr->child_stack);
                    if (curr->child_config) free(curr->child_config);
                    curr->child_stack = NULL;
                    curr->child_config = NULL;
                    break;
                }
                curr = curr->next;
            }
            pthread_mutex_unlock(&ctx.metadata_lock);
        }

        if (client_fd >= 0) {
            control_request_t req;
            control_response_t resp;
            memset(&resp, 0, sizeof(resp));
            if (read(client_fd, &req, sizeof(req)) == sizeof(req)) {
                pthread_mutex_lock(&ctx.metadata_lock);
                
                if (req.kind == CMD_START || req.kind == CMD_RUN) {
                    void *child_stack = malloc(STACK_SIZE);
                    child_config_t *config = malloc(sizeof(child_config_t));
                    memset(config, 0, sizeof(*config));
                    strncpy(config->id, req.container_id, CONTAINER_ID_LEN - 1);
                    strncpy(config->rootfs, req.rootfs, PATH_MAX - 1);
                    strncpy(config->command, req.command, CHILD_COMMAND_LEN - 1);
                    config->nice_value = req.nice_value;

                    int log_pipe[2];
                    pipe(log_pipe);
                    config->log_write_fd = log_pipe[1];

                    pid_t host_pid = clone(child_fn, (char *)child_stack + STACK_SIZE, CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD, config);
                    close(log_pipe[1]);

                    if (host_pid > 0) {
                        producer_arg_t *parg = malloc(sizeof(producer_arg_t));
                        parg->fd = log_pipe[0];
                        strncpy(parg->id, req.container_id, CONTAINER_ID_LEN - 1);
                        parg->buf = &ctx.log_buffer;
                        pthread_t prod_tid;
                        pthread_create(&prod_tid, NULL, producer_thread, parg);
                        pthread_detach(prod_tid);

                        container_record_t *rec = malloc(sizeof(container_record_t));
                        memset(rec, 0, sizeof(*rec));
                        strncpy(rec->id, req.container_id, CONTAINER_ID_LEN - 1);
                        rec->host_pid = host_pid;
                        rec->started_at = time(NULL);
                        rec->state = CONTAINER_RUNNING;
                        rec->soft_limit_bytes = req.soft_limit_bytes;
                        rec->hard_limit_bytes = req.hard_limit_bytes;
                        rec->child_stack = child_stack;
                        rec->child_config = config;
                        rec->client_fd_for_run = -1;
                        if (req.kind == CMD_RUN) rec->client_fd_for_run = client_fd;
                        
                        rec->next = ctx.containers;
                        ctx.containers = rec;

                        if (ctx.monitor_fd >= 0) {
                            register_with_monitor(ctx.monitor_fd, req.container_id, host_pid, req.soft_limit_bytes, req.hard_limit_bytes);
                        }

                        if (req.kind == CMD_START) {
                            resp.status = 0;
                            snprintf(resp.message, sizeof(resp.message), "Container %s started", req.container_id);
                            write(client_fd, &resp, sizeof(resp));
                            close(client_fd);
                        }
                    } else {
                        free(child_stack);
                        free(config);
                        resp.status = 1;
                        snprintf(resp.message, sizeof(resp.message), "Failed to start container");
                        write(client_fd, &resp, sizeof(resp));
                        close(client_fd);
                    }
                } else if (req.kind == CMD_STOP) {
                    container_record_t *curr = ctx.containers;
                    int found = 0;
                    while (curr) {
                        if (strncmp(curr->id, req.container_id, CONTAINER_ID_LEN) == 0 && curr->state == CONTAINER_RUNNING) {
                            curr->stop_requested = 1;
                            kill(curr->host_pid, SIGTERM);
                            found = 1;
                            break;
                        }
                        curr = curr->next;
                    }
                    resp.status = (found) ? 0 : 1;
                    snprintf(resp.message, sizeof(resp.message), found ? "Stop requested" : "Not running");
                    write(client_fd, &resp, sizeof(resp));
                    close(client_fd);
                } else if (req.kind == CMD_PS) {
                    char info[CONTROL_MESSAGE_LEN] = "";
                    container_record_t *curr = ctx.containers;
                    int offset = 0;
                    while (curr && offset < CONTROL_MESSAGE_LEN - 1) {
                        int w = snprintf(info + offset, CONTROL_MESSAGE_LEN - offset, "%s: %s (PID: %d)\n", curr->id, state_to_string(curr->state), curr->host_pid);
                        if (w > 0) offset += w;
                        curr = curr->next;
                    }
                    if (offset == 0) snprintf(info, sizeof(info), "No containers");
                    resp.status = 0;
                    strncpy(resp.message, info, CONTROL_MESSAGE_LEN - 1);
                    write(client_fd, &resp, sizeof(resp));
                    close(client_fd);
                } else {
                    resp.status = 1;
                    snprintf(resp.message, sizeof(resp.message), "Command not recognized internally");
                    write(client_fd, &resp, sizeof(resp));
                    close(client_fd);
                }
                pthread_mutex_unlock(&ctx.metadata_lock);
            } else {
                close(client_fd);
            }
        }
    }

    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);
    bounded_buffer_destroy(&ctx.log_buffer);

    container_record_t *curr = ctx.containers;
    while (curr) {
        if (curr->state == CONTAINER_RUNNING) kill(curr->host_pid, SIGKILL);
        container_record_t *next = curr->next;
        free(curr);
        curr = next;
    }

    pthread_mutex_destroy(&ctx.metadata_lock);
    unlink(CONTROL_PATH);
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
    if (ctx.server_fd >= 0) close(ctx.server_fd);
    return 0;
}

static int send_control_request(const control_request_t *req)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    if (write(sock, req, sizeof(*req)) != sizeof(*req)) {
        perror("write");
        close(sock);
        return 1;
    }

    control_response_t resp;
    int n = read(sock, &resp, sizeof(resp));
    if (n == sizeof(resp)) {
        if (resp.message[0] != '\0') {
            printf("%s\n", resp.message);
        }
        close(sock);
        return resp.status;
    } else if (n == 0) {
        close(sock);
        return 0;
    }

    close(sock);
    return 1;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;

    /* Ensure cleanly passing requests and rendering supervisor response. */
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, argv[2]);
    char cmd[PATH_MAX + 10];
    snprintf(cmd, sizeof(cmd), "cat %s", path);
    return system(cmd);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
