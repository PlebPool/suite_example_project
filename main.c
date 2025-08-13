#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/syscall.h>
#include <arpa/inet.h>

#include "csock.h"
#include "cthread.h"
#include "cssl.h"

SSL_CTX* ctx = NULL;

volatile sig_atomic_t exit_flag = 0;

void sig_handler(const int signo) {
    syslog(LOG_INFO, "Received signal %d", signo);
    exit_flag = 1;
}

void handler(void* arg) {
    csock_epoll_ready_ptr_t* p = arg;
    const int fd = p->sock_fd;
    char buffer[8096];

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);

    if (SSL_accept(ssl) < 0) {
        syslog(LOG_ERR, "SSL_accept() failed %s", strerror(errno));
        return;
    }

    syslog(LOG_INFO, "SSL connection accepted");
    const ssize_t n_read = SSL_read(ssl, buffer, sizeof(buffer)-1);

    buffer[n_read] = '\0';

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(p->addr->sin_addr), ip_str, INET_ADDRSTRLEN);

    syslog(LOG_INFO, "Received request from %s", ip_str);

    const char *response = "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n"
            "\r\n"
            "<html>\n"
            "<head><title>Hello</title></head>\n"
            "<body><h1>Hello HTTPS World!</h1></body>\n"
            "</html>";
    SSL_write(ssl, response, strlen(response));

    SSL_shutdown(ssl);
    SSL_free(ssl);
    shutdown(fd, SHUT_WR);
    free(p->addr);
    free(p);
    close(fd);
}

void http_handler(void* arg) {
    csock_epoll_ready_ptr_t* p = arg;
    const int fd = p->sock_fd;
    char buffer[8096];

    const ssize_t n_read = recv(fd, buffer, sizeof(buffer), 0);
    if (n_read < 0) {
        syslog(LOG_ERR, "recv() failed %s", strerror(errno));
        return;
    }

const char *response = "HTTP/1.1 307 Temporary Redirect\r\n"
            "Location: https://localhost:8081\r\n"
            "Connection: close\r\n"
            "\r\n";
    send(fd, response, strlen(response), 0);
    shutdown(fd, SHUT_WR);
    free(p->addr);
    free(p);
    close(fd);
}

int main(void) {
    openlog("cweb_server", LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGABRT, sig_handler);

    ctx = ssl_ctx_init("./resources/cert.pem", "./resources/key.pem");

    int sock = csock_create_listen(8081);

    threadpool_t* pool = threadpool_create(4);
    csock_epoll_args_t args = {};
    args.sock_fd = sock;
    args.pool = pool;
    args.handle_request = handler;

    pthread_t thread;
    pthread_create(&thread, NULL, csock_epoll, &args);

    int sock_http = csock_create_listen(8080);
    threadpool_t* pool2 = threadpool_create(4);
    csock_epoll_args_t args2 = {};
    args2.sock_fd = sock_http;
    args2.pool = pool2;
    args2.handle_request = http_handler;

    pthread_t thread2;
    pthread_create(&thread2, NULL, csock_epoll, &args2);

    while (!exit_flag) {
        sleep(1);
    }

    pthread_cancel(thread);
    pthread_join(thread, NULL);

    threadpool_destroy(pool);
    ssl_cleanup(ctx);


    return 0;
}
