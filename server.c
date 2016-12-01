#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SOCKS5_VER 0x05
#define SCOKS5_SUPP_METHOD 0x00
#define SOCKS5_UNSUPP_METHOD 0xFF
#define SOCKS5_RSV 0x00
#define SOCKS5_CONN_SUCCEED 0x00
#define SOCKS5_CONN_FAIL 0x01
#define SOCKS5_IPV4 0x01
#define SOCKS5_DOMAINNAME 0x03
#define SOCKS5_IPV6 0x04

/**
 * tunnel_sockets() - create a tunnel between the two file descriptor
 * @fd1: File descriptor
 * @fd2: File descriptor
 *
 * Return: 0 on success, -1 on failure.
 */
int tunnel_sockets(int fd1, int fd2) {
  fd_set master;
  fd_set read_fds;
  FD_ZERO(&master);
  FD_ZERO(&read_fds);
  FD_SET(fd1, &master);
  FD_SET(fd2, &master);
  int fdmax = fd2;
  int nbytes;
  char buf[16384];
  int i;
  int j;
  int temp;

  i = fd1;
  j = fd2;
  while (1) {
    read_fds = master;
    if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
      perror("Error: select()");
      return -1;
    }
    if (FD_ISSET(i, &read_fds)) {
      if ((nbytes = recv(i, buf, sizeof(buf), 0)) <= 0) {
        if (nbytes < 0) {
          perror("Error: recv()");
          return -1;
        }
        close(i);
        FD_CLR(i, &master);
      } else {
        if (FD_ISSET(j, &master)) {
          /* except the listener and ourselves */
          if (send(j, buf, nbytes, 0) == -1) {
            perror("Error: send()");
            return -1;
          }
        }
      }
    }
    temp = i;
    i = j;
    j = temp;
  }
  return 0;
}

/* parse the client request */
int parse_request(int clientfd, int addr_size, char *addr, int *port) {
  int addr_len = 0;
  int i;
  uint8_t atyp;
  uint8_t msg[1024];
  int nbytes = 0;

  memset(msg, 0, sizeof(msg));

  if ((nbytes = recv(clientfd, msg, sizeof(msg), 0)) <= 5) {
    fprintf(stderr, "Error: thread: could not recv parse_request()");
    return -1;
  }

  if (SOCKS5_VER != msg[0]) {
    fprintf(stderr, "Error: thread: invalid VER");
    return -1;
  }

  if (msg[1] != 1) {
    fprintf(stderr, "Error: thread: invalid CMD");
    return -1;
  }

  atyp = msg[3];
  if (atyp != SOCKS5_IPV4 && atyp != SOCKS5_DOMAINNAME && atyp != SOCKS5_IPV6) {
    fprintf(stderr, "Error: thread: invalid ATYP request");
    return -1;
  }

  switch (atyp) {
  case SOCKS5_IPV4: /* IPv4 4bytes */
    addr_len = 4;
    break;
  case SOCKS5_DOMAINNAME: /* domain name */
    addr_len = msg[4];
    break;
  case SOCKS5_IPV6: /* IPv6 16bytes */
    addr_len = 16;
    break;
  default:
    return -1;
  }

  if (nbytes - 5 - 2 < addr_len) {
    fprintf(stderr, "Erorr: thread: nbytes too small \n");
  }

  i = 0;

  if (atyp == SOCKS5_DOMAINNAME) {
    strncpy(addr, msg + 5, addr_len);
    i = 5 + addr_len;
  } else { /* IP */
    strncpy(addr, msg + 3, addr_len - 1);
    i = 3 + addr_len;
  }
  addr[addr_len] = '\0';

  *port = (msg + i)[0] << 8 | (msg + i)[1];

  return 0;
}

/* create connection to remote server */
int create_connection(char *addr, char *port) {
  int sockfd, numbytes;
  struct addrinfo hints, *servinfo, *p;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(addr, port, &hints, &servinfo) != 0) {
    perror("Error: client: getaddrinfo()");
    return -1;
  }

  /* loop through all the results and connect to the first we can */
  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("Error: client: socket()");
      continue;
    }

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      perror("Error: client: connect()");
      close(sockfd);
      continue;
    }
    break;
  }

  if (p == NULL) {
    freeaddrinfo(servinfo);
    return -1;
  }

  freeaddrinfo(servinfo);
  return sockfd;
}

/* send resopnse to client request */
int send_reply(int clientfd, uint8_t rep) {
  char s[] = "0.0.0.0";
  uint8_t reply[9 + sizeof(s)]; /* 9 size of known data */

  /* server returns a reply formed as
       * https://www.ietf.org/rfc/rfc1928.txt (6).
       */
  reply[0] = SOCKS5_VER;
  reply[1] = rep;
  reply[2] = SOCKS5_RSV;
  reply[3] = SOCKS5_DOMAINNAME;
  reply[4] = sizeof(s);
  /* copy "0.0.0.0" to BND.ADDR place in the buffer */
  strncpy(reply + 5, s, sizeof(s));
  reply[5 + sizeof(s)] = 0x00; /* port number */
  reply[6 + sizeof(s)] = 0x00; /* port number */

  if (send(clientfd, reply, sizeof(reply), 0) != sizeof(reply)) {
    fprintf(stderr, "Error: send() \n");
    return -1;
  }

  return 0;
}

/* check version and choose authentication method */
int negotiate_auth_method(int clientfd) {
  uint8_t request[1024];
  uint8_t msg[2];
  uint8_t nmethods;
  uint8_t ver;
  uint8_t method;
  int nbytes;
  int i;

  memset(request, 0, sizeof(request));

  if ((nbytes = recv(clientfd, request, 1024, 0)) < 3) {
    perror("Error: thread: recv()");
    return -1;
  }

  ver = request[0];
  if (ver != SOCKS5_VER) {
    fprintf(stderr, "Error: thread: invalid VER");
    return -1;
  }

  nmethods = request[1];
  for (i = 2; i < nmethods + 2 && i < sizeof(request); i++) {
    method = request[i];
    if (method == SCOKS5_SUPP_METHOD) {
      break;
    }
  }

  /* suppurt only 0x00 method */
  if (method != SCOKS5_SUPP_METHOD) {
    method = SOCKS5_UNSUPP_METHOD;
  }

  /* assemble method selection message */
  msg[0] = ver;
  msg[1] = method;

  /* send  method selection message*/
  if (send(clientfd, msg, sizeof(msg), 0) != 2) {
    fprintf(stderr, "Error: send() less than 2 bytes \n");
    return -1;
  }

  if (method != SOCKS5_UNSUPP_METHOD) {
    return 0;
  }

  return -1;
}

void *serve_socks_client(int clientfd) {
  int port;
  char addr[INET6_ADDRSTRLEN + 1];
  uint8_t rep;
  int targetfd; /* CR(eb): meaningless, conextless name */
  char str_port[4];

  /* CR(eb): it might make sense to log when jumping to cleanup prematurely */

  if (negotiate_auth_method(clientfd) < 0) {
    fprintf(stderr, "Error: negotiate_auth_method()\n");
    goto cleanup;
  }

  if (parse_request(clientfd, sizeof(addr), addr, &port) < 0) {
    fprintf(stderr, "Error: parse_request()\n");
    goto cleanup;
  }

  /* convert port number to string */
  if (snprintf(str_port, sizeof(str_port), "%d", port) <= 0) {
    fprintf(stderr, "Error: snprintf()\n");
    goto cleanup;
  }

  rep = SOCKS5_CONN_SUCCEED; /* Reply field 0x00 succeeded */
  if ((targetfd = create_connection(addr, str_port)) < 0) {
    fprintf(stderr, "create_connection() \n");
    rep = 0x01; /* general SOCKS server failure */
  }

  if (send_reply(clientfd, rep) < 0) {
    fprintf(stderr, "Error: send_reply()\n");
    close(targetfd);
    goto cleanup;
  }

  if (rep == SOCKS5_CONN_FAIL) {
    close(targetfd);
    fprintf(stderr, "Error: general SOCKS server failure\n");
    goto cleanup;
  }

  if (tunnel_sockets(clientfd, targetfd) < 0) {
    fprintf(stderr, "Error: tunnel_sockets()\n");
    close(targetfd);
    goto cleanup;
  }

cleanup:
  close(clientfd);
  /* CR(eb): now that the equivalent _thread function handles the pthread
   * stuff... (also I think calling this function is not mandatory) */
  // TODO : OKEY ?pthread_exit(0);
}

void *serve_socks_client_thread(void *p) {
  int fd = *(int *)p;
  free(p);
  serve_socks_client(fd);
  pthread_exit(0);
}

int init_server_socket(const char *addr, int port) {
  int serverfd;
  struct sockaddr_in server;
  int opt;

  if ((serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Error: socket()");
    return -1;
  }

  opt = 1;
  if (setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0) {
    perror("Error: setsockopt()");
    close(serverfd);
    return -1;
  }

  /* set server listen address */
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(addr);
  server.sin_port = htons(port);

  if (bind(serverfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
    perror("Error: bind()");
    close(serverfd);
    return -1;
  }

  if (listen(serverfd, SOMAXCONN) < 0) {
    perror("Error: listen()");
    close(serverfd);
    return -1;
  }

  return serverfd;
}

void start_socks_server(const char *addr, int port) {
  int serverfd;
  int clientfd;
  struct sockaddr_in client;
  int c, *newfd;

  if ((serverfd = init_server_socket(addr, port)) < 0) {
    fprintf(stderr, "Error: init_server_socket()\n");
    return;
  }

  fprintf(stderr, "Waiting for incoming connections...\n");

  c = -1;
  newfd = NULL;
  while (1) {
    c = sizeof(struct sockaddr_in);
    clientfd = accept(serverfd, (struct sockaddr *)&client, (socklen_t *)&c);
    if (clientfd < 0) {
      fprintf(stderr, "Error: accept()\n");
      close(serverfd);
      return;
    }

    fprintf(stderr, "Connection accepted\n");

    pthread_t worker;

    newfd = malloc(sizeof(int));
    if (NULL == newfd) {
      fprintf(stderr, "Error: malloc()\n");
      goto end;
    }

    *newfd = clientfd;

    if (pthread_create(&worker, NULL, serve_socks_client_thread,
                       (void *)newfd) < 0) {
      fprintf(stderr, "Error: pthread_create()\n");
      free(newfd);
      goto end;
    }
  }

end:
  close(serverfd);
  close(clientfd);
  return;
}

int main(int argc, char *argv[]) {
  const char *addr;
  int port;

  if (argc != 3) {
    fprintf(stderr, "Error: usage: [address] [port]\n");
    return 1;
  }
  addr = argv[1];
  port = atoi(argv[2]);

  if (port <= 0) {
    fprintf(stderr, "Error: usage: invalid port\n");
    return 1;
  }

  start_socks_server(addr, port);
  fprintf(stderr, "Error: start_socks_server()\n");

  return 1;
}
