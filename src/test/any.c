
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT 50000
#define BUF_SIZE 1024

void log_message(const char *msg) {
  FILE *f = fopen("/tmp/knocker.log", "a");
  if (f) {
    time_t now = time(NULL);
    fprintf(f, "[%ld] %s\n", now, msg);
    fclose(f);
  }
}

int main() {
  int sock;
  struct sockaddr_in server, client;
  char buffer[BUF_SIZE];

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    exit(1);
  }

  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons(PORT);

  if (bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
    perror("bind");
    exit(1);
  }

  log_message("UDP listener started");

  while (1) {
    socklen_t len = sizeof(client);
    ssize_t n = recvfrom(sock, buffer, BUF_SIZE - 1, 0,
			 (struct sockaddr *)&client, &len);
    if (n < 0) {
      perror("recvfrom");
      continue;
    }

    buffer[n] = '\0';
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client.sin_addr, ip, sizeof(ip));

    char msg[256];
    snprintf(msg, sizeof(msg), "Received %zd bytes from %s: %s", n, ip, buffer);
    log_message(msg);
  }

  close(sock);
  return 0;
}
