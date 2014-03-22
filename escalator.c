#define _GNU_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

const char *sudo_uid;
char socket_path[512];

struct sockaddr_un unix_socket_name = {0};
static int sock_dgram(int srv)
{
  int fd;
  mode_t old;

  if (sudo_uid)
    seteuid(atoi(sudo_uid));

  if (0) {
    if (unlink(socket_path) < 0) {
      if (errno != ENOENT) {
	perror("unlink");
	return -1;
      }
    }
  }
  
  unix_socket_name.sun_family = AF_UNIX;

  strcpy(unix_socket_name.sun_path, socket_path);
  old = umask(0077);
  fd = socket(PF_UNIX, SOCK_DGRAM, 0);
  if (fd == -1) return -1;
  if (srv && bind(fd, &unix_socket_name, sizeof(unix_socket_name))) {
    close(fd);
    return -1;
  }
  umask(old);
  return fd;
}

void sigchld_handler(int __attribute__((unused)) sig)
{
  waitpid(-1, 0, WNOHANG);
}

void cleanup(int __attribute__((unused)) sig)
{
  unlink(socket_path);
  exit(0);
}

void server()
{
  struct msghdr msg;
  struct iovec iov;
  char buf[512] = { 0, };
  char *ptr;
  int rv;
  int connfd = -1;
  char cmsgs[CMSG_SPACE(sizeof(connfd)*5)];
  struct cmsghdr *cmsg;
  pid_t pid, pid2;
  int sig;
  int i;
  char * argv[16] = { 0, };
  sighandler_t sigchld;
  sighandler_t sigint;

  int fd = sock_dgram(1);
  if (fd == -1) 
  {
    perror("Unable to bind");
    return;
  }

  iov.iov_base = buf;
  iov.iov_len = 512;

  msg.msg_name = 0;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgs;
  msg.msg_controllen = sizeof(cmsgs);

  sigchld = signal(SIGCHLD, sigchld_handler);
  sigint = signal(SIGCHLD, cleanup);
  
  while((rv = recvmsg(fd, &msg, 0))!=-1)
  {
    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg->cmsg_type == SCM_RIGHTS) {
      fprintf(stderr, "got control message of unknown type %d\n", 
	  cmsg->cmsg_type);
      return;
    }

    ptr = buf;
    for(i=0; i<15; i++)
    {
      argv[i] = ptr;
      ptr += strlen(ptr) + 1;
      if (*ptr == 0)
	break;
    }
    argv[i+1] = 0;

    pid = fork();
    if(pid==0)
    {
      signal(SIGCHLD, sigchld);
      signal(SIGINT, cleanup);
      close(fd);
      for(i=0;i<3;i++)
      {
	close(i);
	dup2(((int*)CMSG_DATA(cmsg))[i], i);
	close(((int*)CMSG_DATA(cmsg))[i]);
      }

      pid = fork();
      if (pid == 0)
      {
	close(((int*)CMSG_DATA(cmsg))[3]);
	close(((int*)CMSG_DATA(cmsg))[4]);
	execvp(argv[0], argv);
	exit(1);
      }
      else
      {
	write(((int*)CMSG_DATA(cmsg))[3], &pid, sizeof(pid));
	pid2 = fork();
	if (pid2 == 0)
	{
	  close(((int*)CMSG_DATA(cmsg))[3]);
	  while(read(((int*)CMSG_DATA(cmsg))[4], &sig, sizeof(int)) == sizeof(int))
	    kill(pid, sig);
	  exit(0);
	}
	close(((int*)CMSG_DATA(cmsg))[4]);
	waitpid(pid, 0, 0);
	kill(pid2, SIGINT);
      }
      exit(0);
    }
    else
    {
      for(i=0;i<4;i++)
	close(((int*)CMSG_DATA(cmsg))[i]);
      memset(buf,0,sizeof(buf));

    }
  }
  perror("recvmsg");
}

int kfd = -1;
sighandler_t handlers[32] = { 0, };

void handler(int sig)
{
  if(kfd != -1 && write(kfd, &sig, sizeof(sig)) != sizeof(sig))
    if (handlers[sig])
      handlers[sig](sig);
}

void client(int argc, char **argv)
{
  struct msghdr msg;
  char cmsgs[CMSG_SPACE(sizeof(int) * 5)];
  struct cmsghdr *cmsg;
  struct iovec vec;
  char str[512];
  char *ptr;
  int rv;
  int fds[2];
  int kfds[2];
  char byte;
  pid_t pid;
  int fd;
  size_t len = 0;
  int i;

  fd = sock_dgram(0);
  
  if (fd == -1) 
    return;

  msg.msg_name = (struct sockaddr*)&unix_socket_name;
  msg.msg_namelen = sizeof(unix_socket_name);

  ptr = str;
  for(i=1; i<argc; i++)
  {
    if ((ptr - str) + strlen(argv[i]) + 2 < sizeof(str))
    {
      strcpy(ptr, argv[i]);
      len += strlen(ptr) + 1;
      ptr += strlen(ptr) + 1;
    }
    else
      break;
  }
  *ptr = 0;

  vec.iov_base = str;
  vec.iov_len = len;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;

  msg.msg_control = cmsgs;
  msg.msg_controllen = sizeof(cmsgs);
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int) * 5);
  ((int*)CMSG_DATA(cmsg))[0] = 0;
  ((int*)CMSG_DATA(cmsg))[1] = 1;
  ((int*)CMSG_DATA(cmsg))[2] = 2;
  pipe(fds);
  pipe(kfds);
  ((int*)CMSG_DATA(cmsg))[3] = fds[1];
  ((int*)CMSG_DATA(cmsg))[4] = kfds[0];
  msg.msg_controllen = cmsg->cmsg_len;

  msg.msg_flags = 0;

  rv = (sendmsg(fd, &msg, 0) != -1);
  if (rv) 
  {
    close(kfds[0]);
    kfd = kfds[1];
    close(fds[1]);
    read(fds[0], &pid, sizeof(pid));
    close(0);
    close(1);
    close(2);
    int i;
    for(i=1; i<32; i++)
      handlers[i] = signal(i, handler);
    read(fds[0], &byte, 1);
  }
}

int main(int argc, char **argv)
{
  static char user[16];
  sudo_uid = getenv("SUDO_UID");
  if (!sudo_uid)
  {
    snprintf(user, 16, "%d", getuid());
    sudo_uid = user;
  }
  snprintf(socket_path, sizeof(socket_path), "/tmp/escalator-%s", sudo_uid);

  if (argc == 1)
    server();
  else
    client(argc, argv);
  return 0;
}
