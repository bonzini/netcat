/* Header for poll(2) emulation.
   This file is in the public domain.  */

#ifndef MY_POLL_H
#define MY_POLL_H

#define POLLIN      0x0001	/* mapped to read fds_set */
#define POLLPRI     0x0002	/* mapped to exception fds_set */
#define POLLOUT     0x0004	/* mapped to write fds_set */
#define POLLERR     0x0008
#define POLLHUP     0x0010	/* cannot read data from descriptor */
#define POLLNVAL    0x0020	/* invalid file descriptor */
#define POLLRDNORM  0x0040	/* mapped to read fds_set */
#define POLLRDBAND  0x0080	/* mapped to exception fds_set */
#define POLLWRNORM  0x0100	/* mapped to write fds_set */
#define POLLWRBAND  0x0200	/* mapped to write fds_set */

typedef unsigned long nfds_t;

struct pollfd
{
  int fd;
  short events;	
  short revents;
};

extern int poll (struct pollfd *pfd, nfds_t nfd, int timeout);

#endif
