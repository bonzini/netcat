/* poll(2) emulation.
   This file is in the public domain. */

#include "poll.h"
#include <sys/types.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

int
poll (struct pollfd *ufds, nfds_t nfd, int msec)
{
  fd_set readfds, writefds, exceptfds;
  struct timeval timeout, *ptimeout;
  nfds_t i;
  int max_fd, rc;

  /* compute fd_sets and find largest descriptor */
  FD_ZERO (&readfds);
  FD_ZERO (&writefds);
  FD_ZERO (&exceptfds);
  for (max_fd = -1, i = 0; i < nfd; i++)
    if (ufds[i].fd >= 0)
      {
	if (ufds[i].events & (POLLIN | POLLRDNORM))
	  {
	    FD_SET (ufds[i].fd, &readfds);
	    max_fd = (ufds[i].fd > max_fd) ? ufds[i].fd : max_fd;
	  }
	if (ufds[i].events & (POLLOUT | POLLWRNORM | POLLWRBAND))
	  {
	    FD_SET (ufds[i].fd, &writefds);
	    max_fd = (ufds[i].fd > max_fd) ? ufds[i].fd : max_fd;
	  }
	if (ufds[i].events & (POLLPRI | POLLRDBAND))
	  {
	    FD_SET (ufds[i].fd, &exceptfds);
	    max_fd = (ufds[i].fd > max_fd) ? ufds[i].fd : max_fd;
	  }
      }

  if (max_fd == -1)
    {
      errno = EINVAL;
      return -1;
    }

  /* convert milliseconds to a timeval structure */
  if (msec < 0)
    ptimeout = NULL;
  else
    {
      /* return after msec */
      ptimeout = &timeout;
      timeout.tv_sec = msec / 1000;
      timeout.tv_usec = (msec % 1000) * 1000;
    }

  if (select (max_fd + 1, &readfds, &writefds, &exceptfds, ptimeout) == -1)
    return -1;

  /* ok, proceed to find the results */
  for (rc = 0, i = 0; i < nfd; i++)
    if (ufds[i].fd >= 0)
      {
	ufds[i].revents = 0;
	if (FD_ISSET (ufds[i].fd, &readfds))
	  {
	    /* support for POLLHUP */
	    int save_errno = errno;
	    char data[64];
	    if ((recv (ufds[i].fd, data, 64, MSG_PEEK) == -1)
	         && (errno == ESHUTDOWN || errno == ECONNRESET ||
		     errno == ECONNABORTED || errno == ENETRESET))
	      ufds[i].revents |= POLLHUP;
	    else
	      ufds[i].revents |= ufds[i].events & (POLLIN | POLLRDNORM);

	    errno = save_errno;
	  }

	if (FD_ISSET (ufds[i].fd, &writefds))
	  ufds[i].revents |= ufds[i].events & (POLLOUT | POLLWRNORM | POLLWRBAND);

	if (FD_ISSET (ufds[i].fd, &exceptfds))
	  ufds[i].revents |= ufds[i].events & (POLLPRI | POLLRDBAND);

	if (ufds[i].revents & ~POLLHUP)
	  rc++;
      }
    else
      ufds[i].revents = POLLNVAL;

  return rc;
}
