/* memcmp(3) emulation.
   This file is in the public domain.*/

int
memcmp (a, b, n)
     unsigned char *a, *b;
     int n;
{
  if (n)
    do
      {
	int ch1 = *b++;
	int ch0 = *a++;
        int delta = ch0 - ch1;
        if (delta)
	  return delta;
      }
    while (--n);

  return 0;
}
