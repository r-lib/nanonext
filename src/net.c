// nanonext - C level - Net Utils ----------------------------------------------

#define NANONEXT_NET
#include "nanonext.h"

// IP Addresses ----------------------------------------------------------------

SEXP rnng_ip_addr(void) {

  char out[INET_ADDRSTRLEN];

#ifdef _WIN32

  DWORD ret;
  ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG bufsize = 15000;
  IP_ADAPTER_ADDRESSES *adapter, *addrs;
  IP_ADAPTER_UNICAST_ADDRESS *addr;

  int i = 0;
  do {
    addrs = malloc(bufsize);
    if (addrs == NULL)
      goto exitlevel1;

    ret = GetAdaptersAddresses(AF_INET, flags, NULL, addrs, &bufsize);
    if (ret == ERROR_BUFFER_OVERFLOW)
      free(addrs);
  } while ((ret == ERROR_BUFFER_OVERFLOW) && (++i == 1));

  if (ret != NO_ERROR) {
    free(addrs);
    goto exitlevel1;
  }

  for (adapter = addrs; adapter != NULL; adapter = adapter->Next) {
    if (adapter->OperStatus == IfOperStatusUp) {
      for (addr = adapter->FirstUnicastAddress; addr != NULL; addr = addr->Next) {
        if (addr->Address.lpSockaddr->sa_family == AF_INET) {

          struct sockaddr_in *sa_in = (struct sockaddr_in *) addr->Address.lpSockaddr;
          inet_ntop(AF_INET, &sa_in->sin_addr, out, sizeof(out));

          free(addrs);
          return Rf_mkString(out);

        }
      }
    }
  }
  free(addrs);

#else

  struct ifaddrs *ifaddr, *ifa;
  if (getifaddrs(&ifaddr))
    goto exitlevel1;

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if ((ifa->ifa_addr != NULL) &&
        (ifa->ifa_addr->sa_family == AF_INET) &&
        !(ifa->ifa_flags & IFF_LOOPBACK)) {

      struct sockaddr_in *sa_in = (struct sockaddr_in *) ifa->ifa_addr;
      inet_ntop(AF_INET, &(sa_in->sin_addr), out, sizeof(out));

      freeifaddrs(ifaddr);
      return Rf_mkString(out);

    }
  }
  freeifaddrs(ifaddr);

#endif

  exitlevel1:
  return R_BlankScalarString;

}

// misc utils ------------------------------------------------------------------

SEXP rnng_write_stdout(SEXP x) {

  const char *buf = CHAR(STRING_ELT(x, 0));
#ifdef _WIN32
  DWORD bytes;
  if (WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD) strlen(buf), &bytes, NULL)) {}
#else
  if (write(1, buf, strlen(buf))) {}
#endif
  return R_NilValue;

}

