// nanonext - C level - Net Utils ----------------------------------------------

#define NANONEXT_NET
#include "nanonext.h"

// IP Addresses ----------------------------------------------------------------

SEXP rnng_ip_addr(void) {

  char buf[INET_ADDRSTRLEN];
  int i = 0;
  SEXP out, names;
  PROTECT_INDEX pxi, pxn;
  PROTECT_WITH_INDEX(out = Rf_allocVector(STRSXP, 1), &pxi);
  PROTECT_WITH_INDEX(names = Rf_allocVector(STRSXP, 1), &pxn);

#ifdef _WIN32

  DWORD ret;
  ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG bufsize = 15000;
  IP_ADAPTER_ADDRESSES *adapter, *addrs;
  IP_ADAPTER_UNICAST_ADDRESS *addr;

  int j = 0;
  do {
    addrs = malloc(bufsize);
    NANO_ENSURE_ALLOC(addrs);

    ret = GetAdaptersAddresses(AF_INET, flags, NULL, addrs, &bufsize);
    if (ret == ERROR_BUFFER_OVERFLOW)
      free(addrs);
  } while ((ret == ERROR_BUFFER_OVERFLOW) && (++j == 1));

  if (ret != NO_ERROR) {
    free(addrs);
    goto cleanup;
  }

  for (adapter = addrs; adapter != NULL; adapter = adapter->Next) {
    if (adapter->OperStatus == IfOperStatusUp) {
      for (addr = adapter->FirstUnicastAddress; addr != NULL; addr = addr->Next) {
        if (addr->Address.lpSockaddr->sa_family == AF_INET) {

          struct sockaddr_in *sa_in = (struct sockaddr_in *) addr->Address.lpSockaddr;
          inet_ntop(AF_INET, &sa_in->sin_addr, buf, sizeof(buf));
          if (i) {
            REPROTECT(out = Rf_xlengthgets(out, i + 1), pxi);
            REPROTECT(names = Rf_xlengthgets(names, i + 1), pxn);
          }
          SET_STRING_ELT(out, i, Rf_mkChar(buf));
          int sz = WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, NULL, 0, NULL, NULL);
          char nbuf[sz];
          if (WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, nbuf, sz, NULL, NULL)) {}
          SET_STRING_ELT(names, i++, Rf_mkChar(nbuf));

        }
      }
    }
  }
  free(addrs);

#else

  struct ifaddrs *ifaddr, *ifa;
  if (getifaddrs(&ifaddr))
    goto cleanup;


  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if ((ifa->ifa_addr != NULL) &&
        (ifa->ifa_addr->sa_family == AF_INET) &&
        !(ifa->ifa_flags & IFF_LOOPBACK)) {

      struct sockaddr_in *sa_in = (struct sockaddr_in *) ifa->ifa_addr;
      inet_ntop(AF_INET, &(sa_in->sin_addr), buf, sizeof(buf));
      if (i) {
        REPROTECT(out = Rf_xlengthgets(out, i + 1), pxi);
        REPROTECT(names = Rf_xlengthgets(names, i + 1), pxn);
      }
      SET_STRING_ELT(out, i, Rf_mkChar(buf));
      SET_STRING_ELT(names, i++, Rf_mkChar(ifa->ifa_name));

    }
  }
  freeifaddrs(ifaddr);

#endif

  Rf_setAttrib(out, R_NamesSymbol, names);

  cleanup:
  UNPROTECT(2);
  return out;

}

// misc utils ------------------------------------------------------------------

SEXP rnng_write_stdout(SEXP x) {

  const char *buf = CHAR(STRING_ELT(x, 0));
#ifdef _WIN32
  char nbuf[strlen(buf) + 2];
  snprintf(nbuf, sizeof(nbuf), "%s\n", buf);
  DWORD bytes;
  if (WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), nbuf, (DWORD) strlen(nbuf), &bytes, NULL)) {}
#else
  struct iovec iov[2];
  iov[0].iov_base = (void *) buf;
  iov[0].iov_len = strlen(buf);
  iov[1].iov_base = "\n";
  iov[1].iov_len = 1;
  if (writev(STDOUT_FILENO, iov, 2)) {}
#endif
  return R_NilValue;

}
