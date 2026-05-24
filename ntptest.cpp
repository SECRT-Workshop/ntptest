/*
 * ntptest — NTP Server Query and Date/Time Retrieval Tool
 *
 * This is an original, independent implementation produced by
 * SECRT Workshop <https://secrtworkshop.org>.  It is not affiliated
 * with, derived from, or intended to replace any other software that
 * may share the same name.  All support inquiries specific to this
 * tool should be directed to <support@secrtworkshop.org>.
 *
 * 2026
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

/* ── Identity ─────────────────────────────────────────────────────────────── */
#define NTPTEST_VERSION   "1.0.0"
#define NTPTEST_DEVELOPER "SECRT Workshop"
#define NTPTEST_URL       "https://secrtworkshop.org"
#define NTPTEST_SUPPORT   "support@secrtworkshop.org"
#define NTPTEST_YEAR      "2026"

/* NTP epoch is Jan 1 1900; Unix epoch is Jan 1 1970 — 70 years apart */
#define NTP_UNIX_DELTA 2208988800ULL

/* ── ANSI Color ───────────────────────────────────────────────────────────── */
namespace Color {
    static bool enabled = true;
    static inline std::string c(const char *code) { return enabled ? code : ""; }
    const char *RESET   = "\033[0m";
    const char *BOLD    = "\033[1m";
    const char *DIM     = "\033[2m";
    const char *RED     = "\033[31m";
    const char *GREEN   = "\033[32m";
    const char *YELLOW  = "\033[33m";
    const char *CYAN    = "\033[36m";
}

/* ── NTP packet (RFC 5905) ────────────────────────────────────────────────── */
#pragma pack(push, 1)
struct NTPPacket {
    uint8_t  li_vn_mode;        /* Leap indicator | version | mode         */
    uint8_t  stratum;           /* Stratum level                           */
    uint8_t  poll;              /* Poll exponent (log2 seconds)            */
    int8_t   precision;         /* Clock precision (log2 seconds)          */
    int32_t  root_delay;        /* Round-trip to primary (16.16 fixed pt)  */
    uint32_t root_dispersion;   /* Max error from primary (16.16 fixed pt) */
    uint8_t  ref_id[4];         /* Reference identifier                    */
    uint32_t ref_ts_sec;        /* Reference timestamp (seconds)           */
    uint32_t ref_ts_frac;       /* Reference timestamp (fraction)          */
    uint32_t orig_ts_sec;       /* Origin timestamp (seconds)              */
    uint32_t orig_ts_frac;      /* Origin timestamp (fraction)             */
    uint32_t rx_ts_sec;         /* Receive timestamp (seconds)             */
    uint32_t rx_ts_frac;        /* Receive timestamp (fraction)            */
    uint32_t tx_ts_sec;         /* Transmit timestamp (seconds)            */
    uint32_t tx_ts_frac;        /* Transmit timestamp (fraction)           */
};
#pragma pack(pop)

static_assert(sizeof(NTPPacket) == 48, "NTP packet must be exactly 48 bytes");

/* ── Query result ─────────────────────────────────────────────────────────── */
struct NTPResult {
    bool     ok           = false;
    NTPPacket pkt         = {};
    double   offset_ms    = 0.0;   /* Clock offset in milliseconds         */
    double   rtt_ms       = 0.0;   /* Round-trip delay in milliseconds     */
    double   server_time  = 0.0;   /* Unix timestamp from server tx field  */
};

/* ── Config ───────────────────────────────────────────────────────────────── */
struct Config {
    std::string host;
    int         port      = 123;
    int         timeout   = 5;
    int         count     = 1;      /* number of queries to send            */
    int         interval  = 1;      /* seconds between queries (count > 1)  */
    std::string fmt;                /* strftime format string               */
    bool        verbose   = false;
    bool        raw       = false;
    bool        utc       = false;
    bool        quiet     = false;
    bool        no_color  = false;
    bool        ipv4_only = false;
    bool        ipv6_only = false;
    int         source_port = 0;
};

/* ── Monotonic clock in microseconds ──────────────────────────────────────── */
static double now_us() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

/* ── Current Unix time as a double (for NTP offset math) ─────────────────── */
static double unix_now() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

/* ── Convert NTP 64-bit timestamp to Unix double ──────────────────────────── */
static double ntp_to_unix(uint32_t sec_be, uint32_t frac_be) {
    uint32_t sec  = ntohl(sec_be);
    uint32_t frac = ntohl(frac_be);
    double unix_sec = (double)(sec - NTP_UNIX_DELTA)
                    + (double)frac / 4294967296.0;
    return unix_sec;
}

/* ── 16.16 fixed-point to milliseconds ───────────────────────────────────── */
static double fixed1616_to_ms(int32_t val_be) {
    int32_t val = (int32_t)ntohl((uint32_t)val_be);
    return ((double)val / 65536.0) * 1000.0;
}
static double ufixed1616_to_ms(uint32_t val_be) {
    uint32_t val = ntohl(val_be);
    return ((double)val / 65536.0) * 1000.0;
}

/* ── Leap indicator string ────────────────────────────────────────────────── */
static std::string li_str(uint8_t li) {
    switch (li) {
    case 0: return "0 — no warning";
    case 1: return "1 — last minute of day has 61 seconds";
    case 2: return "2 — last minute of day has 59 seconds";
    case 3: return "3 — clock unsynchronised";
    default: return "unknown";
    }
}

/* ── Stratum description ──────────────────────────────────────────────────── */
static std::string stratum_str(uint8_t s) {
    if (s == 0)  return "0 — unspecified / invalid";
    if (s == 1)  return "1 — primary reference (GPS, atomic, etc.)";
    if (s <= 15) return std::to_string(s) + " — secondary reference";
    if (s == 16) return "16 — unsynchronised";
    return std::to_string(s) + " — reserved";
}

/* ── Reference ID string ──────────────────────────────────────────────────── */
static std::string refid_str(const uint8_t id[4], uint8_t stratum) {
    if (stratum <= 1) {
        /* For stratum 0-1 the ref ID is a 4-char ASCII kiss code / source */
        char buf[5] = {};
        for (int i = 0; i < 4; i++)
            buf[i] = (id[i] >= 32 && id[i] < 127) ? (char)id[i] : '.';
        /* Trim trailing spaces/nulls */
        int len = 3;
        while (len > 0 && (buf[len] == '\0' || buf[len] == ' ')) len--;
        return std::string(buf, len + 1);
    }
    /* For stratum 2+ it is the IPv4 address of the reference server */
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    memcpy(&addr, id, 4);
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

/* ── Format a Unix double timestamp ──────────────────────────────────────── */
static std::string format_unix(double unix_ts, bool utc,
                                const std::string &fmt) {
    time_t t = (time_t)unix_ts;
    struct tm *tm_val = utc ? gmtime(&t) : localtime(&t);
    char buf[256];
    const std::string &f = fmt.empty() ? "%Y-%m-%d %H:%M:%S" : fmt;
    strftime(buf, sizeof(buf), f.c_str(), tm_val);
    return std::string(buf);
}

/* ── Timezone abbreviation ────────────────────────────────────────────────── */
static std::string local_tz() {
    time_t t = time(nullptr);
    struct tm *lt = localtime(&t);
    char buf[64];
    strftime(buf, sizeof(buf), "%Z", lt);
    return std::string(buf);
}

/* ── Privilege elevation ──────────────────────────────────────────────────── */
static void elevate_if_needed(int argc, char *argv[], bool need_root) {
    if (!need_root || geteuid() == 0) return;

    const char *elevators[] = {
        "/usr/bin/doas", "/usr/local/bin/doas",
        "/usr/bin/sudo", "/usr/local/bin/sudo",
        nullptr
    };
    const char *elev = nullptr;
    for (int i = 0; elevators[i]; i++)
        if (access(elevators[i], X_OK) == 0) { elev = elevators[i]; break; }

    if (!elev) {
        std::cerr << "ntptest: this operation requires root privileges,\n"
                     "         but neither doas nor sudo could be found.\n";
        exit(EXIT_FAILURE);
    }

    std::cerr << "ntptest: elevating via " << elev << " …\n";
    std::vector<const char *> nargv;
    nargv.push_back(elev);
    for (int i = 0; i < argc; i++) nargv.push_back(argv[i]);
    nargv.push_back(nullptr);
    execv(elev, const_cast<char *const *>(nargv.data()));
    perror("ntptest: execv");
    exit(EXIT_FAILURE);
}

/* ── Send one NTP query and return parsed result ──────────────────────────── */
static NTPResult query_once(const std::string &host, int port, int timeout_s,
                             int af, int src_port) {
    NTPResult result;

    /* Resolve host */
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = af;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    std::string port_str = std::to_string(port);
    int r = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (r != 0) {
        std::cerr << "ntptest: " << host << ": " << gai_strerror(r) << "\n";
        return result;
    }

    int sockfd = -1;
    struct addrinfo *rp = nullptr;
    for (rp = res; rp; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) continue;

        if (src_port > 0) {
            struct sockaddr_in sa{};
            sa.sin_family      = AF_INET;
            sa.sin_addr.s_addr = INADDR_ANY;
            sa.sin_port        = htons((uint16_t)src_port);
            if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                close(sockfd); sockfd = -1; continue;
            }
        }

        /* Connect the UDP socket so send/recv work cleanly */
        if (::connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sockfd); sockfd = -1;
    }
    freeaddrinfo(res);

    if (sockfd < 0) {
        std::cerr << "ntptest: unable to reach " << host << ":" << port << "\n";
        return result;
    }

    /* Build NTPv4 client request packet */
    NTPPacket req{};
    /* LI=0 (00), VN=4 (100), Mode=3 client (011) → 0b00100011 = 0x23 */
    req.li_vn_mode = 0x23;

    /* Record T1 (client send time) just before sending */
    double T1 = unix_now();
    double mono_send = now_us();

    ssize_t sent = send(sockfd, &req, sizeof(req), 0);
    if (sent != sizeof(req)) {
        std::cerr << "ntptest: send failed: " << strerror(errno) << "\n";
        close(sockfd); return result;
    }

    /* Wait for reply */
    fd_set rfds; FD_ZERO(&rfds); FD_SET(sockfd, &rfds);
    struct timeval tv{ timeout_s, 0 };
    int sel = select(sockfd + 1, &rfds, nullptr, nullptr, &tv);
    if (sel <= 0) {
        std::cerr << "ntptest: no response from " << host
                  << " (timeout " << timeout_s << "s)\n";
        close(sockfd); return result;
    }

    NTPPacket pkt{};
    ssize_t n = recv(sockfd, &pkt, sizeof(pkt), 0);
    double mono_recv = now_us();
    double T4 = unix_now();   /* Record T4 (client receive time) */
    close(sockfd);

    if (n < (ssize_t)sizeof(NTPPacket)) {
        std::cerr << "ntptest: short response (" << n << " bytes)\n";
        return result;
    }

    /* Validate: mode must be 4 (server) */
    uint8_t mode = pkt.li_vn_mode & 0x07;
    if (mode != 4) {
        std::cerr << "ntptest: unexpected mode " << (int)mode
                  << " in response (expected 4)\n";
        return result;
    }

    /* Extract T2 and T3 from packet */
    double T2 = ntp_to_unix(pkt.rx_ts_sec,  pkt.rx_ts_frac);
    double T3 = ntp_to_unix(pkt.tx_ts_sec,  pkt.tx_ts_frac);

    result.ok          = true;
    result.pkt         = pkt;
    result.server_time = T3;
    result.rtt_ms      = (mono_recv - mono_send) / 1000.0;   /* µs → ms */
    result.offset_ms   = (((T2 - T1) + (T3 - T4)) / 2.0) * 1000.0;
    return result;
}

/* ── Display helpers ──────────────────────────────────────────────────────── */
static void sep(int w = 58) {
    std::cout << Color::c(Color::DIM);
    for (int i = 0; i < w; i++) std::cout << "─";
    std::cout << Color::c(Color::RESET) << "\n";
}

static void kv(const std::string &key, const std::string &val,
               const char *vc = nullptr) {
    std::cout << "  "
              << Color::c(Color::BOLD) << std::left << std::setw(22) << key
              << Color::c(Color::RESET) << ": ";
    if (vc) std::cout << Color::c(vc);
    std::cout << val;
    if (vc) std::cout << Color::c(Color::RESET);
    std::cout << "\n";
}

static std::string ms_str(double ms) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(3) << ms << " ms";
    return ss.str();
}

/* ── --help ───────────────────────────────────────────────────────────────── */
static void print_help() {
    std::cout <<
"Usage: ntptest [OPTION]... HOST\n"
"Query an NTP server for time, stratum, offset, and diagnostic information.\n"
"\n"
"  HOST is the hostname or IP address of the NTP server to query.\n"
"\n"
"Connection options:\n"
"  -p, --port=PORT            connect to PORT instead of the default (123)\n"
"  -t, --timeout=SECS         response timeout in seconds (default: 5)\n"
"      --source-port=PORT     bind outgoing socket to local PORT; ports\n"
"                               below 1024 require root and will auto-elevate\n"
"  -4, --ipv4                 force IPv4 only\n"
"  -6, --ipv6                 force IPv6 only\n"
"\n"
"Query options:\n"
"  -c, --count=N              send N queries and report min/avg/max (default: 1)\n"
"  -i, --interval=SECS        wait SECS between queries when using --count\n"
"                               (default: 1)\n"
"\n"
"Output options:\n"
"  -f, --format=FMT           format date/time output using strftime(3) FMT\n"
"                               e.g. --format=\"%%Y-%%m-%%dT%%H:%%M:%%SZ\"\n"
"  -v, --verbose              display full NTP packet field breakdown\n"
"  -r, --raw                  output raw NTP timestamp values\n"
"      --utc                  display times in UTC instead of local time\n"
"  -q, --quiet                suppress decorative output; print time only\n"
"      --no-color             disable ANSI color escape sequences\n"
"\n"
"Miscellaneous:\n"
"      --help                 display this help text and exit\n"
"      --version              output version information and exit\n"
"\n"
"Examples:\n"
"  ntptest time.google.com\n"
"      Query time.google.com on UDP/123 and display full results.\n"
"\n"
"  ntptest -c 5 -i 2 pool.ntp.org\n"
"      Send 5 queries 2 seconds apart and report averaged statistics.\n"
"\n"
"  ntptest --utc --format=\"%Y-%m-%dT%H:%M:%SZ\" time.cloudflare.com\n"
"      Display server time in ISO 8601 UTC format.\n"
"\n"
"  ntptest -q --utc time.google.com\n"
"      Quiet mode — print only the server timestamp.\n"
"\n"
"  ntptest -v ntp.ubuntu.com\n"
"      Show full NTP packet field breakdown.\n"
"\n"
"This is an original, independent implementation produced by " NTPTEST_DEVELOPER ".\n"
"It is not affiliated with, derived from, or intended to replace any other\n"
"software that may share the same name.  For support inquiries or questions\n"
"about this tool or other " NTPTEST_DEVELOPER " software, contact:\n"
"  <" NTPTEST_SUPPORT ">\n"
"\n"
NTPTEST_DEVELOPER " ntptest is free software: you can redistribute it and/or\n"
"modify it under the terms of the GNU General Public License as published by\n"
"the Free Software Foundation, either version 3 of the License, or (at your\n"
"option) any later version.\n"
"\n"
"This program is distributed in the hope that it will be useful, but WITHOUT\n"
"ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS\n"
"FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License along with\n"
"this program.  If not, see <https://www.gnu.org/licenses/>.\n"
"\n"
NTPTEST_DEVELOPER " ntptest home page : <" NTPTEST_URL ">\n"
"Support / contact         : <" NTPTEST_SUPPORT ">\n"
"General help (GNU)        : <https://www.gnu.org/gethelp/>\n"
"GNU General Public License: <https://www.gnu.org/licenses/gpl.html>\n"
"Free Software Foundation  : <https://www.fsf.org>\n";
}

/* ── --version ────────────────────────────────────────────────────────────── */
static void print_version() {
    std::cout <<
"ntptest " NTPTEST_VERSION " (" NTPTEST_DEVELOPER ")\n"
NTPTEST_URL "\n"
NTPTEST_YEAR "\n"
"\n"
"This is an original, independent implementation by " NTPTEST_DEVELOPER ".\n"
"It is not affiliated with or derived from any other software\n"
"sharing the same name.\n"
"\n"
"License: GNU General Public License version 3 or later\n"
"         <https://www.gnu.org/licenses/gpl.html>\n"
"\n"
"This is free software; you are free to change and redistribute it.\n"
"There is NO WARRANTY, to the extent permitted by law.\n"
"\n"
"Support: <" NTPTEST_SUPPORT ">\n";
}

/* ── Argument parsing ─────────────────────────────────────────────────────── */
static const struct option long_opts[] = {
    { "port",        required_argument, nullptr, 'p' },
    { "timeout",     required_argument, nullptr, 't' },
    { "count",       required_argument, nullptr, 'c' },
    { "interval",    required_argument, nullptr, 'i' },
    { "format",      required_argument, nullptr, 'f' },
    { "verbose",     no_argument,       nullptr, 'v' },
    { "raw",         no_argument,       nullptr, 'r' },
    { "utc",         no_argument,       nullptr,  1  },
    { "quiet",       no_argument,       nullptr, 'q' },
    { "no-color",    no_argument,       nullptr,  2  },
    { "source-port", required_argument, nullptr,  3  },
    { "ipv4",        no_argument,       nullptr, '4' },
    { "ipv6",        no_argument,       nullptr, '6' },
    { "help",        no_argument,       nullptr, 'h' },
    { "version",     no_argument,       nullptr, 'V' },
    { nullptr, 0, nullptr, 0 }
};

static Config parse_args(int argc, char *argv[]) {
    Config cfg;
    int opt, idx = 0;
    while ((opt = getopt_long(argc, argv, "p:t:c:i:f:vrq46hV",
                              long_opts, &idx)) != -1) {
        switch (opt) {
        case 'p': cfg.port        = std::stoi(optarg); break;
        case 't': cfg.timeout     = std::stoi(optarg); break;
        case 'c': cfg.count       = std::stoi(optarg); break;
        case 'i': cfg.interval    = std::stoi(optarg); break;
        case 'f': cfg.fmt         = optarg;             break;
        case 'v': cfg.verbose     = true;               break;
        case 'r': cfg.raw         = true;               break;
        case  1 : cfg.utc         = true;               break;
        case 'q': cfg.quiet       = true;               break;
        case  2 : cfg.no_color    = true;               break;
        case  3 : cfg.source_port = std::stoi(optarg); break;
        case '4': cfg.ipv4_only   = true;               break;
        case '6': cfg.ipv6_only   = true;               break;
        case 'h': print_help();    exit(EXIT_SUCCESS);
        case 'V': print_version(); exit(EXIT_SUCCESS);
        default:
            std::cerr << "Try 'ntptest --help' for more information.\n";
            exit(EXIT_FAILURE);
        }
    }
    if (optind >= argc) {
        std::cerr << "ntptest: missing HOST operand\n"
                     "Try 'ntptest --help' for more information.\n";
        exit(EXIT_FAILURE);
    }
    cfg.host = argv[optind];
    return cfg;
}

/* ── Main ─────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    Config cfg = parse_args(argc, argv);

    Color::enabled = !cfg.no_color;

    bool need_root = cfg.source_port > 0 && cfg.source_port < 1024;
    elevate_if_needed(argc, argv, need_root);

    int af = AF_UNSPEC;
    if (cfg.ipv4_only) af = AF_INET;
    if (cfg.ipv6_only) af = AF_INET6;

    /* ── Header ─────────────────────────────────────────────────────────── */
    if (!cfg.quiet) {
        std::cout << "\n"
                  << Color::c(Color::BOLD) << Color::c(Color::CYAN)
                  << "ntptest " NTPTEST_VERSION
                  << Color::c(Color::RESET)
                  << Color::c(Color::DIM) << " — " NTPTEST_DEVELOPER
                  << Color::c(Color::RESET) << "\n";
        sep();
        kv("Host",     cfg.host,                         Color::BOLD);
        kv("Port",     std::to_string(cfg.port) + " (UDP)");
        kv("Protocol", "NTPv4");
        if (cfg.count > 1)
            kv("Queries", std::to_string(cfg.count)
                        + " × (interval " + std::to_string(cfg.interval) + "s)");
        std::cout << "\n";
    }

    /* ── Run queries ────────────────────────────────────────────────────── */
    std::vector<NTPResult> results;
    results.reserve(cfg.count);

    for (int i = 0; i < cfg.count; i++) {
        if (i > 0) sleep((unsigned)cfg.interval);
        NTPResult r = query_once(cfg.host, cfg.port, cfg.timeout,
                                 af, cfg.source_port);
        if (!r.ok) return EXIT_FAILURE;
        results.push_back(r);
    }

    /* Use the last result for server info display */
    const NTPResult &last = results.back();
    const NTPPacket &pkt  = last.pkt;

    uint8_t li      = (pkt.li_vn_mode >> 6) & 0x03;
    uint8_t vn      = (pkt.li_vn_mode >> 3) & 0x07;
    uint8_t mode    = (pkt.li_vn_mode)       & 0x07;
    (void)mode;

    /* ── Server info section ────────────────────────────────────────────── */
    if (!cfg.quiet) {
        sep();
        std::cout << "  " << Color::c(Color::BOLD)
                  << "NTP Server Information"
                  << Color::c(Color::RESET) << "\n";
        sep();

        kv("NTP Version",      "v" + std::to_string(vn));
        kv("Stratum",          stratum_str(pkt.stratum));
        kv("Leap Indicator",   li_str(li));
        kv("Reference ID",     refid_str(pkt.ref_id, pkt.stratum));
        kv("Poll Interval",    std::to_string(pkt.poll)
                             + " (2^" + std::to_string(pkt.poll) + " = "
                             + std::to_string(1 << pkt.poll) + "s)");
        kv("Precision",        std::to_string((int)pkt.precision)
                             + " (2^" + std::to_string((int)pkt.precision)
                             + " ≈ "
                             + [&]() {
                                   std::ostringstream s;
                                   double us = pow(2.0, pkt.precision) * 1e6;
                                   if (us < 1.0)
                                       s << std::fixed << std::setprecision(3)
                                         << us * 1e3 << " ns";
                                   else
                                       s << std::fixed << std::setprecision(3)
                                         << us << " µs";
                                   return s.str();
                               }() + ")");
        kv("Root Delay",       ms_str(fixed1616_to_ms(pkt.root_delay)));
        kv("Root Dispersion",  ms_str(ufixed1616_to_ms(pkt.root_dispersion)));
        std::cout << "\n";
    }

    /* ── Verbose packet dump ────────────────────────────────────────────── */
    if (cfg.verbose && !cfg.quiet) {
        sep();
        std::cout << "  " << Color::c(Color::BOLD)
                  << "Raw Packet Fields"
                  << Color::c(Color::RESET) << "\n";
        sep();

        auto ts_str = [&](uint32_t sec_be, uint32_t frac_be) {
            uint32_t s = ntohl(sec_be), f = ntohl(frac_be);
            std::ostringstream o;
            o << s << "." << std::setw(10) << std::setfill('0') << f
              << " (NTP)";
            if (s >= NTP_UNIX_DELTA) {
                double u = ntp_to_unix(sec_be, frac_be);
                o << "  =  " << format_unix(u, cfg.utc, cfg.fmt)
                  << (cfg.utc ? " UTC" : " " + local_tz());
            }
            return o.str();
        };

        kv("LI/VN/Mode (hex)", [&](){
            std::ostringstream o;
            o << "0x" << std::hex << std::uppercase
              << (int)pkt.li_vn_mode;
            return o.str(); }());
        kv("Stratum (raw)",    std::to_string(pkt.stratum));
        kv("Poll (raw)",       std::to_string(pkt.poll));
        kv("Precision (raw)",  std::to_string((int)pkt.precision));
        kv("Root Delay (raw)", std::to_string(ntohl((uint32_t)pkt.root_delay)));
        kv("Root Disp (raw)",  std::to_string(ntohl(pkt.root_dispersion)));
        kv("Ref Timestamp",    ts_str(pkt.ref_ts_sec,  pkt.ref_ts_frac));
        kv("Orig Timestamp",   ts_str(pkt.orig_ts_sec, pkt.orig_ts_frac));
        kv("Rx Timestamp",     ts_str(pkt.rx_ts_sec,   pkt.rx_ts_frac));
        kv("Tx Timestamp",     ts_str(pkt.tx_ts_sec,   pkt.tx_ts_frac));
        std::cout << "\n";
    }

    /* ── Date / Time section ────────────────────────────────────────────── */
    if (!cfg.quiet) {
        sep();
        std::cout << "  " << Color::c(Color::BOLD)
                  << "Date / Time"
                  << Color::c(Color::RESET) << "\n";
        sep();
    }

    /* Raw mode: just print the NTP transmit timestamp */
    if (cfg.raw) {
        std::cout << ntohl(pkt.tx_ts_sec) << "."
                  << ntohl(pkt.tx_ts_frac) << "\n";
        return EXIT_SUCCESS;
    }

    std::string tz_tag = cfg.utc ? "UTC" : local_tz();

    if (cfg.quiet) {
        /* Quiet: just the formatted server time */
        std::cout << format_unix(last.server_time, cfg.utc, cfg.fmt)
                  << "\n";
    } else {
        kv("Server Time",
           format_unix(last.server_time, cfg.utc, cfg.fmt) + "  " + tz_tag,
           Color::GREEN);

        kv("Local Clock",
           format_unix(unix_now(), cfg.utc, cfg.fmt) + "  " + tz_tag,
           Color::DIM);

        /* RTT and offset for single query */
        if (cfg.count == 1) {
            kv("Round-trip delay",  ms_str(last.rtt_ms));
            std::ostringstream off;
            off << std::showpos << std::fixed << std::setprecision(3)
                << last.offset_ms << " ms";
            kv("Clock offset",
               off.str(),
               std::abs(last.offset_ms) > 100.0 ? Color::YELLOW : Color::GREEN);
        }
    }

    /* ── Multi-query statistics ─────────────────────────────────────────── */
    if (cfg.count > 1 && !cfg.quiet) {
        double sum_off = 0, sum_rtt = 0;
        double min_rtt = results[0].rtt_ms, max_rtt = results[0].rtt_ms;
        double min_off = results[0].offset_ms, max_off = results[0].offset_ms;

        for (auto &res : results) {
            sum_off += res.offset_ms;
            sum_rtt += res.rtt_ms;
            min_rtt  = std::min(min_rtt, res.rtt_ms);
            max_rtt  = std::max(max_rtt, res.rtt_ms);
            min_off  = std::min(min_off, res.offset_ms);
            max_off  = std::max(max_off, res.offset_ms);
        }
        double avg_rtt = sum_rtt / cfg.count;
        double avg_off = sum_off / cfg.count;

        /* Jitter (std dev of RTT) */
        double var = 0;
        for (auto &res : results)
            var += (res.rtt_ms - avg_rtt) * (res.rtt_ms - avg_rtt);
        double jitter = cfg.count > 1 ? sqrt(var / (cfg.count - 1)) : 0.0;

        std::cout << "\n";
        sep();
        std::cout << "  " << Color::c(Color::BOLD)
                  << "Statistics (" << cfg.count << " queries)"
                  << Color::c(Color::RESET) << "\n";
        sep();
        kv("RTT  min/avg/max",
           ms_str(min_rtt) + " / " + ms_str(avg_rtt) + " / " + ms_str(max_rtt));
        kv("Jitter",  ms_str(jitter));
        std::ostringstream off;
        off << std::showpos << std::fixed << std::setprecision(3);
        off << min_off << " ms / " << avg_off << " ms / " << max_off << " ms";
        kv("Offset min/avg/max", off.str());
    }

    /* ── Footer ─────────────────────────────────────────────────────────── */
    if (!cfg.quiet) {
        std::cout << "\n";
        sep();
        std::cout << Color::c(Color::DIM)
                  << "  " NTPTEST_DEVELOPER "  <" NTPTEST_URL ">  "
                     "<" NTPTEST_SUPPORT ">"
                  << Color::c(Color::RESET) << "\n";
        sep();
        std::cout << "\n";
    }

    return EXIT_SUCCESS;
}
