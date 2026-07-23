//
// network_manager.cpp
//

#include "network/network_manager.h"

#include "bmc64_log.h"
#include "circle_glue.h"
#include "cglueio.h"
#include "filetable.h"

#include <circle/net/dnsclient.h>
#include <circle/net/ipaddress.h>
#include <circle/net/netconfig.h>
#include <circle/net/socket.h>
#include <circle/sched/scheduler.h>
#include <circle/sched/task.h>
#include <circle/string.h>
#include <circle/timer.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

struct emux_wifi_ap {
  char ssid[64];
  int freq_mhz;
  int channel;
  int rssi_dbm;
};

namespace {

CNetSubSystem *g_menuNetwork = 0;
bool g_networkFeatureEnabled = false;
char g_networkDiskVolume[16] = "SD";
CBcm4343Device *g_scanWLAN = 0;
bool g_scanWLANRequiresReboot = false;
constexpr int kIpProtoTcp = 6;
constexpr unsigned kWifiScanPollMS = 50;

typedef u16 __le16;
typedef u32 __le32;

struct brcmf_bss_info_le {
  __le32 version;
#define BRCMF_BSS_INFO_VERSION 109
  __le32 length;
  u8 BSSID[6];
  __le16 beacon_period;
  __le16 capability;
  u8 SSID_len;
  u8 SSID[32];
  struct {
    __le32 count;
    u8 rates[16];
  } rateset;
  __le16 chanspec;
  __le16 atim_window;
  u8 dtim_period;
  __le16 RSSI;
  s8 phy_noise;
  u8 n_cap;
  __le32 nbss_cap;
  u8 ctl_ch;
  __le32 reserved32[1];
  u8 flags;
  u8 reserved[3];
  u8 basic_mcs[16];
  __le16 ie_offset;
  __le32 ie_length;
  __le16 SNR;
};

struct brcmf_escan_result_le {
  __le32 buflen;
  __le32 version;
  __le16 sync_id;
  __le16 bss_count;
  struct brcmf_bss_info_le bss_info_le;
};

bool IsNullAddress(const u8 *address) {
  return address == 0 ||
         (address[0] == 0 && address[1] == 0 &&
          address[2] == 0 && address[3] == 0);
}

const char *NetworkAdapterName(TBmxNetworkAdapter adapter) {
  switch (adapter) {
  case BMX_NETWORK_ETHERNET:
    return "ethernet";
  case BMX_NETWORK_WIFI:
    return "wifi";
  case BMX_NETWORK_OFF:
  default:
    return "off";
  }
}

void LogNetworkAddress(CNetSubSystem *net) {
  if (net == 0) {
    return;
  }

  CString ip;
  CString dns;
  net->GetConfig()->GetIPAddress()->Format(&ip);
  net->GetConfig()->GetDNSServer()->Format(&dns);
  BMC64_NET_EVENT("ready ip %s dns %s", (const char *)ip, (const char *)dns);
}

int ChannelFromFrequency(int freq) {
  if (freq == 2484) {
    return 14;
  }
  if (2412 <= freq && freq <= 2472 && (freq - 2407) % 5 == 0) {
    return (freq - 2407) / 5;
  }
  if (5000 <= freq && freq <= 5900 && (freq - 5000) % 5 == 0) {
    return (freq - 5000) / 5;
  }
  return 0;
}

int FrequencyFromChanspec(u16 chanspec) {
  u8 channel = chanspec & 0xff;
  if (1 <= channel && channel <= 14) {
    static const int freqs[] = {
        2412, 2417, 2422, 2427, 2432, 2437, 2442,
        2447, 2452, 2457, 2462, 2467, 2472, 2484};
    return freqs[channel - 1];
  }
  if (32 <= channel && channel <= 173) {
    return 5160 + (channel - 32) * 5;
  }
  return 0;
}

void SleepForScanPoll(void) {
  if (CScheduler::IsActive()) {
    CScheduler::Get()->MsSleep(kWifiScanPollMS);
  } else {
    CTimer::SimpleMsDelay(kWifiScanPollMS);
  }
}

void CopySSID(char *dest, int destLen, const u8 *ssid, unsigned ssidLen) {
  if (dest == 0 || destLen <= 0) {
    return;
  }
  dest[0] = '\0';
  if (ssid == 0 || ssidLen == 0) {
    return;
  }

  unsigned copyLen = ssidLen < (unsigned)destLen - 1
                       ? ssidLen
                       : (unsigned)destLen - 1;
  for (unsigned i = 0; i < copyLen; i++) {
    dest[i] = ssid[i] >= 32 && ssid[i] <= 126 ? (char)ssid[i] : '?';
  }
  dest[copyLen] = '\0';
}

void AddOrUpdateAP(struct emux_wifi_ap *aps, int maxAps, int *count,
                   const struct emux_wifi_ap &candidate) {
  if (aps == 0 || count == 0 || maxAps <= 0 || candidate.ssid[0] == '\0') {
    return;
  }

  for (int i = 0; i < *count; i++) {
    if (strcmp(aps[i].ssid, candidate.ssid) == 0 &&
        aps[i].freq_mhz == candidate.freq_mhz) {
      if (candidate.rssi_dbm > aps[i].rssi_dbm) {
        aps[i] = candidate;
      }
      return;
    }
  }

  if (*count < maxAps) {
    aps[*count] = candidate;
    (*count)++;
  }
}

void ParseScanBuffer(const u8 *buffer, unsigned length,
                     struct emux_wifi_ap *aps, int maxAps, int *count) {
  if (buffer == 0 || length < sizeof(brcmf_escan_result_le)) {
    return;
  }

  const brcmf_escan_result_le *scan =
      (const brcmf_escan_result_le *)buffer;
  const brcmf_bss_info_le *bss = &scan->bss_info_le;
  const u8 *end = buffer + length;

  for (unsigned i = 0; i < scan->bss_count; i++) {
    const u8 *bssStart = (const u8 *)bss;
    if (bssStart + sizeof(brcmf_bss_info_le) > end ||
        bss->length < sizeof(brcmf_bss_info_le) ||
        bssStart + bss->length > end) {
      return;
    }
    if (bss->version == BRCMF_BSS_INFO_VERSION) {
      struct emux_wifi_ap ap;
      memset(&ap, 0, sizeof ap);
      CopySSID(ap.ssid, sizeof ap.ssid, bss->SSID, bss->SSID_len);
      ap.freq_mhz = FrequencyFromChanspec(bss->chanspec);
      ap.channel = ChannelFromFrequency(ap.freq_mhz);
      ap.rssi_dbm = (int)(s16)bss->RSSI;
      AddOrUpdateAP(aps, maxAps, count, ap);
    }
    bss = (const brcmf_bss_info_le *)(bssStart + bss->length);
  }
}

void SortAPsByRSSI(struct emux_wifi_ap *aps, int count) {
  for (int i = 1; i < count; i++) {
    struct emux_wifi_ap value = aps[i];
    int j = i - 1;
    while (j >= 0 && aps[j].rssi_dbm < value.rssi_dbm) {
      aps[j + 1] = aps[j];
      j--;
    }
    aps[j + 1] = value;
  }
}

void EscapeWPAString(FILE *fp, const char *value) {
  if (fp == 0 || value == 0) {
    return;
  }

  for (const char *p = value; *p != '\0'; ++p) {
    if (*p == '"' || *p == '\\') {
      fputc('\\', fp);
    }
    fputc(*p, fp);
  }
}

bool WriteWPAConfig(const char *path, const char *ssid, const char *psk,
                    const char *country) {
  if (path == 0 || ssid == 0 || ssid[0] == '\0' ||
      psk == 0 || psk[0] == '\0') {
    BMC64_NET_EVENT("wifi requires SSID and PSK");
    return false;
  }

  FILE *fp = fopen(path, "w");
  if (fp == 0) {
    BMC64_NET_EVENT("wifi cannot write %s", path);
    return false;
  }

  fprintf(fp, "country=%s\n\n", country != 0 && country[0] != '\0'
                                   ? country : "DE");
  fprintf(fp, "network={\n");
  fprintf(fp, "\tssid=\"");
  EscapeWPAString(fp, ssid);
  fprintf(fp, "\"\n");
  fprintf(fp, "\tpsk=\"");
  EscapeWPAString(fp, psk);
  fprintf(fp, "\"\n");
  fprintf(fp, "}\n");
  fclose(fp);
  return true;
}

void CopyCString(char *dest, int destLen, const CString &src) {
  if (dest == 0 || destLen <= 0) {
    return;
  }
  snprintf(dest, destLen, "%s", (const char *)src);
}

void FormatIP(const CIPAddress *address, char *dest, int destLen) {
  if (dest == 0 || destLen <= 0) {
    return;
  }
  dest[0] = '\0';
  if (address == 0 || !address->IsSet()) {
    return;
  }

  CString formatted;
  address->Format(&formatted);
  CopyCString(dest, destLen, formatted);
}

void FormatIPBytes(const u8 *address, char *dest, int destLen) {
  if (dest == 0 || destLen <= 0) {
    return;
  }
  dest[0] = '\0';
  if (address == 0 || IsNullAddress(address)) {
    return;
  }
  snprintf(dest, destLen, "%u.%u.%u.%u",
           address[0], address[1], address[2], address[3]);
}

void RunNetworkConnectTest(CNetSubSystem *net, const char *host,
                           unsigned port) {
  if (net == 0 || host == 0 || host[0] == '\0' || port == 0) {
    return;
  }

  BMC64_NET_DEBUG("test resolving %s", host);
  CIPAddress remoteIP;
  CDNSClient dns(net);
  if (!dns.Resolve(host, &remoteIP)) {
    BMC64_NET_EVENT("test resolve failed %s", host);
    return;
  }

  CString remote;
  remoteIP.Format(&remote);
  BMC64_NET_DEBUG("test connecting %s:%u", (const char *)remote, port);

  CSocket socket(net, kIpProtoTcp);
  const int result = socket.Connect(remoteIP, (u16)port);
  BMC64_NET_DEBUG("test connect %s", result == 0 ? "ok" : "failed");
  (void)result;
}

class NetworkStatusTask : public CTask {
public:
  NetworkStatusTask(CNetSubSystem *net, unsigned timeoutMS,
                    const char *adapter, const char *testHost,
                    unsigned testPort)
      : CTask(), m_net(net), m_timeoutMS(timeoutMS), m_testPort(testPort),
        m_timeoutLogged(false) {
    SetName("netstatus");
    strncpy(m_adapter, adapter != 0 ? adapter : "network",
            sizeof(m_adapter) - 1);
    m_adapter[sizeof(m_adapter) - 1] = '\0';
    m_testHost[0] = '\0';
    if (testHost != 0) {
      strncpy(m_testHost, testHost, sizeof(m_testHost) - 1);
      m_testHost[sizeof(m_testHost) - 1] = '\0';
    }
  }

  void Run(void) {
    const unsigned start = CTimer::GetClockTicks();
    const unsigned timeoutUS = m_timeoutMS * 1000;

    while (m_net != 0 && !m_net->IsRunning()) {
      if (!m_timeoutLogged && m_timeoutMS != 0 &&
          CTimer::GetClockTicks() - start >= timeoutUS) {
        BMC64_NET_EVENT("%s pending after %u ms", m_adapter, m_timeoutMS);
        m_timeoutLogged = true;
      }
      CScheduler::Get()->MsSleep(50);
    }

    if (m_net != 0) {
      LogNetworkAddress(m_net);
      RunNetworkConnectTest(m_net, m_testHost, m_testPort);
    }
  }

private:
  CNetSubSystem *m_net;
  unsigned m_timeoutMS;
  char m_adapter[16];
  char m_testHost[96];
  unsigned m_testPort;
  bool m_timeoutLogged;
};

} // namespace

namespace bmx {

NetworkManager::NetworkManager(void)
    : m_net(0), m_wlan(0), m_wpaSupplicant(0), m_statusTask(0) {
  m_wlanFirmwarePath[0] = '\0';
  m_wpaConfigPath[0] = '\0';
}

NetworkManager::~NetworkManager(void) {
  if (g_menuNetwork == m_net) {
    g_menuNetwork = 0;
  }
  g_networkFeatureEnabled = false;
  delete m_wpaSupplicant;
  m_wpaSupplicant = 0;
  delete m_wlan;
  m_wlan = 0;
  delete m_net;
  m_net = 0;
  m_statusTask = 0;
}

bool NetworkManager::Initialize(const ViceOptions &options) {
  snprintf(g_networkDiskVolume, sizeof g_networkDiskVolume, "%s",
           options.GetDiskVolume());

  TBmxNetworkAdapter adapter = options.GetNetworkAdapter();
  g_networkFeatureEnabled = adapter != BMX_NETWORK_OFF;
  if (adapter == BMX_NETWORK_OFF) {
    if (options.Rs232NetEnabled()) {
      BMC64_NET_EVENT("disabled; RS232 requires Ethernet or WiFi");
    } else {
      BMC64_NET_EVENT("disabled");
    }
    return true;
  }

  const bool useDHCP = options.NetworkDhcpEnabled();
  const u8 *ip = 0;
  const u8 *netmask = 0;
  const u8 *gateway = 0;
  const u8 *dns = 0;

  if (!useDHCP) {
    if (!options.NetworkStaticAddressValid() ||
        IsNullAddress(options.GetNetworkNetMask())) {
      BMC64_NET_EVENT("static %s requires network_ip and network_netmask",
                      NetworkAdapterName(adapter));
      return true;
    }

    ip = options.GetNetworkIPAddress();
    netmask = options.GetNetworkNetMask();
    if (!IsNullAddress(options.GetNetworkGateway())) {
      gateway = options.GetNetworkGateway();
    }
    if (!IsNullAddress(options.GetNetworkDNSServer())) {
      dns = options.GetNetworkDNSServer();
    }
  }

  BMC64_NET_EVENT("init %s %s", NetworkAdapterName(adapter),
                  useDHCP ? "dhcp" : "static");

  const TNetDeviceType deviceType = adapter == BMX_NETWORK_WIFI
                                      ? NetDeviceTypeWLAN
                                      : NetDeviceTypeEthernet;

  if (adapter == BMX_NETWORK_WIFI) {
    snprintf(m_wlanFirmwarePath, sizeof m_wlanFirmwarePath, "%s:/firmware/",
             options.GetDiskVolume());
    snprintf(m_wpaConfigPath, sizeof m_wpaConfigPath, "%s:/wpa_supplicant.conf",
             options.GetDiskVolume());

    if (!WriteWPAConfig(m_wpaConfigPath, options.GetNetworkWifiSSID(),
                        options.GetNetworkWifiPSK(),
                        options.GetNetworkWifiCountry())) {
      return true;
    }

    m_wlan = new CBcm4343Device(m_wlanFirmwarePath);
    if (m_wlan == 0) {
      BMC64_NET_EVENT("failed to allocate wifi device");
      return true;
    }
    if (!m_wlan->Initialize()) {
      BMC64_NET_EVENT("wifi device initialize failed");
      return true;
    }
  }

  m_net = new CNetSubSystem(ip, netmask, gateway, dns, "bmx", deviceType);
  if (m_net == 0) {
    BMC64_NET_EVENT("failed to allocate network subsystem");
    return true;
  }

  if (!m_net->Initialize(FALSE)) {
    BMC64_NET_EVENT("%s initialize failed", NetworkAdapterName(adapter));
    delete m_net;
    m_net = 0;
    return true;
  }

  CGlueNetworkInit(*m_net);

  if (adapter == BMX_NETWORK_WIFI) {
    m_wpaSupplicant = new CWPASupplicant(m_wpaConfigPath);
    if (m_wpaSupplicant == 0) {
      BMC64_NET_EVENT("failed to allocate wifi supplicant");
      return true;
    }
    if (!m_wpaSupplicant->Initialize()) {
      BMC64_NET_EVENT("wifi supplicant initialize failed");
      return true;
    }
  }

  g_menuNetwork = m_net;
  const unsigned waitMS = options.GetNetworkWaitMS();
  const unsigned start = CTimer::GetClockTicks();
  const unsigned timeoutUS = waitMS * 1000;
  while (waitMS != 0 && !m_net->IsRunning()) {
    if (CTimer::GetClockTicks() - start >= timeoutUS) {
      BMC64_NET_EVENT("%s pending after %u ms", NetworkAdapterName(adapter),
                      waitMS);
      break;
    }
    CScheduler::Get()->Yield();
  }

  if (m_net->IsRunning()) {
    LogNetworkAddress(m_net);
  }
  m_statusTask = new NetworkStatusTask(m_net, waitMS, NetworkAdapterName(adapter),
                                       options.GetNetworkTestHost(),
                                       options.GetNetworkTestPort());
  return true;
}

bool NetworkManager::IsReady(void) const {
  return m_net != 0 && m_net->IsRunning();
}

CNetSubSystem *NetworkManager::GetNetSubSystem(void) const {
  return m_net;
}

void NetworkManager::LogAddress(void) const {
  LogNetworkAddress(m_net);
}

void NetworkManager::RunConnectTest(const ViceOptions &options) {
  RunNetworkConnectTest(m_net, options.GetNetworkTestHost(),
                        options.GetNetworkTestPort());
}

CNetSubSystem *GetActiveNetworkSubsystem(void) {
  if (!g_networkFeatureEnabled || g_menuNetwork == 0 ||
      !g_menuNetwork->IsRunning()) {
    return 0;
  }
  return g_menuNetwork;
}

bool ReadNetworkFeatureState(bool *feature_enabled, bool *ready) {
  if (feature_enabled == 0 || ready == 0) {
    return false;
  }
  *feature_enabled = g_networkFeatureEnabled;
  *ready = g_menuNetwork != 0 && g_menuNetwork->IsRunning();
  return true;
}

} // namespace bmx

extern "C" int emux_get_network_addresses(char *ip, int ipLen,
                                           char *netmask, int netmaskLen,
                                           char *gateway, int gatewayLen,
                                           char *dns, int dnsLen) {
  if (ip != 0 && ipLen > 0) {
    ip[0] = '\0';
  }
  if (netmask != 0 && netmaskLen > 0) {
    netmask[0] = '\0';
  }
  if (gateway != 0 && gatewayLen > 0) {
    gateway[0] = '\0';
  }
  if (dns != 0 && dnsLen > 0) {
    dns[0] = '\0';
  }

  if (g_menuNetwork == 0 || !g_menuNetwork->IsRunning()) {
    return 0;
  }

  CNetConfig *config = g_menuNetwork->GetConfig();
  if (config == 0) {
    return 0;
  }

  FormatIP(config->GetIPAddress(), ip, ipLen);
  FormatIPBytes(config->GetNetMask(), netmask, netmaskLen);
  FormatIP(config->GetDefaultGateway(), gateway, gatewayLen);
  FormatIP(config->GetDNSServer(), dns, dnsLen);
  return 1;
}

extern "C" int emux_wifi_scan_aps(struct emux_wifi_ap *aps, int maxAps,
                                   unsigned timeoutMS) {
  if (aps == 0 || maxAps <= 0) {
    return -1;
  }
  memset(aps, 0, sizeof(*aps) * maxAps);

  CBcm4343Device *wlan =
      (CBcm4343Device *)CNetDevice::GetNetDevice(NetDeviceTypeWLAN);
  char firmwarePath[64];

  if (wlan == 0) {
    if (g_scanWLAN == 0) {
      snprintf(firmwarePath, sizeof firmwarePath, "%s:/firmware/",
               g_networkDiskVolume[0] != '\0' ? g_networkDiskVolume : "SD");
      CBcm4343Device *scanWLAN = new CBcm4343Device(firmwarePath);
      if (scanWLAN == 0) {
        return -1;
      }
      if (!scanWLAN->Initialize()) {
        return -1;
      }
      g_scanWLAN = scanWLAN;
      g_scanWLANRequiresReboot = true;
    }
    wlan = g_scanWLAN;
  }

  unsigned len = 0;
  u8 buffer[FRAME_BUFFER_SIZE];
  while (wlan->ReceiveScanResult(buffer, &len)) {
  }

  if (timeoutMS == 0) {
    timeoutMS = 4500;
  }
  unsigned scanSeconds = (timeoutMS + 999) / 1000;
  if (scanSeconds < 1) {
    scanSeconds = 1;
  }

  if (!wlan->Control("escan %u", scanSeconds)) {
    return -1;
  }

  int count = 0;
  const unsigned timeoutUS = timeoutMS * 1000;
  const unsigned start = CTimer::GetClockTicks();
  do {
    while (wlan->ReceiveScanResult(buffer, &len)) {
      ParseScanBuffer(buffer, len, aps, maxAps, &count);
    }
    SleepForScanPoll();
  } while ((unsigned)(CTimer::GetClockTicks() - start) < timeoutUS);

  while (wlan->ReceiveScanResult(buffer, &len)) {
    ParseScanBuffer(buffer, len, aps, maxAps, &count);
  }

  wlan->Control("escan 0");
  SortAPsByRSSI(aps, count);

  return count;
}

extern "C" int emux_wifi_scan_requires_reboot(void) {
  return g_scanWLANRequiresReboot ? 1 : 0;
}

extern "C" int emux_network_is_ready(void) {
  return g_networkFeatureEnabled && g_menuNetwork != 0 &&
         g_menuNetwork->IsRunning();
}

extern "C" int emux_network_socket_close(int fd) {
  _CircleStdlib::FileTable::FileTableLock fileTableLock;

  _CircleStdlib::CircleFile *const file =
      _CircleStdlib::FileTable::GetFile(fd);
  if (file == 0 || !file->IsOpen()) {
    errno = EBADF;
    return -1;
  }

  _CircleStdlib::CGlueIO *const glue = file->GetGlueIO();
  if (glue == 0 || glue->GetRefCount() == 0) {
    errno = EBADF;
    return -1;
  }

  glue->DecrementRefCount();

  int result = 0;
  if (glue->GetRefCount() == 0) {
    result = glue->Close();
    file->CloseGlueIO();
  }

  if (CScheduler::IsActive()) {
    CScheduler::Get()->Yield();
  }

  return result;
}
