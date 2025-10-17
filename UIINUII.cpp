
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/utsname.h>
#include <fstream>
#include <array>
#include <memory>
#include <limits.h>
#include <algorithm>
#include <regex>
#include <filesystem>
#include <map>
#include <pwd.h>
#include <grp.h>
#include <functional>
#include <cstdlib>
#include <system_error>
#include <cstdio>
#include <sstream>
#include <optional>
#include <unordered_map>
#include <dirent.h>
#include <sys/stat.h>
#include <limits>
#include <netdb.h>
#include <sys/time.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <vector>


namespace fs = std::filesystem;

struct SocketEntry {
    std::string proto;
    std::string local_ip;
    unsigned local_port;
    unsigned long inode;
    std::string state;
};

static std::optional<std::pair<std::string,unsigned>> parse_ip_port_hex(const std::string& hexaddr) {
    auto pos = hexaddr.find(':');
    if (pos == std::string::npos) return std::nullopt;
    std::string hexip = hexaddr.substr(0,pos);
    std::string hexport = hexaddr.substr(pos+1);
    unsigned port = 0;
    std::stringstream ss;
    ss << std::hex << hexport;
    ss >> port;
    if (hexip.size() == 8) {
        unsigned long ipnum = 0;
        std::stringstream sx;
        sx << std::hex << hexip;
        sx >> ipnum;
        unsigned a = (ipnum & 0xFF);
        unsigned b = ((ipnum >> 8) & 0xFF);
        unsigned c = ((ipnum >> 16) & 0xFF);
        unsigned d = ((ipnum >> 24) & 0xFF);
        std::ostringstream ipout;
        ipout << a << "." << b << "." << c << "." << d;
        return std::make_pair(ipout.str(), port);
    }
    return std::nullopt;
}

std::vector<SocketEntry> parse_proc_net(const std::string& path, const std::string& proto) {
    std::vector<SocketEntry> out;
    std::ifstream in(path);
    if (!in.is_open()) return out;
    std::string header;
    std::getline(in, header);
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string sl, local, rem, st;
        if (!(iss >> sl >> local >> rem >> st)) continue;
        std::vector<std::string> toks;
        std::istringstream iss2(line);
        std::string t;
        while (iss2 >> t) toks.push_back(t);
        std::string inode;
        if (toks.size() >= 10) inode = toks[9];
        else {
            for (auto it = toks.rbegin(); it != toks.rend(); ++it) {
                if (std::regex_match(*it, std::regex("^[0-9]+$"))) { inode = *it; break; }
            }
        }
        if (inode.empty()) continue;
        unsigned long inode_val = std::stoul(inode);
        auto la = parse_ip_port_hex(local);
        std::string local_ip = la ? la->first : local;
        unsigned local_port = la ? la->second : 0;
        SocketEntry se;
        se.proto = proto;
        se.local_ip = local_ip;
        se.local_port = local_port;
        se.inode = inode_val;
        se.state = st;
        out.push_back(se);
    }
    return out;
}

std::unordered_map<unsigned long, std::pair<int,std::string>> map_inode_to_pid(bool &permission_error) {
    std::unordered_map<unsigned long, std::pair<int,std::string>> map;
    DIR *d = opendir("/proc");
    if (!d) { permission_error = true; return map; }
    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_type != DT_DIR) continue;
        std::string dname = ent->d_name;
        if (!std::all_of(dname.begin(), dname.end(), ::isdigit)) continue;
        int pid = std::stoi(dname);
        fs::path fdpath = "/proc/" + dname + "/fd";
        std::error_code ec;
        if (!fs::exists(fdpath, ec)) {
            if (ec) { permission_error = true; continue; }
            else continue;
        }
        try {
            for (auto &fdent : fs::directory_iterator(fdpath, ec)) {
                if (ec) { permission_error = true; break; }
                std::error_code re;
                std::string target = fs::read_symlink(fdent.path(), re).string();
                if (re) { permission_error = true; continue; }
                std::smatch m;
                static std::regex sock_re(R"(socket:\[(\d+)\])");
                if (std::regex_search(target, m, sock_re)) {
                    unsigned long inode = std::stoul(m[1].str());
                    if (map.find(inode) == map.end()) {
                        std::string cmd;
                        std::ifstream cmdf("/proc/" + dname + "/cmdline");
                        if (cmdf.is_open()) {
                            std::getline(cmdf, cmd, '\0');
                        }
                        if (cmd.empty()) {
                            std::ifstream commf("/proc/" + dname + "/comm");
                            if (commf.is_open()) std::getline(commf, cmd);
                        }
                        map[inode] = std::make_pair(pid, cmd);
                    }
                }
            }
        } catch (...) {
            permission_error = true;
            continue;
        }
    }
    closedir(d);
    return map;
}

int uid_of_pid(int pid) {
    std::string status = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream in(status);
    if (!in.is_open()) return -1;
    std::string line;
    while (std::getline(in,line)) {
        if (line.rfind("Uid:",0) == 0) {
            std::istringstream iss(line.substr(4));
            int real, eff, saved, fs;
            if (iss >> real >> eff >> saved >> fs) return real;
        }
    }
    return -1;
}

void CheckRootOwnedListeningSockets() {
    bool permission_error = false;
    auto tcp = parse_proc_net("/proc/net/tcp", "tcp");
    auto tcp6 = parse_proc_net("/proc/net/tcp6", "tcp6");
    std::vector<SocketEntry> all;
    all.insert(all.end(), tcp.begin(), tcp.end());
    all.insert(all.end(), tcp6.begin(), tcp6.end());
    bool map_perm_error = false;
    auto inode_map = map_inode_to_pid(map_perm_error);
    if (map_perm_error) permission_error = true;
    std::cout << "\n[Escalation] Root-owned listening sockets assessment\n";
    size_t total = 0;
    size_t findings = 0;
    size_t unexplorable = 0;
    for (auto &s : all) {
        if (s.state != "0A") continue;
        ++total;
        auto it = inode_map.find(s.inode);
        if (it == inode_map.end()) {
            ++unexplorable;
            std::cout << "  [UNEXPLOREABLE] socket inode=" << s.inode << " proto=" << s.proto
                      << " local=" << s.local_ip << ":" << s.local_port
                      << " (owner PID unknown - permission/visibility limits)\n";
            continue;
        }
        int pid = it->second.first;
        std::string cmd = it->second.second;
        int uid = uid_of_pid(pid);
        if (uid == -1) {
            ++unexplorable;
            std::cout << "  [UNEXPLOREABLE] socket inode=" << s.inode << " proto=" << s.proto
                      << " local=" << s.local_ip << ":" << s.local_port
                      << " PID=" << pid << " CMD=" << cmd << " (could not resolve UID)\n";
            continue;
        }
        if (uid == 0) {
            ++findings;
            std::cout << "  [POTENTIALLY_EXPLOITABLE] socket inode=" << s.inode << " proto=" << s.proto
                      << " local=" << s.local_ip << ":" << s.local_port
                      << " PID=" << pid << " CMD=" << cmd << "\n";
        }
    }
    if (total == 0) {
        std::cout << "  No listening TCP sockets found to assess.\n";
        return;
    }
    if (permission_error || unexplorable > 0) {
        std::cout << "  Note: some sockets could not be fully inspected due to permission/visibility restrictions.\n";
        std::cout << "  Entries marked UNEXPLOREABLE are assumed NOT PLAUSIBLE for exploitation by this account.\n";
    }
    std::cout << "  Summary: total_listening=" << total << " root_owned_listening=" << findings
              << " unexplorable=" << unexplorable << "\n";
}


using namespace std;


int OSInfo() {
    struct utsname buf1;
    if (uname(&buf1) != 0) {
        perror("uname failed");
        return 1;
    }

    std::ifstream f("/etc/os-release");
    if (!f) {
        std::cerr << "Could not open /etc/os-release\n";
        return 1;
    }

    std::string line;
    std::string pretty_name;
    while (std::getline(f, line)) {
        if (line.find("PRETTY_NAME=") == 0) {
            auto val = line.substr(12);
            if (!val.empty() && val.front() == '"') val.erase(0,1);
            if (!val.empty() && val.back() == '"') val.pop_back();
            pretty_name = val;
            break;
        }
    }

    std::cout << "Operating System: " << buf1.sysname << ", " << pretty_name << "\n";
    std::cout << "Version: " << buf1.version << "\n";
    std::cout << "Release: " << buf1.release << "\n";
    std::cout << "Architecture: " << buf1.machine << "\n";
    return 0;
}

int ProcessorInfo() {
    std::ifstream f("/proc/cpuinfo");
    std::string line;
    std::string model, vendor, cores;

    while (std::getline(f, line)) {
        if (line.find("model name") != std::string::npos && model.empty())
            model = line.substr(line.find(":") + 2);
        else if (line.find("vendor_id") != std::string::npos && vendor.empty())
            vendor = line.substr(line.find(":") + 2);
        else if (line.find("cpu cores") != std::string::npos && cores.empty())
            cores = line.substr(line.find(":") + 2);
    }

    std::cout << "Vendor     : " << vendor << "\n";
    std::cout << "Model      : " << model << "\n";
    std::cout << "CPU Cores  : " << cores << "\n";

    return 0;
}



int GraphicsInfo() {
    std::array<char, 256> buffer;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("lspci -mm | grep -E 'VGA|3D'", "r"), pclose);
    if (!pipe) {
        std::cerr << "Failed to run lspci\n";
        return 1;
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        std::cout << buffer.data();
    }
    return 0;
}



int WifiCardInfo() {
    std::array<char, 128> buffer;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("lspci | grep -i network", "r"), pclose);
    if (!pipe) {
        std::cerr << "Failed to run lspci\n";
        return 1;
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        std::cout << buffer.data();
    }
    return 0;
}


int StorageDriveInfo() {
    std::array<char, 256> buffer;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("lsblk -o NAME,TYPE,SIZE,MODEL", "r"), pclose);
    if (!pipe) {
        std::cerr << "Failed to run lsblk\n";
        return 1;
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        std::cout << buffer.data();
    }
    return 0;
}


int DisplayInfo(){
    std::array<char, 256> buffer;
    std::string output;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("xrandr --query | grep ' connected'", "r"), pclose);
    if (!pipe) {
        std::cerr << "Failed to run xrandr\n";
        return 1;
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        output += buffer.data();
    }

    if (output.empty()) {
        std::cout << "Headless system (no displays connected)\n";
    } else {
        std::cout << output;
    }
    return 0;
}
std::string getTimezone() {
    std::ifstream tzfile("/etc/timezone");
    if (tzfile) {
        std::string tz;
        std::getline(tzfile, tz);
        if (!tz.empty()) return tz;
    }
    char buf[PATH_MAX];
    ssize_t len = readlink("/etc/localtime", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = 0;
        std::string p(buf);
        auto pos = p.find("zoneinfo/");
        if (pos != std::string::npos)
            return p.substr(pos + 9);
        return p;
    }
    if (char* env = getenv("TZ"))
        return env;
    return "Unknown";
}

std::string KeyBoardLanguage() {
    std::array<char, 128> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("setxkbmap -query | grep layout", "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("Failed to run setxkbmap");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    auto pos = result.find(":");
    if (pos != std::string::npos) {
        std::string layout = result.substr(pos + 1);
        size_t start = layout.find_first_not_of(" \t\n\r");
        size_t end = layout.find_last_not_of(" \t\n\r");
        if (start != std::string::npos && end != std::string::npos) {
            return layout.substr(start, end - start + 1);
        }
    }

    return "Unknown";
}


int GetLocationInfo() {
    std::cout << "System Set Timezone: " << getTimezone() << "\n";
    std::string layout = KeyBoardLanguage();
    std::cout << "Current keyboard layout: " << layout << std::endl;
    return 0;
}

int GetConnectedDevices() {
    namespace fs = std::filesystem;
    fs::path usbroot{"/sys/bus/usb/devices"};
    if (!fs::exists(usbroot)) {
        cerr << "USB sysfs path not found\n";
        return 1;
    }

    auto readFile = [](const fs::path& p) -> string {
        ifstream f(p);
        if (!f.is_open()) return "";
        string s;
        getline(f, s);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        return s;
    };

    for (auto& d : fs::directory_iterator(usbroot)) {
        if (!d.is_directory()) continue;
        fs::path dir = d.path();
        if (!fs::exists(dir / "idVendor") || !fs::exists(dir / "idProduct")) continue;

        string vendor = readFile(dir / "idVendor");
        string product = readFile(dir / "idProduct");
        string manufacturer = readFile(dir / "manufacturer");
        string productName = readFile(dir / "product");
        string serial = readFile(dir / "serial");

        cout << "Device: " << dir.filename().string() << "\n";
        cout << "  Vendor ID : " << vendor << "\n";
        cout << "  Product ID: " << product << "\n";
        if (!manufacturer.empty()) cout << "  Manufacturer: " << manufacturer << "\n";
        if (!productName.empty()) cout << "  Product: " << productName << "\n";
        if (!serial.empty()) cout << "  Serial Number: " << serial << "\n";
        cout << "-----------------------------\n";
    }

    return 0;
}


int GetDrivers() {
    ifstream pm("/proc/modules");
    if (!pm) {
        cerr << "Unable to open /proc/modules\n";
        return 1;
    }
    cout << "=== Loaded Kernel Modules ===\n";
    string line;
    vector<string> loaded;

    while (getline(pm, line)) {
        if (line.empty()) continue;

        string name;
        unsigned long size = 0;
        int users = 0;

        istringstream iss(line);
        iss >> name >> size >> users;

        loaded.push_back(name);
        cout << name;
        if (size) cout << "  size=" << size;
        cout << "  users=" << users << "\n";
    }

    cout << "Total loaded modules: " << loaded.size() << "\n";
    return 0;
}

std::string GetInstalledAppProcess() {
    std::string cmd = "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null";
    std::string result;
    char buffer[256];
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "Error opening pipe.";
    while (fgets(buffer, sizeof(buffer), pipe)) result += buffer;
    pclose(pipe);
    return result.empty() ? "No packages found or unsupported system." : result;
}

namespace fs = std::filesystem;

std::string read_file_trim(const fs::path &p) {
    std::ifstream in(p);
    if (!in.is_open()) return "";
    std::string s;
    std::getline(in, s);
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos || end == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

void GetBiosInfo() {

    fs::path dmi_dir;
    std::vector<fs::path> try_dirs = {
        "/sys/class/dmi/id",
        "/sys/devices/virtual/dmi/id"
    };
    for (auto &dir : try_dirs) {
        if (fs::exists(dir) && fs::is_directory(dir)) {
            dmi_dir = dir;
            break;
        }
    }

    if (dmi_dir.empty()) {
        std::cout << "DMI directory not found. BIOS info unavailable.\n";
        return;
    }

    std::vector<std::pair<std::string, std::string>> fields = {
        {"bios_vendor",      "BIOS Vendor"},
        {"bios_version",     "BIOS Version"},
        {"bios_date",        "BIOS Date"},
        {"bios_release",     "BIOS Release"},
        {"bios_rom_size",    "BIOS ROM Size"},
        {"board_name",       "Board Name"},
        {"board_vendor",     "Board Vendor"},
        {"board_version",    "Board Version"},
        {"product_name",     "Product Name"},
        {"product_version",  "Product Version"},
        {"sys_vendor",       "System Vendor"},
        {"chassis_vendor",   "Chassis Vendor"},
        {"modalias",         "Modalias"},
        {"product_serial",   "Product Serial"},
        {"board_serial",     "Board Serial"},
        {"product_uuid",     "Product UUID"}
    };

    for (const auto &f : fields) {
        std::string val = read_file_trim(dmi_dir / f.first);
        std::cout << f.second << ": " << (val.empty() ? "<unavailable>" : val) << "\n";
    }

    fs::path efi_dir = "/sys/firmware/efi/efivars";
    if (fs::exists(efi_dir) && fs::is_directory(efi_dir)) {
        std::cout << "\nUEFI Boot Mode: Enabled (efivars found)\n";
        std::cout << "Some UEFI variables:\n";
        int count = 0;
        for (const auto &entry : fs::directory_iterator(efi_dir)) {
            std::cout << "- " << entry.path().filename().string() << "\n";
            if (++count >= 10) {
                std::cout << "... (" << (std::distance(fs::directory_iterator(efi_dir), fs::directory_iterator{}) - count) << " more hidden)\n";
                break;
            }
        }
    } else {
        std::cout << "\nUEFI Boot Mode: Disabled or efivars not available\n";
    }

    std::cout << "===================================\n";
}

bool FileExists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

int CountSSHKeys(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return 0;
    int count = 0;
    std::string line;
    while (std::getline(f, line)) {
        size_t i = line.find_first_not_of(" \t\r\n");
        if (i != std::string::npos && line[i] != '#')
            ++count;
    }
    return count;
}

std::vector<std::string> LoadValidShells() {
    std::vector<std::string> shells;
    std::ifstream f("/etc/shells");
    std::string s;
    while (std::getline(f, s)) {
        size_t i = s.find_first_not_of(" \t\r\n");
        if (i == std::string::npos || s[i] == '#') continue;
        size_t j = s.find_last_not_of(" \t\r\n");
        shells.push_back(s.substr(i, j - i + 1));
    }
    return shells;
}

bool IsValidShell(const std::string& shell, const std::vector<std::string>& shells) {
    if (shell.empty()) return false;
    for (const auto& sh : shells) {
        if (sh == shell) return true;
    }

    if (shell.find("nologin") != std::string::npos) return false;
    if (shell.find("false") != std::string::npos) return false;
    return true;
}

void GetAllUsers() {
    auto shells = LoadValidShells();

    std::cout << "\n========== User Recon Report ==========\n\n";

    setpwent();
    struct passwd* pw;

    while ((pw = getpwent()) != nullptr) {
        std::string username = pw->pw_name ? pw->pw_name : "";
        uid_t uid = pw->pw_uid;
        gid_t gid = pw->pw_gid;
        std::string home = pw->pw_dir ? pw->pw_dir : "";
        std::string shell = pw->pw_shell ? pw->pw_shell : "";


        if (uid < 1000) continue;
        if (!IsValidShell(shell, shells)) continue;
        bool in_sudo = false, in_wheel = false;
        int ngroups = 0;
        std::vector<gid_t> groups(16);
        if (getgrouplist(username.c_str(), gid, groups.data(), &ngroups) == -1) {
            groups.resize(ngroups);
            getgrouplist(username.c_str(), gid, groups.data(), &ngroups);
        }
        for (int i = 0; i < ngroups; ++i) {
            struct group* gr = getgrgid(groups[i]);
            if (!gr) continue;
            if (strcmp(gr->gr_name, "sudo") == 0) in_sudo = true;
            if (strcmp(gr->gr_name, "wheel") == 0) in_wheel = true;
        }

        std::string ssh_dir = home + "/.ssh";
        std::string auth_keys_path = ssh_dir + "/authorized_keys";
        std::vector<std::string> priv_keys = {
            ssh_dir + "/id_rsa",
            ssh_dir + "/id_ed25519",
            ssh_dir + "/id_ecdsa",
            ssh_dir + "/id_dsa"
        };

        bool home_exists = FileExists(home);
        bool has_auth_keys = FileExists(auth_keys_path);
        int key_count = has_auth_keys ? CountSSHKeys(auth_keys_path) : 0;
        bool has_private_keys = false;
        for (const auto& key : priv_keys) {
            if (FileExists(key)) {
                has_private_keys = true;
                break;
            }
        }

        bool has_netrc = FileExists(home + "/.netrc");
        bool has_lftp = FileExists(home + "/.lftp/rc");
        bool has_wgetrc = FileExists(home + "/.wgetrc");

        std::cout << "User:        " << username << "\n";
        std::cout << " UID/GID:    " << uid << " / " << gid << "\n";
        std::cout << " Shell:      " << shell << "\n";
        std::cout << " In sudo:    " << (in_sudo ? "Yes" : "No") << "\n";
        std::cout << " In wheel:   " << (in_wheel ? "Yes" : "No") << "\n";
        std::cout << " Home dir:   " << home << (home_exists ? " (exists)" : " (missing)") << "\n";
        std::cout << " SSH Keys:   " << (has_auth_keys ? "Yes" : "No");
        if (has_auth_keys) std::cout << " (" << key_count << " entries)";
        std::cout << "\n";
        std::cout << " Private SSH:" << (has_private_keys ? "Yes" : "No") << "\n";
        std::cout << " .netrc:     " << (has_netrc ? "Yes" : "No") << "\n";
        std::cout << " .lftp/rc:   " << (has_lftp ? "Yes" : "No") << "\n";
        std::cout << " .wgetrc:    " << (has_wgetrc ? "Yes" : "No") << "\n";
        std::cout << "----------------------------------------\n";
    }

    endpwent();
}


void DumpCommandHistory() {
    const std::string home_base = "/home/";
    std::vector<std::string> history_filenames = {
        ".bash_history",
        ".zsh_history",
        ".sh_history",
        ".history"
    };

    for (const auto& dir_entry : std::filesystem::directory_iterator(home_base)) {
        if (dir_entry.is_directory()) {
            std::string user_home = dir_entry.path().string();

            for (const auto& hist_file : history_filenames) {
                std::filesystem::path full_path = user_home + "/" + hist_file;

                if (std::filesystem::exists(full_path)) {
                    std::cout << "==> " << full_path << " <==" << std::endl;
                    std::ifstream infile(full_path);

                    if (infile.is_open()) {
                        std::string line;
                        while (std::getline(infile, line)) {
                            std::cout << line << std::endl;
                        }
                        infile.close();
                    } else {
                        std::cerr << "Could not open " << full_path << std::endl;
                    }
                }
            }
        }
    }
}

void PrintHostname() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        std::cout << "Hostname: " << hostname << "\n";
    } else {
        perror("gethostname");
    }
}

void PrintInterfaces() {
    std::cout << "\n=== Interfaces ===\n";
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;

        std::string iface = ifa->ifa_name;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            void* addr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, addr, ip, sizeof(ip));
            std::cout << "Interface: " << iface << " (IPv4) -> " << ip << "\n";
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            char ip[INET6_ADDRSTRLEN];
            void* addr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
            inet_ntop(AF_INET6, addr, ip, sizeof(ip));
            std::cout << "Interface: " << iface << " (IPv6) -> " << ip << "\n";
        }
    }
    freeifaddrs(ifaddr);
}


void MacInterface() {
    const std::string net_dir = "/sys/class/net/";
    for (const auto& entry : std::filesystem::directory_iterator(net_dir)) {
        std::string iface = entry.path().filename();
        std::string mac, state;

        std::ifstream mac_file(entry.path() / "address");
        std::ifstream state_file(entry.path() / "operstate");

        std::getline(mac_file, mac);
        std::getline(state_file, state);

        std::cout << "Interface: " << iface << " | MAC: " << mac << " | State: " << state << "\n";
    }
}

void RoutingTable() {
    std::ifstream route_file("/proc/net/route");
    std::string line;
    std::getline(route_file, line);

    while (std::getline(route_file, line)) {
        std::istringstream iss(line);
        std::string iface, destination, gateway;
        int flags, refcnt, use, metric, mask;

        iss >> iface >> destination >> gateway;
        std::cout << "Iface: " << iface
                  << " | Destination: 0x" << destination
                  << " | Gateway: 0x" << gateway << "\n";
    }
}

void ARPTable() {
    std::ifstream arp("/proc/net/arp");
    std::string line;
    while (std::getline(arp, line)) {
        std::cout << line << "\n";
    }
}

void DNSInfo() {
    std::ifstream resolv("/etc/resolv.conf");
    std::string line;
    while (std::getline(resolv, line)) {
        if (line.find("nameserver") == 0)
            std::cout << line << "\n";
    }
}


void InterfaceStats() {
    std::ifstream stats("/proc/net/dev");
    std::string line;
    while (std::getline(stats, line)) {
        std::cout << line << "\n";
    }
}

namespace fs = std::filesystem;

void CheckAndPrintFile(const fs::path& file_path) {
    std::error_code ec;
    if (fs::exists(file_path, ec)) {
        std::cout << "[+] Found: " << file_path << "\n";
    } else if (ec) {
        std::cerr << "   (error checking " << file_path << ": " << ec.message() << ")\n";
    }
}

bool starts_with_cxx17(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

void DumpCredentialFiles() {
    std::cout << "=== Credentials Audit ===\n";

    try {
        for (const auto& dir_entry : fs::directory_iterator("/home/")) {
            std::error_code ec;
            if (!dir_entry.is_directory(ec)) continue;

            std::string user_home = dir_entry.path().string();

            std::cout << "\n--- User: " << user_home << " ---\n";

            fs::path ssh_dir = fs::path(user_home) / ".ssh";
            if (fs::exists(ssh_dir)) {
                for (const auto& file : fs::directory_iterator(ssh_dir)) {
                    const std::string fname = file.path().filename().string();
                    if (starts_with_cxx17(fname, "id")) {
                        CheckAndPrintFile(file.path());
                    }
                }
                CheckAndPrintFile(ssh_dir / "config");
                CheckAndPrintFile(ssh_dir / "known_hosts");
            }

            fs::path gnupg_dir = fs::path(user_home) / ".gnupg";
            if (fs::exists(gnupg_dir)) {
                CheckAndPrintFile(gnupg_dir / "secring.gpg");
                CheckAndPrintFile(gnupg_dir / "private-keys-v1.d");
                CheckAndPrintFile(gnupg_dir / "gpg.conf");
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "filesystem error while scanning /home/: " << e.what() << "\n";
    }

    std::cout << "\n--- Kerberos Tickets ---\n";
    try {
        for (const auto& file : fs::directory_iterator("/tmp/")) {
            const std::string fname = file.path().filename().string();
            if (starts_with_cxx17(fname, "krb5cc_") || fname == "krb5.keytab") {
                CheckAndPrintFile(file.path());
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "filesystem error while scanning /tmp/: " << e.what() << "\n";
    }

    std::cout << "\n--- SSH Agent ---\n";
    const char* ssh_sock = std::getenv("SSH_AUTH_SOCK");
    if (ssh_sock) {
        fs::path sockp(ssh_sock);
        std::error_code ec;
        if (fs::exists(sockp, ec)) {
            std::cout << "[+] SSH_AUTH_SOCK: " << sockp << "\n";
        } else if (ec) {
            std::cerr << "   (error checking SSH_AUTH_SOCK: " << ec.message() << ")\n";
        } else {
            std::cout << "[-] SSH_AUTH_SOCK set but socket does not exist: " << sockp << "\n";
        }
    } else {
        std::cout << "[-] SSH_AUTH_SOCK not found or not set\n";
    }

    std::cout << "\n=== End of Credential Dump ===\n";

}


void CheckRootDirectoryPermissions() {
    const fs::path root_dir("/root");
    std::cout << "\n[Escalation] Checking /root directory permissions...\n";

    std::error_code ec;
    if (!fs::exists(root_dir, ec)) {
        std::cout << "  /root does not exist or is inaccessible: " << ec.message() << "\n";
        std::cout << "  => Escalation via /root check is NOT plausible on this host (cannot access /root).\n";
        return;
    }

    size_t total_entries_seen = 0;
    size_t permission_denied_count = 0;
    size_t findings_count = 0;
    fs::directory_options opts = fs::directory_options::skip_permission_denied;

    try {
        for (fs::recursive_directory_iterator it(root_dir, opts, ec), end; it != end; it.increment(ec)) {
            if (ec) {

                std::cout << "  [!] Cannot descend into a subdirectory (permission/IO): " << ec.message() << "\n";
                ++permission_denied_count;
                continue;
            }

            ++total_entries_seen;
            const fs::directory_entry &entry = *it;
            fs::path p = entry.path();
            std::error_code st_ec;
            fs::file_status st = fs::status(p, st_ec);
            if (st_ec) {
                std::cout << "  [!] Permission/IO error for " << p << " : " << st_ec.message() << "\n";
                ++permission_denied_count;
                continue;
            }

            fs::perms perms = st.permissions();

            bool world_read  = (perms & fs::perms::others_read)  != fs::perms::none;
            bool world_write = (perms & fs::perms::others_write) != fs::perms::none;
            bool group_read  = (perms & fs::perms::group_read)   != fs::perms::none;
            bool group_write = (perms & fs::perms::group_write)  != fs::perms::none;

            if (world_read || world_write || group_read || group_write) {
                ++findings_count;
                std::string permflags;
                permflags += (world_read  ? "o=r" : "");
                permflags += (world_write ? (permflags.empty() ? "o=w" : ",o=w") : "");
                permflags += (group_read  ? (permflags.empty() ? "g=r" : ",g=r") : "");
                permflags += (group_write ? (permflags.empty() ? "g=w" : ",g=w") : "");

                std::cout << "  [!] Potentially sensitive file: " << p
                          << "  perms=" << permflags << "\n";
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "  [ERROR] Filesystem exception while scanning /root: " << e.what() << "\n";
        std::cout << "  => Escalation via /root check is NOT plausible (exception occurred).\n";
        return;
    }

    if (total_entries_seen == 0) {
        std::cout << "  No entries were enumerated under /root. Likely inaccessible.\n";
        std::cout << "  => Escalation via /root check is NOT plausible from this account.\n";
        return;
    }

    double denied_ratio = (double)permission_denied_count / (double)total_entries_seen;
    if (denied_ratio > 0.5) {
        std::cout << "  Many entries in /root were inaccessible (" << permission_denied_count << " of " << total_entries_seen << ").\n";
        std::cout << "  => Escalation via /root check is NOT plausible from this account (insufficient visibility).\n";
    } else {
        if (findings_count == 0) {
            std::cout << "  No world/group readable/writable files detected in accessible parts of /root.\n";
            std::cout << "  => No obvious escalation via /root found (from accessible paths).\n";
        } else {
            std::cout << "  Found " << findings_count << " potentially problematic file(s) in /root; investigate further.\n";
            std::cout << "  => Escalation via /root MAY be plausible depending on these findings.\n";
        }
    }
}


void CheckSudoRules() {
    std::cout << "\n[Escalation] Checking sudo rules...\n";

    const char *cmd = "sudo -l -n 2>&1";

    std::array<char, 256> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        std::cerr << "  Failed to run sudo -l (popen failed)\n";
        return;
    }

    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    if (result.find("may not run sudo") != std::string::npos ||
        result.find("a password is required") != std::string::npos ||
        result.find("sudo: a password is required") != std::string::npos) {
        std::cout << "  sudo -l -n indicates sudo requires a password or is not allowed for this user:\n";
        std::cout << "  " << result << "\n";
        std::cout << "  => Cannot determine allowed sudo commands without credentials.\n";
        return;
    }

    std::regex nopasswd_re(R"((NOPASSWD:.*))", std::regex::icase);
    std::regex risky_cmds_re(R"((\/bin\/bash|\/bin\/sh|\/usr\/bin\/vim|\/usr\/bin\/nano|\/usr\/bin\/less|\/usr\/bin\/find|\/usr\/bin\/perl|\/usr\/bin\/python|\/usr\/bin\/awk))", std::regex::icase);

    std::istringstream iss(result);
    std::string line;
    bool found_any_nopasswd = false;
    bool found_risky = false;

    while (std::getline(iss, line)) {
        size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        std::string t = line.substr(first);

        std::smatch m;
        if (std::regex_search(t, m, nopasswd_re)) {
            found_any_nopasswd = true;
            std::cout << "  [!] NOPASSWD sudo rule: " << t << "\n";

            if (std::regex_search(t, risky_cmds_re)) {
                std::cout << "    [!] Contains risky command(s) that may allow shell escapes or file edits.\n";
                found_risky = true;
            }
        } else {
            if (std::regex_search(t, risky_cmds_re)) {
                std::cout << "  [!] Sudo allows potentially risky command: " << t << "\n";
                found_risky = true;
            }
        }
    }

    if (!found_any_nopasswd) {
        std::cout << "  No NOPASSWD entries found (or sudo -l not allowed without password).\n";
    }
    if (!found_risky) {
        std::cout << "  No obvious risky commands detected in sudo output.\n";
    } else {
        std::cout << "  => Review the above sudo rules for potential escalation vectors.\n";
    }
}




void CheckShadowFile() {
    std::cout << "\n[Escalation] Checking /etc/shadow file access...\n";

    const std::string shadow_path = "/etc/shadow";

    if (access(shadow_path.c_str(), R_OK) == 0) {
        std::cout << "  [!] /etc/shadow is readable — this is a serious security issue!\n";
        std::cout << "  Dumping first 5 lines:\n";

        std::ifstream shadow_file(shadow_path);
        if (shadow_file.is_open()) {
            std::string line;
            int count = 0;
            while (std::getline(shadow_file, line) && count < 5) {
                std::cout << "    " << line << "\n";
                ++count;
            }
            shadow_file.close();
        } else {
            std::cout << "  [!] File could not be opened, despite readable access — unexpected.\n";
        }

        std::cout << "  => Escalation likely possible via password hash extraction.\n";
    } else {
        std::cout << "  [-] /etc/shadow is NOT readable by current user.\n";
        std::cout << "  => No direct escalation via /etc/shadow access.\n";
    }
}




struct FileInfo {
    bool exists = false;
    uid_t uid = 0;
    gid_t gid = 0;
    mode_t mode = 0;
    std::string owner_name;
    std::string group_name;
    std::string error_msg;
};

FileInfo stat_file_safe(const fs::path &p) {
    FileInfo info;
    struct stat st;
    if (lstat(p.c_str(), &st) != 0) {
        info.exists = false;
        info.error_msg = std::string("lstat errno=") + std::to_string(errno);
        return info;
    }
    info.exists = true;
    info.uid = st.st_uid;
    info.gid = st.st_gid;
    info.mode = st.st_mode;
    struct passwd *pw = getpwuid(info.uid);
    struct group  *gr = getgrgid(info.gid);
    info.owner_name = pw ? pw->pw_name : std::to_string(info.uid);
    info.group_name = gr ? gr->gr_name : std::to_string(info.gid);
    return info;
}

bool is_world_writable(mode_t mode) { return (mode & S_IWOTH) != 0; }
bool is_group_writable(mode_t mode) { return (mode & S_IWGRP) != 0; }

std::vector<fs::path> extract_paths_from_line(const std::string &line) {
    std::vector<fs::path> paths;
    static const std::regex path_re(R"((/[^ \t;|&]*)|(\.\.?/[^ \t;|&]*))");
    auto it = std::sregex_iterator(line.begin(), line.end(), path_re);
    auto end = std::sregex_iterator();
    for (; it != end; ++it) {
        std::string token = (*it).str();
        size_t cut = token.find_first_of(";,|&");
        if (cut != std::string::npos) token = token.substr(0, cut);
        paths.emplace_back(token);
    }
    return paths;
}

void analyze_crontab_file_with_perm_handling(const fs::path &p, bool system_crontab = false) {
    std::error_code ec;
    std::cout << "\n[CRON FILE] " << p << "\n";

    std::ifstream in(p);
    if (!in.is_open()) {
        std::cout << "  (Could not open " << p << " — permission denied or missing)\n";
        std::cout << "  => ASSESSMENT: UNEXPLOITABLE (cannot read crontab file)\n";
        return;
    }

    std::string line;
    size_t lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        std::string t = line.substr(first);
        if (t.empty() || t[0] == '#') continue;

        std::istringstream iss(t);
        std::vector<std::string> tokens;
        std::string tok;
        while (iss >> tok) {
            tokens.push_back(tok);
            if ((system_crontab && tokens.size() >= 6) || (!system_crontab && tokens.size() >= 5)) break;
        }
        size_t consume_fields = system_crontab ? 6 : 5;
        size_t pos = 0, count = 0;
        while (count < consume_fields && pos < t.size()) {
            while (pos < t.size() && isspace((unsigned char)t[pos])) ++pos;
            while (pos < t.size() && !isspace((unsigned char)t[pos])) ++pos;
            ++count;
        }
        std::string command = (pos < t.size()) ? t.substr(pos) : std::string();
        if (command.empty()) command = "(no command parsed)";

        bool line_has_permission_error = false;
        bool line_may_be_exploitable = false;

        std::cout << "  L" << lineno << ": " << t << "\n";
        std::cout << "    Parsed command: " << command << "\n";

        auto paths = extract_paths_from_line(command);
        if (paths.empty()) {
            std::cout << "    (No explicit absolute/relative paths found in command)\n";
        }

        for (const auto &pp : paths) {

            FileInfo fi = stat_file_safe(pp);
            if (!fi.exists) {
                std::cout << "    (Could not stat " << pp << ") error=" << fi.error_msg << "\n";
                if (fi.error_msg.find("errno=") != std::string::npos) {
                    int e = atoi(fi.error_msg.substr(fi.error_msg.find('=')+1).c_str());
                    if (e == EACCES || e == EPERM) {
                        std::cout << "      [!] Permission denied when inspecting " << pp << " -> mark ENTRY as UNEXPLOITABLE\n";
                        line_has_permission_error = true;
                        break;
                    }
                }

            } else {
                std::cout << "    Path: " << pp << " owner=" << fi.owner_name << ":" << fi.group_name
                          << " mode=" << std::oct << (fi.mode & 0777) << std::dec << "\n";

                if (is_world_writable(fi.mode) || is_group_writable(fi.mode)) {
                    std::cout << "      [!] PATH is writable (world/group) -> POTENTIALLY EXPLOITABLE\n";
                    line_may_be_exploitable = true;
                }
            }

            fs::path parent = pp.parent_path();
            if (parent.empty()) parent = ".";
            FileInfo pfi = stat_file_safe(parent);
            if (!pfi.exists) {
                std::cout << "    (Could not stat parent dir " << parent << ") error=" << pfi.error_msg << "\n";
                if (pfi.error_msg.find("errno=") != std::string::npos) {
                    int e = atoi(pfi.error_msg.substr(pfi.error_msg.find('=')+1).c_str());
                    if (e == EACCES || e == EPERM) {
                        std::cout << "      [!] Permission denied when inspecting parent dir " << parent
                                  << " -> mark ENTRY as UNEXPLOITABLE\n";
                        line_has_permission_error = true;
                        break;
                    }
                }
            } else {
                if (is_world_writable(pfi.mode)) {
                    std::cout << "      [!] PARENT DIR is world-writable: " << parent << " owner=" << pfi.owner_name << "\n";
                    line_may_be_exploitable = true;
                }
            }
        }

        if (line_has_permission_error) {
            std::cout << "    => ASSESSMENT: UNEXPLOITABLE (permission error while probing this cron entry)\n";
        } else if (line_may_be_exploitable) {
            std::cout << "    => ASSESSMENT: POTENTIALLY EXPLOITABLE (writable paths/dirs found)\n";
        } else {
            continue;
        }
    }
}

void CheckCronJobs() {
    std::cout << "\n[Escalation] Checking cron jobs and referenced scripts (with permission-aware assessments)...\n";

    std::vector<fs::path> to_check;

    to_check.push_back("/etc/crontab");

    std::error_code ec;
    if (fs::exists("/etc/cron.d", ec) && fs::is_directory("/etc/cron.d", ec)) {
        for (auto &e : fs::directory_iterator("/etc/cron.d", ec)) {
            if (ec) {
                std::cout << "  (Error iterating /etc/cron.d: " << ec.message() << ") -> treat as UNEXPLOITABLE to be safe\n";
                break;
            }
            to_check.push_back(e.path());
        }
    } else {
        if (ec) std::cout << "  (Cannot access /etc/cron.d: " << ec.message() << ") -> treat as UNEXPLOITABLE\n";
    }

    if (fs::exists("/var/spool/cron", ec) && fs::is_directory("/var/spool/cron", ec)) {
        for (auto &e : fs::directory_iterator("/var/spool/cron", ec)) {
            if (ec) {
                std::cout << "  (Error iterating /var/spool/cron: " << ec.message() << ") -> treat as UNEXPLOITABLE\n";
                break;
            }
            to_check.push_back(e.path());
        }
    } else {
        if (ec) std::cout << "  (Cannot access /var/spool/cron: " << ec.message() << ") -> treat as UNEXPLOITABLE\n";
    }

    if (fs::exists("/var/spool/cron/crontabs", ec) && fs::is_directory("/var/spool/cron/crontabs", ec)) {
        for (auto &e : fs::directory_iterator("/var/spool/cron/crontabs", ec)) {
            if (ec) {
                std::cout << "  (Error iterating /var/spool/cron/crontabs: " << ec.message() << ") -> treat as UNEXPLOITABLE\n";
                break;
            }
            to_check.push_back(e.path());
        }
    }

    const char* cron_groups[] = {"/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"};
    for (auto cg : cron_groups) {
        if (fs::exists(cg, ec) && fs::is_directory(cg, ec)) {
            for (auto &e : fs::directory_iterator(cg, ec)) {
                if (ec) {
                    std::cout << "  (Error iterating " << cg << ": " << ec.message() << ") -> treat as UNEXPLOITABLE\n";
                    break;
                }
                to_check.push_back(e.path());
            }
        } else {
            if (ec) std::cout << "  (Cannot access " << cg << ": " << ec.message() << ") -> treat as UNEXPLOITABLE\n";
        }
    }

    if (to_check.empty()) {
        std::cout << "  No cron files discovered or accessible. Cron-based escalation is UNLIKELY/UNEXPLOITABLE from this account.\n";
        return;
    }

    for (auto &p : to_check) {
        bool system_ct = (p == fs::path("/etc/crontab") || p.parent_path() == fs::path("/etc/cron.d"));
        analyze_crontab_file_with_perm_handling(p, system_ct);
    }

    std::cout << "\n[Escalation] Cron assessment complete.\n";
}





namespace socket_audit_v2 { //This was an absolute nightmare, I have never witnessed such bullshit in my life

struct SocketRec {
    std::string local_ip;
    unsigned local_port = 0;
    unsigned long inode = 0;
    std::string state;
};

static std::optional<std::pair<std::string,unsigned>> parse_hex_ip_port(const std::string &hexaddr) {
    auto p = hexaddr.find(':');
    if (p == std::string::npos) return std::nullopt;
    std::string hip = hexaddr.substr(0,p);
    std::string hport = hexaddr.substr(p+1);
    unsigned port = 0;
    try {
        port = std::stoul(hport, nullptr, 16);
    } catch (...) { return std::nullopt; }

    if (hip.size() == 8) {
        unsigned x = 0;
        try { x = std::stoul(hip, nullptr, 16); } catch(...) { return std::nullopt; }
        unsigned a = (x & 0xFF), b = ((x>>8)&0xFF), c = ((x>>16)&0xFF), d = ((x>>24)&0xFF);
        std::ostringstream o; o<<a<<"."<<b<<"."<<c<<"."<<d;
        return std::make_pair(o.str(), port);
    }
    return std::nullopt;
}

static std::vector<SocketRec> parse_proc_net_file(const std::string& path) {
    std::vector<SocketRec> out;
    std::ifstream ifs(path);
    if (!ifs.is_open()) return out;
    std::string hdr;
    std::getline(ifs, hdr);
    std::string line;
    while (std::getline(ifs,line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string sl, local, rem, st;
        if (!(iss >> sl >> local >> rem >> st)) continue;
        std::vector<std::string> toks;
        std::istringstream iss2(line);
        std::string t;
        while (iss2 >> t) toks.push_back(t);
        std::string inode_str;
        if (toks.size() >= 10) inode_str = toks[9];
        else {
            for (auto it = toks.rbegin(); it != toks.rend(); ++it) {
                if (std::regex_match(*it, std::regex("^[0-9]+$"))) { inode_str = *it; break; }
            }
        }
        if (inode_str.empty()) continue;
        auto ipport = parse_hex_ip_port(local);
        if (!ipport) continue;
        SocketRec r;
        r.local_ip = ipport->first;
        r.local_port = ipport->second;
        try { r.inode = std::stoul(inode_str); } catch(...) { continue; }
        r.state = st;
        out.push_back(r);
    }
    return out;
}

static std::unordered_map<unsigned long, std::pair<int,std::string>> build_inode_pid_map(bool &saw_priv_errors) {
    std::unordered_map<unsigned long, std::pair<int,std::string>> map;
    saw_priv_errors = false;
    std::error_code ec;
    for (auto &p : fs::directory_iterator("/proc", ec)) {
        if (ec) { saw_priv_errors = true; break; }
        if (!p.is_directory(ec)) continue;
        std::string dname = p.path().filename().string();
        if (!std::all_of(dname.begin(), dname.end(), ::isdigit)) continue;
        int pid = 0;
        try { pid = std::stoi(dname); } catch(...) { continue; }
        fs::path fdpath = p.path() / "fd";
        if (!fs::exists(fdpath, ec) || !fs::is_directory(fdpath, ec)) {
            if (ec) { saw_priv_errors = true; continue; }
            continue;
        }
        for (auto &fd : fs::directory_iterator(fdpath, ec)) {
            if (ec) { saw_priv_errors = true; break; }
            std::error_code re;
            fs::path target = fs::read_symlink(fd.path(), re);
            if (re) { saw_priv_errors = true; continue; }
            std::string tstr = target.string();
            std::smatch m;
            static const std::regex sock_re(R"(socket:\[(\d+)\])");
            if (std::regex_search(tstr, m, sock_re)) {
                unsigned long inode = 0;
                try { inode = std::stoul(m[1].str()); } catch(...) { continue; }
                std::error_code ee;
                fs::path exe_path = fs::read_symlink(p.path() / "exe", ee);
                std::string exe = ee ? std::string("(unknown)") : exe_path.string();

                if (map.find(inode) == map.end()) map[inode] = std::make_pair(pid, exe);
            }
        }
    }
    return map;
}

static int uid_for_pid(int pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/status");
    if (!f.is_open()) return -1;
    std::string line;
    while (std::getline(f,line)) {
        if (line.rfind("Uid:",0) == 0) {
            std::istringstream iss(line.substr(4));
            int real= -1;
            if (iss >> real) return real;
            return -1;
        }
    }
    return -1;
}

void RunRootSocketAudit() {
    bool saw_permission_issues = false;
    auto inode_map = build_inode_pid_map(saw_permission_issues);
    auto tcp4 = parse_proc_net_file("/proc/net/tcp");
    auto tcp6 = parse_proc_net_file("/proc/net/tcp6");
    std::vector<SocketRec> all;
    all.insert(all.end(), tcp4.begin(), tcp4.end());
    all.insert(all.end(), tcp6.begin(), tcp6.end());

    size_t total_listen = 0;
    size_t root_owned = 0;
    size_t unexplorable = 0;

    std::cout << "\n[Escalation] Root-owned listening sockets audit\n";

    for (auto &s : all) {
        if (s.state != "0A") continue;
        ++total_listen;
        auto it = inode_map.find(s.inode);
        if (it == inode_map.end()) {
            ++unexplorable;
            std::cout << "  [UNEXPLOREABLE] " << s.local_ip << ":" << s.local_port << " inode=" << s.inode << "\n";
            continue;
        }
        int pid = it->second.first;
        std::string exe = it->second.second;
        int uid = uid_for_pid(pid);
        if (uid == -1) {
            ++unexplorable;
            std::cout << "  [UNEXPLOREABLE] " << s.local_ip << ":" << s.local_port
                      << " inode=" << s.inode << " PID=" << pid << " (cannot read UID)\n";
            continue;
        }
        if (uid == 0) {
            ++root_owned;
            std::cout << "  [POTENTIAL] " << s.local_ip << ":" << s.local_port
                      << " inode=" << s.inode << " PID=" << pid << " EXE=" << exe << "\n";
        }
    }

    std::cout << "\n  Summary: total_listening=" << total_listen
              << " root_owned=" << root_owned << " unexplorable=" << unexplorable << "\n";

    if (saw_permission_issues || unexplorable > 0) {
        std::cout << "  Note: some sockets could not be fully inspected due to permission/visibility restrictions.\n";
        std::cout << "  Entries marked UNEXPLOREABLE are assumed NOT PLAUSIBLE for exploitation from this account.\n";
    } else {
        std::cout << "  All accessible listening sockets inspected.\n";
    }
}

} //Is this even the end of the fucking sockets?- new one below


namespace kerb_audit_v1 {
namespace fs = std::filesystem;

struct KerbFind {
    fs::path path;
    bool exists = false;
    bool readable = false;
    bool stat_error = false;
    std::string stat_errmsg;
    std::string owner;
    std::string perms; // octal string
    uintmax_t size = 0;
};

static KerbFind inspect_path(const fs::path &p) {
    KerbFind r; r.path = p;
    std::error_code ec;
    fs::file_status st = fs::status(p, ec);
    if (ec) { r.stat_error = true; r.stat_errmsg = ec.message(); return r; }
    r.exists = true;
    struct stat sb;
    if (lstat(p.c_str(), &sb) != 0) {
        r.stat_error = true;
        r.stat_errmsg = std::string("lstat errno=") + std::to_string(errno);
        return r;
    }
    struct passwd *pw = getpwuid(sb.st_uid);
    r.owner = pw ? pw->pw_name : std::to_string(sb.st_uid);
    {
        std::ostringstream os;
        os << std::oct << (sb.st_mode & 0777);
        r.perms = os.str();
    }
    r.size = (uintmax_t)sb.st_size;
    if (access(p.c_str(), R_OK) == 0) r.readable = true;
    return r;
}

static std::vector<fs::path> enumerate_tmp_candidates() {
    std::vector<fs::path> out;
    std::error_code ec;
    if (!fs::exists("/tmp", ec)) return out;
    for (auto &e : fs::directory_iterator("/tmp", ec)) {
        if (ec) break;
        std::string fn = e.path().filename().string();
        if (fn.rfind("krb5cc_", 0) == 0) out.push_back(e.path());
        if (fn == "krb5.keytab") out.push_back(e.path());
    }
    return out;
}

void RunKerberosTicketAudit() {
    std::cout << "\n[Kerberos Audit] Scanning ticket caches and keytabs\n";

    bool global_perm_issues = false;
    std::vector<KerbFind> findings;

    auto tmp_candidates = enumerate_tmp_candidates();
    for (auto &p : tmp_candidates) {
        KerbFind info = inspect_path(p);
        if (info.stat_error) global_perm_issues = true;
        findings.push_back(info);
    }

    std::vector<fs::path> extra = { "/etc/krb5.keytab", "/etc/krb5.conf" };
    for (auto &p : extra) {
        std::error_code ec;
        if (fs::exists(p, ec)) {
            KerbFind info = inspect_path(p);
            if (info.stat_error) global_perm_issues = true;
            findings.push_back(info);
        }
    }

    const char* env_cc = std::getenv("KRB5CCNAME");
    if (env_cc) {
        fs::path envp(env_cc);
        KerbFind info = inspect_path(envp);
        if (info.stat_error) global_perm_issues = true;
        findings.push_back(info);
    }

    if (findings.empty()) {
        std::cout << "  No Kerberos ticket caches or keytab candidates discovered under /tmp, /etc, or KRB5CCNAME.\n";
    }

    for (auto &f : findings) {
        std::cout << "\n  Path: " << f.path << "\n";
        if (!f.exists) { std::cout << "    (missing)\n"; continue; }
        if (f.stat_error) {
            std::cout << "    (stat error) " << f.stat_errmsg << "\n";
            std::cout << "    => ASSESSMENT: UNEXPLOREABLE (permission/visibility error for this path)\n";
            continue;
        }
        std::cout << "    owner: " << f.owner << " perms(octal): " << f.perms << " size: " << f.size << "\n";
        if (f.readable) {
            std::cout << "    [!] READABLE: current account can read this file\n";
            std::cout << "    => ASSESSMENT: POTENTIALLY_EXPLOITABLE (ticket/keytab accessible)\n";
        } else {
            std::cout << "    [-] Not readable by current account\n";
            std::cout << "    => ASSESSMENT: NOT_EXPLOITABLE_VIA_THIS_ACCOUNT (no read access)\n";
        }
    }

    if (global_perm_issues) {
        std::cout << "\n  Note: some entries could not be inspected due to permission or IO errors.\n";
        std::cout << "  Entries with stat errors are treated as UNEXPLOREABLE and not assumed exploitable.\n";
    }

    std::cout << "\n[Kerberos Audit] Complete\n"; //End of this one


}

}


namespace gpg_audit_v1 {
namespace fs = std::filesystem;

struct GpgFind {
    fs::path path;
    bool exists = false;
    bool readable = false;
    bool stat_error = false;
    std::string stat_errmsg;
    std::string owner;
    std::string perms;
    uintmax_t size = 0;
};

static GpgFind inspect_path(const fs::path &p) {
    GpgFind r; r.path = p;
    std::error_code ec;
    fs::file_status st = fs::status(p, ec);
    if (ec) { r.stat_error = true; r.stat_errmsg = ec.message(); return r; }
    r.exists = true;
    struct stat sb;
    if (lstat(p.c_str(), &sb) != 0) {
        r.stat_error = true;
        r.stat_errmsg = std::string("lstat errno=") + std::to_string(errno);
        return r;
    }
    struct passwd *pw = getpwuid(sb.st_uid);
    r.owner = pw ? pw->pw_name : std::to_string(sb.st_uid);
    {
        std::ostringstream os;
        os << std::oct << (sb.st_mode & 0777);
        r.perms = os.str();
    }
    r.size = (uintmax_t)sb.st_size;
    if (access(p.c_str(), R_OK) == 0) r.readable = true;
    return r;
}

static std::vector<fs::path> enumerate_gnupg_candidates() {
    std::vector<fs::path> out;
    std::error_code ec;
    fs::path home_base("/home");
    if (fs::exists("/root", ec)) {
        out.push_back("/root/.gnupg");
    }
    if (fs::exists(home_base, ec)) {
        for (auto &d : fs::directory_iterator(home_base, ec)) {
            if (ec) break;
            if (!d.is_directory()) continue;
            out.push_back(d.path() / ".gnupg");
        }
    }
    return out;
}

void RunGPGAudit() {
    std::cout << "\n[GPG Audit] Scanning user .gnupg locations for secret key material\n";
    bool global_perm_errors = false;
    std::vector<GpgFind> findings;
    auto dirs = enumerate_gnupg_candidates();
    for (auto &d : dirs) {
        std::error_code ec;
        if (!fs::exists(d, ec)) continue;
        if (ec) { global_perm_errors = true; findings.push_back(GpgFind{d,false,false,true,ec.message()}); continue; }
        std::vector<fs::path> candidates = {
            d / "secring.gpg",
            d / "private-keys-v1.d",
            d / "private-keys-v1.d" / "key",
            d / "secring.kbx",
            d / "private-keyring",
            d / "pubring.kbx",
            d / "trustdb.gpg"
        };
        // also scan for any files with "secret" or "private" in name incase retard left it findable
        for (auto &entry : fs::directory_iterator(d, ec)) {
            if (ec) { global_perm_errors = true; break; }
            std::string fn = entry.path().filename().string();
            if (fn.find("sec") != std::string::npos || fn.find("private") != std::string::npos) {
                candidates.push_back(entry.path());
            }
        }
        for (auto &p : candidates) {
            GpgFind info = inspect_path(p);
            if (info.stat_error) global_perm_errors = true;
            findings.push_back(info);
        }
    }

    if (findings.empty()) {
        std::cout << "  No candidate GnuPG secret locations discovered under /home or /root.\n";
    }

    for (auto &f : findings) {
        std::cout << "\n  Path: " << f.path << "\n";
        if (!f.exists) { std::cout << "    (missing)\n"; continue; }
        if (f.stat_error) {
            std::cout << "    (stat error) " << f.stat_errmsg << "\n";
            std::cout << "    => ASSESSMENT: UNEXPLOREABLE (permission/visibility error for this path)\n";
            continue;
        }
        std::cout << "    owner: " << f.owner << " perms(octal): " << f.perms << " size: " << f.size << "\n";
        if (f.readable) {
            std::cout << "    [!] READABLE: current account can read this file/directory\n";
            std::cout << "    => ASSESSMENT: POTENTIALLY_EXPLOITABLE (secret keys may be accessible)\n";
        } else {
            std::cout << "    [-] Not readable by current account\n";
            std::cout << "    => ASSESSMENT: NOT_EXPLOITABLE_VIA_THIS_ACCOUNT (no read access)\n";
        }
    }

    if (global_perm_errors) {
        std::cout << "\n  Note: some entries could not be inspected due to permission or IO errors.\n";
        std::cout << "  Entries with stat errors are treated as UNEXPLOREABLE and not assumed exploitable.\n";
    }

    std::cout << "\n[GPG Audit] Complete\n";
}

} // namespace gpg_audit_v1 Stupid ass idea


namespace path_audit_v1 {
namespace fs = std::filesystem;

struct PathFinding {
    fs::path path;
    bool exists = false;
    bool stat_error = false;
    std::string stat_errmsg;
    std::string owner;
    std::string group;
    std::string perms_octal;
    bool world_writable = false;
    bool group_writable = false;
    bool writable_by_current = false;
};

static PathFinding inspect_path(const fs::path &p) {
    PathFinding r;
    r.path = p;
    std::error_code ec;
    fs::file_status st = fs::status(p, ec);
    if (ec) { r.stat_error = true; r.stat_errmsg = ec.message(); return r; }
    r.exists = true;
    struct stat sb;
    if (lstat(p.c_str(), &sb) != 0) {
        r.stat_error = true;
        r.stat_errmsg = std::string("lstat errno=") + std::to_string(errno);
        return r;
    }
    struct passwd *pw = getpwuid(sb.st_uid);
    struct group  *gr = getgrgid(sb.st_gid);
    r.owner = pw ? pw->pw_name : std::to_string(sb.st_uid);
    r.group = gr ? gr->gr_name : std::to_string(sb.st_gid);
    {
        std::ostringstream os;
        os << std::oct << (sb.st_mode & 0777);
        r.perms_octal = os.str();
    }
    r.world_writable = (sb.st_mode & S_IWOTH) != 0;
    r.group_writable = (sb.st_mode & S_IWGRP) != 0;
    r.writable_by_current = (access(p.c_str(), W_OK) == 0);
    return r;
}

static std::vector<fs::path> split_path_env(const std::string &env) {
    std::vector<fs::path> out;
    std::string s = env;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t colon = s.find(':', pos);
        std::string tok = (colon == std::string::npos) ? s.substr(pos) : s.substr(pos, colon - pos);
        if (!tok.empty()) out.push_back(fs::path(tok));
        if (colon == std::string::npos) break;
        pos = colon + 1;
    }
    return out;
}

void RunPathAndWritableAudit() {
    std::cout << "\n[Path/World-Writable Audit] Scanning PATH and common service/plugin locations\n";
    std::vector<fs::path> to_check;
    const char *p_env = std::getenv("PATH");
    if (p_env) {
        auto parts = split_path_env(std::string(p_env));
        for (auto &pp : parts) to_check.push_back(pp);
    }
    std::vector<fs::path> commons = {
        "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin",
        "/opt", "/etc", "/var/www", "/srv", "/usr/lib", "/usr/libexec", "/lib", "/lib64" //prob best to add more but prob wont lmfao
    };
    for (auto &c : commons) to_check.push_back(c);

    std::vector<PathFinding> findings;
    bool global_stat_issues = false;

    for (auto &p : to_check) {
        PathFinding info = inspect_path(p);
        if (info.stat_error) global_stat_issues = true;
        findings.push_back(info);
    }

    for (auto &f : findings) {
        std::cout << "\nPath: " << f.path << "\n";
        if (!f.exists) { std::cout << "  (missing)\n"; continue; }
        if (f.stat_error) {
            std::cout << "  (stat error) " << f.stat_errmsg << "\n";
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE (permission/visibility error for this path)\n";
            continue;
        }
        std::cout << "  owner: " << f.owner << ":" << f.group << " perms(octal): " << f.perms_octal << "\n";
        if (f.world_writable) std::cout << "  [!] WORLD-WRITABLE\n";
        if (f.group_writable) std::cout << "  [!] GROUP-WRITABLE\n";
        if (f.writable_by_current) std::cout << "  [!] WRITABLE BY CURRENT USER\n";

        if (f.stat_error) {
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE\n";
        } else if (f.writable_by_current || f.world_writable || f.group_writable) {
            std::cout << "  => ASSESSMENT: POTENTIALLY_EXPLOITABLE (directory writable)\n";
            if (fs::is_directory(f.path)) {
                std::error_code ec;
                size_t sample = 0;
                for (auto &ent : fs::directory_iterator(f.path, ec)) {
                    if (ec) { global_stat_issues = true; break; }
                    if (++sample > 50) break;
                    PathFinding fe = inspect_path(ent.path());
                    if (!fe.exists || fe.stat_error) continue;
                    if (fe.world_writable || fe.writable_by_current) {
                        std::cout << "    [!] Contained writable entry: " << ent.path() << " perms=" << fe.perms_octal << "\n";
                    }
                }
                if (ec) {
                    std::cout << "    (could not enumerate directory contents: " << ec.message() << ")\n";
                }
            }
        } else {
            std::cout << "  => ASSESSMENT: NOT_EXPLOITABLE_VIA_THIS_ACCOUNT (no writable flags observed)\n";
        }
    }

    if (global_stat_issues) {
        std::cout << "\nNote: some paths could not be inspected due to permission errors and are treated as UNEXPLOREABLE.\n";
    } else {
        std::cout << "\nPath audit complete. No permission errors encountered while scanning listed paths.\n";
    }
}

}

// Call with: path_audit_v1::RunPathAndWritableAudit();


namespace suid_audit_v1 {
namespace fs = std::filesystem;

struct SuidEntry {
    fs::path path;
    bool exists = false;
    bool stat_error = false;
    std::string stat_errmsg;
    std::string owner;
    std::string group;
    std::string perms_octal;
    bool suid = false;
    bool sgid = false;
    bool owner_is_root = false;
    bool file_world_writable = false;
    bool file_group_writable = false;
    bool writable_by_current = false;
};

static SuidEntry inspect_path(const fs::path &p) {
    SuidEntry r;
    r.path = p;
    std::error_code ec;
    fs::file_status st = fs::status(p, ec);
    if (ec) { r.stat_error = true; r.stat_errmsg = ec.message(); return r; }
    r.exists = true;
    struct stat sb;
    if (lstat(p.c_str(), &sb) != 0) {
        r.stat_error = true;
        r.stat_errmsg = std::string("lstat errno=") + std::to_string(errno);
        return r;
    }
    struct passwd *pw = getpwuid(sb.st_uid);
    struct group  *gr = getgrgid(sb.st_gid);
    r.owner = pw ? pw->pw_name : std::to_string(sb.st_uid);
    r.group = gr ? gr->gr_name : std::to_string(sb.st_gid);
    {
        std::ostringstream os;
        os << std::oct << (sb.st_mode & 0777);
        r.perms_octal = os.str();
    }
    r.suid = (sb.st_mode & S_ISUID);
    r.sgid = (sb.st_mode & S_ISGID);
    r.owner_is_root = (sb.st_uid == 0);
    r.file_world_writable = (sb.st_mode & S_IWOTH);
    r.file_group_writable = (sb.st_mode & S_IWGRP);
    r.writable_by_current = (access(p.c_str(), W_OK) == 0);
    return r;
}

static std::vector<fs::path> enumerate_search_dirs() {
    std::vector<fs::path> roots = {
        "/bin","/sbin","/usr/bin","/usr/sbin","/usr/local/bin","/usr/local/sbin",
        "/opt","/usr/lib","/usr/libexec","/snap","/srv"
    };
    std::vector<fs::path> out;
    std::error_code ec;
    for (auto &r : roots) {
        if (fs::exists(r, ec)) out.push_back(r);
    }
    out.push_back("/");
    return out;
}

void RunSuidSgidAudit() {
    std::cout << "\n[SUID/SGID Audit] Scanning for setuid/setgid binaries\n";
    bool global_stat_issues = false;
    std::vector<SuidEntry> findings;
    auto roots = enumerate_search_dirs();
    std::error_code ec;
    for (auto &root : roots) {
        for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end; it != end; it.increment(ec)) {
            if (ec) { global_stat_issues = true; continue; }
            fs::path p = it->path();
            SuidEntry info = inspect_path(p);
            if (info.stat_error) { global_stat_issues = true; continue; }
            if (info.suid || info.sgid) findings.push_back(info);
        }
    }
    if (findings.empty()) {
        std::cout << "  No SUID/SGID files discovered in scanned locations.\n";
    }
    for (auto &f : findings) {
        std::cout << "\nPath: " << f.path << "\n";
        if (!f.exists) { std::cout << "  (missing)\n"; continue; }
        if (f.stat_error) {
            std::cout << "  (stat error) " << f.stat_errmsg << "\n";
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE\n";
            continue;
        }
        std::cout << "  owner: " << f.owner << ":" << f.group << " perms: " << f.perms_octal << "\n";
        if (f.suid) std::cout << "  [!] setuid bit set\n";
        if (f.sgid) std::cout << "  [!] setgid bit set\n";
        if (!f.owner_is_root) std::cout << "  [!] File not owned by root\n";
        if (f.file_world_writable) std::cout << "  [!] File is world-writable\n";
        if (f.file_group_writable) std::cout << "  [!] File is group-writable\n";
        if (f.writable_by_current) std::cout << "  [!] File writable by current user\n";
        bool unex = false;
        if (f.stat_error) unex = true;
        if (unex) {
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE\n";
            continue;
        }
        bool potentially = false;
        if (!f.owner_is_root) potentially = true;
        if (f.file_world_writable || f.file_group_writable) potentially = true;
        if (f.writable_by_current) potentially = true;
        if (potentially) {
            std::cout << "  => ASSESSMENT: POTENTIALLY_EXPLOITABLE\n";
        } else {
            std::cout << "  => ASSESSMENT: NO_IMMEDIATE_EXPLOIT_PATH_DETECTED\n";
        }
    }
    if (global_stat_issues) {
        std::cout << "\nNote: some paths could not be inspected due to permission or IO errors; those are treated as UNEXPLOREABLE.\n";
    } else {
        std::cout << "\nSUID/SGID scan complete.\n";
    }
}

}


// Call: service_config_audit_v1::RunServiceConfigAudit();


namespace service_config_audit_v1 {
namespace fs = std::filesystem;

struct ConfigFind {
    fs::path path;
    bool exists = false;
    bool stat_error = false;
    std::string stat_errmsg;
    std::string owner;
    std::string group;
    std::string perms_octal;
    bool readable = false;
    bool writable_by_current = false;
    uintmax_t size = 0;
};

static ConfigFind inspect_path(const fs::path &p) {
    ConfigFind r; r.path = p;
    std::error_code ec;
    fs::file_status st = fs::status(p, ec);
    if (ec) { r.stat_error = true; r.stat_errmsg = ec.message(); return r; }
    r.exists = true;
    struct stat sb;
    if (lstat(p.c_str(), &sb) != 0) {
        r.stat_error = true;
        r.stat_errmsg = std::string("lstat errno=") + std::to_string(errno);
        return r;
    }
    struct passwd *pw = getpwuid(sb.st_uid);
    struct group  *gr = getgrgid(sb.st_gid);
    r.owner = pw ? pw->pw_name : std::to_string(sb.st_uid);
    r.group = gr ? gr->gr_name : std::to_string(sb.st_gid);
    {
        std::ostringstream os;
        os << std::oct << (sb.st_mode & 0777);
        r.perms_octal = os.str();
    }
    r.size = (uintmax_t)sb.st_size;
    r.readable = (access(p.c_str(), R_OK) == 0);
    r.writable_by_current = (access(p.c_str(), W_OK) == 0);
    return r;
}

static std::vector<fs::path> common_config_paths() {
    std::vector<fs::path> out = {
        "/etc",
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/etc/default",
        "/etc/sysconfig",
        "/etc/apache2",
        "/etc/nginx",
        "/etc/ssh",
        "/etc/mysql",
        "/etc/postgresql", //Maybe add more but cant be fucking asked, def add more limit to file finding on this one so my shitass PC dont blow up
        "/etc/redis",
        "/etc/docker",
        "/etc/init.d",
        "/opt",
        "/usr/local/etc"
    };
    return out;
}

static std::vector<std::pair<int,std::string>> enumerate_process_cmdlines(bool &perm_err) {
    perm_err = false;
    std::vector<std::pair<int,std::string>> out;
    std::error_code ec;
    for (auto &d : fs::directory_iterator("/proc", ec)) {
        if (ec) { perm_err = true; break; }
        if (!d.is_directory(ec)) continue;
        std::string dname = d.path().filename().string();
        if (!std::all_of(dname.begin(), dname.end(), ::isdigit)) continue;
        int pid = 0;
        try { pid = std::stoi(dname); } catch(...) { continue; }
        std::ifstream f("/proc/" + dname + "/cmdline", std::ios::in | std::ios::binary);
        if (!f.is_open()) { perm_err = true; continue; }
        std::string cmdline;
        std::getline(f, cmdline, '\0');
        if (cmdline.empty()) {
            std::ifstream commf("/proc/" + dname + "/comm");
            if (commf.is_open()) std::getline(commf, cmdline);
        }
        if (!cmdline.empty()) out.emplace_back(pid, cmdline);
    }
    return out;
}

static std::vector<fs::path> extract_paths_from_string(const std::string &s) {
    std::vector<fs::path> out;
    static const std::regex path_re(R"((/[^ \t'\";|&()<>]+))");
    auto it = std::sregex_iterator(s.begin(), s.end(), path_re);
    auto end = std::sregex_iterator();
    for (; it != end; ++it) {
        std::string tok = (*it).str();
        out.emplace_back(tok);
    }
    return out;
}

void RunServiceConfigAudit() {
    std::cout << "\n[Service Config Audit] Scanning common config locations and process-supplied config references\n";
    std::vector<fs::path> seeds = common_config_paths();
    bool global_perm_errors = false;
    std::vector<ConfigFind> findings;

    for (auto &root : seeds) {
        std::error_code ec;
        if (!fs::exists(root, ec)) continue;
        if (!fs::is_directory(root, ec)) continue;
        for (auto &entry : fs::directory_iterator(root, ec)) {
            if (ec) { global_perm_errors = true; break; }
            try {
                ConfigFind info = inspect_path(entry.path());
                if (info.stat_error) global_perm_errors = true;
                findings.push_back(info);
                if (fs::is_directory(entry.path(), ec)) {
                    size_t cnt = 0;
                    for (auto &sub : fs::directory_iterator(entry.path(), ec)) {
                        if (ec) { global_perm_errors = true; break; }
                        if (++cnt > 50) break;
                        ConfigFind info2 = inspect_path(sub.path());
                        if (info2.stat_error) global_perm_errors = true;
                        findings.push_back(info2);
                    }
                }
            } catch (...) {
                global_perm_errors = true;
                continue;
            }
        }
    }

    std::vector<fs::path> units;
    std::error_code ecu;
    if (fs::exists("/etc/systemd/system", ecu) && fs::is_directory("/etc/systemd/system")) {
        for (auto &e : fs::directory_iterator("/etc/systemd/system", ecu)) units.push_back(e.path());
    }
    if (fs::exists("/lib/systemd/system", ecu) && fs::is_directory("/lib/systemd/system")) {
        for (auto &e : fs::directory_iterator("/lib/systemd/system", ecu)) units.push_back(e.path());
    }
    for (auto &u : units) {
        ConfigFind info = inspect_path(u);
        if (info.stat_error) global_perm_errors = true;
        findings.push_back(info);
    }

    bool proc_perm_err = false;
    auto procs = enumerate_process_cmdlines(proc_perm_err);
    if (proc_perm_err) global_perm_errors = true;
    for (auto &p : procs) {
        int pid = p.first;
        std::string cmd = p.second;
        auto paths = extract_paths_from_string(cmd);
        for (auto &pp : paths) {

            std::string s = pp.string();
            if (s.rfind("/etc/",0) == 0 || s.rfind("/opt/",0) == 0 || s.rfind("/var/",0) == 0 || s.rfind("/usr/",0) == 0) {
                ConfigFind info = inspect_path(pp);
                if (info.stat_error) global_perm_errors = true;
                findings.push_back(info);
            }
        }
    }

    if (findings.empty()) {
        std::cout << "  No candidate config files/directories discovered in scanned locations.\n";
    }

    std::sort(findings.begin(), findings.end(), [](const ConfigFind &a, const ConfigFind &b){ return a.path.string() < b.path.string(); });
    std::string last;
    for (auto &f : findings) {
        if (f.path.string() == last) continue;
        last = f.path.string();
        std::cout << "\nPath: " << f.path << "\n";
        if (!f.exists) { std::cout << "  (missing)\n"; continue; }
        if (f.stat_error) {
            std::cout << "  (stat error) " << f.stat_errmsg << "\n";
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE (cannot determine permissions for this config)\n";
            continue;
        }
        std::cout << "  owner: " << f.owner << ":" << f.group << " perms(octal): " << f.perms_octal << " size: " << f.size << "\n";
        if (f.readable) std::cout << "  [*] Readable by current account\n";
        if (f.writable_by_current) std::cout << "  [!] Writable by current account\n";
        if (f.writable_by_current) {
            std::cout << "  => ASSESSMENT: POTENTIALLY_EXPLOITABLE (config or plugin file writable)\n";
        } else if (f.readable && (f.path.string().find("/etc/") == 0 || f.path.string().find("/var/") == 0)) {
            std::cout << "  => ASSESSMENT: INFO (config readable; may contain secrets)\n";
        } else {
            std::cout << "  => ASSESSMENT: NOT_EXPLOITABLE_VIA_THIS_ACCOUNT (no writable flags observed)\n";
        }
    }

    if (global_perm_errors) {
        std::cout << "\nNote: some config files or directories could not be inspected due to permission/IO errors.\n";
        std::cout << "Those paths are treated as UNEXPLOREABLE and NOT considered exploitable from this account.\n";
    } else {
        std::cout << "\nService config audit complete. All scanned entries were inspected.\n";
    }
}

}


namespace fs = std::filesystem;

struct SUIDEntry {
    fs::path path;
    std::string owner;
    std::string group;
    std::string perms_octal;
    bool is_suid;
    bool is_sgid;
    bool writable_by_user;
    bool stat_error;
    std::string stat_errmsg;
};

static SUIDEntry inspect_suid_sgid(const fs::path& p) {
    SUIDEntry entry;
    entry.path = p;
    entry.stat_error = false;

    struct stat sb;
    if (lstat(p.c_str(), &sb) != 0) {
        entry.stat_error = true;
        entry.stat_errmsg = std::string("lstat errno=") + std::to_string(errno);
        return entry;
    }

    entry.is_suid = (sb.st_mode & S_ISUID) != 0;
    entry.is_sgid = (sb.st_mode & S_ISGID) != 0;

    struct passwd* pw = getpwuid(sb.st_uid);
    struct group* gr = getgrgid(sb.st_gid);
    entry.owner = pw ? pw->pw_name : std::to_string(sb.st_uid);
    entry.group = gr ? gr->gr_name : std::to_string(sb.st_gid);

    {
        char perms[5];
        snprintf(perms, sizeof(perms), "%03o", sb.st_mode & 0777);
        entry.perms_octal = perms;
    }

    entry.writable_by_user = (access(p.c_str(), W_OK) == 0);

    return entry;
}

void CheckSUID_SGID_Binaries() {
    std::cout << "\n[Escalation] Checking for SUID/SGID binaries with weak permissions...\n";

    std::vector<fs::path> search_paths = {
        "/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"
    };

    std::vector<SUIDEntry> findings;
    bool perm_error = false;

    for (const auto& dir : search_paths) {
        std::error_code ec;
        if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) continue;

        for (auto& entry : fs::directory_iterator(dir, ec)) {
            if (ec) {
                perm_error = true;
                break;
            }
            if (!entry.is_regular_file(ec)) continue;
            SUIDEntry info = inspect_suid_sgid(entry.path());
            if (info.stat_error) {
                perm_error = true;
                continue;
            }
            if (info.is_suid || info.is_sgid) {
                findings.push_back(info);
            }
        }
    }

    if (findings.empty()) {
        std::cout << "  No SUID or SGID binaries found.\n";
    }

    for (auto& f : findings) {
        std::cout << "\nPath: " << f.path << "\n";
        if (f.stat_error) {
            std::cout << "  (stat error) " << f.stat_errmsg << "\n";
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE\n";
            continue;
        }
        std::cout << "  Owner: " << f.owner << " Group: " << f.group << " Perms: " << f.perms_octal << "\n";
        std::cout << "  Flags: " << (f.is_suid ? "SUID " : "") << (f.is_sgid ? "SGID" : "") << "\n";
        if (f.writable_by_user) {
            std::cout << "  [!] Writable by current user - POTENTIALLY_EXPLOITABLE\n";
        } else {
            std::cout << "  [*] Not writable by current user - no direct exploitation via file overwrite\n";
        }
    }

    if (perm_error) {
        std::cout << "\nSome directories or files could not be accessed due to permission errors.\n";
        std::cout << "These entries are marked as UNEXPLOREABLE and assumed not exploitable from this account.\n";
    } else {
        std::cout << "\nSUID/SGID binary permission audit complete.\n";
    }
}


namespace pwbackup_audit_v1 {
namespace fs = std::filesystem;

struct PBInfo {
    fs::path path;
    bool exists = false;
    bool stat_error = false;
    std::string stat_errmsg;
    std::string owner;
    std::string group;
    std::string perms_octal;
    bool readable = false;
    uintmax_t size = 0;
};

static PBInfo inspect_path(const fs::path &p) {
    PBInfo r; r.path = p;
    std::error_code ec;
    fs::file_status st = fs::status(p, ec);
    if (ec) { r.stat_error = true; r.stat_errmsg = ec.message(); return r; }
    r.exists = true;
    struct stat sb;
    if (lstat(p.c_str(), &sb) != 0) {
        r.stat_error = true;
        r.stat_errmsg = std::string("lstat errno=") + std::to_string(errno);
        return r;
    }
    struct passwd *pw = getpwuid(sb.st_uid);
    struct group  *gr = getgrgid(sb.st_gid);
    r.owner = pw ? pw->pw_name : std::to_string(sb.st_uid);
    r.group = gr ? gr->gr_name : std::to_string(sb.st_gid);
    {
        std::ostringstream os; os << std::oct << (sb.st_mode & 0777);
        r.perms_octal = os.str();
    }
    r.size = (uintmax_t)sb.st_size;
    r.readable = (access(p.c_str(), R_OK) == 0);
    return r;
}

static std::vector<fs::path> seed_dirs() {
    std::vector<fs::path> out = {
        "/etc",
        "/root",
        "/home",
        "/var/backups",
        "/var/lib",
        "/var/www",
        "/opt",
        "/srv",
        "/tmp"
    };
    return out;
}

static bool looks_like_backup_or_credential(const fs::path &p) {
    std::string fn = p.filename().string();
    std::string lower = fn;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    static const std::vector<std::string> exts = { ".bak", ".old", ".orig", ".save", ".backup", ".tar", ".tgz", ".gz", ".zip", ".sql", ".dump", ".tar.gz", ".7z" };
    for (auto &e : exts) if (lower.size() >= e.size() && lower.compare(lower.size()-e.size(), e.size(), e) == 0) return true;

    static const std::vector<std::string> keywords = {"passwd","shadow","password","secret","cred","keys","id_rsa","id_ed25519","credentials","auth","config"};
    for (auto &k : keywords) if (lower.find(k) != std::string::npos) return true;

    return false;
}

void RunPasswordBackupAudit() {
    std::cout << "\n[Password & Backup Audit] Searching for potential backup/credential files\n";
    bool global_stat_errors = false;
    std::vector<PBInfo> findings;

    auto seeds = seed_dirs();
    for (auto &sd : seeds) {
        std::error_code ec;
        if (!fs::exists(sd, ec)) continue;

        if (sd == fs::path("/home")) {
            for (auto &u : fs::directory_iterator(sd, ec)) {
                if (ec) { global_stat_errors = true; break; }
                if (!u.is_directory(ec)) continue;
                size_t seen = 0;
                for (auto &ent : fs::directory_iterator(u.path(), ec)) {
                    if (ec) { global_stat_errors = true; break; }
                    if (++seen > 200) break;
                    if (looks_like_backup_or_credential(ent.path())) {
                        PBInfo info = inspect_path(ent.path());
                        if (info.stat_error) global_stat_errors = true;
                        findings.push_back(info);
                    }
                }
            }
        } else {

            size_t seen = 0;
            for (auto &ent : fs::directory_iterator(sd, ec)) {
                if (ec) { global_stat_errors = true; break; }
                if (++seen > 500) break;
                if (looks_like_backup_or_credential(ent.path())) {
                    PBInfo info = inspect_path(ent.path());
                    if (info.stat_error) global_stat_errors = true;
                    findings.push_back(info);
                }
                if (fs::is_directory(ent.path())) {
                    size_t inner = 0;
                    for (auto &sub : fs::directory_iterator(ent.path(), ec)) {
                        if (ec) { global_stat_errors = true; break; }
                        if (++inner > 200) break;
                        if (looks_like_backup_or_credential(sub.path())) {
                            PBInfo info = inspect_path(sub.path());
                            if (info.stat_error) global_stat_errors = true;
                            findings.push_back(info);
                        }
                    }
                }
            }
        }
    }

    if (findings.empty()) {
        std::cout << "  No obvious backup/credential candidate files found in scanned locations.\n";
    }

    std::sort(findings.begin(), findings.end(), [](const PBInfo &a, const PBInfo &b){ return a.path.string() < b.path.string(); });
    std::string last;
    for (auto &f : findings) {
        if (f.path.string() == last) continue;
        last = f.path.string();
        std::cout << "\nPath: " << f.path << "\n";
        if (!f.exists) { std::cout << "  (missing)\n"; continue; }
        if (f.stat_error) {
            std::cout << "  (stat error) " << f.stat_errmsg << "\n";
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE (permission/visibility error for this path)\n";
            continue;
        }
        std::cout << "  owner: " << f.owner << ":" << f.group << " perms(octal): " << f.perms_octal << " size: " << f.size << "\n";
        if (f.readable) {
            std::cout << "  [!] READABLE by current account\n";
            std::cout << "  => ASSESSMENT: POTENTIALLY_EXPLOITABLE (contains passwords/keys/backups readable by this account)\n";
        } else {
            std::cout << "  [-] Not readable by current account\n";
            std::cout << "  => ASSESSMENT: NOT_EXPLOITABLE_VIA_THIS_ACCOUNT\n";
        }
    }

    if (global_stat_errors) {
        std::cout << "\nNote: some directories or files could not be inspected due to permission errors; those entries are treated as UNEXPLOREABLE.\n";
    } else {
        std::cout << "\nPassword & Backup audit complete.\n";
    }
}

}


namespace container_audit_v1 {
namespace fs = std::filesystem;

struct CRTFind {
    fs::path path;
    bool exists = false;
    bool stat_error = false;
    std::string stat_errmsg;
    std::string owner;
    std::string group;
    std::string perms_octal;
    bool readable = false;
    bool writable = false;
    uintmax_t size = 0;
};

static CRTFind inspect_path(const fs::path &p) {
    CRTFind r; r.path = p;
    std::error_code ec;
    fs::file_status st = fs::status(p, ec);
    if (ec) { r.stat_error = true; r.stat_errmsg = ec.message(); return r; }
    r.exists = true;
    struct stat sb;
    if (lstat(p.c_str(), &sb) != 0) {
        r.stat_error = true;
        r.stat_errmsg = std::string("lstat errno=") + std::to_string(errno);
        return r;
    }
    struct passwd *pw = getpwuid(sb.st_uid);
    struct group  *gr = getgrgid(sb.st_gid);
    r.owner = pw ? pw->pw_name : std::to_string(sb.st_uid);
    r.group = gr ? gr->gr_name : std::to_string(sb.st_gid);
    {
        std::ostringstream os; os << std::oct << (sb.st_mode & 0777);
        r.perms_octal = os.str();
    }
    r.size = (uintmax_t)sb.st_size;
    r.readable = (access(p.c_str(), R_OK) == 0);
    r.writable = (access(p.c_str(), W_OK) == 0);
    return r;
}

static bool user_in_group_name(const std::string &groupname) {
    struct group *gr = getgrnam(groupname.c_str());
    if (!gr) return false;
    gid_t gid = gr->gr_gid;

    int ngroups = getgroups(0, nullptr);
    if (ngroups < 0) return false;
    std::vector<gid_t> groups(ngroups);
    if (getgroups(ngroups, groups.data()) < 0) return false;
    for (gid_t g : groups) if (g == gid) return true;

    if (getegid() == gid) return true;
    return false;
}

static std::string current_user_name() {
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    return pw ? std::string(pw->pw_name) : std::to_string(uid);
}

void RunContainerRuntimeAudit() {
    std::cout << "\n[Container Runtime Audit] Checking Docker/Podman/containerd presence & access\n";

    bool global_stat_error = false;

    std::vector<fs::path> sockets = {
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/podman/podman.sock",
        "/var/run/podman.sock",
        "/run/containerd/containerd.sock",
        "/var/run/containerd/containerd.sock"
    };
    std::vector<fs::path> datadirs = {
        "/var/lib/docker",
        "/var/lib/containerd",
        "/var/lib/podman"
    };
    std::vector<std::string> binaries = { "docker", "podman", "containerd", "runc", "ctr" };

    for (auto &s : sockets) {
        CRTFind info = inspect_path(s);
        if (info.stat_error) global_stat_error = true;
        std::cout << "\nSocket: " << s << "\n";
        if (!info.exists) { std::cout << "  (missing)\n"; continue; }
        if (info.stat_error) {
            std::cout << "  (stat error) " << info.stat_errmsg << "\n";
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE\n";
            continue;
        }
        std::cout << "  owner: " << info.owner << ":" << info.group << " perms: " << info.perms_octal << "\n";
        if (info.readable) std::cout << "  [*] socket readable by current account\n";
        if (info.writable) std::cout << "  [*] socket writable by current account\n";
        if (info.writable || info.readable) {
            std::cout << "  => ASSESSMENT: POTENTIALLY_EXPLOITABLE (runtime socket accessible)\n";
        } else {
            std::cout << "  => ASSESSMENT: NOT_EXPLOITABLE_VIA_THIS_ACCOUNT (socket not accessible)\n";
        }
    }

    for (auto &d : datadirs) {
        CRTFind info = inspect_path(d);
        if (info.stat_error) global_stat_error = true;
        std::cout << "\nDataDir: " << d << "\n";
        if (!info.exists) { std::cout << "  (missing)\n"; continue; }
        if (info.stat_error) {
            std::cout << "  (stat error) " << info.stat_errmsg << "\n";
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE\n";
            continue;
        }
        std::cout << "  owner: " << info.owner << ":" << info.group << " perms: " << info.perms_octal << "\n";
        if (info.writable) std::cout << "  [!] Directory writable by current account\n";
        if (info.writable) std::cout << "  => ASSESSMENT: POTENTIALLY_EXPLOITABLE (runtime data dir writable)\n";
        else std::cout << "  => ASSESSMENT: NOT_EXPLOITABLE_VIA_THIS_ACCOUNT\n";
    }

    std::cout << "\nRuntime binaries in PATH (presence/exec not tested):\n";
    std::string pathenv;
    if (const char *p = std::getenv("PATH")) pathenv = p;
    std::vector<fs::path> path_parts;
    {
        size_t pos = 0;
        while (pos < pathenv.size()) {
            size_t colon = pathenv.find(':', pos);
            std::string tok = (colon==std::string::npos) ? pathenv.substr(pos) : pathenv.substr(pos, colon-pos);
            if (!tok.empty()) path_parts.push_back(tok);
            if (colon==std::string::npos) break;
            pos = colon+1;
        }
    }
    for (auto &bin : binaries) {
        bool found = false;
        CRTFind info;
        for (auto &pp : path_parts) {
            fs::path p = pp / bin;
            if (fs::exists(p)) {
                info = inspect_path(p);
                if (info.stat_error) global_stat_error = true;
                found = true;
                break;
            }
        }
        std::cout << "\nBinary: " << bin << "\n";
        if (!found) { std::cout << "  (not found in PATH)\n"; continue; }
        if (info.stat_error) {
            std::cout << "  (stat error) " << info.stat_errmsg << "\n";
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE\n";
            continue;
        }
        std::cout << "  path: " << info.path << " owner: " << info.owner << ":" << info.group << " perms: " << info.perms_octal << "\n";
        std::cout << "  => ASSESSMENT: " << (info.writable ? "POTENTIALLY_EXPLOITABLE (binary writable)" : "NOT_EXPLOITABLE_VIA_THIS_ACCOUNT") << "\n";
    }

    std::cout << "\nGroup membership checks:\n";
    std::vector<std::string> runtime_groups = { "docker", "podman", "containerd" };
    for (auto &g : runtime_groups) {
        bool ingrp = user_in_group_name(g);
        std::cout << "  In group '" << g << "': " << (ingrp ? "YES" : "NO") << "\n";
        if (ingrp) {
            std::cout << "    => ASSESSMENT: POTENTIALLY_EXPLOITABLE (user has runtime group membership)\n";
        }
    }

    std::string home;
    if (const char *h = std::getenv("HOME")) home = h;
    if (!home.empty()) {
        fs::path kube = fs::path(home) / ".kube" / "config";
        CRTFind kinfo = inspect_path(kube);
        std::cout << "\nKube config: " << kube << "\n";
        if (kinfo.stat_error) { global_stat_error = true; std::cout << "  (stat error) " << kinfo.stat_errmsg << "\n"; }
        else if (!kinfo.exists) std::cout << "  (missing)\n";
        else {
            std::cout << "  owner: " << kinfo.owner << ":" << kinfo.group << " perms: " << kinfo.perms_octal << "\n";
            if (kinfo.readable) {
                std::cout << "  [!] READABLE by current account\n";
                std::cout << "  => ASSESSMENT: POTENTIALLY_EXPLOITABLE (kube credentials accessible)\n";
            } else {
                std::cout << "  => ASSESSMENT: NOT_EXPLOITABLE_VIA_THIS_ACCOUNT\n";
            }
        }
    }

    if (global_stat_error) {
        std::cout << "\nNote: some files or directories could not be inspected due to permission errors; those are marked UNEXPLOREABLE.\n";
    } else {
        std::cout << "\nContainer runtime audit complete.\n";
    }
}

}


namespace pam_audit_v1 {

struct FileInfo {
    fs::path path;
    bool exists = false;
    bool stat_error = false;
    std::string stat_errmsg;
    std::string owner;
    std::string group;
    std::string perms_octal;
    bool readable = false;
    bool writable = false;
    bool suspicious_content = false;
    std::vector<std::string> suspicious_lines;
};

static FileInfo inspect_path(const fs::path &p) {
    FileInfo info;
    info.path = p;

    std::error_code ec;
    if (!fs::exists(p, ec)) {
        info.exists = false;
        return info;
    }
    info.exists = true;

    struct stat sb;
    if (lstat(p.c_str(), &sb) != 0) {
        info.stat_error = true;
        info.stat_errmsg = std::string("lstat errno=") + std::to_string(errno);
        return info;
    }

    struct passwd *pw = getpwuid(sb.st_uid);
    struct group  *gr = getgrgid(sb.st_gid);
    info.owner = pw ? pw->pw_name : std::to_string(sb.st_uid);
    info.group = gr ? gr->gr_name : std::to_string(sb.st_gid);

    {
        std::ostringstream os;
        os << std::oct << (sb.st_mode & 0777);
        info.perms_octal = os.str();
    }

    info.readable = (access(p.c_str(), R_OK) == 0);
    info.writable = (access(p.c_str(), W_OK) == 0);

    if (info.readable) {
        std::ifstream file(p);
        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                std::string lower_line = line;
                std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);

                if (lower_line.find("pam_permit.so") != std::string::npos ||
                    lower_line.find("pam_deny.so") != std::string::npos ||  // sometimes deny is also misused in unexpected ways
                    lower_line.find("pam_wheel.so trust") != std::string::npos ||
                    lower_line.find("nullok") != std::string::npos ||
                    lower_line.find("pam_shells.so") != std::string::npos ||
                    lower_line.find("pam_unix.so") != std::string::npos && lower_line.find("nullok") != std::string::npos)
                {
                    info.suspicious_content = true;
                    info.suspicious_lines.push_back(line);
                }
            }
        }
    }

    return info;
}

static std::vector<fs::path> pam_config_dirs() {
    return {
        "/etc/pam.d"
    };
}

static std::vector<fs::path> ldap_sssd_config_files() {
    return {
        "/etc/ldap.conf",
        "/etc/sssd/sssd.conf",
        "/etc/sssd/conf.d"
    };
}

void RunPAMAndAuthConfigAudit() {
    std::cout << "\n[PAM & Auth Config Audit] Scanning PAM, LDAP and SSSD configuration files...\n";

    bool global_stat_errors = false;
    std::vector<FileInfo> findings;

    for (const auto &dir : pam_config_dirs()) {
        std::error_code ec;
        if (!fs::exists(dir, ec)) continue;

        for (const auto &entry : fs::directory_iterator(dir, ec)) {
            if (ec) { global_stat_errors = true; break; }
            if (fs::is_regular_file(entry.path(), ec)) {
                FileInfo info = inspect_path(entry.path());
                if (info.stat_error) global_stat_errors = true;
                findings.push_back(info);
            }
        }
    }

    for (const auto &p : ldap_sssd_config_files()) {
        std::error_code ec;
        if (!fs::exists(p, ec)) continue;

        if (fs::is_directory(p, ec)) {
            for (const auto &entry : fs::directory_iterator(p, ec)) {
                if (ec) { global_stat_errors = true; break; }
                if (fs::is_regular_file(entry.path(), ec)) {
                    FileInfo info = inspect_path(entry.path());
                    if (info.stat_error) global_stat_errors = true;
                    findings.push_back(info);
                }
            }
        } else if (fs::is_regular_file(p, ec)) {
            FileInfo info = inspect_path(p);
            if (info.stat_error) global_stat_errors = true;
            findings.push_back(info);
        }
    }

    if (findings.empty()) {
        std::cout << "  No PAM or LDAP/SSSD config files found.\n";
    }

    std::sort(findings.begin(), findings.end(), [](const FileInfo &a, const FileInfo &b){ return a.path.string() < b.path.string(); });
    std::string last;
    for (const auto &f : findings) {
        if (f.path.string() == last) continue;
        last = f.path.string();

        std::cout << "\nPath: " << f.path << "\n";

        if (!f.exists) {
            std::cout << "  (missing)\n";
            continue;
        }

        if (f.stat_error) {
            std::cout << "  (stat error) " << f.stat_errmsg << "\n";
            std::cout << "  => ASSESSMENT: UNEXPLOREABLE (permission/visibility error for this path)\n";
            continue;
        }

        std::cout << "  owner: " << f.owner << ":" << f.group << " perms(octal): " << f.perms_octal << "\n";
        if (f.readable) {
            std::cout << "  [!] READABLE by current account\n";
            if (f.writable) {
                std::cout << "  [!] WRITABLE by current account\n";
                std::cout << "  => ASSESSMENT: POTENTIALLY_DANGEROUS (Writable auth config is very risky)\n";
            } else {
                std::cout << "  [-] Not writable by current account\n";
            }

            if (f.suspicious_content) {
                std::cout << "  [!] Contains suspicious PAM rules/options:\n";
                for (const auto &line : f.suspicious_lines) {
                    std::cout << "    " << line << "\n";
                }
                std::cout << "  => ASSESSMENT: POTENTIAL_AUTH_BYPASS_RISK\n";
            }
        } else {
            std::cout << "  [-] Not readable by current account\n";
            std::cout << "  => ASSESSMENT: NOT_EXPLOITABLE_VIA_THIS_ACCOUNT\n";
        }
    }

    if (global_stat_errors) {
        std::cout << "\nNote: some directories or files could not be inspected due to permission errors; those entries are treated as UNEXPLOREABLE.\n";
    } else {
        std::cout << "\nPAM & Auth Config audit complete.\n";
    }
}

}

void CheckRootStatus() {
    if (getuid() == 0 || geteuid() == 0) {
        std::cout << "Elevated\n";
        return;
    }

    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("CapEff:", 0) == 0) {
            std::istringstream iss(line.substr(7));
            uint64_t cap = 0;
            iss >> std::hex >> cap;
            if (cap != 0) {
                std::cout << "Elevated Privilages Detected - Using ROOT\n";
                return;
            }
        }
    }

    std::cout << "No Elevated Privilages Detected - NOT using ROOT\n";
}



void DetectPortConfigs() {
    using namespace std;
    namespace fs = std::filesystem;

    auto is_private_ipv4 = [](const string &ip) {

        unsigned a,b,c,d;
        if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return false;
        if (a == 10) return true;
        if (a == 172 && b >= 16 && b <= 31) return true;
        if (a == 192 && b == 168) return true;
        if (a == 127) return true; // loopback treat as private/local I guess?
        return false;
    };

    auto is_unspecified = [](const string &ip) {
        return ip == "0.0.0.0" || ip == "::" || ip == "0:0:0:0:0:0:0:0";
    };

    auto hex_to_ipv4 = [](const string &hex) -> string {
        if (hex.size() < 8) return "";
        unsigned long x = stoul(hex.substr(0,8), nullptr, 16);
        unsigned a = (x & 0xff);
        unsigned b = ((x >> 8) & 0xff);
        unsigned c = ((x >> 16) & 0xff);
        unsigned d = ((x >> 24) & 0xff);
        char buf[64];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a,b,c,d);
        return string(buf);
    };

    auto hex_to_ipv6 = [](const string &hex) -> string {
        if (hex.size() < 32) return "";
        unsigned char bytes[16];
        for (int i = 0; i < 16; ++i) {
            string b = hex.substr(i*2, 2);
            bytes[i] = static_cast<unsigned char>(stoul(b, nullptr, 16));
        }
        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, bytes, buf, sizeof(buf)) == nullptr) return "";
        return string(buf);
    };

    auto parse_addr_port = [&](const string &s, bool is_v6) -> pair<string,int> {
        auto p = s.find(':');
        if (p == string::npos) return {"",0};
        string addr = s.substr(0,p);
        string porthex = s.substr(p+1);
        int port = stoi(porthex, nullptr, 16);
        string ip = is_v6 ? hex_to_ipv6(addr) : hex_to_ipv4(addr);
        return {ip, port};
    };

    struct Entry { string proto; string ip; int port; string state; unsigned long inode; int uid; };

    auto parse_proc_net = [&](const string &path, const string &proto) -> vector<Entry> {
        vector<Entry> out;
        ifstream f(path);
        if (!f.is_open()) return out;
        string line;
        getline(f, line);
        bool v6 = (proto.find('6') != string::npos);
        while (getline(f,line)) {
            if (line.empty()) continue;
            istringstream iss(line);
            string sl, local, rem, state, tx, rx, tr, tm, retr, uid_str, timeout, inode_str;
            if (!(iss >> sl >> local >> rem >> state >> tx >> rx >> tr >> tm >> retr >> uid_str >> timeout >> inode_str)) continue;
            auto ap = parse_addr_port(local, v6);
            if (ap.first.empty()) continue;
            Entry e;
            e.proto = proto;
            e.ip = ap.first;
            e.port = ap.second;
            e.state = state;
            e.inode = 0;
            try { e.inode = stoul(inode_str); } catch(...) {}
            e.uid = stoi(uid_str);
            out.push_back(e);
        }
        return out;
    };

    unordered_map<unsigned long, pair<int,string>> inode_map;
    try {
        regex sock_re(R"(socket:\[(\d+)\])");
        for (const auto &p : fs::directory_iterator("/proc")) {
            if (!p.is_directory()) continue;
            string pidstr = p.path().filename().string();
            if (!all_of(pidstr.begin(), pidstr.end(), ::isdigit)) continue;
            int pid = stoi(pidstr);
            string comm;
            ifstream cf(p.path() / "comm");
            if (cf.is_open()) getline(cf, comm);
            fs::path fdpath = p.path() / "fd";
            if (!fs::exists(fdpath)) continue;
            for (const auto &fd : fs::directory_iterator(fdpath)) {
                error_code ec;
                string target = fs::read_symlink(fd.path(), ec).string();
                if (ec) continue;
                smatch m;
                if (regex_match(target, m, sock_re) && m.size() >= 2) {
                    unsigned long ino = stoul(m[1].str());
                    if (inode_map.find(ino) == inode_map.end()) inode_map[ino] = {pid, comm};
                }
            }
        }
    } catch (...) {}

    vector<Entry> entries;
    auto v = parse_proc_net("/proc/net/tcp", "tcp");
    entries.insert(entries.end(), v.begin(), v.end());
    v = parse_proc_net("/proc/net/tcp6", "tcp6"); entries.insert(entries.end(), v.begin(), v.end());
    v = parse_proc_net("/proc/net/udp", "udp"); entries.insert(entries.end(), v.begin(), v.end());
    v = parse_proc_net("/proc/net/udp6", "udp6"); entries.insert(entries.end(), v.begin(), v.end());
    vector<string> local_ips;
    bool has_public_ip = false;
    {
        struct ifaddrs *ifap = nullptr;
        if (getifaddrs(&ifap) == 0) {
            for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr) continue;
                char buf[INET6_ADDRSTRLEN] = {0};
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    struct sockaddr_in *sa = (struct sockaddr_in*)ifa->ifa_addr;
                    inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
                    string ip(buf);
                    local_ips.push_back(ip);
                    if (!is_private_ipv4(ip) && ip != "0.0.0.0" && ip != "127.0.0.1") has_public_ip = true;
                } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                    struct sockaddr_in6 *sa6 = (struct sockaddr_in6*)ifa->ifa_addr;
                    inet_ntop(AF_INET6, &sa6->sin6_addr, buf, sizeof(buf));
                    string ip(buf);
                    local_ips.push_back(ip);
                    if (ip.find("fe80") != 0 && !is_unspecified(ip)) has_public_ip = true;
                }
            }
            freeifaddrs(ifap);
        }
    }

    auto read_first_line_int = [&](const string &path) -> int {
        ifstream f(path);
        int v = 0;
        if (f.is_open()) { string s; getline(f, s); try { v = stoi(s); } catch(...) { v = 0; } }
        return v;
    };
    int ipv4_forward = read_first_line_int("/proc/sys/net/ipv4/ip_forward");
    int ipv6_forward = read_first_line_int("/proc/sys/net/ipv6/conf/all/forwarding");

    bool found_upnp = false;
    for (auto &p : inode_map) {
        string comm = p.second.second;
        if (comm.find("miniupnpd") != string::npos || comm.find("upnp") != string::npos) { found_upnp = true; break; }
    }

    cout << "\n=== DetectPortConfigs: local listening sockets & exposure heuristics ===\n\n";
    cout << left << setw(6) << "Proto" << setw(24) << "Local Address:Port" << setw(10) << "Bind" << setw(8) << "UID" << "PID/Program\n";
    cout << string(80, '-') << "\n";

    for (const auto &e : entries) {
        bool is_tcp = (e.proto == "tcp" || e.proto == "tcp6");
        if (is_tcp && e.state != "0A") {
            continue;
        }
        string bind = e.ip.empty() ? "-" : e.ip;
        string bindinfo;
        if (is_unspecified(bind)) bindinfo = "ALL";
        else if (!bind.empty() && (is_private_ipv4(bind) == false)) bindinfo = "PUBLIC";
        else bindinfo = "LOCAL";

        string proc = "-";
        auto it = inode_map.find(e.inode);
        if (it != inode_map.end()) {
            proc = to_string(it->second.first) + "/" + (it->second.second.empty() ? "-" : it->second.second);
        }

        ostringstream addr;
        addr << bind << ":" << e.port;
        cout << left << setw(6) << e.proto
             << setw(24) << addr.str()
             << setw(10) << bindinfo
             << setw(8) << e.uid
             << proc << "\n";
    }

    cout << "\nSummary heuristics:\n";
    cout << " - IPv4 forwarding (/proc/sys/net/ipv4/ip_forward): " << (ipv4_forward ? "ENABLED" : "disabled") << "\n";
    cout << " - IPv6 forwarding (/proc/sys/net/ipv6/conf/all/forwarding): " << (ipv6_forward ? "ENABLED" : "disabled") << "\n";
    cout << " - Local public IP present: " << (has_public_ip ? "yes" : "no (only private/internal IPs)") << "\n";
    cout << " - UPnP/IGD process detected (heuristic): " << (found_upnp ? "yes (possible auto port mapping)" : "no") << "\n";

    cout << "\nNotes on interpretation:\n"
         << " * 'ALL' bind means the socket listens on all interfaces (0.0.0.0 or ::) — if this host has a public IP or is behind NAT with port mapping, that port may be reachable externally.\n"
         << " * 'PUBLIC' bind means the socket is directly bound to a non-private IP assigned to this machine — likely externally reachable.\n"
         << " * 'LOCAL' means bound to a private address or loopback and is usually not externally reachable without forwarding/NAT rules.\n"
         << " * This function uses local heuristics only (no external probing). To be certain of public reachability, perform an external port probe from outside the host network.\n";

    cout << "\nDone.\n\n";
}



void SummarizeFirewallAndNAT() {
    using namespace std;
    namespace fs = std::filesystem;

    auto read_first_line = [&](const string &path) -> string {
        ifstream f(path);
        string s;
        if (f.is_open()) {
            if (!getline(f, s)) s.clear();
        }
        return s;
    };

    auto read_int = [&](const string &path) -> int {
        string s = read_first_line(path);
        try { return stoi(s); } catch(...) { return 0; }
    };

    auto file_exists = [&](const string &path)->bool {
        error_code ec;
        return fs::exists(path, ec);
    };

    auto print_header = [&](const string &title) {
        cout << "\n=== " << title << " ===\n";
    };

    print_header("IP Forwarding");
    int ipv4_forward = read_int("/proc/sys/net/ipv4/ip_forward");
    int ipv6_forward = read_int("/proc/sys/net/ipv6/conf/all/forwarding");
    cout << "IPv4 forwarding (/proc/sys/net/ipv4/ip_forward): " << (ipv4_forward ? "ENABLED" : "disabled") << "\n";
    cout << "IPv6 forwarding (/proc/sys/net/ipv6/conf/all/forwarding): " << (ipv6_forward ? "ENABLED" : "disabled") << "\n";

    print_header("Conntrack / Active Connections (sample)");
    const vector<string> conntrack_paths = { "/proc/net/nf_conntrack", "/proc/net/ip_conntrack" };
    bool conntrack_found = false;
    for (auto &p : conntrack_paths) {
        if (file_exists(p)) {
            conntrack_found = true;
            ifstream f(p);
            string line;
            size_t count = 0;
            vector<string> samples;
            while (getline(f, line)) {
                ++count;
                if (samples.size() < 8) samples.push_back(line);
            }
            cout << p << ": entries=" << count << "\n";
            if (!samples.empty()) {
                cout << "Sample entries:\n";
                for (auto &s : samples) {
                    if (s.size() > 200) s = s.substr(0, 200) + "...";
                    cout << "  " << s << "\n";
                }
            }
            break;
        }
    }
    if (!conntrack_found) {
        cout << "No conntrack file found under /proc/net (nf_conntrack/ip_conntrack not present or module not loaded)\n";
    }

    print_header("Firewall subsystem presence");
    bool has_iptables_proc = file_exists("/proc/net/ip_tables_names");
    bool has_nft_proc = file_exists("/proc/net/netfilter");
    bool has_nftables_conf = file_exists("/etc/nftables.conf");
    bool has_iptables_rules_v4 = file_exists("/etc/iptables/rules.v4") || file_exists("/etc/iptables.rules");
    bool has_iptables_rules_v6 = file_exists("/etc/iptables/rules.v6");
    cout << "proc: /proc/net/ip_tables_names: " << (has_iptables_proc ? "present" : "absent") << "\n";
    cout << "proc: /proc/net/netfilter: " << (has_nft_proc ? "present" : "absent") << "\n";
    cout << "etc: /etc/nftables.conf: " << (has_nftables_conf ? "present" : "absent") << "\n";
    cout << "etc: /etc/iptables/rules.v4 or rules: " << (has_iptables_rules_v4 ? "present" : "absent") << "\n";
    cout << "etc: /etc/iptables/rules.v6: " << (has_iptables_rules_v6 ? "present" : "absent") << "\n";


    if (has_iptables_proc) {
        string content = read_first_line("/proc/net/ip_tables_names");
        cout << "iptables tables: " << (content.empty() ? "(none listed)" : content) << "\n";
    }

    print_header("Firewall config file previews (first 8 lines)");
    vector<string> cfgs = { "/etc/iptables/rules.v4", "/etc/iptables/rules.v6", "/etc/nftables.conf" };
    for (auto &cfg : cfgs) {
        if (file_exists(cfg)) {
            cout << cfg << " (exists) — preview:\n";
            ifstream f(cfg);
            string line;
            int ln = 0;
            while (getline(f, line) && ln < 8) {
                cout << "  " << ln+1 << ": " << (line.size() > 200 ? line.substr(0,200) + "..." : line) << "\n";
                ++ln;
            }
            if (ln == 0) cout << "  (empty file)\n";
        }
    }

    print_header("Firewall frontends/management (config dirs)");
    vector<string> dirs = { "/etc/ufw", "/etc/firewalld", "/etc/shorewall" };
    for (auto &d : dirs) {
        cout << d << ": " << (file_exists(d) ? "present" : "absent") << "\n";
    }

    set<string> watchers;
    vector<string> interesting = { "iptables", "ip6tables", "nft", "nftables", "firewalld", "ufw", "conntrack", "conntrackd", "shorewall", "miniupnpd", "upnp" };
    try {
        for (auto &p : fs::directory_iterator("/proc")) {
            if (!p.is_directory()) continue;
            string name = p.path().filename().string();
            if (!all_of(name.begin(), name.end(), ::isdigit)) continue;
            string commPath = p.path().string() + "/comm";
            string comm = read_first_line(commPath);
            if (!comm.empty()) {

                string lcomm = comm;
                transform(lcomm.begin(), lcomm.end(), lcomm.begin(), [](unsigned char c){ return std::tolower(c); });
                for (auto &ii : interesting) {
                    if (lcomm.find(ii) != string::npos) {
                        watchers.insert(comm + " (pid " + name + ")");
                    }
                }
            }
        }
    } catch (...) { /* ignore shit */ }

    if (watchers.empty()) cout << "No obvious firewall/NAT daemons found by process name scanning.\n";
    else {
        cout << "Detected processes:\n";
        for (auto &w : watchers) cout << "  " << w << "\n";
    }

    print_header("Network exposure heuristics");
    bool has_public_ipv4 = false;

    if (file_exists("/proc/net/route")) {
        ifstream rt("/proc/net/route");
        string line;
        getline(rt, line);
        while (getline(rt, line)) {
            if (line.empty()) continue;
            istringstream iss(line);
            string iface, dest;
            if (!(iss >> iface >> dest)) continue;
            if (dest == "00000000") {
                cout << "Default route via interface: " << iface << "\n";
            }
        }
    }

    if (file_exists("/proc/net/arp")) {
        ifstream arpf("/proc/net/arp");
        string l;
        getline(arpf, l);
        int arpCount = 0;
        while (getline(arpf, l) && arpCount < 8) {
            if (l.empty()) continue;
            cout << "ARP: " << l << "\n";
            ++arpCount;
        }
    }

    print_header("NAT / Forwarding heuristics summary");
    int conntrack_entries = 0;
    for (auto &p : conntrack_paths) {
        if (file_exists(p)) {
            ifstream f(p);
            string tmp;
            while (getline(f, tmp)) ++conntrack_entries;
            break;
        }
    }
    cout << "Conntrack entries: " << conntrack_entries << "\n";
    cout << "IPv4 forward: " << (ipv4_forward ? "ENABLED" : "disabled") << "\n";
    cout << "IPv6 forward: " << (ipv6_forward ? "ENABLED" : "disabled") << "\n";
    cout << "iptables/nftables config files present: "
         << (has_iptables_rules_v4 || has_iptables_rules_v6 || has_nftables_conf ? "yes" : "no") << "\n";
    cout << "UPnP/miniupnpd or other automatic mappers detected by process scan: "
         << (watchers.size() ? "possible (see process list above)" : "no obvious evidence") << "\n";

    cout << "\nInterpreting results (guidance):\n";
    cout << " - If IPv4 forwarding is enabled and conntrack entries are present, the host may be forwarding/NATing packets.\n";
    cout << " - Presence of /etc/nftables.conf or /etc/iptables/rules.v4 suggests persistent rules; previewed above if available.\n";
    cout << " - Absence of conntrack and disabled ip_forward does not guarantee no NAT on network (NAT may be done on upstream gateway).\n";
    cout << " - To verify external reachability of specific ports, perform an external probe from outside the network (not done by this function).\n";

    cout << "\nDone.\n\n";
}



namespace fs = std::filesystem;

static std::map<std::string, std::string> gather_packages() {
    std::map<std::string, std::string> out;

    if (fs::exists("/var/lib/dpkg/status")) {
        std::ifstream f("/var/lib/dpkg/status");
        std::string line, pkg, ver;
        while (std::getline(f, line)) {
            if (line.empty()) {
                if (!pkg.empty()) { out[pkg] = ver; pkg.clear(); ver.clear(); }
                continue;
            }
            if (line.rfind("Package:", 0) == 0) {
                pkg = line.substr(8);
                pkg.erase(0, pkg.find_first_not_of(" \t"));
            } else if (line.rfind("Version:", 0) == 0) {
                ver = line.substr(8);
                ver.erase(0, ver.find_first_not_of(" \t"));
            }
        }
        if (!pkg.empty()) out[pkg] = ver;
        if (!out.empty()) return out;
    }

    if (fs::exists("/var/lib/pacman/local")) {
        for (auto &d : fs::directory_iterator("/var/lib/pacman/local")) {
            if (!d.is_directory()) continue;
            std::ifstream f(d.path() / "desc");
            std::string line, name, ver;
            while (std::getline(f, line)) {
                if (line == "%NAME%") std::getline(f, name);
                else if (line == "%VERSION%") std::getline(f, ver);
                if (!name.empty() && !ver.empty()) {
                    out[name] = ver;
                    break;
                }
            }
        }
        if (!out.empty()) return out;
    }

    if (fs::exists("/lib/apk/db/installed")) {
        std::ifstream f("/lib/apk/db/installed");
        std::string line, pkg, ver;
        while (std::getline(f, line)) {
            if (line.rfind("P:", 0) == 0) pkg = line.substr(2);
            else if (line.rfind("V:", 0) == 0) ver = line.substr(2);
            else if (line.empty()) {
                if (!pkg.empty()) { out[pkg] = ver; pkg.clear(); ver.clear(); }
            }
        }
        if (!pkg.empty()) out[pkg] = ver;
        if (!out.empty()) return out;
    }

    if (fs::exists("/bin/rpm") || fs::exists("/usr/bin/rpm")) {
        const char *cmd = "rpm -qa --qf \"%{NAME} %{VERSION}-%{RELEASE}\\n\" 2>/dev/null";
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
        if (pipe) {
            char buf[4096];
            while (fgets(buf, sizeof(buf), pipe.get())) {
                std::string s(buf);
                if (!s.empty() && s.back() == '\n') s.pop_back();
                std::istringstream iss(s);
                std::string name, version;
                if (!(iss >> name)) continue;
                getline(iss, version);
                version.erase(0, version.find_first_not_of(" \t"));
                out[name] = version;
            }
        }
    }

    return out;
}

static std::string detect_distro() {
    if (!fs::exists("/etc/os-release")) return "";
    std::ifstream f("/etc/os-release");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("ID=", 0) == 0) {
            std::string id = line.substr(3);
            if (!id.empty() && id.front() == '"') id = id.substr(1, id.size() - 2);
            std::transform(id.begin(), id.end(), id.begin(), [](unsigned char c) { return std::tolower(c); });
            return id;
        }
    }
    return "";
}

static bool has_curl() {
    return fs::exists("/usr/bin/curl") || fs::exists("/bin/curl") || fs::exists("/usr/local/bin/curl");
}

static std::string curl_post_osv(const std::string &json_payload) {
    std::string safe;
    for (char c : json_payload) {
        if (c == '\'') safe += "'\"'\"'";
        else safe.push_back(c);
    }
    std::string cmd = "curl -sS -X POST -H 'Content-Type: application/json' -d '" + safe + "' https://api.osv.dev/v1/query";
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "";
    std::string resp;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe.get())) {
        resp += buf;
    }
    return resp;
}

void CheckVulnsOnline() {
    using namespace std;

    cout << "\n=== Vulnerability Check (via OSV.dev) ===\n";

    auto pkgs = gather_packages();
    if (pkgs.empty()) {
        cout << "No packages found or unsupported distro.\n";
        return;
    }

    string distro = detect_distro();
    string ecosystem = "UNKNOWN";
    if (distro == "debian" || distro == "ubuntu") ecosystem = "Debian";
    else if (distro == "alpine") ecosystem = "Alpine";
    else if (distro == "arch") ecosystem = "Arch";
    else if (distro == "fedora" || distro == "centos" || distro == "rhel") ecosystem = "RPM";

    if (!has_curl()) {
        cout << "Missing curl. Cannot fetch online CVE data.\n";
        return;
    }

    size_t checked = 0;
    const size_t MAX = 200;
    size_t found = 0;

    for (const auto &kv : pkgs) {
        if (checked++ >= MAX) break;
        const string &pkg = kv.first;
        const string &ver = kv.second;
        if (pkg.empty() || ver.empty()) continue;

        ostringstream js;
        if (ecosystem != "UNKNOWN") {
            js << R"({"package":{"name":")" << pkg << R"(","ecosystem":")" << ecosystem << R"("},"version":")" << ver << R"("})";
        } else {
            js << R"({"package":{"name":")" << pkg << R"("},"version":")" << ver << R"("})";
        }

        string response = curl_post_osv(js.str());
        if (response.empty()) continue;

        std::set<std::string> cves;
        std::smatch m;
        std::regex cve_rx(R"((CVE-\d{4}-\d+))");
        auto begin = std::sregex_iterator(response.begin(), response.end(), cve_rx);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            cves.insert(it->str());
        }

        if (!cves.empty()) {
            ++found;
            cout << "\n[!] " << pkg << " (" << ver << ") — " << cves.size() << " CVE(s):\n";
            for (const auto &cve : cves) cout << "  - " << cve << "\n";
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    cout << "\nChecked " << checked << " packages; found " << found << " with CVEs.\n";
    cout << "Note: Results from OSV.dev — coverage may not include all distro packages.\n\n";
}



struct DeviceInfo {
    std::string ip;
    std::string mac;
    std::string hostname;
};


void GetLocalDevices() {
    auto mac_to_string = [](const unsigned char *mac)->std::string {
        char buf[32];
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    };
    const char *ifname = nullptr;
    in_addr local_addr{}; in_addr netmask{};
    unsigned char local_mac[6] = {0};
    bool found_iface = false;

    struct ifaddrs *ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) return;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;

        struct sockaddr_in *sin = (struct sockaddr_in*)ifa->ifa_addr;
        struct sockaddr_in *mask = (struct sockaddr_in*)ifa->ifa_netmask;
        ifname = ifa->ifa_name;
        local_addr = sin->sin_addr;
        netmask = mask->sin_addr;
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            struct ifreq ifr;
            memset(&ifr,0,sizeof(ifr));
            strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
            if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
                memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);
                found_iface = true;
            }
            close(s);
        }
        break;
    }
    freeifaddrs(ifaddr);
    if (!found_iface) return;
    uint32_t ip_h = ntohl(local_addr.s_addr);
    uint32_t mask_h = ntohl(netmask.s_addr);
    uint32_t network_h = ip_h & mask_h;
    uint32_t broadcast_h = network_h | (~mask_h);

    if (broadcast_h <= network_h + 1) {
        return;
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket(AF_PACKET)");
        return;
    }

    struct ifreq ifr_idx;
    memset(&ifr_idx,0,sizeof(ifr_idx));
    strncpy(ifr_idx.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr_idx) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(sock);
        return;
    }
    int ifindex = ifr_idx.ifr_ifindex;

    struct sockaddr_ll sll;
    memset(&sll,0,sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = ETH_ALEN;
    unsigned char bcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    memcpy(sll.sll_addr, bcast_mac, 6);
    unsigned char packet[42];

    memcpy(packet + 0, bcast_mac, 6);
    memcpy(packet + 6, local_mac, 6);
    packet[12] = 0x08; packet[13] = 0x06;

    packet[14] = 0x00; packet[15] = 0x01;
    packet[16] = 0x08; packet[17] = 0x00;
    packet[18] = 6; packet[19] = 4;       //AAAAAAAAH
    packet[20] = 0x00; packet[21] = 0x01;
    memcpy(packet + 22, local_mac, 6);
    uint32_t sender_ip_n = htonl(ip_h);
    memcpy(packet + 28, &sender_ip_n, 4);
    memset(packet + 32, 0x00, 6);

    for (uint32_t tgt = network_h + 1; tgt < broadcast_h; ++tgt) {
        uint32_t tgt_n = htonl(tgt);
        memcpy(packet + 38, &tgt_n, 4);
        ssize_t sent = sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&sll, sizeof(sll));
        (void)sent;
    }

    std::set<uint32_t> discovered_ips;
    std::map<uint32_t, std::array<unsigned char,6>> discovered_macs;

    struct timeval now{};
    gettimeofday(&now, nullptr);
    struct timeval deadline = now;
    deadline.tv_sec += 2;

    while (true) {
        struct timeval cur{};
        gettimeofday(&cur, nullptr);
        long sec_left = deadline.tv_sec - cur.tv_sec;
        long usec_left = deadline.tv_usec - cur.tv_usec;
        if (usec_left < 0) { usec_left += 1000000; sec_left -= 1; }
        if (sec_left < 0) break;
        struct timeval timeout;
        timeout.tv_sec = sec_left;
        timeout.tv_usec = usec_left;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        int r = select(sock + 1, &rfds, nullptr, nullptr, &timeout);
        if (r < 0) {
            perror("select");
            break;
        }
        if (r == 0) {
            continue;
        }
        if (FD_ISSET(sock, &rfds)) {
            unsigned char buf[65536];
            ssize_t len = recv(sock, buf, sizeof(buf), 0);
            if (len < 42) continue;
            if (buf[12] != 0x08 || buf[13] != 0x06) continue;
            if (buf[20] != 0x00 || buf[21] != 0x02) continue;
            unsigned char sender_mac[6];
            memcpy(sender_mac, buf + 22, 6);
            uint32_t sender_ip_n_recv;
            memcpy(&sender_ip_n_recv, buf + 28, 4);
            uint32_t sender_ip_h_recv = ntohl(sender_ip_n_recv);
            if (sender_ip_h_recv == ip_h) continue;
            discovered_ips.insert(sender_ip_h_recv);
            std::array<unsigned char,6> macarr;
            for (int i=0;i<6;++i) macarr[i] = sender_mac[i];
            discovered_macs[sender_ip_h_recv] = macarr;
        }
    }

    close(sock);

    for (auto ip_h_found : discovered_ips) {
        in_addr a; a.s_addr = htonl(ip_h_found);
        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
        std::cout << "IP: " << ipbuf << "  MAC: " << mac_to_string(discovered_macs[ip_h_found].data());

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr = a;
        char host[NI_MAXHOST];
        int gi = getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD);
        if (gi == 0) {
            std::cout << "  Hostname: " << host;
        }
        std::cout << std::endl;
    }
}



int Check_CVE_2022_0847(const std::string &kernel_arg = "")
{
    std::string kernel = kernel_arg;
    if (kernel.empty()) {
        struct utsname u;
        if (uname(&u) == 0) kernel = u.release;
        else kernel = "";
    }

    size_t dash = kernel.find('-');
    std::string base = (dash == std::string::npos) ? kernel : kernel.substr(0, dash);
    std::vector<int> parts;
    std::istringstream ss(base);
    std::string tok;
    while (std::getline(ss, tok, '.')) {
        try {
            parts.push_back(std::stoi(tok));
        } catch (...) {
            parts.push_back(0);
        }
    }
    parts.resize(3, 0);
    int ver1 = parts[0], ver2 = parts[1], ver3 = parts[2];

    std::cout << ver1 << " " << ver2 << " " << ver3 << "\n";
    bool not_vul = false;
    if ((ver1 < 5) ||
        (ver1 > 5) ||
        (ver1 == 5 && ver2 < 8) ||
        (ver1 == 5 && ver2 == 10 && ver3 == 102) ||
        (ver1 == 5 && ver2 == 10 && ver3 == 92) ||
        (ver1 == 5 && ver2 == 15 && ver3 == 25) ||
        (ver1 == 5 && ver2 >= 16 && ver3 >= 11) ||
        (ver1 == 5 && ver2 > 16))
    {
        not_vul = true;
    }

    if (not_vul) {
        std::cout << "Not vulnerable\n";
        return 0;
    } else {
        std::cout << "Vulnerable\n";
        return 1;
    }
}

void CVE_2022_0847_Wrapper() {
    Check_CVE_2022_0847();
}

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, last - first + 1);
}

std::string runCommand(const char* cmd) {
    std::array<char, 512> buffer{};
    std::string result;
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "ERR";
    while (fgets(buffer.data(), buffer.size(), pipe)) {
        result += buffer.data();
    }
    pclose(pipe);
    return trim(result);
}


std::string runCommand(const std::string& cmd) {
    std::array<char, 512> buffer{};
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "ERR";
    while (fgets(buffer.data(), buffer.size(), pipe)) {
        result += buffer.data();
    }
    pclose(pipe);
    return result;
}


void GetAPInfo() {

    std::cout << "---------------------------\n";
    std::string device = runCommand("nmcli -t -f DEVICE,TYPE,STATE dev | grep ':wifi:connected' | cut -d: -f1");
    device = trim(device);

    if (device.empty()) {
        std::cout << "Not connected to any Wi-Fi network.\n";
        return;
    }

    std::string wifiInfo = runCommand(("nmcli -t -f SSID,BSSID,SIGNAL dev wifi | grep $(iw dev " + device + " link | grep SSID | awk '{print $2}')").c_str());

    std::string ssid = runCommand("nmcli -t -f active,ssid dev wifi | grep '^yes' | cut -d: -f2");
    std::string bssid = runCommand("nmcli -t -f active,bssid dev wifi | grep '^yes' | cut -d: -f2");
    std::string signal = runCommand("nmcli -t -f active,signal dev wifi | grep '^yes' | cut -d: -f2");

    std::cout << "SSID     : " << trim(ssid) << '\n';
    std::cout << "BSSID    : " << trim(bssid) << '\n';
    std::cout << "Signal   : " << trim(signal) << " %" << '\n';
    std::cout << "Device   : " << device << '\n';

    std::string macPath = "/sys/class/net/" + device + "/address";
    std::string localMac = runCommand(("cat " + macPath).c_str());
    std::cout << "Local MAC: " << trim(localMac) << '\n';

    std::string ip = runCommand(("ip -4 addr show " + device + " | grep 'inet ' | awk '{print $2}' | cut -d/ -f1").c_str());
    std::cout << "IP Addr  : " << trim(ip) << '\n';


    std::string gateway = runCommand(("ip route | grep default | grep " + device + " | awk '{print $3}'").c_str());
    std::cout << "Gateway  : " << trim(gateway) << '\n';

    if (system("which iw > /dev/null 2>&1") == 0) {
        std::string iwInfo = runCommand(("iw dev " + device + " link").c_str());

        size_t pos = iwInfo.find("tx bitrate:");
        if (pos != std::string::npos) {
            std::string bitrate = iwInfo.substr(pos + 11, iwInfo.find('\n', pos) - pos - 11);
            std::cout << "Bitrate  : " << trim(bitrate) << '\n';
        }

        pos = iwInfo.find("freq:");
        if (pos != std::string::npos) {
            std::string freq = iwInfo.substr(pos + 5, iwInfo.find('\n', pos) - pos - 5);
            std::cout << "Freq     : " << trim(freq) << " MHz\n";
        }

        pos = iwInfo.find("signal:");
        if (pos != std::string::npos) {
            std::string sig = iwInfo.substr(pos + 7, iwInfo.find('\n', pos) - pos - 7);
            std::cout << "Signal(dBm): " << trim(sig) << '\n';
        }
    } else {
        std::cout << "'iw' not installed. Skipping bitrate/frequency/dBm info.\n";
    }
}

static std::set<std::string> get_local_ipv4_addresses() {
    std::set<std::string> ips;
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) return ips;
    for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            char buf[INET_ADDRSTRLEN] = {0};
            struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
            if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf))) {
                ips.insert(std::string(buf));
            }
        }
    }
    freeifaddrs(ifaddr);
    return ips;
}

static inline std::string now_str() {
    using namespace std::chrono;
    auto t = system_clock::now();
    auto s = system_clock::to_time_t(t);
    auto ms = duration_cast<milliseconds>(t.time_since_epoch()) % 1000;
    std::tm tm{};
    localtime_r(&s, &tm);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, (int)ms.count());
    return std::string(buf);
}

void StartPacketSniffer(const std::string& iface = "") {

    std::set<std::string> local_ips = get_local_ipv4_addresses();

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket(AF_PACKET)");
        std::cerr << "Need root privileges (CAP_NET_RAW) to capture packets.\n";
        return;
    }
    if (!iface.empty()) {
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
            perror("ioctl(SIOCGIFINDEX)");
            close(sock);
            return;
        }
        struct sockaddr_ll sll{};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
            perror("bind(AF_PACKET)");
            close(sock);
            return;
        }
        std::cout << "Capturing on interface: " << iface << "\n";
    } else {
        std::cout << "Capturing on all interfaces\n";
    }

    std::cout << "Press Ctrl+C to stop.\n\n";
    const size_t BUF_SZ = 65536;
    std::vector<uint8_t> buf(BUF_SZ);

    while (true) {
        ssize_t len = recvfrom(sock, buf.data(), (int)BUF_SZ, 0, nullptr, nullptr);
        if (len <= 0) continue;

        if ((size_t)len < sizeof(struct ethhdr) + sizeof(struct iphdr)) continue;

        struct ethhdr* eth = (struct ethhdr*)buf.data();
        uint16_t ethertype = ntohs(eth->h_proto);

        if (ethertype != ETH_P_IP) {
            continue;
        }

        size_t offset = sizeof(struct ethhdr);
        struct iphdr* ip = (struct iphdr*)(buf.data() + offset);
        size_t ip_hdr_len = ip->ihl * 4;
        if ((size_t)len < offset + ip_hdr_len) continue;

        char src_ip[INET_ADDRSTRLEN] = {0}, dst_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

        std::string dir = "UNK";
        if (local_ips.count(src_ip)) dir = "OUT";
        else if (local_ips.count(dst_ip)) dir = "IN";
        else dir = "UNKNOWN";

        uint8_t proto = ip->protocol;
        uint16_t sport = 0, dport = 0;
        std::string proto_name = std::to_string(proto);

        if (proto == IPPROTO_TCP && (size_t)len >= offset + ip_hdr_len + sizeof(struct tcphdr)) {
            struct tcphdr* th = (struct tcphdr*)(buf.data() + offset + ip_hdr_len);
            sport = ntohs(th->source);
            dport = ntohs(th->dest);
            proto_name = "TCP";
        } else if (proto == IPPROTO_UDP && (size_t)len >= offset + ip_hdr_len + sizeof(struct udphdr)) {
            struct udphdr* uh = (struct udphdr*)(buf.data() + offset + ip_hdr_len);
            sport = ntohs(uh->source);
            dport = ntohs(uh->dest);
            proto_name = "UDP";
        } else {
            if (proto == IPPROTO_ICMP) proto_name = "ICMP";
            else proto_name = "IP_PROTO_" + std::to_string(proto);
        }

        std::cout << now_str() << " ";
        std::cout << std::setw(3) << dir << " ";
        std::cout << std::left << std::setw(6) << proto_name << " ";
        std::cout << src_ip;
        if (sport) std::cout << ":" << sport;
        else std::cout << "     ";
        std::cout << " -> ";
        std::cout << dst_ip;
        if (dport) std::cout << ":" << dport;
        std::cout << "  len=" << len << "\n";
        std::cout.flush();
    }
    close(sock);
}


static std::set<std::string> get_local_ipv4_addresses();
static inline std::string now_str();


static bool payload_contains_http(const uint8_t* data, size_t len, std::string &out_line) {
    const char* methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/1.", nullptr};
    for (const char** m = methods; *m; ++m) {
        const char* p = std::search((const char*)data, (const char*)data + len, (*m), (*m) + std::strlen(*m));
        if (p != (const char*)data + len) {
            const char* line_start = p;
            const char* line_end = (const char*)memchr(line_start, '\n', ((const char*)data + len) - line_start);
            if (!line_end) line_end = (const char*)data + len;
            out_line.assign(line_start, line_end);
            while (!out_line.empty() && (out_line.back() == '\r' || out_line.back() == '\n')) out_line.pop_back();
            return true;
        }
    }
    return false;
}

static bool parse_tls_client_hello_sni(const uint8_t* data, size_t len, std::string &sni_out, std::string &tls_version_out) {
    sni_out.clear();
    tls_version_out.clear();
    if (len < 5) return false;
    if (data[0] != 0x16) return false;
    uint16_t record_version = (data[1] << 8) | data[2];
    tls_version_out = (record_version == 0x0301 ? "TLS1.0/SSL3.1" :
                       record_version == 0x0302 ? "TLS1.1" :
                       record_version == 0x0303 ? "TLS1.2" :
                       record_version == 0x0304 ? "TLS1.3" : "TLS_UNKNOWN");
    if (len < 5 + 4) return false;
    const uint8_t* p = data + 5;
    size_t remaining = len - 5;
    if (p[0] != 0x01) return false;
    if (remaining < 4) return false;
    uint32_t handshake_len = (p[1] << 16) | (p[2] << 8) | p[3];
    if (handshake_len + 4 > remaining) {
    }

    size_t idx = 4;
    if (remaining < idx + 2 + 32 + 1) return false;
    idx += 2 + 32;
    if (idx + 1 > remaining) return false;
    uint8_t session_id_len = p[idx];
    idx += 1 + session_id_len;
    if (idx + 2 > remaining) return false;
    uint16_t cs_len = (p[idx] << 8) | p[idx + 1];
    idx += 2 + cs_len;
    if (idx + 1 > remaining) return false;
    uint8_t comp_len = p[idx];
    idx += 1 + comp_len;
    if (idx + 2 > remaining) return false;
    uint16_t ext_total_len = (p[idx] << 8) | p[idx + 1];
    idx += 2;
    size_t ext_end = idx + ext_total_len;
    if (ext_end > remaining) {
        ext_end = remaining;
    }
    while (idx + 4 <= ext_end) {
        uint16_t ext_type = (p[idx] << 8) | p[idx + 1];
        uint16_t ext_len = (p[idx + 2] << 8) | p[idx + 3];
        idx += 4;
        if (idx + ext_len > ext_end) break;
        if (ext_type == 0x0000) {
            if (ext_len < 2) break;
            uint16_t list_len = (p[idx] << 8) | p[idx + 1];
            size_t li = idx + 2;
            size_t list_end = idx + ext_len;
            while (li + 3 <= list_end) {
                uint8_t name_type = p[li];
                uint16_t name_len = (p[li + 1] << 8) | p[li + 2];
                li += 3;
                if (li + name_len > list_end) break;
                if (name_type == 0) {
                    sni_out.assign((const char*)(p + li), name_len);
                    return true;
                }
                li += name_len;
            }
        }
        idx += ext_len;
    }
    return false;
}

void StartHTTPMonitorLoop(std::atomic<bool>& running, const std::string& iface = "") {
    std::set<std::string> local_ips = get_local_ipv4_addresses();

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket(AF_PACKET)");
        std::cerr << "Need root privileges (CAP_NET_RAW) to capture packets.\n";
        return;
    }

    if (!iface.empty()) {
        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
            perror("ioctl(SIOCGIFINDEX)");
            close(sock);
            return;
        }
        struct sockaddr_ll sll{};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
            perror("bind(AF_PACKET)");
            close(sock);
            return;
        }
        std::cout << "HTTP Monitor capturing on interface: " << iface << "\n";
    } else {
        std::cout << "HTTP Monitor capturing on all interfaces\n";
    }
    struct timeval tv{0, 200000}; // 200ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    const size_t BUF_SZ = 65536;
    std::vector<uint8_t> buf(BUF_SZ);

    std::cout << "Press Enter to stop monitor.\n\n";
    while (running.load()) {
        ssize_t len = recvfrom(sock, buf.data(), (int)BUF_SZ, 0, nullptr, nullptr);
        if (len <= 0) continue;
        if ((size_t)len < sizeof(struct ethhdr) + sizeof(struct iphdr)) continue;

        struct ethhdr* eth = (struct ethhdr*)buf.data();
        uint16_t ethertype = ntohs(eth->h_proto);
        if (ethertype != ETH_P_IP) continue;

        size_t offset = sizeof(struct ethhdr);
        struct iphdr* ip = (struct iphdr*)(buf.data() + offset);
        size_t ip_hdr_len = ip->ihl * 4;
        if ((size_t)len < offset + ip_hdr_len) continue;

        char src_ip[INET_ADDRSTRLEN] = {0}, dst_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

        std::string dir = "UNK";
        if (local_ips.count(src_ip)) dir = "OUT";
        else if (local_ips.count(dst_ip)) dir = "IN";
        else dir = "UNKNOWN";

        if (ip->protocol != IPPROTO_TCP) continue;

        size_t tcp_offset = offset + ip_hdr_len;
        if ((size_t)len < tcp_offset + sizeof(struct tcphdr)) continue;
        struct tcphdr* th = (struct tcphdr*)(buf.data() + tcp_offset);
        size_t tcp_hdr_len = th->doff * 4;
        size_t payload_offset = tcp_offset + tcp_hdr_len;
        if ((size_t)len <= payload_offset) continue;
        const uint8_t* payload = buf.data() + payload_offset;
        size_t payload_len = (size_t)len - payload_offset;

        uint16_t sport = ntohs(th->source);
        uint16_t dport = ntohs(th->dest);

        std::string http_line;
        bool is_http = false;
        if (sport == 80 || dport == 80) {
            is_http = payload_contains_http(payload, payload_len, http_line);
        } else {

            is_http = payload_contains_http(payload, payload_len, http_line);
        }

        if (is_http) {
            std::cout << now_str() << " " << std::setw(3) << dir << " "
                      << "HTTP   " << src_ip << ":" << sport << " -> " << dst_ip << ":" << dport
                      << "  \"" << http_line << "\"\n";
            continue;
        }
        std::string sni, tlsver;
        if (payload_len >= 5 && payload[0] == 0x16) {
            if (parse_tls_client_hello_sni(payload, payload_len, sni, tlsver)) {
                std::cout << now_str() << " " << std::setw(3) << dir << " "
                          << "TLS-HS " << src_ip << ":" << sport << " -> " << dst_ip << ":" << dport
                          << "  SNI=\"" << sni << "\"  " << tlsver << "\n";
                continue;
            }
        }
    }

    close(sock);
}

void RunHTTPMonitorNonblocking() {
    std::string iface;
    std::cout << "Interface to capture on (blank = all): ";
    std::getline(std::cin, iface);

    std::atomic<bool> running(true);
    std::thread t([&running, iface]() {
        StartHTTPMonitorLoop(running, iface);
    });

    std::cout << "HTTP/HTTPS monitor running. Press Enter to stop...\n";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    running.store(false);
    if (t.joinable()) t.join();
    std::cout << "Monitor stopped.\n";
}



void ShowBanner() {
    const char* CYAN = "\033[36m";
    const char* YELLOW = "\033[33m\033[1m";
    const char* RESET = "\033[0m";

    std::cout << CYAN << R"(

   /\_/\  _   _  _  _  _   _   _  _  _
  ( o_o )| | | || || || \ | | | || || |
  /  _  \| |_| || || ||  \| |_| || || |
  \_/ \_/ \__  ||_||_||_|\_\___ ||_||_|

)" << RESET;
    std::cout << YELLOW << "  'Unified Intrusion Inventory - Network \n Utility Inspection Instrument' (UII-NUII) (Prv)" << RESET << "\n\n";
}

//

void WaitForEnter() {
    std::cout << "\nPress Enter to continue...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    system("clear");
}



int main() {

    ShowBanner();

    std::map<int, std::pair<std::string, std::function<void()>>> options = {


// Hardware Recon
{1,  {"OS Info",                        OSInfo}},
{2,  {"Kernel Drivers",                  GetDrivers}},
{3,  {"Installed Packages",              [](){ std::cout << GetInstalledAppProcess(); }}},
{4,  {"BIOS / Firmware",                 GetBiosInfo}},
{5,  {"User Accounts",                   GetAllUsers}},
{6,  {"CPU Info",                        ProcessorInfo}},
{7,  {"GPU Info",                        GraphicsInfo}},
{8,  {"WiFi Adapter",                    WifiCardInfo}},
{9,  {"Storage Drives",                  StorageDriveInfo}},
{10, {"Display",                         DisplayInfo}},
{11, {"USB Devices",                     GetConnectedDevices}},
{12, {"Timezone & Keyboard",             GetLocationInfo}},
{13, {"Command History",                 DumpCommandHistory}},
{14, {"Package Vulnerabilities",         CheckVulnsOnline}},

// Network Recon
{15,   {" Network Interfaces",              PrintInterfaces}},
{16,   {" MAC Addresses",                   MacInterface}},
{17,   {" Routing Table",                   RoutingTable}},
{18,   {" ARP Table",                       ARPTable}},
{19,   {" DNS Info",                        DNSInfo}},
{20,   {" Interface Stats",                  InterfaceStats}},
{21,   {" Credential Files (Location)",    DumpCredentialFiles}},
{22,   {" Local/Public Port Configurations",  DetectPortConfigs}},
{23,   {" Summarize Firewall & NAT",          SummarizeFirewallAndNAT}},
{24,   {" Get Local Devices (Requires ROOT)",GetLocalDevices}},
{25,   {" WAP/Routing Information", GetAPInfo}},
{26,   {" TCP/UDP Sniffer (Requires ROOT)", [](){ StartPacketSniffer(""); }}},
{27,   {" HTTP/HTTPS Sniffer (Requires ROOT)", [](){ RunHTTPMonitorNonblocking(); }}},


// Priv Escalation Recon
{28, {" Root-dir Permissions (writable?)",            CheckRootDirectoryPermissions}},
{29, {" Sudo Rules (NOPASSWD, allowed cmds)",         CheckSudoRules}},
{30, {" Shadow File Access (readable?)",              CheckShadowFile}},
{31, {" System Cron Jobs (writable entries)",         CheckCronJobs}},
{32, {" Root-owned Listening Sockets (perms)",        CheckRootOwnedListeningSockets}},
{33, {" Kerberos Cache Audit (tmp/krb5)",             kerb_audit_v1::RunKerberosTicketAudit}},
{34, {" GPG Key Locations (permissions & presence)",  gpg_audit_v1::RunGPGAudit}},
{35, {" Writable Paths & Plugins (conf/plugin dirs)",   path_audit_v1::RunPathAndWritableAudit}},
{36, {" SUID/SGID Files (suspicious binaries)",     suid_audit_v1::RunSuidSgidAudit}},
{37, {" Service Config Audit (writable configs)",     service_config_audit_v1::RunServiceConfigAudit}},
{38, {" Shared Lib & Config Perms (LD_PRELOAD risk)", CheckSUID_SGID_Binaries}},
{39, {" Backup Files Audit (old creds/configs)",      pwbackup_audit_v1::RunPasswordBackupAudit}},
{40, {" Container/K8s Runtime Configs (readable)",   container_audit_v1::RunContainerRuntimeAudit}},
{41, {" PAM & Auth Config Audit (sssd/lpa/pam)",     pam_audit_v1::RunPAMAndAuthConfigAudit}},
{42, {" Check Privilege Status (UID/caps/SUID)",      CheckRootStatus}},
{43, {" Check for CVE-2022-0847-DirtyPipe", CVE_2022_0847_Wrapper}},


    };

    std::vector<int> col_hw = {1,2,3,4,5,6,7,8,9,10,11,12,13,14};

    std::vector<int> col_net = {15,16,17,18,19,20,21,22,23,24,25,26,27}; //the methods of subcats

    std::vector<int> col_priv = {28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43};


    const int colWidth = 42; // Adjust width for columns

    while (true) {
        size_t rows = std::max({col_hw.size(), col_net.size(), col_priv.size()});
        std::cout << "\n" << std::left
                  << std::setw(colWidth) << "Hardware/Sys Reconnaissance:"
                  << std::setw(colWidth) << "Network Reconnaissance:"
                  << std::setw(colWidth) << "Privilege Escalation Reconnaissance:"
                  << "\n";

        std::cout << std::string(colWidth * 4, '-') << "\n";

        for (size_t r = 0; r < rows; ++r) {
            if (r < col_hw.size()) {
                int k = col_hw[r];
                auto it = options.find(k);
                if (it != options.end()) {
                    std::ostringstream oss;
                    oss << k << ") " << it->second.first;
                    std::cout << std::setw(colWidth) << oss.str();
                } else {
                    std::cout << std::setw(colWidth) << "";
                }
            } else {
                std::cout << std::setw(colWidth) << "";
            }

            if (r < col_net.size()) {
                int k = col_net[r];
                auto it = options.find(k);
                if (it != options.end()) {
                    std::ostringstream oss;
                    oss << k << ") " << it->second.first;
                    std::cout << std::setw(colWidth) << oss.str();
                } else {
                    std::cout << std::setw(colWidth) << "";
                }
            } else {
                std::cout << std::setw(colWidth) << "";
            }

            if (r < col_priv.size()) {
                int k = col_priv[r];
                auto it = options.find(k);
                if (it != options.end()) {
                    std::ostringstream oss;
                    oss << k << ") " << it->second.first;
                    std::cout << std::setw(colWidth) << oss.str();
                } else {
                    std::cout << std::setw(colWidth) << "";
                }
            } else {
                std::cout << std::setw(colWidth) << "";
            }

            std::cout << "\n";
        }

        std::cout << "\n0) Exit\n";
        std::cout << "Select an option: ";

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input, please enter a number.\n";
            continue;
        }

        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear newline

        if (choice == 0) {
            break;
        }

        auto it = options.find(choice);
        if (it == options.end()) {
            std::cout << "Invalid choice. Please try again.\n";
            continue;
        }

        std::cout << "\n--- " << it->second.first << " ---\n";
        it->second.second();
        std::cout << "---------------------------\n";

        WaitForEnter();
    }

    return 0;
}






