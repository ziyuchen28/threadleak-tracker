
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <thread>

#include <libproc.h>
#include <sys/proc_info.h>
#include <unistd.h>

namespace fs = std::filesystem;

static volatile sig_atomic_t g_stop = 0;

struct ProcCtx
{
    pid_t pid = 0;
    std::string proc_str;
    fs::path out_dir;
    fs::path csv_path;
    std::ofstream csv;
    int rows_since_flush = 0;
    long long first_seen_ms = 0;
    // JFR
    bool jfr_started = false;
    fs::path jfr_path;
    fs::path jfr_threadstart_txt;
    // jvm summary 
    long long heap_used_kb = 0;
    long long heap_total_kb = 0;
    int thr_total = 0;
    std::string thr_top1;
    std::string thr_top2;
    std::string thr_top3;
    std::string thr_top4;
    std::string thr_top5;
    long long last_jvm_summary_ms = -1; 
    // vmmap
    long long last_vmmap_summary_ms = -1; 
};


static void on_sig(int)
{
    g_stop = 1;
}


static bool exec_to_file(const std::string &cmd, const fs::path &path)
{
    std::string full = cmd + " > " + path.string() + " 2>&1";
    int rc = std::system(full.c_str());
    return rc == 0;
}

static std::string exec_capture(const std::string &cmd)
{
    std::string out;
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp) {
        return out;
    }
    char buf[4096];
    while (true) {
        size_t n = std::fread(buf, 1, sizeof(buf), fp);
        if (n > 0) {
            out.append(buf, buf + n);
        }
        if (n < sizeof(buf)) {
            break;
        }
}
    pclose(fp);
    return out;
}


//==============================================================================
//  kernel vmmap metrics (vmmap -summary parsing)
//==============================================================================

struct VmmapStats
{
    long long stack_vsz_kb = 0;
    long long stack_rss_kb = 0;
    long long vm_allocate_rss_kb = 0;
    long long vm_allocate_swapped_kb = 0;
    long long malloc_rss_kb = 0; // sum of MALLOC_* 
    long long total_rss_kb = 0;
    long long total_swapped_kb = 0;
};

struct VmmapRow
{
    std::string name;
    long long virtual_kb = 0;
    long long resident_kb = 0;
    long long swapped_kb = 0;
};

static bool parse_size_token_kb(const std::string &tok, long long &out_kb)
{
    if (tok.empty()) {
        return false;
    }
    // unit
    char unit = tok.back();
    double mul = 1.0;
    if (unit == 'K') mul = 1.0;
    else if (unit == 'M') mul = 1024.0;
    else if (unit == 'G') mul = 1024.0 * 1024.0;
    else return false;
    // value string
    std::string num = tok.substr(0, tok.size() - 1);
    if (num.empty()) return false;
    // value
    char *endp = nullptr;
    double v = std::strtod(num.c_str(), &endp);
    if (endp == num.c_str()) return false;
    out_kb = static_cast<long long>(std::llround(v * mul));
    return true;
}

static bool is_size_token(const std::string &tok)
{
    long long kb = 0;
    return parse_size_token_kb(tok, kb);
}


static std::string trim(const std::string &s)
{
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) b++;
    size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) e--;
    return s.substr(b, e - b);
}


static std::optional<VmmapRow> parse_vmmap_row(const std::string &line)
{
    std::string s = trim(line);
    if (s.empty()) return std::nullopt;
    // fast path - Table rows start with alpha or _
    if (!(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_')) {
        return std::nullopt;
    }
    // chop by space
    std::istringstream iss(s);
    std::vector<std::string> toks;
    {
        std::string t;
        while (iss >> t) {
            toks.push_back(t);
        }
    }
    // run vmmap --summary <pid> for reference
    if (toks.size() < 6) {
        return std::nullopt;
    }
    // first size token index.
    size_t first_size = toks.size();
    for (size_t i = 0; i < toks.size(); i++) {
        if (is_size_token(toks[i])) {
            first_size = i;
            break;
        }
    }
    if (first_size == toks.size() || first_size == 0) {
        return std::nullopt;
    }
    // Region name could be muti words separated by space such as Activity Tracing
    std::string name;
    for (size_t i = 0; i < first_size; i++) {
        if (!name.empty()) name.push_back(' ');
        name += toks[i];
    }
    // collect VIRTUAL, RESIDENT, DIRTY, SWAPPED
    std::vector<long long> sizes_kb;
    size_t i = first_size;
    for (; i < toks.size(); i++) {
        long long kb = 0;
        if (!parse_size_token_kb(toks[i], kb)) {
            break;
        }
        sizes_kb.push_back(kb);
    }
    if (sizes_kb.size() < 4) {
        return std::nullopt;
    }
    VmmapRow row;
    row.name = name;
    row.virtual_kb = sizes_kb[0];
    row.resident_kb = sizes_kb[1];
    row.swapped_kb = sizes_kb[3];
    return row;
}

static std::string to_lower_ascii(std::string s)
{
    for (char &c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

static VmmapStats parse_vmmap_summary_text(const std::string &txt)
{
    VmmapStats st;
    std::istringstream iss(txt);
    std::string line;
    while (std::getline(iss, line)) {
        auto row_opt = parse_vmmap_row(line);
        if (!row_opt.has_value()) continue;
        VmmapRow row = *row_opt;
        std::string name_l = to_lower_ascii(row.name);
        if (name_l == "stack") {
            st.stack_vsz_kb = row.virtual_kb;
            st.stack_rss_kb = row.resident_kb;
            continue;
        }
        if (name_l.rfind("vm_allocate", 0) == 0) {
            st.vm_allocate_rss_kb = row.resident_kb;
            st.vm_allocate_swapped_kb = row.swapped_kb;
            continue;
        }

        if (name_l.rfind("malloc_", 0) == 0) {
            st.malloc_rss_kb += row.resident_kb;
            continue;
        }
        if (name_l == "total") {
            st.total_rss_kb = row.resident_kb;
            st.total_swapped_kb = row.swapped_kb;
            continue;
        }
    }
    return st;
}


static VmmapStats collect_vmmap_stats(ProcCtx &pc, long long elapsed_ms)
{
    std::string out = exec_capture("vmmap -summary " + std::to_string(pc.pid) + " 2>/dev/null");
    fs::path raw_path = pc.out_dir / ("vmmap_" + std::to_string(elapsed_ms) + "ms.txt");
    {
        std::ofstream f(raw_path, std::ios::out | std::ios::trunc);
        f << out;
    }
    return parse_vmmap_summary_text(out);
}


//==============================================================================
//  Thread Summary (jcmd Thread.print parsing)
//==============================================================================

struct ThreadTop
{
    int total_threads = 0;                
    std::vector<std::string> top5; // groups by pool like "pool-55:8"
};

static std::string group_thread_name(const std::string &name)
{
    // pool-55-thread-1  -> pool-55
    if (name.rfind("pool-", 0) == 0) {
        size_t pos = name.find("-thread-");
        if (pos != std::string::npos) {
            return name.substr(0, pos);
        }
        return name;
    }
    // ForkJoinPool-1-worker-3 -> ForkJoinPool-1
    if (name.rfind("ForkJoinPool-", 0) == 0) {
        size_t pos = name.find("-worker-");
        if (pos != std::string::npos) {
            return name.substr(0, pos);
        }
        return name;
    }
    // ForkJoinPool.commonPool-worker-3 -> ForkJoinPool.commonPool
    if (name.rfind("ForkJoinPool.commonPool-worker-", 0) == 0) {
        return "ForkJoinPool.commonPool";
    }
    return name;
}

static ThreadTop summarize_thread_print_text(const std::string &thread_print_text,
                                             const fs::path &summary_path)
{
    std::unordered_map<std::string, int> counts;
    int total = 0;

    std::istringstream iss(thread_print_text);
    std::string line;
    while (std::getline(iss, line)) {
        // example
        // "pool-1-thread-3" #25 daemon prio=5 os_prio=31  .... waiting on condition  [0x0000000171e7e000]
        if (line.empty() || line[0] != '"') continue;
        size_t end = line.find('"', 1);
        if (end == std::string::npos || end <= 1) continue;
        std::string name = line.substr(1, end - 1);
        std::string key = group_thread_name(name);
        counts[key]++;
        total++;
    }

    std::vector<std::pair<std::string, int>> items;
    items.reserve(counts.size());
    for (const auto &kv : counts) {
        items.emplace_back(kv.first, kv.second);
    }

    std::sort(items.begin(), items.end(),
              [](const auto &a, const auto &b) {
                  if (a.second != b.second) return a.second > b.second;
                  return a.first < b.first;
              });

    ThreadTop out;
    out.total_threads = total;
    // dump summary & print top five to csv 
    std::ofstream f(summary_path, std::ios::out | std::ios::trunc);
    f << "total_threads=" << total << "\n";
    for (size_t i = 0; i < items.size(); i++) {
        f << items[i].first << ":" << items[i].second << "\n";
        if (i < 5) {
            out.top5.push_back(items[i].first + "=" + std::to_string(items[i].second));
        }
    }
    while (out.top5.size() < 5) {
        out.top5.push_back(""); 
    }
    return out;
}


//==============================================================================
//  Heap Summary (jcmd GC.heap_info parsing)
//==============================================================================

static bool parse_first_number_before_k(const std::string &s, 
                                        size_t start, 
                                        long long &out)
{
    // trim space and parse digits until 'K'
    // example
    //  garbage-first heap   total 275456K, used 140812K [0x00000007e0000000, 0x0000000800000000)
    size_t i = start;
    while (i < s.size() && (s[i] == ' ')) i++;
    if (i >= s.size() || s[i] < '0' || s[i] > '9') return false;

    long long val = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        val = val * 10 + (s[i] - '0');
        i++;
    }
    if (i >= s.size() || s[i] != 'K') return false;
    out = val;
    return true;
}

static bool parse_heap_used_total_kb(const std::string &heap_info_text, 
                                     long long &used_kb, 
                                     long long &total_kb)
{
    // example
    // 3173:
    //  garbage-first heap   total 275456K, used 140812K [0x00000007e0000000, 0x0000000800000000)
    //   region size 1024K, 117 young (119808K), 12 survivors (12288K)
    //  Metaspace       used 73199K, committed 73792K, reserved 1114112K
    //   class space    used 10666K, committed 10944K, reserved 1048576K
    std::istringstream iss(heap_info_text);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("heap") == std::string::npos) continue;
        size_t pos_total = line.find("total");
        size_t pos_used = line.find("used");
        if (pos_total == std::string::npos || pos_used == std::string::npos) continue;
        long long t = 0;
        long long u = 0;
        if (!parse_first_number_before_k(line, pos_total + 5, t)) continue;
        if (!parse_first_number_before_k(line, pos_used + 4, u)) continue;
        total_kb = t;
        used_kb = u;
        return true;
    }
    return false;
}


static void refresh_thread_and_heap_summary(ProcCtx &pc, long long elapsed_ms)
{
    // jcmd Thread.print
    std::string tp = exec_capture("jcmd " + std::to_string(pc.pid) + " Thread.print 2>/dev/null");
    if (!tp.empty()) {
        fs::path summary_file = pc.out_dir / ("thread_summary_" + std::to_string(elapsed_ms) + "ms.txt");
        ThreadTop top = summarize_thread_print_text(tp, summary_file);
        pc.thr_total = top.total_threads;
        pc.thr_top1 = top.top5[0];
        pc.thr_top2 = top.top5[1];
        pc.thr_top3 = top.top5[2];
        pc.thr_top4 = top.top5[3];
        pc.thr_top5 = top.top5[4];
    }
    // jcmd heap_info
    fs::path heap_file = pc.out_dir / ("heap_info_" + std::to_string(elapsed_ms) + "ms.txt");
    exec_to_file("jcmd " + std::to_string(pc.pid) + " GC.heap_info", heap_file);
    std::string heap_text;
    {
        std::ifstream f(heap_file);
        std::ostringstream ss;
        ss << f.rdbuf();
        heap_text = ss.str();
    }
    if (!parse_heap_used_total_kb(heap_text, pc.heap_used_kb, pc.heap_total_kb)) {
        std::cerr << "[x] parse heap info failed" << std::endl;
    }
    pc.last_jvm_summary_ms = elapsed_ms;
}


//==============================================================================
//  JFR recording for thread pool start stack trace
//==============================================================================

static bool start_jfr_on_pid(pid_t pid, ProcCtx &pc)
{
    pc.jfr_path = pc.out_dir / "recording.jfr";
    pc.jfr_threadstart_txt = pc.out_dir / "jfr_threadstart.txt";
    // jcmd <pid> JFR.start name=... settings=profile dumponexit=true filename=...
    std::string cmd =
        "jcmd " + std::to_string(pid) +
        " JFR.start name=jvmprof settings=profile dumponexit=true filename=" +
        pc.jfr_path.string() +
        " > /dev/null 2>&1";
    int rc = std::system(cmd.c_str());
    pc.jfr_started = (rc == 0);
    return pc.jfr_started;
}


static void summarize_jfr_threadstart(const ProcCtx &pc)
{
    if (!pc.jfr_started) {
        return;
    }
    // dump may appear slightly after process exit 
    for (int i = 0; i < 50; i++) { 
        if (fs::exists(pc.jfr_path)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (!fs::exists(pc.jfr_path)) {
        return;
    }
    std::string cmd =
        "jfr print --events jdk.ThreadStart --stack-depth 256 " +
        pc.jfr_path.string() +
        " > " + pc.jfr_threadstart_txt.string() +
        " 2>&1";
    (void)std::system(cmd.c_str());
}


//==============================================================================
//  Surefire PID Discovery (jcmd -l)
//==============================================================================

static bool process_alive(pid_t pid)
{
    if (pid <= 0) {
        return false;
    }
    int rc = kill(pid, 0);
    if (rc == 0) {
        return true;
    }
    return errno != ESRCH;
}

static std::vector<std::pair<pid_t, std::string>> jcmd_list()
{
    std::string out = exec_capture("jcmd -l 2>/dev/null");
    std::vector<std::pair<pid_t, std::string>> v;
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream ls(line);
        long pid_long = 0;
        ls >> pid_long;
        if (pid_long <= 0) {
            continue;
        }
        std::string rest;
        std::getline(ls, rest);
        size_t first = rest.find_first_not_of(' ');
        if (first != std::string::npos) {
            rest = rest.substr(first);
        } else {
            rest.clear(); 
        }
        v.emplace_back((pid_t)pid_long, rest);
    }
    return v;
}


static bool is_surefire(const std::string &proc_str)
{
    if (proc_str.find("surefirebooter") != std::string::npos) return true;
    if (proc_str.find("ForkedBooter") != std::string::npos) return true;
    if (proc_str.find("surefire") != std::string::npos 
        && proc_str.find("booter") != std::string::npos) {
        return true;
    }
    return false;
}


static void sync_surefire_proc(std::unordered_map<pid_t, ProcCtx> &active, 
                               const fs::path &out_dir,
                               long long elapsed_ms)
{
    std::unordered_map<pid_t, std::string> current;
    // fetch processes from jcmd
    auto list = jcmd_list();
    for (const auto &it : list) {
        pid_t pid = it.first;
        const std::string &proc_str = it.second;
        if (!is_surefire(proc_str)) continue;
        current.emplace(pid, proc_str);
    }
    for (auto &it : current) {
        pid_t pid = it.first;
        if (active.find(pid) != active.end()) continue;
        // new surefire process found
        ProcCtx pc;
        std::cout << "[+] detected surefire pid=" << pid << "\n";
        pc.pid = pid;
        pc.proc_str = std::move(it.second);
        pc.first_seen_ms = elapsed_ms;
        // set up metrics piping 
        pc.out_dir = out_dir / ("pid" + std::to_string(pid));
        fs::create_directories(pc.out_dir);
        pc.csv_path = out_dir / ("pid" + std::to_string(pid) + ".csv");
        pc.csv.open(pc.csv_path, std::ios::out | std::ios::trunc);
        pc.csv << "t_ms,alive,kernel_basic_rss_kb,kernel_basic_threads_total,"
               << "jvm_heap_used_kb,jvm_heap_total_kb,"
               << "jvm_thread_total,thread_top1,thread_top2,thread_top3,thread_top4,thread_top5,"
               << "kernel_vmmap_stack_vsz_kb,kernel_vmmap_stack_rss_kb,"
               << "kernel_vmmap_vm_allocate_rss_kb,kernel_vmmap_vm_allocate_swapped_kb,"
               << "kernel_vmmap_malloc_rss_kb,kernel_vmmap_total_rss_kb,kernel_vmmap_total_swapped_kb\n";
        pc.csv.flush();
        pc.rows_since_flush = 0;
        if (start_jfr_on_pid(pid, pc)) {
            std::cout << "[*] jfr started on " << pc.jfr_path << std::endl;
        }
        active.emplace(pid, std::move(pc));
    }
    // remove inactive surefire processes
    for (auto it = active.begin(); it != active.end();) {
        pid_t pid = it->first;
        ProcCtx &pc = it->second;
        if ((current.find(pid) == current.end()) || !process_alive(pid)) {
            std::cout << "[-] detected inactive/exited surefire pid=" << pid << std::endl;
            summarize_jfr_threadstart(pc);
            std::cout << "[-] summarized jfr recording in " << pc.jfr_threadstart_txt << std::endl;
            pc.csv.flush();
            it = active.erase(it);
        }
        else it++;
    }
}


//==============================================================================
// Main metrics sample loop 
//==============================================================================

static void sample_proc(std::unordered_map<pid_t, ProcCtx> &active, 
                        long long elapsed_ms,
                        int jvm_summary_secs,
                        int vmmap_summary_secs)
{
    for (auto &it : active) {
        pid_t pid = it.first;
        ProcCtx &pc = it.second;
        proc_taskinfo ti{};
        bool alive;
        int rc = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof(ti));
        uint64_t rss_kb = 0;
        int32_t os_thread_count = 0;
        if (rc != (int)sizeof(ti)) {
            alive = false;
            rss_kb = 0; 
            os_thread_count = 0;  
        } else {
            alive = true;
            rss_kb = ti.pti_resident_size / 1024; 
            os_thread_count = ti.pti_threadnum;  
        }
        pc.csv << elapsed_ms << ","
               << alive << ","
               << rss_kb << ","
               << os_thread_count << ",";
        // refresh thread+heap summary on cadence
        if (pc.last_jvm_summary_ms < 0 ||
            (elapsed_ms - pc.last_jvm_summary_ms) >= static_cast<long long>(jvm_summary_secs) * 1000LL) {
            refresh_thread_and_heap_summary(pc, elapsed_ms);
            pc.csv << pc.heap_used_kb << ","
                   << pc.heap_total_kb << ","
                   << pc.thr_total << ","
                   << pc.thr_top1 << ","
                   << pc.thr_top2 << ","
                   << pc.thr_top3 << ","
                   << pc.thr_top4 << ","
                   << pc.thr_top5 << ",";
        }
        else {
            pc.csv << ",,,,,,,";
        }
        // refresh kernel vmmap summary on cadence
        if (pc.last_vmmap_summary_ms < 0 ||
            (elapsed_ms - pc.last_vmmap_summary_ms) >= static_cast<long long>(vmmap_summary_secs) * 1000LL) {
            VmmapStats vmst = collect_vmmap_stats(pc, elapsed_ms);
            pc.csv << vmst.stack_vsz_kb << ","
                   << vmst.stack_rss_kb << ","
                   << vmst.vm_allocate_rss_kb << ","
                   << vmst.vm_allocate_swapped_kb << ","
                   << vmst.malloc_rss_kb << ","
                   << vmst.total_rss_kb << ","
                   << vmst.total_swapped_kb << "\n";
        }
        else {
            pc.csv << ",,,,,,\n";
        }
        if (++pc.rows_since_flush >= 10) {
            pc.csv.flush();
            pc.rows_since_flush = 0;
        }
    }
}

static std::string now_timestamp()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    std::tm tm {};
    localtime_r(&t, &tm);
    char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "%04d%02d%02d-%02d%02d%02d",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return std::string(buf);
}

static void Usage()
{
    std::cerr
        << "Usage: jvm_profiler [--jvm-interval-secs N] [--vmmap-interval-secs N] [--interval-ms N]\n";
}


int main(int argc, char **argv)
{
    std::signal(SIGINT, on_sig);

    // int duration_secs = 600;
    int interval_ms = 1000;
    int jvm_summary_secs = 15;
    int vmmap_summary_secs = 30;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--interval-ms") {
            if (i + 1 >= argc) {
                Usage();
                return 1;
            }
            interval_ms = std::atoi(argv[++i]);
            if (interval_ms < 50) interval_ms = 50;
        }
        else if (a == "--jvm-summary-secs") {
            if (i + 1 >= argc) { 
                Usage(); 
                return 1; 
            }
            jvm_summary_secs = std::atoi(argv[++i]);
            if (jvm_summary_secs < 1) jvm_summary_secs = 1;
        }
        else if (a == "--vmmap-summary-secs") {
            if (i + 1 >= argc) { 
                Usage(); 
                return 1; 
            }
            vmmap_summary_secs = std::atoi(argv[++i]);
            if (vmmap_summary_secs < 1) jvm_summary_secs = 1;
        }
        else {
            Usage();
            return 1;
        }
    }

    fs::path project_root = fs::current_path(); 
    fs::path out_dir = project_root / fs::path("tmp") / ("jvm_prof-" + now_timestamp());
    fs::create_directories(out_dir);
    std::cout << "[*] output dir: " << out_dir.string() << "\n";
    std::cout << "[*] kernel basic metrics(rss + OS threads) collection interval=" << interval_ms << "ms\n" 
              << "[*] jvm metrics(thread print + java heap info) collection interval=" << jvm_summary_secs << "s\n"
              << "[*] kernel vmmap metrics(stack, malloc, vm_allocate) collection interval=" << vmmap_summary_secs << "s\n";

    std::unordered_map<pid_t, ProcCtx> active;

    using namespace std::chrono;
    auto t0 = std::chrono::steady_clock::now();
    // log every heartbeat
    auto last_hb = t0;

    int idle_exit_secs = 120;
    auto last_surefire_seen = t0;

    while (!g_stop) {

        auto now = steady_clock::now();
        long long elapsed_ms = duration_cast<milliseconds>(now - t0).count();
        long long elapsed_secs = elapsed_ms / 1000;

        sync_surefire_proc(active, out_dir, elapsed_ms);
        sample_proc(active, elapsed_ms, jvm_summary_secs, vmmap_summary_secs); 

        auto hb_age = duration_cast<seconds>(now - last_hb).count();
        if (hb_age >= 30) {
            last_hb = now;
            std::cout << "[*] heartbeat t=" << elapsed_secs 
                      << "s active surefire processes=" << active.size() 
                      << "\n";
        }
        if (!active.empty()) {
            last_surefire_seen = now;
        } else {
            auto idle = duration_cast<seconds>(now - last_surefire_seen).count();
            if (idle >= idle_exit_secs) {
                std::cout << "[*] idle exit: no surefire seen for " << idle_exit_secs << "s\n";
                break;
            }
        }
        std::this_thread::sleep_for(milliseconds(interval_ms));
    }

    std::cout << "[*] Done.\n";
    return 0;
}

