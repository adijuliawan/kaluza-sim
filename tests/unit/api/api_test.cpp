// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The control API (P1 N8; ADR 0009 point 7; cli.md §2): replies and their exit
// codes, wait over the event ring with its evidence, and the HTTP server on a
// UNIX socket (routes, JSON bodies, refusals, the link for a long path).

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <thread>
#include <vector>

#include <httplib.h>

#include "api/http.hpp"
#include "api/reply.hpp"
#include "api/wait.hpp"
#include "platform/clock.hpp"

namespace ksim::api {
namespace {

std::string temp_dir() {
    std::string t = (std::filesystem::temp_directory_path() / "ksim-api-XXXXXX").string();
    char* d = ::mkdtemp(t.data());
    EXPECT_NE(d, nullptr);
    return t;
}

TEST(Reply, RoundTripsAndMapsExitCodesToHttp) {
    Reply r;
    r.set("UE", "imsi-001010000300001").set("SEQ", 42);
    auto back = Reply::parse(r.body());
    ASSERT_TRUE(back);
    EXPECT_EQ(back->exit, Exit::ok);
    EXPECT_EQ(back->kv.dump(), R"({"UE":"imsi-001010000300001","SEQ":"42"})");   // order kept
    EXPECT_EQ(Reply::fail(Exit::timeout, "timeout").http_status(), 504);
    EXPECT_EQ(Reply::fail(Exit::unknown, "no such UE").http_status(), 404);
    EXPECT_EQ(Reply::fail(Exit::wrong_state, "off").http_status(), 409);
    EXPECT_FALSE(Reply::parse("{}"));
    EXPECT_FALSE(Reply::parse("not json"));
}

TEST(Reply, KvLinesKeepOneKeyPerLine) {
    json kv = json::object();
    kv["A"] = "1";
    kv["B"] = "two\nlines";
    EXPECT_EQ(kv_lines(kv), "A=1\nB=two\\nlines\n");
}

TEST(Wait, MatchesByNameSubjectAndFieldsAndPrintsTheEvidence) {
    ManualClock clock;
    EventRing ring(64, clock);
    ring.emit("nas.reg.request", "ue:imsi-001010000300001", {{"type", "initial"}});
    ring.emit("nas.reg.accept", "ue:imsi-001010000300002", {{"guti", "x"}});
    ring.emit("nas.reg.accept", "ue:imsi-001010000300001", {{"guti", "00101-ca-001-01-00000001"}, {"t3512_s", "3600"}});
    WaitQuery q;
    q.until = {"nas.reg.accept"};
    q.subject = "ue:imsi-001010000300001";
    q.timeout = std::chrono::milliseconds(10);
    Reply r = wait(ring, q);
    EXPECT_EQ(r.exit, Exit::ok);
    EXPECT_EQ(r.kv["EVENT"], "nas.reg.accept");
    EXPECT_EQ(r.kv["SEQ"], "3");
    EXPECT_EQ(r.kv["UE"], "imsi-001010000300001");
    EXPECT_EQ(r.kv["GUTI"], "00101-ca-001-01-00000001");
    EXPECT_EQ(r.kv["T3512_S"], "3600");
    q.since = 3;   // --new after the accept: nothing more comes
    EXPECT_EQ(wait(ring, q).exit, Exit::timeout);
    q.since = 0;
    q.where = {{"guti", "nope"}};
    EXPECT_EQ(wait(ring, q).exit, Exit::timeout);
}

TEST(Wait, AFailEventEndsTheWaitWithItsCause) {
    ManualClock clock;
    EventRing ring(64, clock);
    std::thread later([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        ring.emit("nas.reg.reject", "ue:imsi-001010000300001", {{"cause", "7"}});
    });
    WaitQuery q;
    q.until = {"nas.reg.accept"};
    q.fail = split_names("nas.reg.reject,nas.reg.abort");
    q.timeout = std::chrono::seconds(5);
    Reply r = wait(ring, q);
    later.join();
    EXPECT_EQ(r.exit, Exit::failed);
    EXPECT_EQ(r.kv["CAUSE"], "7");
    EXPECT_EQ(r.kv["EVENT"], "nas.reg.reject");
    EXPECT_EQ(split_names(",a,,b,"), (std::vector<std::string>{"a", "b"}));
}

Reply get(const std::string& sock, const std::string& path) {
    httplib::Client c(socket_target(sock));
    c.set_address_family(AF_UNIX);
    auto res = c.Get(path);
    EXPECT_TRUE(res);
    auto r = res ? Reply::parse(res->body) : Result<Reply>(make_error(Errc::io, 0, "no answer"));
    EXPECT_TRUE(r);
    return r ? *r : Reply{};
}

TEST(Server, ServesRoutesOnAUnixSocketAndRefusesWhatItCannotRead) {
    const std::string dir = temp_dir();
    Server s;
    s.get("/v1/ue/:sel/status", [](const Request& req) {
        Reply r;
        r.set("SEL", req.params.at("sel"));
        r.set("Q", req.arg("q", "-"));
        return r;
    });
    s.post("/v1/ue/:sel/power", [](const Request& req) {
        if (req.arg("state") != "on") {
            return Reply::fail(Exit::usage, "power on|off");
        }
        Reply r;
        r.set("WAIT_MS", req.arg("wait_ms"));
        return r;
    });
    ASSERT_TRUE(s.listen_unix(dir + "/ctl.sock"));
    Reply st = get(dir + "/ctl.sock", "/v1/ue/17/status?q=x");
    EXPECT_EQ(st.kv["SEL"], "17");
    EXPECT_EQ(st.kv["Q"], "x");
    EXPECT_EQ(get(dir + "/ctl.sock", "/v1/nothing").exit, Exit::usage);

    httplib::Client c(dir + "/ctl.sock");
    c.set_address_family(AF_UNIX);
    auto ok = c.Post("/v1/ue/1/power", R"({"state":"on","wait_ms":"500"})", "application/json");
    ASSERT_TRUE(ok);
    EXPECT_EQ(ok->status, 200);
    EXPECT_EQ(Reply::parse(ok->body)->kv["WAIT_MS"], "500");
    auto bad = c.Post("/v1/ue/1/power", "{not json", "application/json");
    ASSERT_TRUE(bad);
    EXPECT_EQ(bad->status, 400);
    s.stop();
    EXPECT_FALSE(s.listen_tcp("10.0.0.1", 9400));   // loopback only
    std::filesystem::remove_all(dir);
}

// KS-PLAT-D8: a burst of connects, as ksim-ctl --parallel 64 makes, all get in. With
// httplib's backlog of 5 a non-blocking AF_UNIX connect past it is EAGAIN, a failed call.
TEST(Server, ABurstOfConnectsFindsRoomInTheBacklog) {
    const std::string dir = temp_dir();
    Server s;
    s.get("/v1/info", [](const Request&) { return Reply{}; });
    ASSERT_TRUE(s.listen_unix(dir + "/ctl.sock"));
    sockaddr_un sa{};
    sa.sun_family = AF_UNIX;
    const std::string path = dir + "/ctl.sock";
    std::memcpy(sa.sun_path, path.c_str(), path.size() + 1);
    std::vector<int> fds;
    int refused = 0;
    for (int i = 0; i < 64; ++i) {
        const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        ASSERT_GE(fd, 0);
        if (::connect(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) != 0) {   // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): the sockets API
            ++refused;
        }
        fds.push_back(fd);
    }
    for (const int fd : fds) {
        ::close(fd);
    }
    EXPECT_EQ(refused, 0);
    s.stop();
    std::filesystem::remove_all(dir);
}

TEST(Server, ALongSocketPathBecomesALinkToAShortSocket) {
    const std::string dir = temp_dir();
    const std::string deep = dir + "/" + std::string(60, 'r') + "/" + std::string(40, 'u');
    std::filesystem::create_directories(deep);
    const std::string path = deep + "/ctl.sock";
    ASSERT_GE(path.size(), 108u);
    Server s;
    s.get("/v1/version", [](const Request&) {
        Reply r;
        r.set("VERSION", "test");
        return r;
    });
    ASSERT_TRUE(s.listen_unix(path));
    EXPECT_TRUE(std::filesystem::is_symlink(path));
    EXPECT_LT(socket_target(path).size(), 108u);
    EXPECT_EQ(get(path, "/v1/version").kv["VERSION"], "test");
    s.stop();
    std::filesystem::remove_all(dir);
}

} // namespace
} // namespace ksim::api
