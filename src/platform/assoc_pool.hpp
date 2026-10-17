// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Several associations behind one listening side (P3 R2; ADR 0013 point 2): a
// CU-CP serves several DUs over F1-C, each its own association, where P2's
// AssocSlot took one. A pool hands each association a LinkId, forwards its
// messages and events with that id, and sends on the link a caller names. An
// association joins either borrowed (memlink pairs in-process; the caller keeps
// it) or taken (accepted from a listener; the pool owns it until it goes and the
// next accept frees it, never inside its own callbacks). `limit` bounds the links
// up at once (0: no bound); one over it is aborted and counted. Pure: no socket
// here, so memlink and SCTP serve alike.

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <vector>

#include "platform/transport.hpp"

namespace ksim {

using LinkId = std::uint32_t;

class IAssocPool {
public:
    using OnMessage = std::function<void(LinkId link, ByteView msg, SctpMeta meta)>;
    using OnEvent = std::function<void(LinkId link, LinkEvent event)>;

    virtual ~IAssocPool() = default;
    virtual void set_handlers(OnMessage on_message, OnEvent on_event) = 0;
    /// Errc::closed for a link that is not up or not known.
    virtual Result<void> send(LinkId link, ByteView msg, SctpMeta meta) = 0;
    virtual bool up(LinkId link) const noexcept = 0;
    virtual std::uint16_t out_streams(LinkId link) const noexcept = 0;
    /// The links that are up, in the order they joined.
    virtual std::vector<LinkId> links() const = 0;
};

class AssocPool final : public IAssocPool {
public:
    explicit AssocPool(std::size_t limit = 0) : limit_(limit) {}
    ~AssocPool() override;
    AssocPool(const AssocPool&) = delete;
    AssocPool& operator=(const AssocPool&) = delete;

    /// A borrowed association (it must outlive the pool): its own events come through,
    /// so a memlink pair's connect() reports it up. Returns its link.
    LinkId add(IAssoc& a);
    /// An accepted association, born up (it says nothing itself, as AssocSlot's). False
    /// when `limit` links are up already: then it is aborted and dropped.
    bool take(std::unique_ptr<IAssoc> a);
    std::uint64_t taken() const noexcept { return taken_; }
    std::uint64_t refused() const noexcept { return refused_; }

    void set_handlers(OnMessage on_message, OnEvent on_event) override;
    Result<void> send(LinkId link, ByteView msg, SctpMeta meta) override;
    bool up(LinkId link) const noexcept override;
    std::uint16_t out_streams(LinkId link) const noexcept override;
    std::vector<LinkId> links() const override;
    void shutdown_all();
    void abort_all();
    /// Drops every link (the owned ones are freed): for the owner's stop, outside any callback.
    void clear();

private:
    struct Link {
        IAssoc* a = nullptr;
        std::unique_ptr<IAssoc> owned;
    };
    void wire(LinkId id, IAssoc& a);
    std::size_t up_count() const;

    std::size_t limit_;
    LinkId next_ = 1;
    std::map<LinkId, Link> links_;
    std::vector<std::unique_ptr<IAssoc>> retired_;
    OnMessage on_message_;
    OnEvent on_event_;
    std::uint64_t taken_ = 0;
    std::uint64_t refused_ = 0;
};

/// One borrowed association seen as a pool of one link (link 1): what a CU-CP of
/// one DU, as P1 and P2 built it, is given.
class SingleAssocPool final : public IAssocPool {
public:
    explicit SingleAssocPool(IAssoc& a) : a_(a) {}
    void set_handlers(OnMessage on_message, OnEvent on_event) override;
    Result<void> send(LinkId link, ByteView msg, SctpMeta meta) override;
    bool up(LinkId link) const noexcept override { return link == 1 && a_.up(); }
    std::uint16_t out_streams(LinkId link) const noexcept override { return link == 1 ? a_.out_streams() : 0; }
    std::vector<LinkId> links() const override;

private:
    IAssoc& a_;
};

} // namespace ksim
