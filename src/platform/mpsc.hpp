// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// A bounded multi-producer, single-consumer queue (plan M13): a shard's inbox.
// A ring of cells, each with a sequence number that says whose turn it is
// (the bounded queue of D. Vyukov's design notes, written here from that
// description): producers claim a position with a CAS on the enqueue counter,
// fill the cell and publish it by storing its sequence with release order; the
// one consumer reads a cell whose sequence says it is filled, with acquire
// order, and hands the cell back a lap later. No locks, no allocation after
// construction; try_push fails when the ring is full (the caller decides).

#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <new>
#include <optional>
#include <utility>

namespace ksim {

template <class T>
class MpscQueue {
public:
    /// capacity: rounded up to a power of two, at least 2.
    explicit MpscQueue(std::size_t capacity) {
        std::size_t c = 2;
        while (c < capacity) {
            c <<= 1;
        }
        mask_ = c - 1;
        cells_ = std::make_unique<Cell[]>(c);
        for (std::size_t i = 0; i < c; ++i) {
            cells_[i].seq.store(i, std::memory_order_relaxed);
        }
    }

    MpscQueue(const MpscQueue&) = delete;
    MpscQueue& operator=(const MpscQueue&) = delete;

    ~MpscQueue() {
        while (try_pop()) {
        }
    }

    std::size_t capacity() const noexcept { return mask_ + 1; }

    /// Any thread. False when the queue is full; `v` is then left as it was.
    bool try_push(T& v) {
        std::size_t pos = enqueue_.load(std::memory_order_relaxed);
        for (;;) {
            Cell& c = cells_[pos & mask_];
            const std::size_t seq = c.seq.load(std::memory_order_acquire);
            const auto diff = static_cast<std::ptrdiff_t>(seq) - static_cast<std::ptrdiff_t>(pos);
            if (diff == 0) {
                if (enqueue_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    ::new (static_cast<void*>(c.storage)) T(std::move(v));
                    c.seq.store(pos + 1, std::memory_order_release);
                    return true;
                }
            } else if (diff < 0) {
                return false;   // the consumer has not freed this cell yet: full
            } else {
                pos = enqueue_.load(std::memory_order_relaxed);
            }
        }
    }

    bool try_push(T&& v) { return try_push(v); }

    /// The consumer thread only.
    std::optional<T> try_pop() {
        Cell& c = cells_[dequeue_ & mask_];
        const std::size_t seq = c.seq.load(std::memory_order_acquire);
        if (seq != dequeue_ + 1) {
            return std::nullopt;   // empty (or a producer is still filling it)
        }
        T* p = std::launder(reinterpret_cast<T*>(c.storage));
        std::optional<T> out(std::move(*p));
        p->~T();
        c.seq.store(dequeue_ + mask_ + 1, std::memory_order_release);
        ++dequeue_;
        return out;
    }

private:
    struct Cell {
        std::atomic<std::size_t> seq{0};
        alignas(T) unsigned char storage[sizeof(T)];
    };

    std::unique_ptr<Cell[]> cells_;
    std::size_t mask_ = 0;
    alignas(64) std::atomic<std::size_t> enqueue_{0};
    alignas(64) std::size_t dequeue_ = 0;
};

} // namespace ksim
