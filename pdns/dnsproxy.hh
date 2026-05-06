/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <boost/optional.hpp>

#include "dnspacket.hh"
#include "lock.hh"
#include "iputils.hh"
#include "stat_t.hh"

#include "namespaces.hh"

/*
  DNSProxy: handles ALIAS-record expansion by proxying queries to a recursor.

  Architecture: N independent Shards. Each shard owns its own UDP socket to
  the recursor, its own conntrack table (a fixed-size slot array indexed by
  16-bit DNS id), its own free-id deque, and its own reply thread. A query
  picks a shard by hash(aname) % N. There is no shared mutex across shards.

  The reply thread's critical section is reduced to lookup + move-out + free-id;
  packet parsing, answer rewriting and sendmsg() happen with no lock held.

  Stale entries (recursor never replied) are reaped by a per-shard sweeper
  that runs once per second, driven by SO_RCVTIMEO on the shard socket.
*/

class DNSProxy
{
public:
  DNSProxy(Logr::log_t slog, const string& remote, const string& udpPortRange,
           unsigned int numShards, std::chrono::milliseconds timeout);
  ~DNSProxy();
  DNSProxy(const DNSProxy&) = delete;
  DNSProxy(DNSProxy&&) = delete;
  DNSProxy& operator=(const DNSProxy&) = delete;
  DNSProxy& operator=(DNSProxy&&) = delete;

  void go();
  bool completePacket(std::unique_ptr<DNSPacket>& reply, const DNSName& target, const DNSName& aname, uint8_t scopeMask);

  enum class SlotState : uint8_t {
    FREE,      // unused
    IN_USE,    // outgoing query sent, waiting for recursor reply
    RESPONDED, // reply delivered; id pushed to back of freeIds immediately, slot
               // keeps this state until that id is reallocated — catches late duplicates
  };

  struct Slot
  {
    SlotState state{SlotState::FREE};
    std::chrono::steady_clock::time_point created{};
    boost::optional<ComboAddress> anyLocal;
    DNSName qname;
    DNSName aname;
    std::unique_ptr<DNSPacket> complete;
    ComboAddress remote;
    uint16_t id{0};
    uint16_t qtype{0};
    uint8_t anameScopeMask{0};
    int outsock{-1};
  };

  struct Hot
  {
    std::array<Slot, 65536> table;
    std::deque<uint16_t> freeIds;
  };

  // Initialize freeIds to contain 0..65535 in order. Inline so unit tests
  // can exercise slot mechanics without linking dnsproxy.cc.
  static void initHot(Hot& hot)
  {
    hot.freeIds.clear();
    for (uint32_t i = 0; i < 65536; ++i) {
      hot.freeIds.push_back(static_cast<uint16_t>(i));
    }
  }

private:
  struct Shard
  {
    Shard() = default;
    Shard(const Shard&) = delete;
    Shard(Shard&&) = delete;
    Shard& operator=(const Shard&) = delete;
    Shard& operator=(Shard&&) = delete;
    ~Shard() = default;

    LockGuarded<Hot> hot;
    int sock{-1};
    uint16_t xorSeed{0};
    std::thread loop;
    std::atomic<bool> stop{false};
    pdns::stat_t slotExhaustion;
    pdns::stat_t staleReaped;
    pdns::stat_t duplicateReplies;
  };

  void mainloop(Shard& shard, unsigned int shardIndex);
  void sweepStale(Shard& shard);
  Shard& pickShard(const DNSName& aname);

  std::vector<std::unique_ptr<Shard>> d_shards;
  ComboAddress d_remote;
  AtomicCounter* d_resanswers{nullptr};
  AtomicCounter* d_udpanswers{nullptr};
  AtomicCounter* d_resquestions{nullptr};
  std::shared_ptr<Logr::Logger> d_slog;
  std::chrono::milliseconds d_timeout;
};
