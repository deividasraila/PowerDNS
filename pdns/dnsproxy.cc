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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <cerrno>

#include "packetcache.hh"
#include "utility.hh"
#include "pdnsexception.hh"
#include "dns.hh"
#include "logger.hh"
#include "statbag.hh"
#include "dns_random.hh"
#include "stubresolver.hh"
#include "arguments.hh"
#include "threadname.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "dnsproxy.hh"

#include <boost/uuid/uuid_io.hpp>

extern StatBag S;

namespace
{
// Open a UDP socket to the recursor: bind to a random port in
// [portRangeLow, portRangeHigh], then connect() to remote. Throws
// PDNSException on failure. Sets a 200ms SO_RCVTIMEO so the mainloop
// can periodically run the stale sweeper and observe the stop flag.
int openRecursorSocket(const ComboAddress& remote, unsigned long portRangeLow, unsigned long portRangeHigh)
{
  int fd = socket(remote.sin4.sin_family, SOCK_DGRAM, 0);
  if (fd < 0) {
    throw PDNSException(string("socket: ") + stringerror());
  }

  ComboAddress local;
  if (remote.sin4.sin_family == AF_INET) {
    local = ComboAddress("0.0.0.0");
  }
  else {
    local = ComboAddress("::");
  }

  unsigned int attempts = 0;
  for (; attempts < 10; attempts++) {
    local.sin4.sin_port = htons(portRangeLow + dns_random(portRangeHigh - portRangeLow));
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&local), local.getSocklen()) >= 0) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      break;
    }
  }
  if (attempts == 10) {
    closesocket(fd);
    throw PDNSException(string("binding dnsproxy socket: ") + stringerror());
  }

  if (connect(fd, reinterpret_cast<const sockaddr*>(&remote), remote.getSocklen()) < 0) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    int err = errno;
    closesocket(fd);
    throw PDNSException("Unable to UDP connect to remote nameserver " + remote.toStringWithPort() + ": " + stringerror(err));
  }

  struct timeval tv{};
  tv.tv_sec = 0;
  tv.tv_usec = 200'000;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    int err = errno;
    closesocket(fd);
    throw PDNSException(string("setting SO_RCVTIMEO on dnsproxy socket: ") + stringerror(err));
  }

  return fd;
}
}

DNSProxy::DNSProxy(Logr::log_t slog, const string& remote, const string& udpPortRange,
                   unsigned int numShards, std::chrono::milliseconds timeout) :
  d_slog(slog),
  d_timeout(timeout)
{
  if (numShards == 0) {
    throw PDNSException("DNS Proxy requires at least one shard");
  }

  d_resanswers = S.getPointer("recursing-answers");
  d_resquestions = S.getPointer("recursing-questions");
  d_udpanswers = S.getPointer("udp-answers");

  vector<string> addresses;
  stringtok(addresses, remote, " ,\t");
  d_remote = ComboAddress(addresses[0], 53);

  vector<string> parts;
  stringtok(parts, udpPortRange, " ");
  if (parts.size() != 2) {
    throw PDNSException("DNS Proxy UDP port range must contain exactly one lower and one upper bound");
  }
  unsigned long portRangeLow = std::stoul(parts.at(0));
  unsigned long portRangeHigh = std::stoul(parts.at(1));
  if (portRangeLow < 1 || portRangeHigh > 65535) {
    throw PDNSException("DNS Proxy UDP port range values out of valid port bounds (1 to 65535)");
  }
  if (portRangeLow >= portRangeHigh) {
    throw PDNSException("DNS Proxy UDP port range upper bound " + std::to_string(portRangeHigh) + " must be higher than lower bound (" + std::to_string(portRangeLow) + ")");
  }

  d_shards.reserve(numShards);
  for (unsigned int i = 0; i < numShards; ++i) {
    auto shard = std::make_unique<Shard>();
    shard->sock = openRecursorSocket(d_remote, portRangeLow, portRangeHigh);
    shard->xorSeed = dns_random_uint16();
    {
      auto hot = shard->hot.lock();
      initHot(*hot);
    }

    ComboAddress bound;
    socklen_t boundLen = bound.getSocklen();
    int boundPort = -1;
    if (getsockname(shard->sock, reinterpret_cast<struct sockaddr*>(&bound), &boundLen) == 0) { // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      boundPort = ntohs(bound.sin4.sin_port);
    }
    SLOG(g_log << Logger::Error << "DNS Proxy shard " << i << " launched, local port " << boundPort << ", remote " << d_remote.toStringWithPort() << endl,
         d_slog->info(Logr::Error, "DNS Proxy shard launched", "shard", Logging::Loggable(i), "local port", Logging::Loggable(boundPort), "remote", Logging::Loggable(d_remote.toStringWithPort())));

    d_shards.push_back(std::move(shard));
  }
}

DNSProxy::Shard& DNSProxy::pickShard(const DNSName& aname)
{
  return *d_shards[aname.hash() % d_shards.size()];
}

void DNSProxy::go()
{
  for (unsigned int i = 0; i < d_shards.size(); ++i) {
    Shard& shard = *d_shards[i];
    shard.loop = std::thread([this, &shard, i]() { mainloop(shard, i); });
  }
}

bool DNSProxy::completePacket(std::unique_ptr<DNSPacket>& reply, const DNSName& target, const DNSName& aname, const uint8_t scopeMask)
{
  string ECSOptionStr;

  if (reply->hasEDNSSubnet()) {
    DLOG(SLOG(g_log << "dnsproxy::completePacket: Parsed edns source: " << reply->d_eso.getSource().toString() << ", scope: " << Netmask(reply->d_eso.getSource().getNetwork(), reply->d_eso.getScopePrefixLength()).toString() << ", family = " << std::to_string(reply->d_eso.getFamily()) << endl,
              d_slog->info(Logr::Debug, "DNSProxy::completePacket: Parsed EDNS", "source", Logging::Loggable(reply->d_eso.getSource()), "scope", Logging::Loggable(Netmask(reply->d_eso.getSource().getNetwork(), reply->d_eso.getScopePrefixLength())), "family", Logging::Loggable(reply->d_eso.getFamily()))));
    ECSOptionStr = reply->d_eso.makeOptString();
    DLOG(SLOG(g_log << "from dnsproxy::completePacket: Creating ECS option string " << makeHexDump(ECSOptionStr) << endl,
              d_slog->info(Logr::Debug, "DNSProxy::completePacket: Creating ECS option string", "string", Logging::Loggable(makeHexDump(ECSOptionStr)))));
  }

  if (reply->d_tcp) {
    vector<DNSZoneRecord> ips;
    int ret1 = 0;
    int ret2 = 0;
    // rip out edns info here, pass it to the stubDoResolve
    if (reply->qtype == QType::A || reply->qtype == QType::ANY) {
      ret1 = stubDoResolve(d_slog, target, QType::A, ips, reply->hasEDNSSubnet() ? &reply->d_eso : nullptr);
    }
    if (reply->qtype == QType::AAAA || reply->qtype == QType::ANY) {
      ret2 = stubDoResolve(d_slog, target, QType::AAAA, ips, reply->hasEDNSSubnet() ? &reply->d_eso : nullptr);
    }

    if (ret1 != RCode::NoError || ret2 != RCode::NoError) {
      if (g_slogStructured) {
        d_slog->info(Logr::Error, "Error resolving ALIAS target over UDP, original query came in over TCP, returning SERVFAIL", "target", Logging::Loggable(target), "A record query", Logging::Loggable(RCode::to_s(ret1)), "AAAA record query", Logging::Loggable(RCode::to_s(ret2)));
      }
      else {
        g_log << Logger::Error << "Error resolving for " << aname << " ALIAS " << target << " over UDP, original query came in over TCP";
        if (ret1 != RCode::NoError) {
          g_log << Logger::Error << ", A-record query returned " << RCode::to_s(ret1);
        }
        if (ret2 != RCode::NoError) {
          g_log << Logger::Error << ", AAAA-record query returned " << RCode::to_s(ret2);
        }
        g_log << Logger::Error << ", returning SERVFAIL" << endl;
      }
      reply->clearRecords();
      reply->setRcode(RCode::ServFail);
    }
    else {
      for (auto& ip : ips) { // NOLINT(readability-identifier-length)
        ip.dr.d_name = aname;
        reply->addRecord(std::move(ip));
      }
    }

    uint16_t len = htons(reply->getString().length());
    string buffer((const char*)&len, 2);
    buffer.append(reply->getString());
    writen2WithTimeout(reply->getSocket(), buffer.c_str(), buffer.length(), timeval{::arg().asNum("tcp-idle-timeout"), 0});

    return true;
  }

  Shard& shard = pickShard(aname);
  uint16_t qtype = reply->qtype.getCode();
  uint16_t id = 0;

  {
    auto hot = shard.hot.lock();
    if (hot->freeIds.empty()) {
      shard.slotExhaustion++;
      S.inc("recursing-slot-exhaustion");
      SLOG(g_log << Logger::Warning << "DNS Proxy shard exhausted available IDs, dropping ALIAS lookup for " << aname << endl,
           d_slog->info(Logr::Warning, "DNS Proxy shard exhausted available IDs, dropping ALIAS lookup", "alias", Logging::Loggable(aname)));
      return false;
    }
    id = hot->freeIds.front();
    hot->freeIds.pop_front();

    Slot& slot = hot->table[id];
    slot.state = SlotState::IN_USE;
    slot.created = std::chrono::steady_clock::now();
    slot.id = reply->d.id;
    slot.remote = reply->d_remote;
    slot.outsock = reply->getSocket();
    slot.qtype = qtype;
    slot.qname = target;
    slot.anyLocal = reply->d_anyLocal;
    slot.aname = aname;
    slot.anameScopeMask = scopeMask;
    slot.complete = std::move(reply);
  }

  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, target, qtype);
  pw.getHeader()->rd = true;
  pw.getHeader()->id = id ^ shard.xorSeed;
  // Add EDNS Subnet if the client sent one - issue #5469
  if (!ECSOptionStr.empty()) {
    DLOG(SLOG(g_log << "from dnsproxy::completePacket: adding ECS option string to packet options " << makeHexDump(ECSOptionStr) << endl,
              d_slog->info(Logr::Debug, "DNSProxy::completePacket: adding ECS option string to packet options", "ECS options", Logging::Loggable(makeHexDump(ECSOptionStr)))));
    DNSPacketWriter::optvect_t opts;
    opts.emplace_back(EDNSOptionCode::ECS, ECSOptionStr);
    pw.addOpt(512, 0, 0, opts);
    pw.commit();
  }

  if (send(shard.sock, packet.data(), packet.size(), 0) < 0) { // zoom
    int err = errno;
    SLOG(g_log << Logger::Error << "Unable to send a packet to our recursing backend: " << stringerror(err) << endl,
         d_slog->error(Logr::Error, err, "Unable to send a packet to our recursing backend"));
    auto hot = shard.hot.lock();
    Slot& slot = hot->table[id];
    if (slot.state == SlotState::IN_USE) {
      reply = std::move(slot.complete);
      slot = Slot{};
      hot->freeIds.push_back(id);
    }
    return false;
  }
  (*d_resquestions)++;
  return true;
}

void DNSProxy::sweepStale(Shard& shard)
{
  const auto deadline = std::chrono::steady_clock::now() - d_timeout;
  auto hot = shard.hot.lock();
  for (uint32_t i = 0; i < hot->table.size(); ++i) {
    Slot& slot = hot->table[i];
    if (slot.state == SlotState::IN_USE && slot.created < deadline) {
      SLOG(g_log << Logger::Warning << "Recursive query for remote " << slot.remote.toStringWithPort() << " with internal id " << i << " was not answered by backend within timeout, reusing id" << endl,
           d_slog->info(Logr::Warning, "Recursive query was not answered by backend within timeout, reusing id", "remote", Logging::Loggable(slot.remote), "id", Logging::Loggable(i)));
      S.inc("recursion-unanswered");
      shard.staleReaped++;
      slot = Slot{};
      hot->freeIds.push_back(static_cast<uint16_t>(i));
    }
  }
}

void DNSProxy::mainloop(Shard& shard, unsigned int shardIndex)
{
  setThreadName("pdns/dnsproxy-" + std::to_string(shardIndex));
  try {
    char buffer[1500];
    auto lastSweep = std::chrono::steady_clock::now();

    while (!shard.stop.load(std::memory_order_acquire)) {
      ComboAddress fromaddr;
      socklen_t fromaddrSize = sizeof(fromaddr);
      ssize_t len = recvfrom(shard.sock, &buffer[0], sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&fromaddr), &fromaddrSize); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

      const auto now = std::chrono::steady_clock::now();
      if (now - lastSweep >= std::chrono::seconds(1)) {
        sweepStale(shard);
        lastSweep = now;
      }

      if (len < 0) {
        int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR) {
          continue; // recv timeout or interrupted: loop and re-check stop/sweep
        }
        if (shard.stop.load(std::memory_order_acquire)) {
          break;
        }
        SLOG(g_log << Logger::Error << "Error receiving packet from recursor backend: " << stringerror(err) << endl,
             d_slog->error(Logr::Error, err, "Error receiving packet from recursor backend"));
        continue;
      }
      if (len < static_cast<ssize_t>(sizeof(dnsheader))) {
        if (len == 0) {
          SLOG(g_log << Logger::Error << "Error receiving packet from recursor backend, EOF" << endl,
               d_slog->info(Logr::Error, "Error receiving packet from recursor backend (EOF)"));
        }
        else {
          SLOG(g_log << Logger::Error << "Short packet from recursor backend, " << len << " bytes" << endl,
               d_slog->info(Logr::Error, "Short packet from recursor backend", "length", Logging::Loggable(len)));
        }
        continue;
      }
      if (fromaddr != d_remote) {
        // Defense in depth: kernel filters by 4-tuple via connect(), but
        // log if anything slips through.
        SLOG(g_log << Logger::Error << "Got answer from unexpected host " << fromaddr.toStringWithPort() << " instead of our recursor backend " << d_remote.toStringWithPort() << endl,
             d_slog->info(Logr::Error, "Got answer from unexpected host instead of our recursor backend", "answer from", Logging::Loggable(fromaddr.toStringWithPort()), "expected", Logging::Loggable(d_remote.toStringWithPort())));
        continue;
      }
      (*d_resanswers)++;
      (*d_udpanswers)++;

      dnsheader dHead{};
      memcpy(&dHead, &buffer[0], sizeof(dHead));
      uint16_t id = dHead.id ^ shard.xorSeed;

      // Critical section: lookup, take ownership of slot contents, free the id.
      Slot taken;
      bool ok = false;
      {
        auto hot = shard.hot.lock();
        Slot& slot = hot->table[id];
        if (slot.state == SlotState::FREE) {
          SLOG(g_log << Logger::Error << "Discarding untracked packet from recursor backend with id " << id << endl,
               d_slog->info(Logr::Error, "Discarding untracked packet from recursor backend", "id", Logging::Loggable(id)));
        }
        else if (slot.state == SlotState::RESPONDED) {
          shard.duplicateReplies++;
          S.inc("recursing-duplicate-replies");
          SLOG(g_log << Logger::Error << "Received packet from recursor backend with id " << id << " which is a duplicate" << endl,
               d_slog->info(Logr::Error, "Discarding received packet from recursor backend with duplicate id", "id", Logging::Loggable(id)));
        }
        else {
          taken = std::move(slot);
          slot = Slot{};
          slot.state = SlotState::RESPONDED;
          hot->freeIds.push_back(id);
          ok = true;
        }
      }
      if (!ok) {
        continue;
      }

      // Heavy work: parsing, building reply, sendmsg() — all without the lock.
      dHead.id = taken.id;
      memcpy(&buffer[0], &dHead, sizeof(dHead)); // commit spoofed id

      DNSPacket parsed(d_slog, false);
      parsed.parse(&buffer[0], static_cast<size_t>(len));

      if (parsed.qtype.getCode() != taken.qtype || parsed.qdomain != taken.qname) {
        SLOG(g_log << Logger::Error << "Discarding packet from recursor backend with id " << id << ", qname or qtype mismatch (" << parsed.qtype.getCode() << " v " << taken.qtype << ", " << parsed.qdomain << " v " << taken.qname << ")" << endl,
             d_slog->info(Logr::Error, "Discarding received packet from recursor backend with name or type mismatch", "id", Logging::Loggable(id), "type", Logging::Loggable(parsed.qtype), "expected type", Logging::Loggable(taken.qtype), "name", Logging::Loggable(parsed.qdomain), "expected name", Logging::Loggable(taken.qname)));
        continue;
      }

      MOADNSParser mdp(false, parsed.getString());
      // update the EDNS options with info from the resolver - issue #5469
      // note that this relies on the ECS string encoder to use the source network, and only take the prefix length from scope
      // Use the more restrictive scope: ALIAS record selection scope vs recursor reply scope.
      // Prevents resolvers from over-caching geo-targeted responses across subnets.
      uint8_t effectiveScope = std::max(taken.anameScopeMask,
          static_cast<uint8_t>(parsed.d_eso.getScopePrefixLength()));
      taken.complete->d_eso.setScopePrefixLength(effectiveScope);
      DLOG(SLOG(g_log << "from dnsproxy::mainLoop: updated EDNS options from resolver EDNS source: " << taken.complete->d_eso.getSource().toString() << " EDNS scope: " << taken.complete->d_eso.getScope().toString() << endl,
                d_slog->info(Logr::Debug, "DNSProxy::mainloop: updated EDNS options from resolver EDNS", "source", Logging::Loggable(taken.complete->d_eso.getSource()), "scope", Logging::Loggable(taken.complete->d_eso.getScope()))));

      if (mdp.d_header.rcode == RCode::NoError) {
        for (const auto& answer : mdp.d_answers) {
          if (answer.d_place == DNSResourceRecord::ANSWER || (answer.d_place == DNSResourceRecord::AUTHORITY && answer.d_type == QType::SOA)) {
            if (answer.d_type == taken.qtype || (taken.qtype == QType::ANY && (answer.d_type == QType::A || answer.d_type == QType::AAAA))) {
              DNSZoneRecord dzr;
              dzr.dr.d_name = taken.aname;
              dzr.dr.d_type = answer.d_type;
              dzr.dr.d_ttl = answer.d_ttl;
              dzr.dr.d_place = answer.d_place;
              dzr.dr.setContent(answer.getContent());
              taken.complete->addRecord(std::move(dzr));
            }
          }
        }
        taken.complete->setRcode(mdp.d_header.rcode);
      }
      else {
        // SLOG(g_log << Logger::Error << "Error resolving for " << taken.aname << " ALIAS " << taken.qname << " over UDP, " << QType(taken.qtype).toString() << "-record query returned " << RCode::to_s(mdp.d_header.rcode) << ", returning SERVFAIL" << endl,
        //      d_slog->info(Logr::Error, "Error resolving ALIAS over UDP, returning SERVFAIL", "alias", Logging::Loggable(taken.aname), "query", Logging::Loggable(taken.qname), "type", Logging::Loggable(taken.qtype), "result", Logging::Loggable(RCode::to_s(mdp.d_header.rcode))));
        taken.complete->clearRecords();
        taken.complete->setRcode(RCode::ServFail);
      }

      string reply = taken.complete->getString();
      struct msghdr msgh{};
      struct iovec iov{};
      cmsgbuf_aligned cbuf{};
      iov.iov_base = const_cast<void*>(static_cast<const void*>(reply.c_str())); // NOLINT(cppcoreguidelines-pro-type-const-cast)
      iov.iov_len = reply.length();
      msgh.msg_iov = &iov;
      msgh.msg_iovlen = 1;
      msgh.msg_name = reinterpret_cast<struct sockaddr*>(&taken.remote); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      msgh.msg_namelen = taken.remote.getSocklen();
      msgh.msg_control = nullptr;
      if (taken.anyLocal) {
        addCMsgSrcAddr(&msgh, &cbuf, taken.anyLocal.get_ptr(), 0);
      }
      if (sendmsg(taken.outsock, &msgh, 0) < 0) {
        int err = errno;
        SLOG(g_log << Logger::Warning << "dnsproxy.cc: Error sending reply with sendmsg (socket=" << taken.outsock << "): " << stringerror(err) << endl,
             d_slog->error(Logr::Warning, err, "DNSProxy::mainloop: sendmsg() failed", "socket", Logging::Loggable(taken.outsock)));
      }
    }
  }
  catch (PDNSException& ae) {
    SLOG(g_log << Logger::Error << "Fatal error in DNS proxy shard " << shardIndex << ": " << ae.reason << endl,
         d_slog->error(Logr::Error, ae.reason, "Fatal error in DNS proxy shard", "shard", Logging::Loggable(shardIndex)));
  }
  catch (std::exception& e) {
    SLOG(g_log << Logger::Error << "DNS Proxy shard " << shardIndex << " thread died because of STL error: " << e.what() << endl,
         d_slog->error(Logr::Error, e.what(), "DNS proxy shard thread died because of STL error", "shard", Logging::Loggable(shardIndex)));
  }
  catch (...) {
    SLOG(g_log << Logger::Error << "DNS Proxy shard " << shardIndex << " caught an unknown exception" << endl,
         d_slog->info(Logr::Error, "DNS proxy shard caught an unknown exception", "shard", Logging::Loggable(shardIndex)));
  }
}

DNSProxy::~DNSProxy()
{
  for (auto& shard : d_shards) {
    shard->stop.store(true, std::memory_order_release);
    if (shard->sock >= 0) {
      ::shutdown(shard->sock, SHUT_RD);
    }
  }
  for (auto& shard : d_shards) {
    if (shard->loop.joinable()) {
      shard->loop.join();
    }
    if (shard->sock >= 0) {
      try {
        closesocket(shard->sock);
      }
      catch (const PDNSException&) {
      }
      shard->sock = -1;
    }
  }
}
