#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <chrono>
#include <memory>
#include <set>
#include <boost/test/unit_test.hpp>

#include "dnsproxy.hh"

// Hot is ~13 MB (std::array<Slot, 65536>); heap-allocate it in every case.

BOOST_AUTO_TEST_SUITE(test_dnsproxy_cc)

BOOST_AUTO_TEST_CASE(test_initHot_populates_full_id_space)
{
  auto hot = std::make_unique<DNSProxy::Hot>();
  DNSProxy::initHot(*hot);

  BOOST_CHECK_EQUAL(hot->freeIds.size(), 65536U);
  BOOST_CHECK_EQUAL(hot->table.size(), 65536U);

  for (const auto& slot : hot->table) {
    BOOST_CHECK(slot.state == DNSProxy::SlotState::FREE);
  }
}

BOOST_AUTO_TEST_CASE(test_freeIds_are_unique)
{
  auto hot = std::make_unique<DNSProxy::Hot>();
  DNSProxy::initHot(*hot);

  std::set<uint16_t> seen;
  while (!hot->freeIds.empty()) {
    uint16_t id = hot->freeIds.front();
    hot->freeIds.pop_front();
    BOOST_CHECK(seen.insert(id).second);
  }
  BOOST_CHECK_EQUAL(seen.size(), 65536U);
}

BOOST_AUTO_TEST_CASE(test_acquire_release_round_trip)
{
  auto hot = std::make_unique<DNSProxy::Hot>();
  DNSProxy::initHot(*hot);

  uint16_t id = hot->freeIds.front();
  hot->freeIds.pop_front();
  BOOST_CHECK_EQUAL(hot->freeIds.size(), 65535U);

  DNSProxy::Slot& slot = hot->table[id];
  slot.state = DNSProxy::SlotState::IN_USE;
  slot.created = std::chrono::steady_clock::now();

  hot->freeIds.push_back(id);
  slot = DNSProxy::Slot{};
  slot.state = DNSProxy::SlotState::RESPONDED;

  BOOST_CHECK_EQUAL(hot->freeIds.size(), 65536U);
  BOOST_CHECK(hot->table[id].state == DNSProxy::SlotState::RESPONDED);
}

BOOST_AUTO_TEST_CASE(test_slot_state_machine_transitions)
{
  auto hot = std::make_unique<DNSProxy::Hot>();
  DNSProxy::initHot(*hot);

  uint16_t id = hot->freeIds.front();
  hot->freeIds.pop_front();
  BOOST_CHECK_EQUAL(id, 0U);

  DNSProxy::Slot& slot = hot->table[id];
  BOOST_CHECK(slot.state == DNSProxy::SlotState::FREE);

  slot.state = DNSProxy::SlotState::IN_USE;
  slot.qtype = 1;
  BOOST_CHECK(slot.state == DNSProxy::SlotState::IN_USE);

  slot.state = DNSProxy::SlotState::RESPONDED;
  hot->freeIds.push_back(id);

  BOOST_CHECK(slot.state == DNSProxy::SlotState::RESPONDED);

  uint16_t recycled = hot->freeIds.back();
  hot->freeIds.pop_back();
  BOOST_CHECK_EQUAL(recycled, id);
  hot->table[recycled] = DNSProxy::Slot{};
  hot->table[recycled].state = DNSProxy::SlotState::IN_USE;
  BOOST_CHECK(hot->table[recycled].state == DNSProxy::SlotState::IN_USE);
}

BOOST_AUTO_TEST_CASE(test_id_space_exhaustion)
{
  auto hot = std::make_unique<DNSProxy::Hot>();
  DNSProxy::initHot(*hot);

  while (!hot->freeIds.empty()) {
    uint16_t id = hot->freeIds.front();
    hot->freeIds.pop_front();
    hot->table[id].state = DNSProxy::SlotState::IN_USE;
  }

  BOOST_CHECK(hot->freeIds.empty());
  BOOST_CHECK_EQUAL(hot->freeIds.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_stale_sweep_logic)
{
  auto hot = std::make_unique<DNSProxy::Hot>();
  DNSProxy::initHot(*hot);

  const auto now = std::chrono::steady_clock::now();

  hot->table[10].state = DNSProxy::SlotState::IN_USE;
  hot->table[10].created = now;
  hot->table[200].state = DNSProxy::SlotState::IN_USE;
  hot->table[200].created = now - std::chrono::seconds(120);
  hot->table[3000].state = DNSProxy::SlotState::IN_USE;
  hot->table[3000].created = now - std::chrono::seconds(120);

  hot->freeIds.erase(std::remove(hot->freeIds.begin(), hot->freeIds.end(), 10), hot->freeIds.end());
  hot->freeIds.erase(std::remove(hot->freeIds.begin(), hot->freeIds.end(), 200), hot->freeIds.end());
  hot->freeIds.erase(std::remove(hot->freeIds.begin(), hot->freeIds.end(), 3000), hot->freeIds.end());
  BOOST_CHECK_EQUAL(hot->freeIds.size(), 65533U);

  const auto deadline = now - std::chrono::seconds(60);
  size_t reaped = 0;
  for (uint32_t i = 0; i < hot->table.size(); ++i) {
    auto& slot = hot->table[i];
    if (slot.state == DNSProxy::SlotState::IN_USE && slot.created < deadline) {
      slot = DNSProxy::Slot{};
      hot->freeIds.push_back(static_cast<uint16_t>(i));
      ++reaped;
    }
  }

  BOOST_CHECK_EQUAL(reaped, 2U);
  BOOST_CHECK_EQUAL(hot->freeIds.size(), 65535U);
  BOOST_CHECK(hot->table[10].state == DNSProxy::SlotState::IN_USE);
  BOOST_CHECK(hot->table[200].state == DNSProxy::SlotState::FREE);
  BOOST_CHECK(hot->table[3000].state == DNSProxy::SlotState::FREE);
}

BOOST_AUTO_TEST_SUITE_END()
