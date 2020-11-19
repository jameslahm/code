/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
  for(auto iter=m_cacheEntries.begin();iter!=m_cacheEntries.end();){
    auto entry = *iter;
    if(!entry->isValid){
      iter=m_cacheEntries.erase(iter);
    }
    else
    {
      ++iter;
    }
  }

  

  for(auto iter=m_arpRequests.begin();iter!=m_arpRequests.end();){
    auto now = steady_clock::now();
    auto request = *iter;
    if((now-request->timeSent)>seconds(1)){
      if((request->nTimesSent)>=5){
        // TODO: send icmp host unreachable
        iter++;
        std::cout<<"Arp not received: remove request"<<std::endl;
        
        for (auto it = request->packets.begin(); it != request->packets.end(); it++)
        {
          ethernet_hdr *eth_header = (ethernet_hdr *)((it->packet).data());
          ip_hdr *ip_header = (ip_hdr *)((unsigned char *)eth_header + sizeof(ethernet_hdr));

          auto route_entry = m_router.getRoutingTable().lookup(ntohl(ip_header->ip_src));
          auto iface = m_router.findIfaceByName(route_entry.ifName);

          ethernet_hdr ethe_reply;
          ethe_reply.ether_type = htons(ethertype_ip);
          std::copy(iface->addr.begin(), iface->addr.end(), ethe_reply.ether_shost);

          ip_hdr ip_reply;
          ip_reply.ip_ttl = 64;
          ip_reply.ip_off = htons(IP_RF);
          ip_reply.ip_v = 4;
          ip_reply.ip_hl = 5;

          ip_reply.ip_p = 1;
          ip_reply.ip_src = iface->ip;
          ip_reply.ip_dst = ip_header->ip_src;

          icmp_t3_hdr icmp_reply;
          icmp_reply.icmp_type = 3;
          icmp_reply.icmp_code = 3;
          std::copy((uint8_t *)ip_header, (uint8_t *)ip_header + ICMP_DATA_SIZE, icmp_reply.data);

          icmp_reply.icmp_sum = simple_router::calcIcmpChecksum((icmp_hdr *)&icmp_reply, sizeof(icmp_t3_hdr));

          ip_reply.ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
          ip_reply.ip_sum = calcIpChecksum(&ip_reply);

          Buffer packet;
          packet.insert(packet.end(), (unsigned char *)&ethe_reply, (unsigned char *)&ethe_reply + sizeof(ethernet_hdr));
          packet.insert(packet.end(), (unsigned char *)&ip_reply, (unsigned char *)&ip_reply + sizeof(ip_hdr));
          packet.insert(packet.end(), (unsigned char *)&icmp_reply, (unsigned char *)&icmp_reply + sizeof(icmp_t3_hdr));

          m_router.sendPacket(packet, iface->name);
          printf("Send:\n");
          print_hdrs(packet);
        }
        m_arpRequests.remove(request);
        std::cout<<"Arp not received: removed"<<std::endl;
      }
      else{
        request->timeSent=now;
        request->nTimesSent++;

        arp_hdr arp_request;
        arp_request.arp_hrd = htons(arp_hrd_ethernet);
        arp_request.arp_pro = htons(ethertype_ip);
        arp_request.arp_op =htons(arp_op_request);
        arp_request.arp_hln = 0x06;
        arp_request.arp_pln = 0x04;

        auto route_entry = m_router.getRoutingTable().lookup(ntohl(request->ip));

        auto iface = m_router.findIfaceByName(route_entry.ifName);

        std::copy(iface->addr.begin(), iface->addr.end(), arp_request.arp_sha);
        arp_request.arp_sip = iface->ip;

        uint8_t empty_tha[6]={0,0,0,0,0,0};
        uint8_t broadcast_tha[6]={0xff,0xff,0xff,0xff,0xff,0xff};

        std::copy(empty_tha, empty_tha + 6, arp_request.arp_tha);
        arp_request.arp_tip = request->ip;

        ethernet_hdr ethe_request;
        ethe_request.ether_type = htons(ethertype_arp);
        std::copy(iface->addr.begin(), iface->addr.end(), ethe_request.ether_shost);
        std::copy(broadcast_tha, broadcast_tha + 6, ethe_request.ether_dhost);

        Buffer packet;
        packet.insert(packet.end(), (unsigned char *)&ethe_request, (unsigned char *)&ethe_request + sizeof(ethe_request));
        packet.insert(packet.end(), (unsigned char *)&arp_request, (unsigned char *)&arp_request + sizeof(arp_request));

        m_router.sendPacket(packet, iface->name);
        std::cout<<"Send:"<<std::endl;
        print_hdrs(packet);

        iter++;
      }
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
