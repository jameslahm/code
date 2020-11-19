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
          ethernet_hdr *ethe_header = (ethernet_hdr *)((it->packet).data());
          ip_hdr *ip_header = (ip_hdr *)((unsigned char *)ethe_header + sizeof(ethernet_hdr));

          auto route_entry = m_router.getRoutingTable().lookup(ntohl(ip_header->ip_src));
          auto iface = m_router.findIfaceByName(route_entry.ifName);

          auto ethe_reply = construct_ethe_header(ethertype_ip,(uint8_t *)(iface->addr.data()),ethe_header->ether_dhost);

          auto ip_reply = construct_ip_header(IP_P_ICMP,iface->ip,ip_header->ip_src);

          auto icmp_reply = construct_icmp_t3_header(ICMP_TYPE_PORT_UNREACHABLE,ICMP_CODE_PORT_UNREACHABLE,(uint8_t *)ip_header);

          ip_reply.ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
          ip_reply.ip_sum = calcIpChecksum(&ip_reply);


          auto packet = construct_icmp_t3_packet(ethe_reply,ip_reply,icmp_reply);

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

        auto route_entry = m_router.getRoutingTable().lookup(ntohl(request->ip));

        auto iface = m_router.findIfaceByName(route_entry.ifName);

        uint8_t empty_tha[6]={0,0,0,0,0,0};
        uint8_t broadcast_tha[6]={0xff,0xff,0xff,0xff,0xff,0xff};

        auto arp_request = construct_arp_header(arp_op_request,(uint8_t *)(iface->addr.data()),empty_tha,iface->ip,request->ip);

        auto ethe_request = construct_ethe_header(ethertype_arp,(uint8_t *)(iface->addr.data()),broadcast_tha);

        auto packet = construct_arp_packet(ethe_request,arp_request);

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
