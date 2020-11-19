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

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router
{
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////
  // IMPLEMENT THIS METHOD
  void
  SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface)
  {
    // std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface *iface = findIfaceByName(inIface);
    if (iface == nullptr)
    {
      std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
      return;
    }

    // std::cerr << getRoutingTable() << std::endl;

    // FILL THIS IN

    // DEBUG INFO
    std::cout << "Recv:" << std::endl;
    print_hdrs(packet);

    int length = packet.size();

    // parse ethenet header
    length -= sizeof(ethernet_hdr);

    if (length < 0)
    {
      std::cerr << "Failed to parse ETHERNET header, insufficient length" << std::endl;
      return;
    }

    ethernet_hdr *eth_header = (ethernet_hdr *)packet.data();

    // check if broadcase or mathc mac address
    if (!checkIfBroadcast(eth_header->ether_dhost) && !checkIfMatchMac(eth_header->ether_dhost, iface->addr))
    {
      std::cerr << "Received packet,ignore because of not match broadcase or mac address" << std::endl;
      return;
    }

    // handle arp packet
    if (ntohs(eth_header->ether_type) == ethertype_arp)
    {
      length -= sizeof(arp_hdr);
      if (length < 0)
      {
        std::cerr << "Failed to parse ETHERNET header, insufficient length" << std::endl;
        return;
      }

      arp_hdr *arp_header = (arp_hdr *)((unsigned char *)eth_header + sizeof(ethernet_hdr));

      // check if request
      if (ntohs(arp_header->arp_op) == arp_op_request)
      {
        // check if target here
        if (arp_header->arp_tip == iface->ip)
        {
          // send arp reply packet
          arp_hdr arp_reply;
          arp_reply.arp_hrd = htons(arp_hrd_ethernet);
          arp_reply.arp_pro = htons(ethertype_ip);
          arp_reply.arp_op = htons(arp_op_reply);
          arp_reply.arp_hln = 0x06;
          arp_reply.arp_pln = 0x04;
          std::copy(iface->addr.begin(), iface->addr.end(), arp_reply.arp_sha);
          arp_reply.arp_sip = iface->ip;
          std::copy(arp_header->arp_sha, arp_header->arp_sha + 6, arp_reply.arp_tha);
          arp_reply.arp_tip = arp_header->arp_sip;

          ethernet_hdr ethe_reply;
          ethe_reply.ether_type = htons(ethertype_arp);
          std::copy(iface->addr.begin(), iface->addr.end(), ethe_reply.ether_shost);
          std::copy(arp_header->arp_sha, arp_header->arp_sha + 6, ethe_reply.ether_dhost);

          Buffer reply;
          reply.insert(reply.end(), (unsigned char *)&ethe_reply, (unsigned char *)&ethe_reply + sizeof(ethe_reply));
          reply.insert(reply.end(), (unsigned char *)&arp_reply, (unsigned char *)&arp_reply + sizeof(arp_reply));

          sendPacket(reply, iface->name);
          std::cout << "Send:" << std::endl;
          print_hdrs(reply);
        }
      }

      if (ntohs(arp_header->arp_op) == arp_op_reply)
      {
        auto sha = new Buffer;
        sha->insert(sha->end(), arp_header->arp_sha, arp_header->arp_sha + 6);

        auto arp_entry = m_arp.lookup(arp_header->arp_sip);

        if (arp_entry == nullptr)
        {
          auto request = m_arp.insertArpEntry(*sha, arp_header->arp_sip);
          if (request != nullptr)
          {
            printf("Pending packets\n");
            for (auto iter = request->packets.begin(); iter != request->packets.end(); iter++)
            {
              ethernet_hdr *ethe_header = (ethernet_hdr *)(iter->packet.data());
              std::copy(sha->begin(), sha->end(), ethe_header->ether_dhost);
              sendPacket(iter->packet, iter->iface);
              printf("Send:\n");
              print_hdrs(iter->packet);
            }
            m_arp.removeRequest(request);
          }
          else
          {
            printf("No pending requests\n");
          }
        }
      }
    }

    // handle ip packet
    if (ntohs(eth_header->ether_type) == ethertype_ip)
    {
      length -= sizeof(ip_hdr);
      if (length < 0)
      {
        std::cerr << "Failed to parse ETHERNET header, insufficient length" << std::endl;
        return;
      }

      ip_hdr *ip_header = (ip_hdr *)((unsigned char *)eth_header + sizeof(ethernet_hdr));

      uint16_t checksum = calcIpChecksum(ip_header);
      if (checksum != ip_header->ip_sum)
      {
        std::cerr << "Checksum not correct" << std::endl;
        return;
      }

      // check if destined to the router
      const Interface *tiface = findIfaceByIp(ip_header->ip_dst);

      // forward
      if (tiface == nullptr)
      {
        auto route_entry = m_routingTable.lookup(ntohl(ip_header->ip_dst));
        // auto arp_entry = m_arp.lookup(route_entry.gw);
        auto arp_entry = m_arp.lookup(ip_header->ip_dst);

        ip_header->ip_ttl--;

        // icmp time exceeded message
        if (ip_header->ip_ttl == 0)
        {
          ethernet_hdr ethe_reply;
          ethe_reply.ether_type = htons(ethertype_ip);
          std::copy(iface->addr.begin(), iface->addr.end(), ethe_reply.ether_shost);
          std::copy(eth_header->ether_shost, eth_header->ether_shost + 6, ethe_reply.ether_dhost);

          ip_hdr ip_reply;
          ip_reply.ip_ttl = 64;
          ip_reply.ip_off = htons(IP_DF);
          ip_reply.ip_v = 4;
          ip_reply.ip_hl = 5;

          ip_reply.ip_p = 1;
          ip_reply.ip_src = iface->ip;
          ip_reply.ip_dst = ip_header->ip_src;

          icmp_t3_hdr icmp_reply;
          icmp_reply.icmp_type = 11;
          icmp_reply.icmp_code = 0;
          std::copy((uint8_t *)ip_header, (uint8_t *)ip_header + ICMP_DATA_SIZE, icmp_reply.data);

          icmp_reply.icmp_sum = calcIcmpChecksum((icmp_hdr *)&icmp_reply, sizeof(icmp_t3_hdr));

          ip_reply.ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
          ip_reply.ip_sum = calcIpChecksum(&ip_reply);

          Buffer packet;
          packet.insert(packet.end(), (unsigned char *)&ethe_reply, (unsigned char *)&ethe_reply + sizeof(ethernet_hdr));
          packet.insert(packet.end(), (unsigned char *)&ip_reply, (unsigned char *)&ip_reply + sizeof(ip_hdr));
          packet.insert(packet.end(), (unsigned char *)&icmp_reply, (unsigned char *)&icmp_reply + sizeof(icmp_t3_hdr));

          sendPacket(packet, iface->name);
          printf("Send TTL=0:\n");
          print_hdrs(packet);
          return;
        }

        ip_header->ip_sum = calcIpChecksum(ip_header);
        auto tiface = findIfaceByName(route_entry.ifName);

        // ATTENTION: copy src mac to dst mac
        std::copy(eth_header->ether_shost,eth_header->ether_shost+6,eth_header->ether_dhost);

        std::copy(tiface->addr.begin(), tiface->addr.end(), eth_header->ether_shost);


        if (arp_entry == nullptr)
        {
          // m_arp.queueRequest(route_entry.gw, packet, route_entry.ifName);
          m_arp.queueRequest(ip_header->ip_dst, packet, route_entry.ifName);
        }
        else
        {
          std::copy(arp_entry->mac.begin(), arp_entry->mac.end(), eth_header->ether_dhost);
          sendPacket(packet, route_entry.ifName);
          printf("Send:\n");
          print_hdrs(packet);
        }
      }

      // handle
      else
      {
        if (ip_header->ip_p == 1)
        {
          length -= sizeof(icmp_hdr);
          if (length < 0)
          {
            std::cerr << "Failed to parse ETHERNET header, insufficient length" << std::endl;
            return;
          }
          icmp_hdr *icmp_header = (icmp_hdr *)((unsigned char *)ip_header + sizeof(ip_hdr));

          // TODO: checksum

          // echo
          if (icmp_header->icmp_type == 8)
          {
            icmp_header->icmp_type = 0;
            uint32_t tmp = ip_header->ip_src;
            ip_header->ip_src = ip_header->ip_dst;
            ip_header->ip_dst = tmp;
            // ip_header->ip_ttl--;
            std::copy(eth_header->ether_shost, eth_header->ether_shost + 6, eth_header->ether_dhost);
            std::copy(iface->addr.begin(), iface->addr.end(), eth_header->ether_shost);

            icmp_header->icmp_sum = calcIcmpChecksum(icmp_header, length + sizeof(icmp_hdr));

            sendPacket(packet, iface->name);
            printf("Send:\n");
            print_hdrs(packet);
          }
        }
        if (ip_header->ip_p == 6 || ip_header->ip_p == 17)
        {
          ethernet_hdr ethe_reply;
          ethe_reply.ether_type = htons(ethertype_ip);
          std::copy(iface->addr.begin(), iface->addr.end(), ethe_reply.ether_shost);
          std::copy(eth_header->ether_shost, eth_header->ether_shost + 6, ethe_reply.ether_dhost);

          ip_hdr ip_reply;
          ip_reply.ip_ttl = 64;
          ip_reply.ip_off = htons(IP_DF);
          ip_reply.ip_v = 4;
          ip_reply.ip_hl = 5;

          ip_reply.ip_p = 1;
          ip_reply.ip_src = iface->ip;
          ip_reply.ip_dst = ip_header->ip_src;

          icmp_t3_hdr icmp_reply;
          icmp_reply.icmp_type = 3;
          icmp_reply.icmp_code = 3;
          std::copy((uint8_t *)ip_header, (uint8_t *)ip_header + ICMP_DATA_SIZE, icmp_reply.data);

          icmp_reply.icmp_sum = calcIcmpChecksum((icmp_hdr *)&icmp_reply, sizeof(icmp_t3_hdr));

          ip_reply.ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
          ip_reply.ip_sum = calcIpChecksum(&ip_reply);

          Buffer packet;
          packet.insert(packet.end(), (unsigned char *)&ethe_reply, (unsigned char *)&ethe_reply + sizeof(ethernet_hdr));
          packet.insert(packet.end(), (unsigned char *)&ip_reply, (unsigned char *)&ip_reply + sizeof(ip_hdr));
          packet.insert(packet.end(), (unsigned char *)&icmp_reply, (unsigned char *)&icmp_reply + sizeof(icmp_t3_hdr));

          sendPacket(packet, iface->name);
          printf("Send:\n");
          print_hdrs(packet);
          return;
        }
      }
    }

    // ignore
  }
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.
  SimpleRouter::SimpleRouter()
      : m_arp(*this)
  {
  }

  void
  SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
  {
    m_pox->begin_sendPacket(packet, outIface);
  }

  bool
  SimpleRouter::loadRoutingTable(const std::string &rtConfig)
  {
    return m_routingTable.load(rtConfig);
  }

  void
  SimpleRouter::loadIfconfig(const std::string &ifconfig)
  {
    std::ifstream iff(ifconfig.c_str());
    std::string line;
    while (std::getline(iff, line))
    {
      std::istringstream ifLine(line);
      std::string iface, ip;
      ifLine >> iface >> ip;

      in_addr ip_addr;
      if (inet_aton(ip.c_str(), &ip_addr) == 0)
      {
        throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
      }

      m_ifNameToIpMap[iface] = ip_addr.s_addr;
    }
  }

  void
  SimpleRouter::printIfaces(std::ostream &os)
  {
    if (m_ifaces.empty())
    {
      os << " Interface list empty " << std::endl;
      return;
    }

    for (const auto &iface : m_ifaces)
    {
      os << iface << "\n";
    }
    os.flush();
  }

  const Interface *
  SimpleRouter::findIfaceByIp(uint32_t ip) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface) {
      return iface.ip == ip;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByMac(const Buffer &mac) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface) {
      return iface.addr == mac;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByName(const std::string &name) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface) {
      return iface.name == name;
    });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  void
  SimpleRouter::reset(const pox::Ifaces &ports)
  {
    std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

    m_arp.clear();
    m_ifaces.clear();

    for (const auto &iface : ports)
    {
      auto ip = m_ifNameToIpMap.find(iface.name);
      if (ip == m_ifNameToIpMap.end())
      {
        std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
        continue;
      }

      m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
    }

    printIfaces(std::cerr);
  }

} // namespace simple_router
