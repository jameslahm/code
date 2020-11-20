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

    ethernet_hdr *ethe_header = (ethernet_hdr *)packet.data();

    // check if broadcase or mathc mac address
    if (!checkIfBroadcast(ethe_header->ether_dhost) && !checkIfMatchMac(ethe_header->ether_dhost, iface->addr))
    {
      std::cerr << "Received packet,ignore because of not match broadcast or mac address" << std::endl;
      return;
    }

    // handle arp packet
    if (ntohs(ethe_header->ether_type) == ethertype_arp)
    {
      length -= sizeof(arp_hdr);
      if (length < 0)
      {
        std::cerr << "Failed to parse ETHERNET header, insufficient length" << std::endl;
        return;
      }

      arp_hdr *arp_header = (arp_hdr *)((unsigned char *)ethe_header + sizeof(ethernet_hdr));

      // check if request
      if (ntohs(arp_header->arp_op) == arp_op_request)
      {
        // if (!checkIfBroadcast(ethe_header->ether_dhost)){
        //   std::cerr << "Received Arp packet,ignore because of not match broadcast" << std::endl;
        //   return;
        // }

        // check if target here
        if (arp_header->arp_tip == iface->ip)
        {

          auto arp_reply = construct_arp_header(arp_op_reply, (uint8_t *)(iface->addr.data()), arp_header->arp_sha, iface->ip, arp_header->arp_sip);

          auto ethe_reply = construct_ethe_header(ethertype_arp, (uint8_t *)(iface->addr.data()), arp_header->arp_sha);

          auto reply = construct_arp_packet(ethe_reply, arp_reply);

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
    if (ntohs(ethe_header->ether_type) == ethertype_ip)
    {
      length -= sizeof(ip_hdr);
      if (length < 0)
      {
        std::cerr << "Failed to parse ETHERNET header, insufficient length" << std::endl;
        return;
      }

      ip_hdr *ip_header = (ip_hdr *)((unsigned char *)ethe_header + sizeof(ethernet_hdr));

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

          auto ethe_reply = construct_ethe_header(ethertype_ip, (uint8_t *)(iface->addr.data()), ethe_header->ether_shost);

          auto ip_reply = construct_ip_header(IP_P_ICMP, iface->ip, ip_header->ip_src);

          auto icmp_reply = construct_icmp_t3_header(ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TIME_EXCEEDED, (uint8_t *)ip_header);

          ip_reply.ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
          ip_reply.ip_sum = calcIpChecksum(&ip_reply);

          auto packet = construct_icmp_t3_packet(ethe_reply, ip_reply, icmp_reply);

          sendPacket(packet, iface->name);
          printf("Send TTL=0:\n");
          print_hdrs(packet);
          return;
        }

        ip_header->ip_sum = calcIpChecksum(ip_header);
        auto tiface = findIfaceByName(route_entry.ifName);

        // ATTENTION: copy src mac to dst mac
        std::copy(ethe_header->ether_shost, ethe_header->ether_shost + 6, ethe_header->ether_dhost);

        std::copy(tiface->addr.begin(), tiface->addr.end(), ethe_header->ether_shost);

        if (arp_entry == nullptr)
        {
          // m_arp.queueRequest(route_entry.gw, packet, route_entry.ifName);
          m_arp.queueRequest(ip_header->ip_dst, packet, route_entry.ifName);
        }
        else
        {
          std::copy(arp_entry->mac.begin(), arp_entry->mac.end(), ethe_header->ether_dhost);
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
            ip_header->ip_ttl = 64;
            // ip_header->ip_ttl--;
            std::copy(ethe_header->ether_shost, ethe_header->ether_shost + 6, ethe_header->ether_dhost);
            std::copy(iface->addr.begin(), iface->addr.end(), ethe_header->ether_shost);

            icmp_header->icmp_sum = calcIcmpChecksum(icmp_header, length + sizeof(icmp_hdr));

            sendPacket(packet, iface->name);
            printf("Send:\n");
            print_hdrs(packet);
          }
        }
        if (ip_header->ip_p == 6 || ip_header->ip_p == 17)
        {
          auto ethe_reply = construct_ethe_header(ethertype_ip, (uint8_t *)(iface->addr.data()), ethe_header->ether_shost);

          auto ip_reply = construct_ip_header(IP_P_ICMP, iface->ip, ip_header->ip_src);

          auto icmp_reply = construct_icmp_t3_header(ICMP_TYPE_PORT_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, (uint8_t *)ip_header);

          ip_reply.ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
          ip_reply.ip_sum = calcIpChecksum(&ip_reply);

          auto packet = construct_icmp_t3_packet(ethe_reply, ip_reply, icmp_reply);

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
