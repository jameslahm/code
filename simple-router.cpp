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

namespace simple_router {

bool checkIfMatchMac(uint8_t addr[6],Buffer mac_addr){
  for(int i=0;i<6;i++){
    if(addr[i]!=mac_addr.at(i)){
      return false;
    }
  }
  return true;
}

// check if broadcase addr
bool checkIfBroadcast(uint8_t addr[6]){
  uint8_t broadcase_addr[6]={0xff,0xff,0xff,0xff,0xff,0xff};
  for(int i=0;i<6;i++){
    if(addr[i]!=broadcase_addr[i]){
      return false;
    }
  }
  return true;
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  // DEBUG INFO
  print_hdrs(packet);

  ethernet_hdr* eth_header=(ethernet_hdr*)packet.data();

  // check if broadcase or mathc mac address
  if(!checkIfBroadcast(eth_header->ether_dhost) && checkIfMatchMac(eth_header->ether_dhost,iface->addr)){
    std::cerr<<"Received packet,ignore because of not match broadcase or mac address";
  }

  // handle arp packet
  if(eth_header->ether_type==ethertype_arp){
    arp_hdr *arp_header=(arp_hdr*)(eth_header+sizeof(ethernet_hdr));

    // check if request
    if(arp_header->arp_op==arp_op_request){
      // check if target here
      if(arp_header->arp_tip==iface->ip){
        // send arp reply packet
        arp_hdr arp_reply;
        arp_reply.arp_hrd=arp_hrd_ethernet;
        arp_reply.arp_pro=ethertype_ip;
        arp_reply.arp_op=arp_op_reply;
        arp_reply.arp_hln=0x06;
        arp_reply.arp_pln=0x04;
        std::copy(iface->addr.begin(),iface->addr.end(),arp_reply.arp_hrd);
        arp_reply.arp_sip=iface->ip;
        std::copy(arp_header->arp_sha,arp_header->arp_sha+6,arp_reply.arp_tha);
        arp_reply.arp_tip=arp_header->arp_sip;

        ethernet_hdr ethe_reply;
        ethe_reply.ether_type=ethertype_arp;
        std::copy(iface->addr.begin(),iface->addr.end(),ethe_reply.ether_shost);
        std::copy(arp_header->arp_sha,arp_header->arp_sha+6,ethe_reply.ether_dhost);

        Buffer reply;
        reply.insert(reply.end(),(unsigned char*)&ethe_reply,(unsigned char*)&ethe_reply+sizeof(ethe_reply));
        reply.insert(reply.end(),(unsigned char*)&arp_reply,(unsigned char*)&arp_reply+sizeof(arp_reply));

        sendPacket(reply,iface->name);
      }
    }

    if(arp_header->arp_op==arp_op_reply){
      Buffer sha(arp_header->arp_sha,arp_header->arp_sha+6);
      auto request = m_arp.insertArpEntry(sha,arp_header->arp_sip);
      if(request!=nullptr){
        for(auto iter=request->packets.begin();iter!=request->packets.end();iter++){
          sendPacket(iter->packet,iter->iface);
        }
        m_arp.removeRequest(request);
      }

    }
  }

  // handle ip packet
  if(eth_header->ether_type==ethertype_ip){
    ip_hdr *ip_header= (ip_hdr*)(eth_header+sizeof(ethernet_hdr));
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
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
