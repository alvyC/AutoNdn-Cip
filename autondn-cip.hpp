#ifndef AUTO_NDN_HPP
#define AUTO_NDN_HPP

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-info.hpp>

namespace autondn_cip {

class AutoNdnCip {

public:
  AutoNdnCip(ndn::Face&, ndn::util::Scheduler&, ndn::Name&);

  void
  run();

private:
  void
  initialize();

  void
  initializeKey();

  void
  setInterestFilter(); // set interest filter for general and key

  void
  onKeyRequestInitInterest(const ndn::Name&, const ndn::Interest& interest);

  void
  onKeyInterest(const ndn::Name& name, const ndn::Interest& interest);

  void
  onCertInterest(const ndn::Name& name, const ndn::Interest& interest);
public:
  static const ndn::Name KeyRequestInitPrefix;
private:
  ndn::Face& m_face;
  ndn::Scheduler& m_scheduler;
  ndn::Name& m_name;
  ndn::security::SigningInfo m_signingInfo;
};

}

#endif // AUTO_NDN_HPP