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
  setKeyInterestFilter();

  void
  onKeyInterest(const ndn::Name& name, const ndn::Interest& interest);

  void
  setCertIssueInterestFilter();

private:
  ndn::Face& m_face;
  ndn::Name& m_name;
  ndn::security::SigningInfo m_signingInfo;
};

}

#endif // AUTO_NDN_HPP