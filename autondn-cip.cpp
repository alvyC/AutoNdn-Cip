#include "autondn-cip.hpp"

namespace autondn_cip {
  AutoNdnCip::AutoNdnCip(ndn::Face& face, ndn::util::Scheduler& scheduler, ndn::Name& name)
    : m_face(face)
    , m_scheduler(scheduler)
    , m_name(name)
    {
    }

  void
  AutoNdnCip::initializeKey() {

  }

  void
  AutoNdnCip::setKeyInterestFilter() {
    ndn::Name keyPrefix = m_name;
    m_face.setInterestFilter(keyPrefix,
                             std::bind(&AutoNdnCip::onKeyInterest,
                                       this, _1, _2),
                             std::bind(&AutoNdnCip::onKeyPrefixRegSuccess,
                                       this, _1, _2),
                             std::bind(&AutoNdn::onRegistrationFailed, this, _1),
                             m_signingInfo);
  }

  void
  AutoNdnCip::onKeyInterest(const ndn::Name& name, const ndn::Interest& interest) {

  }

  void
  AutoNdnCip::initialize() {
    initializeKey();
    setKeyInterestFilter();
    setCertIssueInterestFilter();
  }

  void
  AutoNdnCip::run() {
    initialize();
  }
}