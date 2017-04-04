#include "autondn-cip.hpp"

namespace autondn_cip {

  const ndn::Name AutoNdnCip::KeyRequestInitPrefix = ndn::Name("/autondn/CIP/request-key");

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
  AutoNdnCip::setInterestFilter() {
    // set interest filter for key-request initiation: /autondn/CIP/request-key
    m_face.setInterestFilter(KeyRequestInitPrefix,
                             std::bind(&AutoNdnCip::onKeyRequestInitInterest,
                                       this, _1, _2),
                             std::bind([] {}),
                             std::bind([] {}),
                             m_signingInfo);

    // set interest filter for interest for CIP's key: /autondn/CIP/<cip-id>/KEYS
    ndn::Name keyPrefix = m_name;
    keyPrefix.append("KEYS");
    m_face.setInterestFilter(keyPrefix,
                             std::bind(&AutoNdnCip::onKeyInterest,
                                       this, _1, _2),
                             std::bind([] {}),
                             std::bind([] {}),
                             m_signingInfo);

    //  set interest filter on proxy's name (/autondn/CIP/<cip-id>)
    // The interest name: /autondn/CIP/<cip-id>/E-CIP{manufacturer, E-Man{vid, K-VCurr, K-VNew}}
    m_face.setInterestFilter(m_name,
                             std::bind(&AutoNdnCip::onCertInterest,
                                       this, _1, _2),
                             std::bind([] {}),
                             std::bind([] {}));
  }

  void
  AutoNdnCip::onKeyRequestInitInterest(const ndn::Name&, const ndn::Interest& interest) {
    // send name and public key of the cip
  }

  void
  AutoNdnCip::onKeyInterest(const ndn::Name& name, const ndn::Interest& interest) {
    // send public key of the cip
  }

  void
  AutoNdnCip::onCertInterest(const ndn::Name& name, const ndn::Interest& interest) {
    // change the name of the interest and send it to manufacturer.
  }

  void
  AutoNdnCip::initialize() {
    initializeKey();
    setInterestFilter();
  }

  void
  AutoNdnCip::run() {
    initialize();
  }
}