#include "autondn-cip.hpp"

#include <ndn-cxx/util/io.hpp>

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
    ndn::Name defaultIdentity = m_name;
    m_signingInfo = ndn::security::SigningInfo(ndn::security::SigningInfo::SIGNER_TYPE_ID, defaultIdentity);
    m_keyChain.addIdentity(defaultIdentity);
  }

  void
  AutoNdnCip::setInterestFilter() {
    // set interest filter for key-request initiation: /autondn/CIP/request-key
    m_face.setInterestFilter(KeyRequestInitPrefix,
                             std::bind(&AutoNdnCip::onKeyRequestInitInterest,
                                       this, _1, _2),
                             std::bind([] {}),
                             std::bind([] {}));

    // set interest filter for interest for CIP's key: /autondn/CIP/<cip-id>/KEYS
    ndn::Name keyPrefix = m_name;
    keyPrefix.append("KEYS");
    m_face.setInterestFilter(keyPrefix,
                             std::bind(&AutoNdnCip::onKeyInterest,
                                       this, _1, _2),
                             std::bind([] {}),
                             std::bind([] {}));

    //  set interest filter on proxy's name (/autondn/CIP/<cip-id>)
    // The interest name: /autondn/CIP/<cip-id>/E-CIP{manufacturer, E-Man{vid, K-VCurr, K-VNew}}
    m_face.setInterestFilter(m_name,
                             std::bind(&AutoNdnCip::onVehicleCertInterest,
                                       this, _1, _2),
                             std::bind([] {}),
                             std::bind([] {}));
  }

  void
  AutoNdnCip::onKeyRequestInitInterest(const ndn::Name& name, const ndn::Interest& interest) {
    // send name and public key of the cip
    std::shared_ptr<const ndn::IdentityCertificate> cert = m_certStore.getCertificate();
    std::shared_ptr<ndn::Data> data = std::make_shared<ndn::Data>();

    ndn::Name dataName = interest.getName();
    dataName.append(m_name);

    data->setName(dataName);
    data->setContent(cert->wireEncode());

    m_face.put(*data);
  }

  void
  AutoNdnCip::onKeyInterest(const ndn::Name& name, const ndn::Interest& interest) {
    // send public key of the cip

  }

  void
  AutoNdnCip::onVehicleCertInterest(const ndn::Name& name, const ndn::Interest& interest) {
     /*  Interest: /autondn/CIP/<cip-id>/E-CIP{manufacturer, E-Man{vid, K-VCurr, K-VNew}}
         (1) Decrypt the "manufacturer" part
         (2) Construct a new signed interest
             New Interest: /<manufacturer>/ E-Man{vid, K-VCurr, K-VNew}
         (3) Send the new interest to manufacturer
     */
  }

  void
  AutoNdnCip::loadCertToPublish() {
    std::shared_ptr<ndn::IdentityCertificate> idCert = ndn::io::load<ndn::IdentityCertificate>("proxy.cert");
    m_certStore.saveCertificate(idCert);
  }

  void
  AutoNdnCip::initialize() {
    initializeKey();
    setInterestFilter();
    loadCertToPublish();
  }

  void
  AutoNdnCip::run() {
    initialize();
  }
}