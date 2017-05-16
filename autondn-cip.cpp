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
    // The interest name: /autondn/CIP/<cip-id>/E-CIP{manufacturer}/ E-Man{vid}/ E-man{K-VCurr}/ E-man{K-VNew}
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
  AutoNdnCip::onVehicleCertInterest(const ndn::Name& name, const ndn::Interest& originalInterest) {
     /*  Interest:  /autondn/CIP/<cip-id>/E-CIP{manufacturer}/ E-Man{vid}/ E-man{K-VCurr}/ E-man{K-VNew}
         (1) Decrypt the "manufacturer" part (need to get proxy's private key)
         (2) Construct a new signed interest
             New Interest: /<manufacturer>/ E-Man{vid, K-VCurr, K-VNew}
         (3) Send the new interest to manufacturer
     */

    /* Step (1)
       - Get cipher text of manufacturer name from the interest name
       - Decrypt using private key of the proxy
    */
    std::string manufacturernameCipher = originalInterest.getName().get(-4).toUri();
    ndn::Name proxyKeyName = m_keyChain.getDefaultKeyNameForIdentity(m_name);

    std::vector<uint8_t> myVector(manufacturernameCipher.begin(), manufacturernameCipher.end());
    uint8_t *p1 = &myVector[0];
    ndn::ConstBufferPtr manufacturerNamePlainText = m_keyChain.getTpm().decryptInTpm(p1, myVector.size(), proxyKeyName, false);


    /* Step (2)
     */
    std::string manufacturerNameString( reinterpret_cast<char const*>(manufacturerNamePlainText->buf()), manufacturerNamePlainText->size() );
    ndn::Name interestToManName(manufacturerNameString);

    for (unsigned int i = 4; i < originalInterest.getName().size(); ++i) {
      interestToManName.append(originalInterest.getName().get(i));
    }

    /* Step (3)
      - Create interest
      - Sign the interest
      - Send the interest
     */
    ndn::Interest interestToMan(interestToManName);
    m_keyChain.sign(interestToMan);
    m_face.expressInterest(interestToMan,
                           std::bind(&AutoNdnCip::onReceivingVehicleCert, this, _1, _2, originalInterest), // got vehicle's cert, need to forward it to the vehicle
                           std::bind([]{})); // timeout
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

  void
  AutoNdnCip::onReceivingVehicleCert(const ndn::Interest& sentInterest, const ndn::Data& data,
                                     const ndn::Interest& originalInterest) {
    /* (1) Create a new data packet from the received data packet.
       (2) Sign the data and send it
     */
    std::shared_ptr<ndn::Data> newData = ndn::make_shared<ndn::Data>(data);
    newData->setName(originalInterest.getName());

    m_keyChain.sign(*newData);
    m_face.put(*newData);
  }
}