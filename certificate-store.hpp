#ifndef AUTONDN_CERTIFICATE_STORE_HPP
#define AUTONDN_CERTIFICATE_STORE_HPP

#include <ndn-cxx/security/identity-certificate.hpp>

#include <map>

namespace autondn_cip {

class CertificateStore
{
public:
 void
 saveCertificate(std::shared_ptr<ndn::IdentityCertificate> certificate) {
  m_cert = certificate;
 }

 std::shared_ptr<const ndn::IdentityCertificate>
 getCertificate() const {
  return m_cert;
 }

private:
 std::shared_ptr<ndn::IdentityCertificate> m_cert;
};
} // end of namespace autondn

#endif // AUTONDN_CERTIFICATE_STORE_HPP