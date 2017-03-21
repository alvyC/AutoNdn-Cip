#include <iostream>

int main() {
  boost::asio::io_service ioService;

  ndn::Face face(ioService);
  ndn::util::Scheduler scheduler(face.getIoService());
  ndn::Name name("/autondn/cip1");

  autondn_cip::AutoNdnCip cip(face, scheduler, name);
  cip.run();
}