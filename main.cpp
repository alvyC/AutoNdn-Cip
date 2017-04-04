// g++ -o ndn-cxx_test -std=c++0x ndn-cxx_test.cpp $(pkg-config --cflags --libs libndn-cxx)

#include <boost/cstdint.hpp>

#include "autondn-cip.hpp"

int main() {
  boost::asio::io_service ioService;

  ndn::Face face(ioService);
  ndn::util::Scheduler scheduler(face.getIoService());
  ndn::Name name("/autondn/CIP/1");

  autondn_cip::AutoNdnCip cip(face, scheduler, name);
  cip.run();
}