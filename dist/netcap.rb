class Netcap < Formula
  desc "A framework for secure and scalable network traffic analysis"
  homepage "https://github.com/dreadl0ck/netcap"
  url "https://github.com/dreadl0ck/netcap/releases/download/v0.3.8/netcap_0.3.8_darwin_amd64.tar.gz"
  version "0.3.8"
  sha256 "075ad68b81b48dc8331096e6f31ffcab251ce733d1a090387d0540fb129d862a"

  def install
    bin.install "netcap"
  end
end
