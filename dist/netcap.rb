class Netcap < Formula
  desc "A framework for secure and scalable network traffic analysis"
  homepage "https://github.com/dreadl0ck/netcap"
  url "https://github.com/dreadl0ck/netcap/releases/download/v0.3.6/netcap_0.3.6_darwin_amd64.tar.gz"
  version "0.3.6"
  sha256 "df23a2d3bf9e94a46760519bfa1ead00e5c09dfc9fea765afe4e27df9e08f7e4"

  def install
    bin.install "netcap"
  end
end
