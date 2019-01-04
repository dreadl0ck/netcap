class Netcap < Formula
  desc "A framework for secure and scalable network traffic analysis"
  homepage "https://github.com/dreadl0ck/netcap"
  url "https://github.com/dreadl0ck/netcap/releases/download/v0.3.7/netcap_0.3.7_darwin_amd64.tar.gz"
  version "0.3.7"
  sha256 "84b603758288ec886c57e4eddbc2d084255601d858bbdaade80489aca5abb57d"

  def install
    bin.install "netcap"
  end
end
