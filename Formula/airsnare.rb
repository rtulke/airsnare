class Airsnare < Formula
  desc "WPA handshake capture with deauthentication and PMKID extraction"
  homepage "https://github.com/rtulke/airsnare"
  url "https://github.com/rtulke/airsnare/archive/refs/tags/v0.9.0.tar.gz"
  sha256 "0c9319a843ff57c32d398332cbaedb44824fa3c1b1839396725049d3eeb55d04"
  license "MIT"
  head "https://github.com/rtulke/airsnare.git", branch: "master"

  uses_from_macos "libpcap"

  def install
    system "make", "release"
    bin.install "src/airsnare"
    doc.install "README.md", "airsnare.conf.example", "CHANGES"
  end

  def caveats
    <<~EOS
      AirSnare requires root to open the wireless interface in monitor mode:
        sudo airsnare -i en0 -c 6 -n

      Channel switching is automatic: networksetup is tried first (Monterey
      and earlier), airport is the fallback (Ventura+). Both require sudo.

      Packet injection (deauthentication) is not supported on built-in Wi-Fi
      adapters on Apple Silicon. Use passive mode (-n) or an external USB
      adapter with monitor-mode driver support.

      A minimal config file is installed at:
        #{doc}/airsnare.conf.example
      Copy it to ~/.airsnarerc and adjust as needed.
    EOS
  end

  test do
    assert_match "AirSnare v#{version}", shell_output("#{bin}/airsnare 2>&1", 1)
  end
end
