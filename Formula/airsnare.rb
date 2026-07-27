class Airsnare < Formula
  desc "WPA handshake capture with deauthentication and PMKID extraction"
  homepage "https://github.com/rtulke/airsnare"
  url "https://github.com/rtulke/airsnare/archive/refs/tags/v0.10.0.tar.gz"
  sha256 "9dd4b26a6f9bd6f961628aacd79beb0b0051ff4c1eb338022f6f134a37279868"
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

      Channel switching is automatic via the native CoreWLAN framework
      (-setWLANChannel:); no external helpers are needed. Requires sudo.

      Packet injection (deauthentication) is not supported on built-in Wi-Fi
      adapters on Apple Silicon. Use passive mode (-n) or an external USB
      adapter with monitor-mode driver support.

      A minimal config file is installed at:
        #{doc}/airsnare.conf.example
      Copy it to ~/.airsnarerc and adjust as needed.

      To convert captures for hashcat cracking:
        brew install hcxtools
        hcxpcapngtool -o hashes.hc22000 out.pcap
        hashcat -m 22000 hashes.hc22000 wordlist.txt
    EOS
  end

  test do
    assert_match "AirSnare v#{version}", shell_output("#{bin}/airsnare 2>&1", 1)
  end
end
