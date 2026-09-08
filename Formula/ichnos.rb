class Ichnos < Formula
  desc "Modular, low-level command-line security and CTF analysis toolkit"
  homepage "https://github.com/mohith-krishna-mahesh/ichnos"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mohith-krishna-mahesh/ichnos/releases/download/v0.1.0/ichnos-macos-arm64"
      sha256 "REPLACE_WITH_MACOS_ARM64_SHA256"
    else
      url "https://github.com/mohith-krishna-mahesh/ichnos/releases/download/v0.1.0/ichnos-macos-x86_64"
      sha256 "REPLACE_WITH_MACOS_X86_64_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/mohith-krishna-mahesh/ichnos/releases/download/v0.1.0/ichnos-linux-arm64"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    else
      url "https://github.com/mohith-krishna-mahesh/ichnos/releases/download/v0.1.0/ichnos-linux-x86_64"
      sha256 "REPLACE_WITH_LINUX_X86_64_SHA256"
    end
  end

  def install
    binary_name = "ichnos-#{OS.kernel_name.downcase}-#{Hardware::CPU.arch}"
    bin.install binary_name => "ichnos" if File.exist?(binary_name)
    bin.install Dir["ichnos*"].first => "ichnos" unless File.exist?("#{bin}/ichnos")
  end

  test do
    output = shell_output("#{bin}/ichnos --version")
    assert_match "ichnos 0.1.0", output
  end
end
