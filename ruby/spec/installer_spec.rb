# frozen_string_literal: true

require "spec_helper"

RSpec.describe Soteria::Installer do
  subject(:installer) { described_class.new }

  describe "MODES" do
    it "defines three security modes" do
      expect(Soteria::Installer::MODES.keys).to contain_exactly("personal", "professional", "fortress")
    end

    # Each mode has a name, description, and features.
    it "each mode has required fields" do
      Soteria::Installer::MODES.each do |_key, mode|
        expect(mode).to have_key(:name)
        expect(mode).to have_key(:desc)
        expect(mode).to have_key(:rotation)
        expect(mode).to have_key(:features)
      end
    end
  end

  describe "#print_banner" do
    it "prints without error" do
      expect { installer.print_banner }.to output(/Soteria/).to_stdout
    end
  end
end
