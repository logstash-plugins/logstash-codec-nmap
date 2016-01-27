require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/nmap"
require "logstash/event"
require "insist"

describe LogStash::Codecs::Nmap do
  context "#decode" do
    subject do
      events = []
      LogStash::Codecs::Nmap.new.decode(xml_string) do |event|
        events << event
      end
      events
    end

    shared_examples_for "a valid parse" do
      it "should decode without error" do
        expect(subject).to be_a(Array)
      end

      it "should encode at least one thing" do
        expect(subject.length > 0).to eql(true)
      end

      it "should encode the output as LogStash::Event objects" do
        subject.each do |event|
          expect(event).to be_a(LogStash::Event)
        end
      end

      let(:ids) { subject.map {|e| e["id"] } }
      it "should add a unique id field to all events" do
        expect(ids).to eql(ids.uniq)
      end

      it "should not have any null id fields" do
        expect(ids.include?(nil)).to be_falsey
      end
    end

    describe "parsing traceroutes" do
      let(:xml_string) { File.open("spec/fixtures/traceroutes.xml").read }
      it_should_behave_like "a valid parse"
    end

    # This is broken until https://github.com/sophsec/ruby-nmap/pull/40 is accepted
    # describe "parsing ipv6" do
      # let(:xml_string) { File.open("spec/fixtures/ipv6_all.xml").read }

      # it_should_behave_like "a valid parse"
    # end

    describe "parsing pingsweeps" do
      let(:xml_string) { File.open("spec/fixtures/pingsweep.xml").read }
      it_should_behave_like "a valid parse"
    end

    describe "localscan.xml" do
      let(:xml_string) { File.open("spec/fixtures/localscan.xml").read }
      it_should_behave_like "a valid parse"
    end

    describe "scanme_A.xml" do
      let(:xml_string) { File.open("spec/fixtures/scanme_A.xml").read }
      it_should_behave_like "a valid parse"
    end

    describe "full_scan.xml" do
      let(:xml_string) { File.open("spec/fixtures/full_scan.xml").read }
      it_should_behave_like "a valid parse"
    end

    describe "nothingup.xml" do
      let(:xml_string) { File.open("spec/fixtures/nothingup.xml").read }
      it_should_behave_like "a valid parse"
    end

    describe "ip_down.xml" do
      let(:xml_string) { File.open("spec/fixtures/ip_down.xml").read }
      it_should_behave_like "a valid parse"
    end

  end

end
