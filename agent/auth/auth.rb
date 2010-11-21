require 'socket'

module MCollective
  module Agent
    class Auth<RPC::Agent
      metadata    :name        => "SimpleRPC Scan Auth.log Agent",
                  :description => "An agent that scans auth.log for failed attempts",
                  :author      => "Anton Lindstrom",
                  :license     => "GPLv2",
                  :version     => "0.1",
                  :url         => "http://github.com/antonlindstrom/",
                  :timeout     => 10

      action "internal" do
        internal(scan)
      end

      action "external" do
        external(scan)
      end

      action "threshold" do
        validate :tvalue, Integer

        threshold(scan, request[:tvalue])
      end
    
      private
      def scan

        logger.debug("Starting to scan auth.log")
        # hash of found ips used to store the ips found in the 
        # auth.log
        ipFound = Hash.new(0)

        # 1. read in the auth.log
        authLog = File.open('/var/log/auth.log','r')

        authLog.each_line do |line|
          # 2. check for the ip addresses that are scanning
          if line =~ /Failed password for invalid user/
            if line =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/
              @ipaddress = $1
              #add it to the list
              ipFound[@ipaddress] += 1
            end
          end
        end

        authLog.close

        ipFound
      end

      def internal(scanned)
        logger.debug("Listing internal failed login attempts")
        array_out = Array.new

        scanned.each_pair do |ip,count|
          if rfc1918?(ip)
            array_out << "#{ip}:#{count}"
          end
        end
        reply[:output] = array_out.join("-")
       end

      def external(scanned)
        logger.debug("Listing external failed login attempts")
        array_out = Array.new

        scanned.each_pair do |ip,count|
          #unless rfc1918?(ip)
            array_out << "#{ip}:#{count}"
          #end
        end
        reply[:output] = array_out.join("-")
      end

      def threshold(scanned, threshold)
        logger.debug("Listing failed login attempts with threshold over #{threshold}")
        array_out = Array.new

        scanned.each_pair do |ip,count|
          if count < threshold
            array_out << "#{ip}:#{count}"
          end
        end
        reply[:output] = array_out.join("-")
      end

      def rfc1918?(ip)
        rfc1918 = /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.1[6-9]\.\d{1,3}\.\d{1,3}/
        ip =~ rfc1918
      end

    end
  end
end
