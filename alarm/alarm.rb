require 'packetfu'
require 'optparse'


def read_live
	stream = PacketFu::Capture.new(:start => true, :iface => 'en0', :promisc => true)
	#stream.show_live()
	stream.stream.each do |raw|
		pkt = PacketFu::Packet.parse(raw)
		if pkt.is_tcp?
			#get the source IP address of the scan
			sIP = pkt.ip_saddr

			#get all protocols used in packet
			protocol = pkt.proto

			#get last protocol used
			p = protocol.last
			
			#NULL scan
			if pkt.tcp_flags.urg == 0 and pkt.tcp_flags.ack == 0 and pkt.tcp_flags.psh == 0 and
				pkt.tcp_flags.rst == 0 and pkt.tcp_flags.syn == 0 and pkt.tcp_flags.fin == 0
				puts "ALERT: NULL scan is detected from " + sIP + " (" + p + ") " + "(" + pkt.payload + ")!"
			end
			
			#FIN scan
			if pkt.tcp_flags.urg == 0 and pkt.tcp_flags.ack == 0 and pkt.tcp_flags.psh == 0 and
				pkt.tcp_flags.rst == 0 and pkt.tcp_flags.syn == 0 and pkt.tcp_flags.fin == 1
				puts "ALERT: FIN scan is detected from " + sIP + " (" + p + ") " + "(" + pkt.payload + ")!"
			end
			
			#Xmas scan
			if pkt.tcp_flags.urg == 1 and pkt.tcp_flags.ack == 0 and pkt.tcp_flags.psh == 1 and
				pkt.tcp_flags.rst == 0 and pkt.tcp_flags.syn == 0 and pkt.tcp_flags.fin == 1
				puts "ALERT: XMAS scan is detected from " + sIP + " (" + p + ") " + "(" + pkt.payload + ")!"
			end				

			#Other Nmap scans
			if pkt.payload.scan(/\x4E\x6D\x61\x70/)
				puts "ALERT: Nmap scan is detected from " + sIP + " (" + p + ") " + "(" + "(" + pkt.payload + ")!"
			end
			
			#Nikto scan 
			if pkt.payload.scan(/\x4E\x69\x6B\x74\x6F\x0A/)
				puts "ALERT: Nikto scan is detected from " + sIP + " (" + p + ") " + "(" + pkt.payload + ")!"
			end

			#Credit card leak 
			
		end
	end			
end

def read_log (file)
	puts "read in file"

end


options = {:read => nil}
OptionParser.new do |opts|
  opts.banner = "Usage: alarm.rb [options]"

  opts.on("-r", "--read [FILEPATH] ", "Read access log") do |r|
    options[:read] = r
  end
end.parse!

if options[:read] == nil
	read_live
	elsif
		read_log options[:read]
	else
		puts "Unknown flag"
	end


#puts "Dest IP => " + pkt.ip_daddr
	#If an incident is detected, alert must be displayed in the format:
	#{incident_number}. ALERT: #{incident} is detected from #{source IP address} (#{protocol}) (#{payload})!
#Examples:
#ALERT: NULL scan is detected from 192.168.1.3 (UDP) (binary data)!
#ALERT: Credit card leaked in the clear from 192.168.1.7 (HTTP) (binary data)!
#Alert message can be displayed multiple times for a source IP address (e.g., from an XMAS scan).







