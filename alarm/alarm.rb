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
			#{incident_number}. ALERT: #{incident} is detected from #{source IP address} (#{protocol}) (#{payload})!
		end
	end			
end

def read_log (file)
	line_num=0
	text = File.open(file).read
	#text.gsub!(/\r\n?/, "\n")
	text.each_line do |line|
		if line =~ /Nmap(.*)/
			match = line.match(/^(.*?)(?=-)/)
			ip = match.to_s
			puts "ALERT: Nmap scan is detected from " + ip
		end
	end
#{incident_number}. ALERT: #{incident} is detected from #{source IP address} (#{protocol}) (#{payload})!
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
	end







