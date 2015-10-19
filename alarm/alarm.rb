require 'packetfu'
require 'optparse'


#Read live: scans a live stream of packets && looks for malicious scans
def read_live
	#incident number counter
	i = 0
	stream = PacketFu::Capture.new(:start => true, :iface => 'en0', :promisc => true)
	#stream.show_live()
	stream.stream.each do |raw|
		pkt = PacketFu::Packet.parse(raw)
		if pkt.is_tcp?
			#update incident number
			i= i + 1

			#get the source IP address of the scan
			sIP = pkt.ip_saddr

			#get all protocols used in packet
			protocol = pkt.proto

			#get last protocol used
			p = protocol.last
			
			#NULL scan
			if pkt.tcp_flags.urg == 0 && pkt.tcp_flags.ack == 0 && pkt.tcp_flags.psh == 0 &&
				pkt.tcp_flags.rst == 0 && pkt.tcp_flags.syn == 0 && pkt.tcp_flags.fin == 0
				puts i.to_s + ". ALERT: NULL scan is detected from " + sIP + " (" + p + ") " + "(" + pkt.payload + ")!"
			end
			
			#FIN scan
			if pkt.tcp_flags.urg == 0 && pkt.tcp_flags.ack == 0 && pkt.tcp_flags.psh == 0 &&
				pkt.tcp_flags.rst == 0 && pkt.tcp_flags.syn == 0 && pkt.tcp_flags.fin == 1
				puts i.to_s + ". ALERT: FIN scan is detected from " + sIP + " (" + p + ") " + "(" + pkt.payload + ")!"
			end
			
			#Xmas scan
			if pkt.tcp_flags.urg == 1 && pkt.tcp_flags.ack == 0 && pkt.tcp_flags.psh == 1 &&
				pkt.tcp_flags.rst == 0 && pkt.tcp_flags.syn == 0 && pkt.tcp_flags.fin == 1
				puts i.to_s + ". ALERT: XMAS scan is detected from " + sIP + " (" + p + ") " + "(" + pkt.payload + ")!"
			end				

			#Other Nmap scans
			if pkt.payload.scan(/\x4E\x6D\x61\x70/)
				puts i.to_s + ". ALERT: Nmap scan is detected from " + sIP + " (" + p + ") " + "(" + "(" + pkt.payload + ")!"
			end
			
			#Nikto scan 
			if pkt.payload.scan(/\x4E\x69\x6B\x74\x6F\x0A/)
				puts i.to_s + ". ALERT: Nikto scan is detected from " + sIP + " (" + p + ") " + "(" + pkt.payload + ")!"
			end

			#Credit card leak 
			if pkt.payload.scan(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) || pkt.payload.scan(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) || pkt.payload.scan(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) || pkt.payload.scan(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/)
				puts i.to_s + ". ALERT: Credit card leaked in the clear from " + sIP + " (" + p + ") " + "(" + pkt.payload + ")!"
			end
		end
	end			
end

#Read log: takes a log input file && reports any incidents 
def read_log (file)
	#incident number counter
	i = 0

	text = File.open(file).read
	#text.gsub!(/\r\n?/, "\n")
	text.each_line do |line|
		#grab the ip address from the line
			ipmatch = line.match(/^(.*?)(?=-)/)
			ip = ipmatch.to_s

		#find protocol
			proto = ""
			protomatch = line.match(/HTTP/)
			proto = protomatch.to_s

		#NMAP scan (2)
		if /Nmap*/.match(line)
			i = i + 1
			puts i.to_s + ". ALERT: Nmap scan is detected from " + ip + "(" + proto + ") " + "(" + line + ")!"
		end
		
		#Nikto scan (0)
		if /Nikto*/.match(line)
			i = i + 1
			puts i.to_s + ". ALERT: Nikto scan is detected from " + ip + "(" + proto + ") " + "(" + line + ")!"
		end

		#Rob Graham's Masscan (19)
		if line =~ /masscan*/
			i = i + 1
			puts i.to_s + ". ALERT: Someone is looking for masscan, scan is detected from " + ip + "(" + proto + ") " + "(" + line + ")!"
		end

		#Shellshock vulnerability
		if line =~ /{ :;};echo/
			i = i + 1
			puts i.to_s + ". ALERT: Someone is looking for Shellshock vulnerability, scan is detected from " + ip + "(" + proto + ") " + "(" + line + ")!"
		end

		#phpMyAdmin
		if line =~ /phpMyAdmin*/
			i = i + 1
			puts i.to_s + ". ALERT: Someone is looking for phpMyAdmin, scan is detected from " + ip + "(" + proto + ") " + "(" + line + ")!"
		end

		#other shellcode
		if /xeb*/.match(line) || /xEB.*/.match(line) || /x16.*/.match(line) || /%2D%*/.match(line) || /perl*/.match(line)
			i = i + 1
			puts i.to_s + ". ALERT: Someone is trying to run shellcode, scan is detected from " + ip + "(" + proto + ") " + "(" + line + ")!"
		end
	end
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







