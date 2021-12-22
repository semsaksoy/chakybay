#!/usr/bin/env ruby

require_relative("helper")

report = ""
conf_list = JSON.parse(File.read("list.cnf"))


Parallel.each(conf_list, in_threads: @concurency, progress: {title: "Exporting", length: 68, format: "%t |%B| %a"}) do |c|


  verbose = $VERBOSE
  $VERBOSE = nil
  begin
    path = ""
    prxy = @gsni if c["gsni"] != false

    cf = {:password => Base64.decode64(c["pass"]).strip, :timeout => 60, :proxy => prxy, :paranoid => false}


    Net::SSH.start(c["ip"], c["user"], cf) do |ssh|

      h = Device.new(ssh, c["vdom"])

      p = Axlsx::Package.new
      p.use_shared_strings = true

      p.workbook.add_worksheet(:name => "Rules") do |sheet|


        ls = h.rules

        sheet.add_row ["Order", "Rule", "Action", "Src Int", "Dst Int", "Src Addr", "Dst Addr","Users", "Groups", "Service", "Nat","IPS Profile","SSL Profile", "Comments", "Status", "Pkts/Bytes", "Hit Count"]
        ls.each do |l|
          sheet.add_row l.values
        end
        sheet["A1:Q1"].each { |c| c.b = true; c.sz = 13 }
        sheet.auto_filter = "A1:Q1"
        if ls.count > 0
          sheet["C2:C#{ls.count + 1}"].each { |c| c.b = true; c.color = "8B0000"; (c.color = "008000") if c.value == "accept" }
          sheet["O2:O#{ls.count + 1}"].each_with_index { |c, i| sheet["A#{i + 2}:Q#{i + 2}"].each { |z| z.color = "808080" } if c.value == "disable" }
        end

      end
      p.workbook.add_worksheet(:name => "Nat") do |sheet|
        ls = h.nats
        sheet.add_row ["Order", "Name", "Original IP", "Tranlated IP", "Original Port", "Translated Port"]
        ls.each do |l|
          sheet.add_row l.values
        end
        sheet["A1:F1"].each { |c| c.b = true; c.sz = 13 }
        sheet.auto_filter = "A1:F1"
      end

      p.workbook.add_worksheet(:name => "User Group") do |sheet|
        ls = h.user_groups
        sheet.add_row ["Order", "Name", "Member", "Group"]
        ls.each do |l|
          sheet.add_row l.values
        end
        sheet["A1:D1"].each { |c| c.b = true; c.sz = 13 }
        sheet.auto_filter = "A1:D1"
      end

      p.workbook.add_worksheet(:name => "User") do |sheet|
        ls = h.users
        sheet.add_row ["Order", "Name", "Type", "Status"]
        ls.each do |l|
          sheet.add_row l.values
        end
        sheet["A1:D1"].each { |c| c.b = true; c.sz = 13 }
        sheet.auto_filter = "A1:D1"
        if ls.count > 0
          sheet["D2:D#{ls.count + 1}"].each_with_index { |c, i| sheet["A#{i + 2}:D#{i + 2}"].each { |z| z.color = "808080" } if c.value == "disable" }
        end
      end


      p.workbook.add_worksheet(:name => "Address Group") do |sheet|
        ls = h.addressgroup
        sheet.add_row ["Order", "Name", "Member"]
        ls.each do |l|
          sheet.add_row l.values
        end
        sheet["A1:C1"].each { |c| c.b = true; c.sz = 13 }
        sheet.auto_filter = "A1:C1"
      end

      p.workbook.add_worksheet(:name => "Service Group") do |sheet|
        ls = h.servicegroup
        sheet.add_row ["Order", "Name", "Member"]
        ls.each do |l|
          sheet.add_row l.values
        end
        sheet["A1:C1"].each { |c| c.b = true; c.sz = 13 }
        sheet.auto_filter = "A1:C1"
      end

      if c["dir"].nil?
        Dir.mkdir "Export" unless File.exists?("Export")
        path = "Export/#{c["client"]}_#{c["vdom"]}.xlsx"

      else
        path = "#{c["dir"]}/#{c["client"]}_#{c["vdom"]}.xlsx"


      end

      IO.binwrite(path, p.to_stream.read)
      ssh.close

    end

    report += "#{c["client"]}\t#{path}\n"

    if c["receiver"]


      mail = MailFactory.new()

      mail.to = c["receiver"].strip
      mail.from = @mail_from
      mail.subject = "#{c["client"]}_#{c["vdom"]}"

      mail.html = "<a target='_blank' href='cid:#{c["client"]}_#{c["vdom"]}.xlsx'>Report</a>"
      mail.attach(path, nil, "Content-ID: <#{c["client"]}_#{c["vdom"]}.xlsx>")


      begin
        Net::SMTP.start(@mail_server, @mail_port, "mail.example.org", nil, nil, :plain) do |smtp|
          smtp.send_message mail.to_s, @mail_from, c["receiver"].strip
        end
      rescue Exception => e
        print "Exception occured: #{e.message}"
      end



    end
  rescue Exception => ex
    #4.times { pb.increment }
    print "#{ex.message} #{ex.backtrace}"
    report += "#{c["client"]}\t#{ex.message}\n"
  end
  $VERBOSE = verbose

end
print report

File.write("report.txt", report)
