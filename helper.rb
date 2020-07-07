require 'bundler/inline'
gemfile do
  source 'https://rubygems.org'
  gem "parallel"
  gem "net-ssh"
  gem "axlsx"
  gem "mail"
  gem "ruby-progressbar"
end

require "net/ssh"
require 'net/ssh/proxy/errors'
require 'net/ssh/proxy/socks5'
require "axlsx"
require "json"
require "date"
require "ruby-progressbar"
require "mailfactory"
require "parallel"


##config
@concurency=8
@mail_server="localhost"
@mail_port=25
@mail_from="fortireport@domain.com"
@gsni = Net::SSH::Proxy::SOCKS5.new('158.98.136.75',1080, :user => 'TRZZ', :password => '')
##config

Mail.defaults do
  delivery_method :smtp, address: @mail_server, port: @mail_port
end

require_relative("device")

system("clear")
print "Chakybay 2.0\nlinkedin.com/in/semsaksoy\n"
print "\n\n"


def grep(str, regex)
  get=str.match(regex)[1].strip.gsub("\"", "") if str.match(regex)
end

