#!/usr/bin/env ruby

require 'flickraw'

FlickRaw.api_key=""
FlickRaw.shared_secret=""

token = flickr.get_request_token
auth_url = flickr.get_authorize_url(token['oauth_token'], :perms => 'delete')

puts "Open this url in your process to complete the authication process : #{auth_url}"
puts "Copy here the number given when you complete the process."
verify = gets.strip

begin
  flickr.get_access_token(token['oauth_token'], token['oauth_token_secret'], verify)
  login = flickr.test.login
  puts "You are now authenticated as #{login.username} with token #{flickr.access_token} and secret #{flickr.access_secret}"
rescue FlickRaw::FailedResponse => e
  puts "Authentication failed : #{e.msg}"
end


PHOTO_PATH='photo.jpg'

# You need to be authentified to do that, see the previous examples.
flickr.upload_photo PHOTO_PATH, :title => "Title", :description => "This is the description"