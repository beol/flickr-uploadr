#!/usr/bin/env ruby

require 'flickraw'
require 'yaml'
require 'exifr'
require 'time'
require 'digest'

def login
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

  File.write(File.expand_path("../config/secret.yml", __FILE__), { "access_token" => flickr.access_token, "access_secret" => flickr.access_secret }.to_yaml)
end

def logged_in?
  begin
    secret_file = File.expand_path('../config/secret.yml', __FILE__)
    secret_hash = File.exists?(secret_file) ? YAML.load_file(secret_file) : {}

    if secret_hash.has_key?('access_token') && secret_hash.has_key?('access_secret')
      flickr.access_token = secret_hash['access_token']
      flickr.access_secret = secret_hash['access_secret']

      # From here you are logged:
      login = flickr.test.login
      puts "You are now authenticated as #{login.username}"

      true
    else
      false
    end

  rescue FlickRaw::FailedResponse => e
    puts "Authentication failed : #{e.msg}"
    false
  end
end

def not_logged_in?
  !logged_in?
end

unless ARGV.length == 1
  exit 1
end

if File.directory?(ARGV.first)
  path = ARGV.shift
else
  exit 1
end

FlickRaw.api_key="9f349da7346078183faa00bb3d8dd9e2"
FlickRaw.shared_secret="b71ee65a3a09547e"

if not_logged_in?
  login
end

cache_file = File.expand_path("../cache/uploaded_pictures.yml", __FILE__)

if File.exists?(cache_file)
  uploaded_pictures = YAML.load_file(cache_file) || {}
else
  uploaded_pictures = {}
end

flickr.people.getPhotos(:user_id => 'me', :extras => 'date_taken', :per_page => '500').each do |response|
  unless uploaded_pictures.has_key?(response.id)
    uploaded_pictures[response.id] = { "title" => response.title, "date_taken" => response.datetaken }
  end
end

File.open(cache_file, 'w') do |file|
  file.write uploaded_pictures.to_yaml
end

begin
  files = {}

  Dir.glob("#{path}/**/*.{jpg,JPG}").sort.each do |file|
    digest = Digest::SHA1.file(file).hexdigest

    unless files.has_key?(digest)
      files[digest] = file
    end
  end

  files.each_value do |file|
    title = File.basename(file, ".JPG")

    unless uploaded_pictures.has_value?(
        {
            'title' => title,
            'date_taken' => EXIFR::JPEG.new(file).date_time_original.strftime("%Y-%m-%d %H:%M:%S")
        }
    )
      flickr.upload_photo file
      puts "#{File.basename(file)} uploaded"
    end
  end

rescue JSON::ParserError => e
  puts "Upload timed out"
end