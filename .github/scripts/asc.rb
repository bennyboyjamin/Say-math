# Creates (and later removes) the App Store signing files through the
# App Store Connect API, so no Mac or registered device is needed.
#   ruby asc.rb setup    -> distribution certificate + App Store profile
#   ruby asc.rb cleanup  -> revokes the certificate and deletes the profile
require 'openssl'; require 'json'; require 'base64'; require 'net/http'; require 'uri'; require 'fileutils'; require 'time'

KID = ENV.fetch('KEY_ID').strip
ISS = ENV.fetch('ISSUER').strip
BID = ENV.fetch('BUNDLE_ID').strip
KEYFILE = File.expand_path(ENV.fetch('KEYFILE'))
WORK = ENV.fetch('SIGN_DIR')
PROFILE_NAME = ENV.fetch('PROFILE_NAME')
FileUtils.mkdir_p(WORK)

def token
  key = OpenSSL::PKey.read(File.read(KEYFILE))
  b64 = ->(s) { Base64.urlsafe_encode64(s, padding: false) }
  now = Time.now.to_i
  data = b64.({ alg: 'ES256', kid: KID, typ: 'JWT' }.to_json) + '.' +
         b64.({ iss: ISS, iat: now, exp: now + 1100, aud: 'appstoreconnect-v1' }.to_json)
  seq = OpenSSL::ASN1.decode(key.sign(OpenSSL::Digest::SHA256.new, data))
  data + '.' + b64.(seq.value.map { |i| i.value.to_s(2).rjust(32, "\0") }.join)
end

def api(method, path, body = nil)
  uri = URI("https://api.appstoreconnect.apple.com#{path}")
  req = { get: Net::HTTP::Get, post: Net::HTTP::Post, delete: Net::HTTP::Delete }[method].new(uri)
  req['Authorization'] = "Bearer #{token}"
  if body
    req['Content-Type'] = 'application/json'
    req.body = body.to_json
  end
  res = Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |h| h.request(req) }
  [res.code.to_i, (res.body.to_s.empty? ? {} : JSON.parse(res.body))]
end

def fail!(msg)
  puts "::error::#{msg}"
  exit 1
end

def apple_error(j)
  (j['errors'] || []).map { |e| "#{e['title']}: #{e['detail']}" }.join(' | ')
end

case ARGV[0]
when 'setup'
  # 1. the App ID
  code, j = api(:get, "/v1/bundleIds?filter[identifier]=#{BID}&limit=20")
  fail!("Apple login failed (#{code}). Check ASC_KEY_ID, ASC_ISSUER_ID and ASC_KEY_P8.") unless code == 200
  bundle = j['data'].find { |d| d['attributes']['identifier'] == BID }
  fail!("The App ID #{BID} is not registered at developer.apple.com > Identifiers.") unless bundle

  # 2. tidy up certificates and profiles left by builds more than a day old.
  #    (Never remove them at the end of a build: Apple checks the signature
  #    while processing the upload, and a revoked certificate fails that check.)
  day_ago = Time.now - 86_400
  code, j = api(:get, '/v1/certificates?filter[certificateType]=DISTRIBUTION&limit=50')
  if code == 200
    old = j['data'].select { |c| (Time.parse(c['attributes']['expirationDate']) - 365 * 86_400) < day_ago }
    if j['data'].size >= 2
      old.each do |c|
        rc, = api(:delete, "/v1/certificates/#{c['id']}")
        puts "Revoked an old build certificate from #{(Time.parse(c['attributes']['expirationDate']) - 365 * 86_400).strftime('%b %-d')} (#{rc})."
      end
    end
  end
  code, j = api(:get, '/v1/profiles?filter[profileType]=IOS_APP_STORE&limit=200')
  if code == 200
    j['data'].each do |pr|
      next unless pr['attributes']['name'].to_s.start_with?('Say Math CI ') && pr['attributes']['name'] != PROFILE_NAME
      api(:delete, "/v1/profiles/#{pr['id']}")
    end
  end

  # 3. a fresh Apple Distribution certificate from a new private key
  key = OpenSSL::PKey::RSA.new(2048)
  File.write("#{WORK}/dist.key", key.to_pem)
  csr = OpenSSL::X509::Request.new
  csr.version = 0
  csr.subject = OpenSSL::X509::Name.parse('/CN=Say Math CI/O=Say Math')
  csr.public_key = key.public_key
  csr.sign(key, OpenSSL::Digest::SHA256.new)
  code, j = api(:post, '/v1/certificates',
                { data: { type: 'certificates', attributes: { certificateType: 'DISTRIBUTION', csrContent: csr.to_pem } } })
  unless code == 201
    fail!("Apple could not make a distribution certificate (#{code}). #{apple_error(j)} " \
          "If it says you have too many certificates, wait a day before building again, or revoke old Apple Distribution certificates at developer.apple.com > Certificates.")
  end
  cert_id = j['data']['id']
  File.write("#{WORK}/cert_id", cert_id)
  File.binwrite("#{WORK}/dist.cer", Base64.decode64(j['data']['attributes']['certificateContent']))

  # 4. an App Store provisioning profile for this app + certificate
  code, j = api(:post, '/v1/profiles', {
    data: { type: 'profiles', attributes: { name: PROFILE_NAME, profileType: 'IOS_APP_STORE' },
            relationships: { bundleId: { data: { type: 'bundleIds', id: bundle['id'] } },
                             certificates: { data: [{ type: 'certificates', id: cert_id }] } } } })
  fail!("Apple could not make the App Store profile (#{code}). #{apple_error(j)}") unless code == 201
  File.write("#{WORK}/profile_id", j['data']['id'])
  File.write("#{WORK}/profile_uuid", j['data']['attributes']['uuid'])
  File.binwrite("#{WORK}/app.mobileprovision", Base64.decode64(j['data']['attributes']['profileContent']))
  puts "Made the Apple Distribution certificate and the App Store profile \"#{PROFILE_NAME}\"."

when 'cleanup'
  if File.exist?("#{WORK}/profile_id")
    code, = api(:delete, "/v1/profiles/#{File.read("#{WORK}/profile_id").strip}")
    puts "Removed the temporary profile (#{code})."
  end
  if File.exist?("#{WORK}/cert_id")
    code, = api(:delete, "/v1/certificates/#{File.read("#{WORK}/cert_id").strip}")
    puts "Revoked the temporary certificate (#{code}). Apps already uploaded are not affected."
  end
else
  fail!('usage: asc.rb setup|cleanup')
end
