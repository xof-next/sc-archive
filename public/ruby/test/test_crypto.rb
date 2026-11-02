require 'minitest/autorun'
require_relative '../sc'

class SCArchiveV2CryptoTest < Minitest::Test
  PASSWORD = 'correct horse battery staple 2026'
  TOKEN = SCArchive.generate_recovery_token

  def setup
    
    @test_log_n = 14
    @header, @data_key, = SCArchive.build_header(PASSWORD, TOKEN, @test_log_n)
  end

  def teardown
    @data_key&.replace("\0" * @data_key.bytesize)
  end

  def test_header_has_v2_size_and_prefix
    assert_equal SCArchive::HEADER_LEN, @header.bytesize
    assert_equal 'SCAR', @header.byteslice(0, 4)
    assert_equal 2, @header.getbyte(4)
  end

  def test_password_and_recovery_token_unlock_the_same_data_key
    password_key = SCArchive.unwrap_data_key(@header, PASSWORD, :password)
    recovery_key = SCArchive.unwrap_data_key(@header, TOKEN, :recovery)

    assert_equal @data_key, password_key
    assert_equal @data_key, recovery_key
  ensure
    password_key&.replace("\0" * password_key.bytesize)
    recovery_key&.replace("\0" * recovery_key.bytesize)
  end

  def test_wrong_password_is_rejected
    error = assert_raises(SCArchive::Error) do
      SCArchive.unwrap_data_key(@header, 'an incorrect password', :password)
    end
    assert_match(/Authentication failed/, error.message)
  end

  def test_wrong_recovery_token_is_rejected
    wrong_token = SCArchive.generate_recovery_token
    error = assert_raises(SCArchive::Error) do
      SCArchive.unwrap_data_key(@header, wrong_token, :recovery)
    end
    assert_match(/Authentication failed/, error.message)
  end

  def test_header_tampering_invalidates_key_wrap
    modified = @header.dup
    modified.setbyte(4, modified.getbyte(4) ^ 1)
    error = assert_raises(SCArchive::Error) do
      SCArchive.unwrap_data_key(modified, PASSWORD, :password)
    end
    assert_match(/Authentication failed/, error.message)
  end

  def test_payload_round_trip_with_both_credentials
    Dir.mktmpdir('sc-v2-test-') do |dir|
      source = File.join(dir, 'payload.zip')
      archive = File.join(dir, 'payload.sc')
      from_password = File.join(dir, 'from-password.zip')
      from_recovery = File.join(dir, 'from-recovery.zip')
      payload = Random.new(2026).bytes(SCArchive::CHUNK_SIZE + 29)
      File.binwrite(source, payload)

      SCArchive.encrypt_zip(source, archive, PASSWORD, TOKEN, SCArchive::STANDARD_LOG_N)
      SCArchive.decrypt_archive(archive, from_password, PASSWORD, :password)
      SCArchive.decrypt_archive(archive, from_recovery, TOKEN, :recovery)

      assert_equal payload, File.binread(from_password)
      assert_equal payload, File.binread(from_recovery)
    end
  end

  def test_wrong_password_does_not_create_decrypted_output
    Dir.mktmpdir('sc-v2-test-') do |dir|
      source = File.join(dir, 'payload.zip')
      archive = File.join(dir, 'payload.sc')
      restored = File.join(dir, 'restored.zip')
      File.binwrite(source, 'encrypted-payload-fixture')
      SCArchive.encrypt_zip(source, archive, PASSWORD, TOKEN, SCArchive::STANDARD_LOG_N)

      assert_raises(SCArchive::Error) do
        SCArchive.decrypt_archive(archive, restored, 'wrong password value', :password)
      end
      refute File.exist?(restored)
    end
  end

  def test_cross_language_key_wrap_vector
    password = 'Cross-language passphrase 2026'
    token = 'A' * 43
    password_salt = 'P' * 16
    recovery_salt = 'R' * 16
    nonce_prefix = 'N' * 8
    password_nonce = 'p' * 12
    recovery_nonce = 'r' * 12
    data_key = 'D' * 32
    prefix = SCArchive.make_prefix(password_salt, recovery_salt, nonce_prefix, 14)
    password_key = SCArchive.derive_key(password, password_salt, 14)
    recovery_key = SCArchive.derive_key(token, recovery_salt, 14)

    password_wrap = SCArchive.encrypt_message(data_key, password_key, password_nonce, prefix + SCArchive::PASSWORD_AAD)
    recovery_wrap = SCArchive.encrypt_message(data_key, recovery_key, recovery_nonce, prefix + SCArchive::RECOVERY_AAD)

    assert_equal 'd38950ae3318bdd71bb554d2cba4d9dc84a9c4725dbf20ebd34d9608239fb2618e17115dc412847c2fb842a838bb517f', password_wrap.unpack1('H*')
    assert_equal 'de4645061092c8b19abcd45957b13a07c012342aa5725ce6d5977ebd21dbfac94a1d3f7399ae7b4b472e7a908e4a5d56', recovery_wrap.unpack1('H*')
  ensure
    password_key&.replace("\0" * password_key.bytesize)
    recovery_key&.replace("\0" * recovery_key.bytesize)
  end

  def test_cross_language_payload_record_vector
    password = 'Cross-language passphrase 2026'
    token = 'A' * 43
    password_salt = 'P' * 16
    recovery_salt = 'R' * 16
    nonce_prefix = 'N' * 8
    password_nonce = 'p' * 12
    recovery_nonce = 'r' * 12
    data_key = 'D' * 32
    prefix = SCArchive.make_prefix(password_salt, recovery_salt, nonce_prefix, 14)
    password_key = SCArchive.derive_key(password, password_salt, 14)
    recovery_key = SCArchive.derive_key(token, recovery_salt, 14)
    password_wrap = SCArchive.encrypt_message(data_key, password_key, password_nonce, prefix + SCArchive::PASSWORD_AAD)
    recovery_wrap = SCArchive.encrypt_message(data_key, recovery_key, recovery_nonce, prefix + SCArchive::RECOVERY_AAD)
    header = prefix + password_nonce + password_wrap + recovery_nonce + recovery_wrap
    plaintext = 'Cross-language encrypted record fixture.'
    counter = 7
    aad = header + [counter, plaintext.bytesize].pack('N2')
    nonce = nonce_prefix + [counter].pack('N')
    record = SCArchive.encrypt_message(plaintext, data_key, nonce, aad)

    assert_equal 178, header.bytesize
    assert_equal '51f23b3c7f809b82e26eb3732cca95a2778894743fcd9dc80ae12e830f35eef98b8271e6b6d12ea184ad9458122c0897b40d40635b0f79d7', record.unpack1('H*')
  ensure
    password_key&.replace("\0" * password_key.bytesize)
    recovery_key&.replace("\0" * recovery_key.bytesize)
  end

  def test_recovery_token_has_256_bits_of_random_material
    decoded = Base64.urlsafe_decode64(TOKEN + '=')
    assert_equal 32, decoded.bytesize
    assert_match(/\A[A-Za-z0-9_-]{43}\z/, TOKEN)
    assert_equal TOKEN, SCArchive.validate_recovery_token(TOKEN)
  end
end
