require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require_relative '../sc'

class SCArchiveTokenStoreTest < Minitest::Test
  def test_saves_and_reads_token_with_private_permissions
    Dir.mktmpdir do |root|
      path = File.join(root, 'archive.sc.recovery')
      token = SCArchive.generate_recovery_token
      SCArchive::TokenStore.save(token, path)
      assert_equal token, SCArchive::TokenStore.read(path)
      refute File.world_readable?(path) unless SCArchive::TokenStore.windows?
    end
  end

  def test_refuses_to_overwrite_existing_file
    Dir.mktmpdir do |root|
      path = File.join(root, 'token')
      File.write(path, 'existing')
      assert_raises(SCArchive::Error) { SCArchive::TokenStore.save(SCArchive.generate_recovery_token, path) }
      assert_equal 'existing', File.read(path)
    end
  end

  def test_rejects_world_readable_token_file
    skip 'POSIX permission check' if SCArchive::TokenStore.windows?
    Dir.mktmpdir do |root|
      path = File.join(root, 'token')
      File.write(path, SCArchive.generate_recovery_token)
      File.chmod(0o644, path)
      assert_raises(SCArchive::Error) { SCArchive::TokenStore.read(path) }
    end
  end

  def test_rejects_symlink_token_file
    skip 'Symlink test unavailable' if SCArchive::TokenStore.windows?
    Dir.mktmpdir do |root|
      real = File.join(root, 'real')
      link = File.join(root, 'link')
      File.write(real, SCArchive.generate_recovery_token)
      File.chmod(0o600, real)
      File.symlink(real, link)
      assert_raises(SCArchive::Error) { SCArchive::TokenStore.read(link) }
    end
  end
end
