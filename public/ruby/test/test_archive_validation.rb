require 'minitest/autorun'
require 'tmpdir'
require_relative '../sc'

class SCArchiveValidationTest < Minitest::Test
  def test_rejects_archive_symlink
    skip 'Symlink test unavailable' if SCArchive::TokenStore.windows?
    Dir.mktmpdir do |root|
      real = File.join(root, 'real.sc')
      link = File.join(root, 'archive.sc')
      File.write(real, 'x' * (SCArchive::HEADER_LEN + 64))
      File.symlink(real, link)
      assert_raises(SCArchive::Error) { SCArchive::Security.validate_archive_file!(link) }
    end
  end

  def test_rejects_tiny_archive
    Dir.mktmpdir do |root|
      path = File.join(root, 'empty.sc')
      File.write(path, 'tiny')
      assert_raises(SCArchive::Error) { SCArchive::Security.validate_archive_file!(path) }
    end
  end

  def test_inspect_rejects_unknown_profile
    Dir.mktmpdir do |root|
      path = File.join(root, 'bad.sc')
      prefix = SCArchive.make_prefix('p' * 16, 'r' * 16, 'n' * 8, 15)
      File.binwrite(path, prefix + ('x' * (SCArchive::HEADER_LEN - SCArchive::PREFIX_LEN)) + "\0\0\0\0" + ('x' * 16))
      assert_raises(SCArchive::Error) { SCArchive.inspect_archive(path) }
    end
  end
end
