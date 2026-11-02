require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require 'base64'
require_relative '../sc'

class SCArchiveSecurityTest < Minitest::Test
  def test_accepts_long_passphrase
    assert SCArchive::Security.validate_password!('correct horse battery staple')
  end

  def test_rejects_short_password
    error = assert_raises(SCArchive::Error) do
      SCArchive::Security.validate_password!('short password')
    end
    assert_match(/at least 16/, error.message)
  end

  def test_rejects_repeated_character_password
    assert_raises(SCArchive::Error) do
      SCArchive::Security.validate_password!('aaaaaaaaaaaaaaaa')
    end
  end

  def test_rejects_control_characters_in_password
    assert_raises(SCArchive::Error) do
      SCArchive::Security.validate_password!("valid-looking-pass\nphrase")
    end
  end

  def test_rejects_path_traversal_variants
    Dir.mktmpdir do |root|
      ['../escape', '/absolute', 'C:/drive', 'folder/../../escape', 'folder\\..\\escape'].each do |path|
        assert_raises(SCArchive::Error, path) do
          SCArchive.safe_entry_path(path, root)
        end
      end
    end
  end

  def test_rejects_windows_special_names_and_alternate_streams
    Dir.mktmpdir do |root|
      ['CON', 'nul.txt', 'folder/file:stream', 'trailing.', 'trailing '].each do |path|
        assert_raises(SCArchive::Error, path) do
          SCArchive.safe_entry_path(path, root)
        end
      end
    end
  end

  def test_accepts_portable_relative_paths
    Dir.mktmpdir do |root|
      assert_equal File.join(root, 'folder', 'file.txt'),
        SCArchive.safe_entry_path('folder/file.txt', root)
      assert_equal File.join(root, 'folder'),
        SCArchive.safe_entry_path('folder/', root, directory: true)
    end
  end

  def test_rejects_duplicate_and_casefold_collisions
    registry = {}
    SCArchive::Security.register_archive_path!(registry, 'Folder/a.txt')
    assert_raises(SCArchive::Error) do
      SCArchive::Security.register_archive_path!(registry, 'folder/A.TXT')
    end
  end

  def test_rejects_file_directory_collisions
    registry = {}
    SCArchive::Security.register_archive_path!(registry, 'root/file')
    assert_raises(SCArchive::Error) do
      SCArchive::Security.register_archive_path!(registry, 'root/file/child')
    end
  end

  def test_rejects_symlinks_in_source_tree
    Dir.mktmpdir do |root|
      source = File.join(root, 'source')
      FileUtils.mkdir_p(source)
      File.write(File.join(source, 'real.txt'), 'safe')
      File.symlink(File.join(source, 'real.txt'), File.join(source, 'link.txt'))
      assert_raises(SCArchive::Error) { SCArchive::Security.validate_source_tree!(source) }
    end
  end

  def test_rejects_output_inside_source_directory
    Dir.mktmpdir do |root|
      source = File.join(root, 'project')
      FileUtils.mkdir_p(source)
      assert_raises(SCArchive::Error) do
        SCArchive::Security.ensure_destination_outside_source!(source, File.join(source, 'archive.sc'), 'Output')
      end
    end
  end

  def test_validates_recovery_token_length_and_encoding
    token = SCArchive.generate_recovery_token
    assert_equal token, SCArchive.validate_recovery_token(token)
    assert_raises(SCArchive::Error) { SCArchive.validate_recovery_token('not-a-token') }
  end
  def test_rejects_non_canonical_base64url_recovery_token
    token = 'A' * 42 + 'B'
    assert_raises(SCArchive::Error) { SCArchive.validate_recovery_token(token) }
  end

  def test_legacy_passwords_remain_usable_for_existing_archives
    assert SCArchive::Security.validate_password!('aaaaaaaaaaaa', minimum: 12, strict: false)
    assert_raises(SCArchive::Error) do
      SCArchive::Security.validate_password!('aaaaaaaaaaaa', minimum: 16, strict: true)
    end
  end

  def test_rejects_unicode_compatibility_collisions
    registry = {}
    SCArchive::Security.register_archive_path!(registry, "Ａ/file.txt")
    assert_raises(SCArchive::Error) do
      SCArchive::Security.register_archive_path!(registry, 'A/file.txt')
    end
  end

  def test_resolves_symlinked_ancestor_when_destination_suffix_is_missing
    skip 'Symlink test unavailable' if SCArchive::TokenStore.windows?
    Dir.mktmpdir do |root|
      real = File.join(root, 'real')
      source = File.join(real, 'project')
      FileUtils.mkdir_p(source)
      alias_path = File.join(root, 'alias')
      File.symlink(real, alias_path)
      destination = File.join(alias_path, 'project', 'not-created', 'archive.sc')
      assert_raises(SCArchive::Error) do
        SCArchive::Security.ensure_destination_outside_source!(source, destination, 'Output')
      end
    end
  end

  def test_resolves_symlinked_destination_parent_before_containment_check
    skip 'Symlink test unavailable' if SCArchive::TokenStore.windows?
    Dir.mktmpdir do |root|
      real = File.join(root, 'real')
      alias_path = File.join(root, 'alias')
      source = File.join(real, 'project')
      FileUtils.mkdir_p(source)
      File.symlink(real, alias_path)
      assert_raises(SCArchive::Error) do
        SCArchive::Security.ensure_destination_outside_source!(source, File.join(alias_path, 'project', 'output.sc'), 'Output')
      end
    end
  end

end
