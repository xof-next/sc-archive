require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require_relative '../sc'

class SCArchiveZipSafetyTest < Minitest::Test
  def setup
    begin
      require 'zip'
    rescue LoadError
      skip 'RubyZip is not installed; ZIP integration test skipped.'
    end
  end

  def write_zip(path, entries)
    Zip::OutputStream.open(path) do |stream|
      entries.each do |name, content|
        stream.put_next_entry(name)
        stream.write(content)
      end
    end
  end

  def test_archive_entry_registry_rejects_traversal_and_collisions
    registry = {}
    assert_raises(SCArchive::Error) do
      SCArchive.safe_entry_path('../outside.txt', Dir.tmpdir)
    end
    SCArchive::Security.register_archive_path!(registry, 'safe/file.txt')
    assert_raises(SCArchive::Error) do
      SCArchive::Security.register_archive_path!(registry, 'SAFE/FILE.TXT')
    end
  end

  def test_validate_zip_rejects_parent_traversal
    Dir.mktmpdir do |directory|
      archive = File.join(directory, 'traversal.zip')
      write_zip(archive, [['../outside.txt', 'blocked']])
      assert_raises(SCArchive::Error) { SCArchive.validate_zip(archive) }
    end
  end

  def test_validate_zip_rejects_casefold_duplicate_entries
    Dir.mktmpdir do |directory|
      archive = File.join(directory, 'duplicates.zip')
      write_zip(archive, [['Folder/item.txt', 'one'], ['folder/ITEM.TXT', 'two']])
      assert_raises(SCArchive::Error) { SCArchive.validate_zip(archive) }
    end
  end

  def test_valid_zip_is_validated_and_extracted
    Dir.mktmpdir do |directory|
      archive = File.join(directory, 'safe.zip')
      output = File.join(directory, 'restored')
      write_zip(archive, [['folder/hello.txt', 'SC Archive test']])
      assert SCArchive.validate_zip(archive)
      assert SCArchive.extract_zip(archive, output)
      assert_equal 'SC Archive test', File.read(File.join(output, 'folder', 'hello.txt'))
    end
  end
end
