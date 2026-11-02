require 'minitest/autorun'
require 'tmpdir'
require_relative '../sc'

class SCArchiveAuditLogTest < Minitest::Test
  def test_symlinked_audit_file_is_not_followed
    Dir.mktmpdir do |home|
      original_home = Dir.home
      Dir.singleton_class.send(:define_method, :home) { home }
      audit_dir = File.join(home, '.sc-archive')
      Dir.mkdir(audit_dir, 0o700)
      external = File.join(home, 'external.txt')
      File.write(external, "do-not-modify\n")
      File.symlink(external, File.join(audit_dir, 'audit.jsonl'))

      assert_output(nil, /Warning: local audit log could not be written/) do
        SCArchive.audit('pack', 'ok')
      end
      assert_equal "do-not-modify\n", File.read(external)
    ensure
      Dir.singleton_class.send(:define_method, :home) { original_home }
    end
  end

  def test_audit_record_does_not_accept_or_store_paths_or_credentials
    Dir.mktmpdir do |home|
      original_home = Dir.home
      Dir.singleton_class.send(:define_method, :home) { home }
      SCArchive.audit('pack', 'ok')
      content = File.read(File.join(home, '.sc-archive', 'audit.jsonl'))
      assert_includes content, '"action":"pack"'
      refute_includes content, 'password'
      refute_includes content, 'secret-token'
      refute_includes content, '/sensitive/path'
    ensure
      Dir.singleton_class.send(:define_method, :home) { original_home }
    end
  end
end
