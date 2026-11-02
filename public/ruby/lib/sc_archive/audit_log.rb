

require 'json'
require 'fileutils'

module SCArchive
  module AuditLog
    MAX_BYTES = 1_048_576
    ROTATIONS = 3

    module_function

    def write(action, result, version)
      directory = File.join(Dir.home, '.sc-archive')
      if File.exist?(directory) || File.symlink?(directory)
        directory_stat = File.lstat(directory)
        raise Error, 'Audit directory must not be a symbolic link.' if directory_stat.symlink?
        raise Error, 'Audit path must be a directory.' unless directory_stat.directory?
      else
        Dir.mkdir(directory, 0o700)
      end
      File.chmod(0o700, directory) unless TokenStore.windows?

      path = File.join(directory, 'audit.jsonl')
      if File.exist?(path) || File.symlink?(path)
        path_stat = File.lstat(path)
        raise Error, 'Audit log must be a regular file, not a symbolic link.' if path_stat.symlink? || !path_stat.file?
        rotate(path) if path_stat.size >= MAX_BYTES
      end
      flags = File::WRONLY | File::CREAT | File::APPEND
      flags |= File::NOFOLLOW if defined?(File::NOFOLLOW)
      record = {
        at_unix: Time.now.to_i,
        action: action.to_s,
        result: result.to_s,
        version: version.to_s
      }
      File.open(path, flags, 0o600) do |file|
        raise Error, 'Audit log must be a regular file.' unless file.stat.file?
        file.chmod(0o600) unless TokenStore.windows?
        file.flock(File::LOCK_EX)
        file.write(JSON.generate(record) + "\n")
        file.flush
        file.fsync
      end
      true
    rescue StandardError
      warn 'Warning: local audit log could not be written.'
      false
    end

    def rotate(path)
      ROTATIONS.downto(1) do |index|
        source = index == 1 ? path : "#{path}.#{index - 1}"
        destination = "#{path}.#{index}"
        next unless File.file?(source) && !File.symlink?(source)
        if File.exist?(destination) || File.symlink?(destination)
          destination_stat = File.lstat(destination)
          raise Error, 'Refusing to rotate a non-regular audit file.' if destination_stat.symlink? || !destination_stat.file?
        end
        File.rename(source, destination)
      end
    end
  end
end
