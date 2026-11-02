

require 'base64'

module SCArchive
  module TokenStore
    module_function

    def save(token, path)
      path = File.expand_path(path)
      parent = File.dirname(path)
      raise Error, 'Recovery-token directory does not exist.' unless File.directory?(parent)
      flags = File::WRONLY | File::CREAT | File::EXCL
      flags |= File::NOFOLLOW if defined?(File::NOFOLLOW)
      File.open(path, flags, 0o600) do |file|
        file.write(token)
        file.write("\n")
        file.flush
        file.fsync
      end
      File.chmod(0o600, path) unless windows?
      true
    rescue Errno::EEXIST
      raise Error, 'Recovery-token file already exists; refusing to overwrite it.'
    end

    def read(path)
      path = File.expand_path(path)
      stat = File.lstat(path)
      raise Error, 'Recovery-token path must not be a symbolic link.' if stat.symlink?
      raise Error, 'Recovery-token path must be a regular file.' unless stat.file?
      unless windows?
        raise Error, 'Recovery-token file permissions are too broad; use chmod 600.' unless (stat.mode & 0o077).zero?
      end
      raise Error, 'Recovery-token file is too large.' if stat.size > 128
      flags = File::RDONLY
      flags |= File::NOFOLLOW if defined?(File::NOFOLLOW)
      value = File.open(path, flags) { |file| file.read(129) }
      raise Error, 'Recovery-token file is too large.' if value.bytesize > 128
      token = value.force_encoding(Encoding::UTF_8).strip
      Security.validate_recovery_token!(token)
      token
    rescue Errno::ENOENT
      raise Error, 'Recovery-token file does not exist.'
    ensure
      value&.replace("\0" * value.bytesize)
    end

    def windows?
      /mswin|mingw|cygwin/i.match?(RUBY_PLATFORM)
    end
  end
end
