

require 'find'
require 'pathname'

module SCArchive
  module Security
    MIN_PASSWORD_CHARS = 16
    MAX_PASSWORD_BYTES = 4096
    MAX_PATH_BYTES = 4096
    MAX_COMPONENT_BYTES = 255
    WINDOWS_RESERVED = /\A(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9]|LPT[1-9])(?:\..*)?\z/i

    module_function

    def validate_password!(password, minimum: MIN_PASSWORD_CHARS, strict: true)
      utf8_compatible = password.encoding == Encoding::UTF_8 || (password.ascii_only? && password.encoding.ascii_compatible?)
      raise Error, 'Password must be valid UTF-8.' unless password.valid_encoding? && utf8_compatible
      raise Error, "Password must contain at least #{minimum} characters." if password.each_char.count < minimum
      raise Error, "Password is too long (maximum #{MAX_PASSWORD_BYTES} UTF-8 bytes)." if password.bytesize > MAX_PASSWORD_BYTES
      if strict
        raise Error, 'Password must not contain control characters.' if password.match?(/\p{Cc}/)
        raise Error, 'Password must not consist of one repeated character.' if password.chars.uniq.length == 1
      end
      true
    end

    def validate_recovery_token!(token)
      raise Error, 'Invalid recovery token format.' unless token.is_a?(String) && token.match?(/\A[A-Za-z0-9_-]{43}\z/)
      decoded = Base64.urlsafe_decode64(token + '=')
      canonical = Base64.urlsafe_encode64(decoded, padding: false)
      raise Error, 'Invalid recovery token format.' unless decoded.bytesize == 32 && canonical == token
      true
    rescue ArgumentError
      raise Error, 'Invalid recovery token format.'
    ensure
      decoded&.replace("\0" * decoded.bytesize)
    end

    def validate_source_tree!(source)
      source = File.expand_path(source)
      root_stat = File.lstat(source)
      raise Error, 'Symbolic links are not accepted as input.' if root_stat.symlink?
      raise Error, 'Input must be a regular file or directory.' unless root_stat.file? || root_stat.directory?

      count = 0
      total = 0
      visit = lambda do |path|
        stat = File.lstat(path)
        raise Error, "Symbolic links are not accepted: #{path}" if stat.symlink?
        raise Error, "Unsupported filesystem object: #{path}" unless stat.file? || stat.directory?
        count += 1
        raise Error, 'Input contains too many filesystem entries.' if count > MAX_ENTRIES
        if stat.file?
          raise Error, 'Input file exceeds the per-file safety limit.' if stat.size > MAX_ENTRY_SIZE
          total += stat.size
          raise Error, 'Input exceeds the total archive safety limit.' if total > MAX_EXTRACT_SIZE
        end
      end

      if root_stat.directory?
        Find.find(source) do |path|
          visit.call(path)
        end
      else
        visit.call(source)
      end
      true
    rescue Errno::ENOENT
      raise Error, 'Input path does not exist.'
    end

    def canonical_future_path(path)
      cursor = File.expand_path(path)
      missing_components = []
      loop do
        if File.exist?(cursor) || File.symlink?(cursor)
          cursor = File.realpath(cursor)
          break
        end
        parent = File.dirname(cursor)
        raise Error, 'Destination path could not be normalized.' if parent == cursor
        missing_components << File.basename(cursor)
        cursor = parent
      end
      missing_components.reverse_each { |component| cursor = File.join(cursor, component) }
      cursor
    rescue Errno::ENOENT, Errno::EACCES
      raise Error, 'Destination path could not be normalized.'
    end

    def ensure_destination_outside_source!(source, destination, label)
      source = File.realpath(source)
      destination = canonical_future_path(destination)
      if File.directory?(source)
        prefix = source.end_with?(File::SEPARATOR) ? source : source + File::SEPARATOR
        raise Error, "#{label} must be outside the source directory." if destination == source || destination.start_with?(prefix)
      elsif destination == source
        raise Error, "#{label} must not overwrite the input file."
      end
      true
    end

    def validate_archive_file!(path)
      stat = File.lstat(path)
      raise Error, 'Archive path must not be a symbolic link.' if stat.symlink?
      raise Error, 'Archive path must be a regular file.' unless stat.file?
      raise Error, 'Archive file is unexpectedly small.' if stat.size < HEADER_LEN + 4 + TAG_LEN
      true
    rescue Errno::ENOENT
      raise Error, 'Archive file does not exist.'
    end

    def safe_entry_path(name, root, directory: false)
      raise Error, 'ZIP entry name is invalid.' unless name.is_a?(String) && name.valid_encoding?
      normalized = name.tr('\\', '/')
      raise Error, 'Unsafe path found in ZIP archive.' if normalized.empty? || normalized.bytesize > MAX_PATH_BYTES
      raise Error, 'Unsafe path found in ZIP archive.' if normalized.start_with?('/') || normalized.match?(/\A[A-Za-z]:/)
      raise Error, 'Unsafe path found in ZIP archive.' if normalized.include?("\0") || normalized.match?(/[\x01-\x1f\x7f]/)
      normalized = normalized.delete_suffix('/') if directory
      parts = normalized.split('/', -1)
      raise Error, 'Unsafe path found in ZIP archive.' if parts.empty? || parts.any?(&:empty?)

      parts.each do |part|
        raise Error, 'Unsafe path found in ZIP archive.' if part == '.' || part == '..'
        raise Error, 'Unsafe path found in ZIP archive.' if part.bytesize > MAX_COMPONENT_BYTES
        raise Error, 'Unsafe path found in ZIP archive.' if part.end_with?('.', ' ')
        raise Error, 'Unsafe path found in ZIP archive.' if part.include?(':')
        raise Error, 'Unsafe path found in ZIP archive.' if part.match?(WINDOWS_RESERVED)
      end

      target = File.expand_path(parts.join(File::SEPARATOR), root)
      root = File.expand_path(root)
      prefix = root.end_with?(File::SEPARATOR) ? root : root + File::SEPARATOR
      raise Error, 'Unsafe path found in ZIP archive.' unless target.start_with?(prefix)
      target
    end

    
    
    def register_archive_path!(registry, name, directory: false)
      path = name.tr('\\', '/').delete_suffix('/')
      parts = path.split('/')
      key_parts = parts.map { |part| part.unicode_normalize(:nfkc).downcase }
      key = key_parts.join('/')

      ancestors = []
      key_parts[0...-1].each do |part|
        ancestors << part
        ancestor_key = ancestors.join('/')
        ancestor = registry[ancestor_key]
        raise Error, 'ZIP file/directory path collision.' if ancestor == :file
        registry[ancestor_key] ||= :implicit_directory
      end

      current = registry[key]
      if current == :file || current == :directory
        raise Error, 'Duplicate ZIP entry or cross-platform path collision.'
      end
      if current == :implicit_directory
        raise Error, 'ZIP file/directory path collision.' unless directory
        registry[key] = :directory
      else
        registry[key] = directory ? :directory : :file
      end

      true
    end
  end
end
