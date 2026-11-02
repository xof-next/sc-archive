#!/usr/bin/env ruby



require 'openssl'
require 'securerandom'
require 'base64'
require 'tmpdir'
require 'fileutils'
require 'find'
require 'pathname'
require 'json'
require 'time'
require 'io/console'
require 'optparse'
require 'set'
require_relative 'lib/sc_archive/security'
require_relative 'lib/sc_archive/token_store'
require_relative 'lib/sc_archive/audit_log'

module SCArchive
  MAGIC = 'SCAR'.b
  FORMAT_VERSION = 2
  VERSION_TEXT = '1.0.0'
  STANDARD_LOG_N = 17
  HIGH_LOG_N = 18
  SCRYPT_R = 8
  SCRYPT_P = 1
  KEY_LEN = 32
  SALT_LEN = 16
  NONCE_LEN = 12
  NONCE_PREFIX_LEN = 8
  TAG_LEN = 16
  CHUNK_SIZE = 1_048_576
  PREFIX_LEN = 58
  WRAPPED_KEY_LEN = KEY_LEN + TAG_LEN
  HEADER_LEN = PREFIX_LEN + NONCE_LEN + WRAPPED_KEY_LEN + NONCE_LEN + WRAPPED_KEY_LEN
  MAX_ENTRIES = 50_000
  MAX_ENTRY_SIZE = 1 * 1024 * 1024 * 1024
  MAX_EXTRACT_SIZE = 4 * 1024 * 1024 * 1024
  PASSWORD_AAD = 'SCAR-V2-PASSWORD-WRAP'.b
  RECOVERY_AAD = 'SCAR-V2-RECOVERY-WRAP'.b

  class Error < StandardError; end

  module_function

  def read_secret(label)
    raise Error, 'Interactive input is required for credentials.' unless STDIN.tty?
    print label
    value = STDIN.noecho(&:gets).to_s.chomp
    puts
    value
  end

  def ask_password(confirm: false, new_archive: false)
    password = read_secret('Password: ').force_encoding(Encoding::UTF_8)
    begin
      Security.validate_password!(password, minimum: new_archive ? 16 : 12, strict: new_archive)
      if confirm
        again = read_secret('Confirm password: ').force_encoding(Encoding::UTF_8)
        begin
          raise Error, 'Passwords do not match.' unless password == again
        ensure
          again&.replace("\0" * again.bytesize)
        end
      end
      password
    rescue StandardError
      password&.replace("\0" * password.bytesize)
      raise
    end
  end

  def validate_recovery_token(token)
    Security.validate_recovery_token!(token)
    token
  end

  def generate_recovery_token
    raw = SecureRandom.random_bytes(32)
    Base64.urlsafe_encode64(raw, padding: false)
  ensure
    raw&.replace("\0" * raw.bytesize)
  end

  def derive_key(secret, salt, log_n)
    OpenSSL::KDF.scrypt(
      secret,
      salt: salt,
      N: 1 << log_n,
      r: SCRYPT_R,
      p: SCRYPT_P,
      length: KEY_LEN
    )
  rescue OpenSSL::KDF::KDFError => e
    raise Error, "Key derivation failed: #{e.message}"
  end

  def encrypt_message(plain, key, nonce, aad)
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_data = aad
    (cipher.update(plain) + cipher.final) + cipher.auth_tag(TAG_LEN)
  end

  def decrypt_message(encrypted_and_tag, key, nonce, aad)
    raise Error, 'Invalid encrypted record.' if encrypted_and_tag.bytesize < TAG_LEN
    ciphertext = encrypted_and_tag.byteslice(0, encrypted_and_tag.bytesize - TAG_LEN)
    tag = encrypted_and_tag.byteslice(-TAG_LEN, TAG_LEN)
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.decrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_tag = tag
    cipher.auth_data = aad
    cipher.update(ciphertext) + cipher.final
  rescue OpenSSL::Cipher::CipherError
    raise Error, 'Authentication failed: incorrect credential or damaged archive.'
  end

  def make_prefix(password_salt, recovery_salt, nonce_prefix, log_n)
    MAGIC + [FORMAT_VERSION, log_n].pack('CC') +
      [SCRYPT_R, SCRYPT_P].pack('NN') + password_salt + recovery_salt +
      nonce_prefix + [CHUNK_SIZE].pack('N')
  end

  def make_nonce(prefix, counter)
    prefix + [counter].pack('N')
  end

  def build_header(password, recovery_token, log_n)
    password_salt = SecureRandom.random_bytes(SALT_LEN)
    recovery_salt = SecureRandom.random_bytes(SALT_LEN)
    nonce_prefix = SecureRandom.random_bytes(NONCE_PREFIX_LEN)
    prefix = make_prefix(password_salt, recovery_salt, nonce_prefix, log_n)
    data_key = SecureRandom.random_bytes(KEY_LEN)
    password_nonce = SecureRandom.random_bytes(NONCE_LEN)
    recovery_nonce = SecureRandom.random_bytes(NONCE_LEN)
    password_key = derive_key(password, password_salt, log_n)
    recovery_key = derive_key(recovery_token, recovery_salt, log_n)
    password_wrap = encrypt_message(data_key, password_key, password_nonce, prefix + PASSWORD_AAD)
    recovery_wrap = encrypt_message(data_key, recovery_key, recovery_nonce, prefix + RECOVERY_AAD)
    header = prefix + password_nonce + password_wrap + recovery_nonce + recovery_wrap
    raise Error, 'Internal header length mismatch.' unless header.bytesize == HEADER_LEN
    [header, data_key, nonce_prefix]
  rescue StandardError
    data_key&.replace("\0" * data_key.bytesize)
    raise
  ensure
    password_key&.replace("\0" * password_key.bytesize)
    recovery_key&.replace("\0" * recovery_key.bytesize)
  end

  def unwrap_data_key(header, credential, mode)
    prefix = header.byteslice(0, PREFIX_LEN)
    log_n = header.getbyte(5)
    password_salt = header.byteslice(14, SALT_LEN)
    recovery_salt = header.byteslice(30, SALT_LEN)
    if mode == :password
      salt = password_salt
      nonce_offset = PREFIX_LEN
      wrap_offset = PREFIX_LEN + NONCE_LEN
      aad_label = PASSWORD_AAD
    else
      salt = recovery_salt
      nonce_offset = PREFIX_LEN + NONCE_LEN + WRAPPED_KEY_LEN
      wrap_offset = nonce_offset + NONCE_LEN
      aad_label = RECOVERY_AAD
    end
    key = derive_key(credential, salt, log_n)
    nonce = header.byteslice(nonce_offset, NONCE_LEN)
    wrapped = header.byteslice(wrap_offset, WRAPPED_KEY_LEN)
    data_key = decrypt_message(wrapped, key, nonce, prefix + aad_label)
    raise Error, 'Invalid wrapped data key.' unless data_key.bytesize == KEY_LEN
    data_key
  ensure
    key&.replace("\0" * key.bytesize)
  end

  def build_zip(source, zip_path)
    require 'zip'
    source = File.expand_path(source)
    Security.validate_source_tree!(source)

    Zip::File.open(zip_path, create: true) do |zip|
      registry = {}
      if File.file?(source)
        name = File.basename(source)
        safe_entry_path(name, Dir.tmpdir)
        Security.register_archive_path!(registry, name)
        zip.add(name, source)
      else
        parent = File.dirname(source)
        Find.find(source) do |entry|
          raise Error, "Symbolic links are not accepted: #{entry}" if File.symlink?(entry)
          relative = Pathname.new(entry).relative_path_from(Pathname.new(parent)).to_s.tr(File::SEPARATOR, '/')
          if File.directory?(entry)
            safe_entry_path(relative, Dir.tmpdir, directory: true)
            Security.register_archive_path!(registry, relative, directory: true)
            zip.mkdir(relative) unless zip.find_entry(relative)
          elsif File.file?(entry)
            safe_entry_path(relative, Dir.tmpdir)
            Security.register_archive_path!(registry, relative)
            zip.add(relative, entry)
          else
            raise Error, "Unsupported filesystem object: #{entry}"
          end
        end
      end
    end
  end

  def encrypt_zip(zip_path, output_path, password, recovery_token, log_n)
    header, data_key, nonce_prefix = build_header(password, recovery_token, log_n)
    created = false
    begin
      File.open(output_path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |out|
        created = true
        out.binmode
        out.write(header)
        counter = 0
        File.open(zip_path, 'rb') do |input|
          loop do
            plain = input.read(CHUNK_SIZE)
            break if plain.nil? || plain.empty?
            raise Error, 'Archive is too large for this format version.' if counter >= 0xffff_ffff
            length = plain.bytesize
            aad = header + [counter, length].pack('N2')
            encrypted = encrypt_message(plain, data_key, make_nonce(nonce_prefix, counter), aad)
            out.write([length].pack('N'))
            out.write(encrypted)
            counter += 1
          end
        end
        terminal_aad = header + [counter, 0].pack('N2')
        terminal = encrypt_message(''.b, data_key, make_nonce(nonce_prefix, counter), terminal_aad)
        out.write([0].pack('N'))
        out.write(terminal)
        out.flush
        out.fsync
      end
    rescue StandardError
      File.delete(output_path) if created && File.exist?(output_path)
      raise
    ensure
      data_key&.replace("\0" * data_key.bytesize)
    end
  end

  def read_exact(io, length)
    data = io.read(length)
    raise Error, 'Damaged or incomplete archive.' unless data && data.bytesize == length
    data
  end

  def decrypt_archive(archive_path, zip_path, credential, mode)
    Security.validate_archive_file!(archive_path)
    created = false
    data_key = nil
    begin
      File.open(archive_path, 'rb') do |input|
        prefix = read_exact(input, PREFIX_LEN)
        raise Error, 'This is not a supported SC Archive.' unless prefix.byteslice(0, 4) == MAGIC
        version = prefix.getbyte(4)
        log_n = prefix.getbyte(5)
        r, p = prefix.byteslice(6, 8).unpack('N2')
        chunk_size = prefix.byteslice(54, 4).unpack1('N')
        unless version == FORMAT_VERSION && [STANDARD_LOG_N, HIGH_LOG_N].include?(log_n) &&
               r == SCRYPT_R && p == SCRYPT_P && chunk_size == CHUNK_SIZE
          raise Error, 'Unsupported or invalid archive parameters.'
        end
        header = prefix + read_exact(input, HEADER_LEN - PREFIX_LEN)
        nonce_prefix = prefix.byteslice(46, NONCE_PREFIX_LEN)
        data_key = unwrap_data_key(header, credential, mode)
        File.open(zip_path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |out|
          created = true
          counter = 0
          total = 0
          loop do
            length = read_exact(input, 4).unpack1('N')
            if length.zero?
              terminal = read_exact(input, TAG_LEN)
              aad = header + [counter, 0].pack('N2')
              decrypt_message(terminal, data_key, make_nonce(nonce_prefix, counter), aad)
              break
            end
            raise Error, 'Invalid encrypted block size.' if length > CHUNK_SIZE
            raise Error, 'Archive contains too many blocks.' if counter >= 0xffff_ffff
            encrypted = read_exact(input, length + TAG_LEN)
            aad = header + [counter, length].pack('N2')
            plain = decrypt_message(encrypted, data_key, make_nonce(nonce_prefix, counter), aad)
            raise Error, 'Invalid decrypted block length.' unless plain.bytesize == length
            total += plain.bytesize
            raise Error, 'Decrypted payload exceeds the safety limit.' if total > MAX_EXTRACT_SIZE
            out.write(plain)
            counter += 1
          end
          raise Error, 'Unexpected trailing data in archive.' unless input.read(1).nil?
          raise Error, 'Archive payload is empty or invalid.' if counter.zero?
          out.flush
          out.fsync
        end
      end
      true
    rescue StandardError
      File.delete(zip_path) if created && File.exist?(zip_path)
      raise
    ensure
      data_key&.replace("\0" * data_key.bytesize)
    end
  end

  def safe_entry_path(name, root, directory: false)
    Security.safe_entry_path(name, root, directory: directory)
  end

  def validate_zip(zip_path, output_root: nil)
    require 'zip'
    root = output_root && File.expand_path(output_root)
    count = 0
    total_size = 0
    registry = {}
    Zip::File.open(zip_path) do |zip|
      zip.each do |entry|
        count += 1
        raise Error, 'ZIP contains too many entries.' if count > MAX_ENTRIES
        raise Error, 'Symbolic-link entries are not supported.' if entry.symlink?
        directory = entry.directory?
        safe_entry_path(entry.name, root || Dir.tmpdir, directory: directory)
        Security.register_archive_path!(registry, entry.name, directory: directory)
        if directory
          raise Error, 'ZIP directory entries must not contain file data.' unless entry.size.zero? && entry.compressed_size.zero?
          next
        end

        raise Error, 'ZIP entry exceeds the safety limit.' if entry.size > MAX_ENTRY_SIZE
        total_size += entry.size
        raise Error, 'ZIP expanded size exceeds the safety limit.' if total_size > MAX_EXTRACT_SIZE
        written = 0
        stream = entry.get_input_stream
        begin
          while (buffer = stream.read(64 * 1024)) && !buffer.empty?
            written += buffer.bytesize
            raise Error, 'ZIP entry expanded beyond its declared size.' if written > entry.size || written > MAX_ENTRY_SIZE
            raise Error, 'ZIP expanded size exceeds the safety limit.' if written + total_size - entry.size > MAX_EXTRACT_SIZE
          end
        ensure
          stream.close
        end
        raise Error, 'ZIP entry size did not match its directory record.' unless written == entry.size
      end
    end
    raise Error, 'Archive contains no entries.' if count.zero?
    true
  end

  def extract_zip(zip_path, output_root)
    require 'zip'
    FileUtils.mkdir_p(output_root, mode: 0o700)
    root = File.expand_path(output_root)
    count = 0
    total_size = 0
    registry = {}
    Zip::File.open(zip_path) do |zip|
      zip.each do |entry|
        count += 1
        raise Error, 'ZIP contains too many entries.' if count > MAX_ENTRIES
        raise Error, 'Symbolic-link entries are not supported.' if entry.symlink?
        directory = entry.directory?
        target = safe_entry_path(entry.name, root, directory: directory)
        Security.register_archive_path!(registry, entry.name, directory: directory)
        if directory
          raise Error, 'ZIP directory entries must not contain file data.' unless entry.size.zero? && entry.compressed_size.zero?
          FileUtils.mkdir_p(target, mode: 0o700)
          next
        end

        raise Error, 'ZIP entry exceeds the safety limit.' if entry.size > MAX_ENTRY_SIZE
        total_size += entry.size
        raise Error, 'ZIP expanded size exceeds the safety limit.' if total_size > MAX_EXTRACT_SIZE
        FileUtils.mkdir_p(File.dirname(target), mode: 0o700)
        raise Error, 'Extraction target unexpectedly exists.' if File.exist?(target) || File.symlink?(target)
        File.open(target, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |out|
          written = 0
          stream = entry.get_input_stream
          begin
            while (buffer = stream.read(64 * 1024)) && !buffer.empty?
              written += buffer.bytesize
              raise Error, 'ZIP entry expanded beyond its declared size.' if written > entry.size || written > MAX_ENTRY_SIZE
              raise Error, 'ZIP expanded size exceeds the safety limit.' if written + total_size - entry.size > MAX_EXTRACT_SIZE
              out.write(buffer)
            end
          ensure
            stream.close
          end
          raise Error, 'ZIP entry size did not match its directory record.' unless written == entry.size
          out.flush
          out.fsync
        end
      end
    end
    raise Error, 'Archive contains no entries.' if count.zero?
    true
  end

  def default_pack_output(source)
    expanded = File.expand_path(source)
    File.join(File.dirname(expanded), "#{File.basename(expanded)}.sc")
  end

  def default_unpack_output(archive)
    expanded = File.expand_path(archive)
    stem = File.basename(expanded).sub(/\.sc\z/i, '')
    File.join(File.dirname(expanded), "#{stem}_restored")
  end

  def save_token(token, path)
    TokenStore.save(token, path)
  end

  def read_token(path)
    TokenStore.read(path)
  end

  def audit(action, result)
    AuditLog.write(action, result, VERSION_TEXT)
  end

  def pack(source, output, obfuscation, recovery_file)
    raise Error, 'Output filename must end with .sc.' unless output.downcase.end_with?('.sc')
    Security.validate_source_tree!(source)
    raise Error, 'Output file already exists.' if File.exist?(output) || File.symlink?(output)
    Security.ensure_destination_outside_source!(source, output, 'Archive output')
    if recovery_file
      Security.ensure_destination_outside_source!(source, recovery_file, 'Recovery-token file')
      raise Error, 'Recovery-token file already exists.' if File.exist?(recovery_file) || File.symlink?(recovery_file)
      raise Error, 'Archive output and recovery-token file must be different paths.' if File.expand_path(output) == File.expand_path(recovery_file)
    end
    password = ask_password(confirm: true, new_archive: true)
    recovery_token = generate_recovery_token
    log_n = obfuscation == 'high' ? HIGH_LOG_N : STANDARD_LOG_N
    begin
      Dir.mktmpdir('sc-pack-') do |work|
        zip_path = File.join(work, 'payload.zip')
        build_zip(source, zip_path)
        encrypt_zip(zip_path, output, password, recovery_token, log_n)
      end
      if recovery_file
        begin
          save_token(recovery_token, recovery_file)
          puts "Recovery token saved: #{File.expand_path(recovery_file)}"
        rescue StandardError => e
          warn "Warning: could not save recovery token file: #{e.message}"
        end
      end
      puts "Created: #{output}"
      puts 'RECOVERY TOKEN (store this securely; it is shown only once):'
      puts recovery_token
      puts "Obfuscation: #{obfuscation}"
    ensure
      password&.replace("\0" * password.bytesize)
      recovery_token&.replace("\0" * recovery_token.bytesize)
    end
  end

  def restore(archive, output, credential, mode)
    Security.validate_archive_file!(archive)
    raise Error, 'Destination already exists; choose a new output directory.' if File.exist?(output) || File.symlink?(output)
    parent = File.dirname(File.expand_path(output))
    FileUtils.mkdir_p(parent)
    Dir.mktmpdir('sc-unpack-work-') do |work|
      zip_path = File.join(work, 'payload.zip')
      decrypt_archive(archive, zip_path, credential, mode)
      Dir.mktmpdir('.sc-extract-', parent) do |staging|
        extract_zip(zip_path, staging)
        raise Error, 'Destination appeared while extracting.' if File.exist?(output)
        File.rename(staging, output)
      end
    end
    puts "Restored: #{output}"
  end

  def inspect_archive(archive)
    Security.validate_archive_file!(archive)
    File.open(archive, 'rb') do |input|
      prefix = read_exact(input, PREFIX_LEN)
      raise Error, 'This is not a supported SC Archive.' unless prefix.byteslice(0, 4) == MAGIC
      version = prefix.getbyte(4)
      log_n = prefix.getbyte(5)
      r, p = prefix.byteslice(6, 8).unpack('N2')
      chunk_size = prefix.byteslice(54, 4).unpack1('N')
      unless version == FORMAT_VERSION && [STANDARD_LOG_N, HIGH_LOG_N].include?(log_n) &&
             r == SCRYPT_R && p == SCRYPT_P && chunk_size == CHUNK_SIZE
        raise Error, 'Unsupported or invalid archive parameters.'
      end
      puts "Format: SCAR v#{version}"
      puts "Profile: #{log_n == HIGH_LOG_N ? 'high' : 'standard'}"
      puts "KDF: scrypt (N=2^#{log_n}, r=#{r}, p=#{p})"
      puts 'Payload: AES-256-GCM, 1 MiB authenticated records'
      puts "Archive size: #{File.size(archive)} bytes"
    end
  end

  def verify_archive(archive, credential, mode)
    Security.validate_archive_file!(archive)
    Dir.mktmpdir('sc-verify-') do |work|
      zip_path = File.join(work, 'payload.zip')
      decrypt_archive(archive, zip_path, credential, mode)
      validate_zip(zip_path)
    end
    puts 'Verification: passed (credential, authenticated records, terminal tag, ZIP structure)'
  end

  def main(argv)
    command = argv.shift
    if command.nil? || %w[help --help -h].include?(command)
      puts usage
      return 0
    end
    if %w[--version -v version].include?(command)
      puts "SC Archive #{VERSION_TEXT}"
      return 0
    end

    case command
    when 'inspect'
      archive = argv.shift or raise Error, 'Usage: sc inspect ARCHIVE.sc'
      raise Error, "Unexpected argument: #{argv.first}" unless argv.empty?
      inspect_archive(File.expand_path(archive))
      audit('inspect', 'ok')
    when 'verify'
      options = { token_file: nil }
      parser = OptionParser.new do |opts|
        opts.banner = 'Usage: sc verify [OPTIONS] ARCHIVE.sc'
        opts.on('--token-file PATH', 'Verify with the admin recovery token from a protected file') { |value| options[:token_file] = value }
        opts.on('-h', '--help', 'Show command help') { puts opts; return 0 }
      end
      parser.parse!(argv)
      archive = argv.shift or raise Error, parser.to_s
      raise Error, "Unexpected argument: #{argv.first}" unless argv.empty?
      if options[:token_file]
        credential = read_token(options[:token_file])
        mode = :recovery
      else
        credential = ask_password
        mode = :password
      end
      begin
        verify_archive(File.expand_path(archive), credential, mode)
      ensure
        credential&.replace("\0" * credential.bytesize)
      end
      audit('verify', 'ok')
    when 'pack'
      options = { obfuscation: 'standard', recovery_file: nil, output: nil }
      parser = OptionParser.new do |opts|
        opts.banner = 'Usage: sc pack [OPTIONS] INPUT'
        opts.on('-o', '--output PATH', 'Output archive path (must end in .sc)') { |value| options[:output] = value }
        opts.on('--obfuscation LEVEL', %w[standard high], 'Obfuscation profile: standard or high') { |value| options[:obfuscation] = value }
        opts.on('--recovery-file PATH', 'Save the one-time admin recovery token to a new file') { |value| options[:recovery_file] = value }
        opts.on('-h', '--help', 'Show command help') { puts opts; return 0 }
      end
      parser.parse!(argv)
      source = argv.shift or raise Error, parser.to_s
      raise Error, "Unexpected argument: #{argv.first}" unless argv.empty?
      output = options[:output] || default_pack_output(source)
      pack(File.expand_path(source), File.expand_path(output), options[:obfuscation], options[:recovery_file] && File.expand_path(options[:recovery_file]))
      audit('pack', 'ok')
    when 'unpack', 'recover'
      options = { output: nil, token_file: nil }
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: sc #{command} [OPTIONS] ARCHIVE.sc"
        opts.on('-C', '--output-dir PATH', 'Restore into a new directory') { |value| options[:output] = value }
        if command == 'recover'
          opts.on('--token-file PATH', 'Read the recovery token from a protected file') { |value| options[:token_file] = value }
        end
        opts.on('-h', '--help', 'Show command help') { puts opts; return 0 }
      end
      parser.parse!(argv)
      archive = argv.shift or raise Error, parser.to_s
      raise Error, "Unexpected argument: #{argv.first}" unless argv.empty?
      output = File.expand_path(options[:output] || default_unpack_output(archive))
      if command == 'unpack'
        credential = ask_password
        begin
          restore(File.expand_path(archive), output, credential, :password)
        ensure
          credential&.replace("\0" * credential.bytesize)
        end
      else
        token = if options[:token_file]
                  read_token(options[:token_file])
                else
                  read_secret('Admin recovery token: ')
                end
        validate_recovery_token(token)
        begin
          restore(File.expand_path(archive), output, token, :recovery)
        ensure
          token&.replace("\0" * token.bytesize)
        end
      end
      audit(command, 'ok')
    else
      raise Error, "Unknown command: #{command}\n#{usage}"
    end
    0
  end

  def usage
    <<~TEXT
      SC Archive #{VERSION_TEXT}
      Encrypted .sc archives with Ruby/Rust-compatible format.

      Usage:
        sc pack [OPTIONS] INPUT
        sc unpack [OPTIONS] ARCHIVE.sc
        sc recover [OPTIONS] ARCHIVE.sc
        sc inspect ARCHIVE.sc
        sc verify [--token-file PATH] ARCHIVE.sc
        sc --help
        sc --version

      Commands:
        pack       Create an encrypted archive and a one-time recovery token.
        unpack     Restore an archive using its password.
        recover    Restore an archive using its admin recovery token.
        inspect    Display non-secret archive metadata without unlocking it.
        verify     Authenticate the archive and validate its ZIP structure.

      Pack options:
        -o, --output PATH          Output path (default: INPUT.sc beside INPUT)
            --obfuscation LEVEL    standard or high (default: standard)
            --recovery-file PATH   Save the recovery token to a new file

      Restore options:
        -C, --output-dir PATH      Destination directory (must not exist)
            --token-file PATH      Read token from file (recover only)

      Examples:
        ./sc.sh pack . --obfuscation high --recovery-file ./project.sc.recovery
        ./sc.sh pack ./project -o ./backup.sc
        ./sc.sh unpack ./backup.sc -C ./restored
        ./sc.sh inspect ./backup.sc
        ./sc.sh verify ./backup.sc
        ./admin/recover.sh ./backup.sc -C ./restored --token-file ./backup.sc.recovery

      Passwords and recovery tokens are never accepted as command-line arguments.
      Passwords must contain at least 16 characters and no control characters.
      Input symlinks, ZIP path traversal, duplicate paths and unsafe file names are rejected.
    TEXT
  end
end

if $PROGRAM_NAME == __FILE__
  action = ARGV.first || 'help'
  begin
    exit SCArchive.main(ARGV)
  rescue Interrupt
    SCArchive.audit(action, 'interrupted')
    warn "\nCancelled."
    exit 130
  rescue StandardError => e
    SCArchive.audit(action, 'error')
    warn "Error: #{e.message}"
    exit 1
  end
end
